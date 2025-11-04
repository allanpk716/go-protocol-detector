package sftp

import (
	"fmt"
	"net"
	"github.com/allanpk716/go-protocol-detector/internal/custom_error"
	"github.com/allanpk716/go-protocol-detector/internal/utils"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"time"
)

type SFTPHelper struct {
	uri     string
	timeout time.Duration
}

func NewSFTPHelper(host, port string, timeout time.Duration) *SFTPHelper {
	uri := net.JoinHostPort(host, port)
	sftpHelper := SFTPHelper{
		uri:     uri,
		timeout: timeout,
	}
	return &sftpHelper
}

func (s SFTPHelper) Check(user, password, priKeyFullPath string) error {

	var authMethod ssh.AuthMethod
	// use password login
	if priKeyFullPath == "" {
		authMethod = ssh.Password(password)
	} else {
		// 验证私钥文件路径是否安全
		if err := utils.ValidatePrivateKeyPath(priKeyFullPath); err != nil {
			return fmt.Errorf("invalid private key path: %w", err)
		}

		// use private key login, password belong to private key
		keyData, err := os.ReadFile(priKeyFullPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file %s: %w", filepath.Base(priKeyFullPath), err)
		}

		var signer ssh.Signer
		if password != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(password))
			if err != nil {
				return fmt.Errorf("failed to parse private key with passphrase: %w", err)
			}
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
			if err != nil {
				return fmt.Errorf("failed to parse private key: %w", err)
			}
		}
		authMethod = ssh.PublicKeys(signer)
	}

	return s.check(user, authMethod)
}

func (s SFTPHelper) check(user string, authMethod ssh.AuthMethod) error {
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.timeout,
	}
	sshCon, channel, req, err := ssh.NewClientConn(netConn, s.uri, config)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	sshClient := ssh.NewClient(sshCon, channel, req)
	ftp, err := sftp.NewClient(sshClient)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	// read a directory
	_, err = ftp.ReadDir("/")
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	return nil
}
