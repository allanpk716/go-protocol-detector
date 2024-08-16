package sftp

import (
	"github.com/TheBestLL/go-protocol-detector/internal/custom_error"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
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
		// use private key login, password belong to private key
		keyData, err := ioutil.ReadFile(priKeyFullPath)
		if err != nil {
			return err
		}
		var signer ssh.Signer
		if password != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(password))
			if err != nil {
				return err
			}
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
			if err != nil {
				return err
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
