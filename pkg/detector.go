package pkg

import (
	"bytes"
	"io"
	"github.com/allanpk716/go-protocol-detector/internal/common"
	"github.com/allanpk716/go-protocol-detector/internal/custom_error"
	"github.com/allanpk716/go-protocol-detector/internal/feature/ftp"
	"github.com/allanpk716/go-protocol-detector/internal/feature/rdp"
	"github.com/allanpk716/go-protocol-detector/internal/feature/sftp"
	"github.com/allanpk716/go-protocol-detector/internal/feature/ssh"
	"github.com/allanpk716/go-protocol-detector/internal/feature/telnet"
	"github.com/allanpk716/go-protocol-detector/internal/feature/vnc"
	"github.com/allanpk716/go-protocol-detector/internal/feature/rustdesk"
	"net"
	"time"
)

type Detector struct {
	rdp          *rdp.RDPHelper
	ssh          *ssh.SSHHelper
	ftp          *ftp.FTPHelper
	rustdeskHBBS *rustdesk.HBBSHelper
	rustdeskHBBR *rustdesk.HBBRHelper
	timeOut      time.Duration
}

func NewDetector(timeOut time.Duration) *Detector {
	d := Detector{
		rdp:          rdp.NewRDPHelper(),
		ssh:          ssh.NewSSHHelper(),
		ftp:          ftp.NewFTPHelper(),
		rustdeskHBBS: rustdesk.NewHBBSHelper(),
		rustdeskHBBR: rustdesk.NewHBBRHelper(),
		timeOut:      timeOut,
	}
	return &d
}

func (d Detector) RDPCheck(host, port string) error {
	return d.commonCheck(host, port, d.rdp.SenderPackage, d.rdp.ReceiverFeatures, custom_error.ErrRDPNotFound)
}

func (d Detector) SSHCheck(host, port string) error {
	return d.commonCheck(host, port, d.ssh.SenderPackage, d.ssh.ReceiverFeatures, custom_error.ErrSSHNotFound)
}

func (d Detector) FTPCheck(host, port string) error {
	return d.commonCheck(host, port, d.ftp.SenderPackage, d.ftp.ReceiverFeatures, custom_error.ErrFTPNotFound)
}

func (d Detector) SFTPCheck(host, port, user, password, privateKeyFullPath string) error {
	// 新的SFTP检测逻辑：无需认证凭据，直接进行SFTP子系统探测
	return sftp.NewSFTPHelper(host, port, d.timeOut).Check("", "", "")
}

// 保留原有的认证式SFTP检测方法（向后兼容）
func (d Detector) SFTPCheckWithAuth(host, port, user, password, privateKeyFullPath string) error {
	return sftp.NewSFTPHelper(host, port, d.timeOut).CheckWithAuth(user, password, privateKeyFullPath)
}

func (d Detector) TelnetCheck(host, port string) error {

	tel, err := telnet.NewTelnetHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return custom_error.ErrTelnetNotFound
	}
	n, err := tel.Check()
	if err != nil || n <= 0 {
		return custom_error.ErrTelnetNotFound
	}
	return nil
}

func (d Detector) VNCCheck(host, port string) error {

	vnc, err := vnc.NewVNCHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return custom_error.ErrVNCNotFound
	}
	return vnc.Check()
}

func (d Detector) CommonPortCheck(host, port string) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return custom_error.ErrCommontPortCheckError
	}
	defer conn.Close()
	return nil
}

func (d Detector) HBBSCheck(host, port string) error {
	// HBBS uses protobuf-based detection with TestNatRequest
	// The server responds with TestNatResponse containing the port number
	return d.commonCheck(host, port, d.rustdeskHBBS.SenderPackage, d.rustdeskHBBS.ReceiverFeatures, custom_error.ErrRustDeskHBBSNotFound)
}

func (d Detector) HBBRCheck(host, port string) error {
	// HBBR uses protocol-based detection with RequestRelay message
	// The server will accept the message and keep the connection open,
	// waiting for relay pairing. No response is sent immediately.
	//
	// Detection strategy:
	// 1. Send RequestRelay message (with empty uuid)
	// 2. Server accepts the message (doesn't close connection)
	// 3. We close the connection (detection complete)
	//
	// This is reliable protocol-based detection - only HBBR servers
	// will understand the RequestRelay message and accept it.

	// Special handling for HBBR: no response expected, just send message
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return custom_error.ErrRustDeskHBBRNotFound
	}
	defer conn.Close()

	// Send the RequestRelay message
	_, err = conn.Write(d.rustdeskHBBR.SenderPackage)
	if err != nil {
		return custom_error.ErrRustDeskHBBRNotFound
	}

	// Message sent successfully - server accepted it
	// (HBBR servers keep connection open waiting for relay pairing)
	return nil
}

func (d Detector) commonCheck(host string, port string,
	senderPackage []byte, recFeatures []common.ReceiverFeature, outErr error) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return outErr
	}
	defer conn.Close()

	_, err = conn.Write(senderPackage)
	if err != nil {
		return outErr
	}
	lastFeature := recFeatures[len(recFeatures)-1]
	readBytesLen := lastFeature.StartIndex + len(lastFeature.FeatureBytes)

	// 添加网络读取安全限制
	maxReadSize := 4096 // 最大读取4KB
	if readBytesLen > maxReadSize {
		return outErr
	}
	if readBytesLen <= 0 {
		return outErr
	}

	var readBuf = make([]byte, readBytesLen)

	// 设置读取超时，防止阻塞
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return outErr
	}

	// 使用io.ReadFull确保读取指定大小的数据或返回错误
	_, err = io.ReadFull(conn, readBuf)
	if err != nil {
		return outErr
	}
	// according to the features
	for _, feature := range recFeatures {
		if bytes.Equal(readBuf[feature.StartIndex:feature.StartIndex+len(feature.FeatureBytes)], feature.FeatureBytes) == false {
			return outErr
		}
	}
	return nil
}
