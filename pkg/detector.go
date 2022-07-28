package pkg

import (
	"bytes"
	"github.com/allanpk716/go-protocol-detector/internal/common"
	"github.com/allanpk716/go-protocol-detector/internal/custom_error"
	"github.com/allanpk716/go-protocol-detector/internal/feature/ftp"
	"github.com/allanpk716/go-protocol-detector/internal/feature/rdp"
	"github.com/allanpk716/go-protocol-detector/internal/feature/sftp"
	"github.com/allanpk716/go-protocol-detector/internal/feature/ssh"
	"github.com/allanpk716/go-protocol-detector/internal/feature/telnet"
	"github.com/allanpk716/go-protocol-detector/internal/feature/vnc"
	"net"
	"time"
)

type Detector struct {
	rdp     *rdp.RDPHelper
	ssh     *ssh.SSHHelper
	ftp     *ftp.FTPHelper
	timeOut time.Duration
}

func NewDetector(timeOut time.Duration) *Detector {
	d := Detector{
		rdp:     rdp.NewRDPHelper(),
		ssh:     ssh.NewSSHHelper(),
		ftp:     ftp.NewFTPHelper(),
		timeOut: timeOut,
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
	return sftp.NewSFTPHelper(host, port, d.timeOut).Check(user, password, privateKeyFullPath)
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
	var readBuf = make([]byte, readBytesLen)
	_, err = conn.Read(readBuf)
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
