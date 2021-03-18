package Detector

import (
	"bytes"
	"github.com/allanpk716/go-protocol-detector/CustomError"
	"github.com/allanpk716/go-protocol-detector/FTPFeature"
	"github.com/allanpk716/go-protocol-detector/Model"
	"github.com/allanpk716/go-protocol-detector/RDPFeature"
	"github.com/allanpk716/go-protocol-detector/SFTPFeature"
	"github.com/allanpk716/go-protocol-detector/SSHFeature"
	"github.com/allanpk716/go-protocol-detector/TelnetFeature"
	"github.com/allanpk716/go-protocol-detector/VNCFeature"
	"net"
	"time"
)
type Detector struct {
	rdp		*RDPFeature.RDPHelper
	ssh		*SSHFeature.SSHHelper
	ftp		*FTPFeature.FTPHelper
	timeOut time.Duration
}

func NewDetector(timeOut time.Duration) *Detector {
	d := Detector{
		rdp: RDPFeature.NewRDPHelper(),
		ssh: SSHFeature.NewSSHHelper(),
		ftp: FTPFeature.NewFTPHelper(),
		timeOut: timeOut,
	}
	return &d
}

func (d Detector) RDPCheck(host, port string) error {
	return d.commonCheck(host, port, d.rdp.SenderPackage, d.rdp.ReceiverFeatures, CustomError.ErrRDPNotFound)
}

func (d Detector) SSHCheck(host, port string) error {
	return d.commonCheck(host, port, d.ssh.SenderPackage, d.ssh.ReceiverFeatures, CustomError.ErrSSHNotFound)
}

func (d Detector) FTPCheck(host, port string) error {
	return d.commonCheck(host, port, d.ftp.SenderPackage, d.ftp.ReceiverFeatures, CustomError.ErrFTPNotFound)
}

func (d Detector) SFTPCheck(host, port, user, password, privateKeyFullPath string) error {
	return SFTPFeature.NewSFTPHelper(host, port, d.timeOut).Check(user, password, privateKeyFullPath)
}

func (d Detector) TelnetCheck(host, port string) error {

	tel, err := TelnetFeature.NewTelnetHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CustomError.ErrTelnetNotFound
	}
	n, err := tel.Check()
	if err != nil || n <= 0 {
		return CustomError.ErrTelnetNotFound
	}
	return nil
}

func (d Detector) VNCCheck(host, port string) error {

	vnc, err := VNCFeature.NewVNCHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CustomError.ErrVNCNotFound
	}
	return vnc.Check()
}

func (d Detector) commonCheck(host string, port string,
	senderPackage []byte, recFeatures []Model.ReceiverFeature, outErr error) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return outErr
	}
	if conn != nil {
		defer conn.Close()
	}
	_, err = conn.Write(senderPackage)
	if err != nil {
		return outErr
	}
	lastFeature := recFeatures[len(recFeatures)-1]
	readBytesLen := lastFeature.StartIndex + len(lastFeature.FeatureBytes)
	var readBuf = make([]byte, readBytesLen)
	err = conn.SetReadDeadline(time.Now().Add(d.timeOut))
	if err != nil {
		return CustomError.ErrTelnetNotFound
	}
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