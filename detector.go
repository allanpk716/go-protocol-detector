package Detector

import (
	"bytes"
	"github.com/allanpk716/go-protocol-detector/FTPFeature"
	"github.com/allanpk716/go-protocol-detector/Model"
	"github.com/allanpk716/go-protocol-detector/RDPFeature"
	"github.com/allanpk716/go-protocol-detector/SSHFeature"
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
	timeout := 3 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return ErrRDPNotFound
	}
	if conn != nil {
		defer conn.Close()
	}
	_, err = conn.Write(d.rdp.SenderPackage)
	if err != nil {
		return ErrRDPNotFound
	}
	var readBuf = make([]byte, len(d.rdp.ReceiverFeature))
	_, err = conn.Read(readBuf)
	if err != nil {
		return ErrRDPNotFound
	}
	if bytes.Equal(d.rdp.ReceiverFeature, readBuf) == true {
		return nil
	} else {
		return ErrRDPNotFound
	}
}

func (d Detector) SSHCheck(host, port string) error {
	return d.commonCheck(host, port, d.ssh.SenderPackage, d.ssh.ReceiverFeatures, ErrSSHNotFound)
}

func (d Detector) FTPCheck(host, port string) error {
	return d.commonCheck(host, port, d.ftp.SenderPackage, d.ftp.ReceiverFeatures, ErrFTPNotFound)
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