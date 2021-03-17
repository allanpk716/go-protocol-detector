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
}

func NewDetector() *Detector {
	d := Detector{
		rdp: RDPFeature.NewRDPHelper(),
		ssh: SSHFeature.NewSSHHelper(),
		ftp: FTPFeature.NewFTPHelper(),
	}
	return &d
}

func (d Detector) RDPCheck(host, port string) error {
	timeout := 3 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return err
	}
	if conn != nil {
		defer conn.Close()
	}
	_, err = conn.Write(d.rdp.SenderPackage)
	if err != nil {
		return err
	}
	var readBuf = make([]byte, len(d.rdp.ReceiverFeature))
	_, err = conn.Read(readBuf)
	if err != nil {
		return err
	}
	if bytes.Equal(d.rdp.ReceiverFeature, readBuf) == true {
		return nil
	} else {
		return ErrRDPNotFound
	}
}

func (d Detector) SSHCheck(host, port string) error {
	err2, done := d.commonCheck(host, port, d.ssh.SenderPackage, d.ssh.ReceiverFeatures, ErrSSHNotFound)
	if done {
		return err2
	}
	return nil
}

func (d Detector) FTPCheck(host, port string) error {
	err2, done := d.commonCheck(host, port, d.ftp.SenderPackage, d.ftp.ReceiverFeatures, ErrFTPNotFound)
	if done {
		return err2
	}
	return nil
}

func (d Detector) commonCheck(host string, port string,
	senderPackage []byte, recFeatures []Model.ReceiverFeature, outErr error) (error, bool) {
	timeout := 3 * time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return err, true
	}
	if conn != nil {
		defer conn.Close()
	}
	_, err = conn.Write(senderPackage)
	if err != nil {
		return err, true
	}
	lastFeature := recFeatures[len(recFeatures)-1]
	readBytesLen := lastFeature.StartIndex + len(lastFeature.FeatureBytes)
	var readBuf = make([]byte, readBytesLen)
	_, err = conn.Read(readBuf)
	if err != nil {
		return err, true
	}
	// according to the features
	for _, feature := range recFeatures {
		if bytes.Equal(readBuf[feature.StartIndex:feature.StartIndex+len(feature.FeatureBytes)], feature.FeatureBytes) == false {
			return outErr, true
		}
	}
	return nil, false
}