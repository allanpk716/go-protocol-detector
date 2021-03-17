package detector

import (
	"bytes"
	"github.com/allanpk716/go-protocol-detector/RDPFeature"
	"github.com/allanpk716/go-protocol-detector/SSHFeature"
	"net"
	"time"
)

type Detector struct {
	rdp		*RDPFeature.RDPHelper
	ssh		*SSHFeature.SSHHelper
}

func NewDetector() *Detector {
	d := Detector{
		rdp: RDPFeature.NewRDPHelper(),
		ssh: SSHFeature.NewSSHHelper(),
	}
	return &d
}

func (d Detector) RDPCheck(host, port string) error {
	timeout := time.Second
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
	timeout := time.Second
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return err
	}
	if conn != nil {
		defer conn.Close()
	}
	_, err = conn.Write(d.ssh.SenderPackage)
	if err != nil {
		return err
	}
	lastFeature := d.ssh.ReceiverFeatures[len(d.ssh.ReceiverFeatures) - 1]
	readBytesLen := lastFeature.StartIndex + len(lastFeature.FeatureBytes)
	var readBuf = make([]byte, readBytesLen)
	_, err = conn.Read(readBuf)
	if err != nil {
		return err
	}
	// according to the features
	for _, feature := range d.ssh.ReceiverFeatures {
		if bytes.Equal(readBuf[feature.StartIndex:feature.StartIndex + len(feature.FeatureBytes)], feature.FeatureBytes) == false {
			return ErrSSHNotFound
		}
	}

	return nil
}