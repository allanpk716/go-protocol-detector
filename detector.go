package detector

import (
	"bytes"
	"github.com/allanpk716/go-protocol-detector/RDPFeature"
	"net"
	"time"
)

type Detector struct {
	rdp		*RDPFeature.RDPHelper
}

func NewDetector() *Detector {
	d := Detector{
		rdp: RDPFeature.NewRDPHelper(),
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