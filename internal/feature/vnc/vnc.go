package vnc

import (
	"bytes"
	"github.com/TheBestLL/go-protocol-detector/internal/common"
	"github.com/TheBestLL/go-protocol-detector/internal/custom_error"
	"net"
	"time"
)

type VNCHelper struct {
	net.Conn
	ReceiverFeatures []common.ReceiverFeature
	timeout          time.Duration
	version          string
}

func NewVNCHelper(network, addr string, timeout time.Duration) (*VNCHelper, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	vnc := VNCHelper{
		Conn:    conn,
		timeout: timeout,
		ReceiverFeatures: []common.ReceiverFeature{
			{
				StartIndex:   0,
				FeatureBytes: []byte("RFB "),
			},
		},
		version: "v0.1",
	}
	return &vnc, nil
}

func (v VNCHelper) GetVersion() string {
	return v.version
}

func (v VNCHelper) Check() error {

	err := v.Conn.SetReadDeadline(time.Now().Add(v.timeout))
	if err != nil {
		return custom_error.ErrVNCNotFound
	}
	feature := v.ReceiverFeatures[0]
	var readBuf = make([]byte, len(feature.FeatureBytes))
	_, err = v.Conn.Read(readBuf)
	if err != nil {
		return custom_error.ErrVNCNotFound
	}
	if bytes.Equal(readBuf[feature.StartIndex:feature.StartIndex+len(feature.FeatureBytes)], feature.FeatureBytes) == false {
		return custom_error.ErrVNCNotFound
	}
	return nil
}
