package vnc

import (
	"bytes"
	"io"
	"github.com/allanpk716/go-protocol-detector/internal/common"
	"github.com/allanpk716/go-protocol-detector/internal/custom_error"
	"github.com/allanpk716/go-protocol-detector/internal/utils"
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

// CheckDetailed preserves the EXACT detection semantics of Check (single
// 4-byte read + prefix match — a peer sending only "RFB " still hits), then
// attempts a best-effort read of the remaining 8 bytes of the 12-byte RFB
// version string for the banner. The continuation read is bounded (500ms) and
// NEVER changes the hit/fail outcome; its failure only yields an empty banner.
func (v VNCHelper) CheckDetailed() (string, string, error) {
	if err := v.Conn.SetReadDeadline(time.Now().Add(v.timeout)); err != nil {
		return "", utils.ReasonUnknown, custom_error.ErrVNCNotFound
	}
	feature := v.ReceiverFeatures[0]
	head := make([]byte, len(feature.FeatureBytes)) // 4 bytes: "RFB "
	if _, err := v.Conn.Read(head); err != nil {
		return "", utils.ClassifyNetError(err), custom_error.ErrVNCNotFound
	}
	if !bytes.Equal(head[feature.StartIndex:feature.StartIndex+len(feature.FeatureBytes)], feature.FeatureBytes) {
		return "", utils.ReasonProtocolMismatch, custom_error.ErrVNCNotFound
	}
	// Detection succeeded — best-effort banner continuation.
	rest := make([]byte, 8)
	_ = v.Conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := io.ReadFull(v.Conn, rest); err != nil {
		return "", "", nil // partial-data peer: hit with no banner (old semantics)
	}
	return utils.SanitizeBanner(append(head, rest...)), "", nil
}
