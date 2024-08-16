package rdp

import (
	"github.com/TheBestLL/go-protocol-detector/internal/common"
)

type RDPHelper struct {
	SenderPackage    []byte
	ReceiverFeatures []common.ReceiverFeature
	version          string
	supportOSVersion map[string]string
}

func NewRDPHelper() *RDPHelper {
	rdp := RDPHelper{
		SenderPackage: []byte("\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"),
		ReceiverFeatures: []common.ReceiverFeature{
			{
				StartIndex:   0,
				FeatureBytes: []byte("\x03\x00\x00\x13\x0e"),
			},
		},
		version: "v0.1",
		supportOSVersion: map[string]string{
			"2003":  "",
			"Win7":  "",
			"2008":  "",
			"2012":  "",
			"Win10": "10.0.18363.1256",
			"2016":  "",
			"2019":  "10.0.17763.1397",
		},
	}

	return &rdp
}

func (r RDPHelper) GetVersion() string {
	return r.version
}

func (r RDPHelper) GetSupportOSVersion() map[string]string {
	return r.supportOSVersion
}
