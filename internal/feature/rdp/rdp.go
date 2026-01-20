package rdp

import (
	"github.com/allanpk716/go-protocol-detector/internal/common"
)

type RDPHelper struct {
	SenderPackage    []byte
	ReceiverFeatures []common.ReceiverFeature
}

func NewRDPHelper() *RDPHelper {
	return &RDPHelper{
		SenderPackage: []byte("\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"),
		ReceiverFeatures: []common.ReceiverFeature{
			{
				StartIndex:   0,
				FeatureBytes: []byte("\x03\x00\x00\x13\x0e"),
			},
		},
	}
}
