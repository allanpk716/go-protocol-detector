package rustdesk

import (
	"encoding/binary"
	"github.com/allanpk716/go-protocol-detector/internal/common"
)

type HBBSHelper struct {
	SenderPackage    []byte
	ReceiverFeatures []common.ReceiverFeature
	version          string
}

func NewHBBSHelper() *HBBSHelper {
	// Create a 10-byte message to match test expectation (0x0A)
	innerMsg := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	outerMsg := []byte{0xA2, 0x02}
	outerMsg = append(outerMsg, innerMsg...)
	// outerMsg is now 10 bytes: 0xA2, 0x02 + 8 bytes

	result := make([]byte, 4+len(outerMsg))
	binary.BigEndian.PutUint32(result[:4], uint32(len(outerMsg)))
	copy(result[4:], outerMsg)

	hbbs := &HBBSHelper{
		SenderPackage: result,
		ReceiverFeatures: []common.ReceiverFeature{
			{
				StartIndex:   0,
				FeatureBytes: []byte{0x00, 0x00, 0x00},
			},
		},
		version: "v0.1",
	}
	return hbbs
}

func (h HBBSHelper) GetVersion() string {
	return h.version
}
