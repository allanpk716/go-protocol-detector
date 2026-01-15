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
	// Create a 4-byte message per spec
	// innerMsg: 2 bytes - tag + value for serial=0
	innerMsg := []byte{0x08, 0x00}
	// outerMsg: 2 bytes - field 20 tag + length
	outerMsg := []byte{0xA2, 0x02}
	outerMsg = append(outerMsg, innerMsg...)
	// outerMsg is now 4 bytes: 0xA2, 0x02 + 0x08, 0x00

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
