// Package rustdesk implements protocol detection helpers for RustDesk remote desktop software.
//
// This module provides detection for:
//   - HBBS (HeartBeat/Broker Server): RustDesk's rendezvous/signaling server (ports 21115, 21116)
//   - HBBR (HeartBeat/Broker Relay): RustDesk's relay server (port 21117)
//
// The HBBS protocol uses protobuf-encoded messages. This helper sends a TestNatRequest
// message to detect active HBBS servers.
package rustdesk

import (
	"github.com/allanpk716/go-protocol-detector/internal/common"
)

type HBBSHelper struct {
	SenderPackage    []byte
	ReceiverFeatures []common.ReceiverFeature
}

func NewHBBSHelper() *HBBSHelper {
	// Create protobuf message for TestNatRequest with serial=0
	// innerMsg: 2 bytes - tag + value for serial=0
	innerMsg := []byte{0x08, 0x00}
	// outerMsg: 2 bytes - field 20 tag + length
	outerMsg := []byte{0xA2, 0x02}
	outerMsg = append(outerMsg, innerMsg...)
	// outerMsg is now 4 bytes: 0xA2, 0x02, 0x08, 0x00

	// hbb_common's BytesCodec uses variable-length encoding:
	// - For length <= 0x3F: 1 byte header = (length << 2)
	// - For length <= 0x3FFF: 2 byte header LE = (length << 2) | 0x1
	// - For length <= 0x3FFFFF: 3 byte header LE = (length << 2) | 0x2
	// - For length <= 0x3FFFFFFF: 4 byte header LE = (length << 2) | 0x3
	//
	// Our message is 4 bytes, which uses 1-byte header: (4 << 2) = 0x10
	length := len(outerMsg)
	var header []byte
	if length <= 0x3F {
		header = []byte{byte(length << 2)}
	} else if length <= 0x3FFF {
		header = []byte{byte((length << 2) | 0x1), byte((length << 2) >> 8)}
	} else if length <= 0x3FFFFF {
		h := (length << 2) | 0x2
		header = []byte{byte(h), byte(h >> 8), byte(h >> 16)}
	} else {
		h := (length << 2) | 0x3
		header = []byte{byte(h), byte(h >> 8), byte(h >> 16), byte(h >> 24)}
	}

	result := append(header, outerMsg...)

	// Expected response: TestNatResponse with port field
	// Format: [length_header][0xAA 0x04][0x08 port_varint]
	// where 0xAA = field 21 (test_nat_response), 0x08 = field 1 (port)
	// For port 21115: port_varint = 0xB3 0xA5 0x01
	// For port 21116: port_varint = 0xB4 0xA5 0x01
	// For port 21117: port_varint = 0xB5 0xA5 0x01
	// Response bytes: [len][0xAA 0x04 0x08 0xBx 0xA5 0x01]
	return &HBBSHelper{
		SenderPackage: result,
		ReceiverFeatures: []common.ReceiverFeature{
			{
				// Check for field 21 (test_nat_response) tag
				StartIndex:   1, // Skip length header
				FeatureBytes: []byte{0xAA},
			},
			{
				// Check for field 1 (port) tag and length
				StartIndex:   3,
				FeatureBytes: []byte{0x08},
			},
		},
	}
}
