// Package rustdesk implements protocol detection helpers for RustDesk remote desktop software.
//
// HBBS21116Helper detects RustDesk HBBS services on port 21116
// (ID registration, heartbeat, and TCP hole punching services).
//
// Detection strategy:
// - Send RegisterPk message with no_register_device=true
// - Server responds with RegisterPkResponse
// - Verify response contains RegisterPkResponse field (field 16)
package rustdesk

import (
	"github.com/allanpk716/go-protocol-detector/internal/common"
)

type HBBS21116Helper struct {
	SenderPackage    []byte
	ReceiverFeatures []common.ReceiverFeature
	version          string
}

// NewHBBS21116Helper creates a new HBBS 21116 protocol detection helper
//
// Port 21116 is used for:
// - UDP: ID registration and heartbeat services
// - TCP: TCP hole punching and connection services
//
// Detection uses RegisterPk message with no_register_device=true,
// which the server will accept without requiring valid device keys.
func NewHBBS21116Helper() *HBBS21116Helper {
	// Build RegisterPk protobuf message with minimal fields:
	// - id: "test" (any string works for detection)
	// - no_register_device: true (skip device binding)
	//
	// Protobuf encoding:
	// Field 1 (id, string): tag 0x0A, length 4, value "test" -> 0x0A 0x04 0x74 0x65 0x73 0x74
	// Field 5 (no_register_device, bool): tag 0x28, value 0x01 -> 0x28 0x01
	// Inner message total: 8 bytes
	//
	// Field 15 (RegisterPk in RendezvousMessage):
	// - Tag: (15 << 3) | 2 = 0x7A (field number + wire type 2)
	// - Length: 8 (inner message length)
	// -> 0x7A 0x08
	//
	// Outer message total: 10 bytes (0x7A 0x08 + 8 bytes inner)
	//
	// hbb_common BytesCodec length header:
	// - For length <= 0x3F: 1 byte = (length << 2)
	// - Message length 10: (10 << 2) = 0x28
	//
	// Full encoded message:
	// [0x28][0x7A 0x08][0x0A 0x04 0x74 0x65 0x73 0x74][0x28 0x01]

	// Inner message fields
	idField := []byte{0x0A, 0x04, 0x74, 0x65, 0x73, 0x74} // id="test"
	noDeviceField := []byte{0x28, 0x01}                    // no_register_device=true
	innerMsg := append(idField, noDeviceField...)           // 8 bytes

	// Outer wrapper (field 15 = RegisterPk)
	outerTag := []byte{0x7A, 0x08} // field 15, length 8
	outerMsg := append(outerTag, innerMsg...) // 10 bytes

	// BytesCodec length header
	length := len(outerMsg)           // 10
	header := []byte{byte(length << 2)} // 0x28

	// Complete message
	senderPkg := append(header, outerMsg...)

	// Expected response: RegisterPkResponse (field 16)
	// Format: [length][0x82 0x02][result][keep_alive]
	// We only verify field 16 tag is present
	helper := &HBBS21116Helper{
		SenderPackage: senderPkg,
		ReceiverFeatures: []common.ReceiverFeature{
			{
				// Check for field 16 (register_pk_response) tag
				// Tag: (16 << 3) | 2 = 0x82
				StartIndex:    1, // Skip length header
				FeatureBytes: []byte{0x82},
			},
		},
		version: "v0.1",
	}
	return helper
}

// GetVersion returns the helper version
func (h HBBS21116Helper) GetVersion() string {
	return h.version
}
