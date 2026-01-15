// Package rustdesk implements protocol detection helpers for RustDesk remote desktop software.
//
// This module provides detection for:
//   - HBBS (HeartBeat/Broker Server): RustDesk's rendezvous/signaling server (ports 21115, 21116)
//   - HBBR (HeartBeat/Broker Relay): RustDesk's relay server (port 21117)
//
// The HBBR protocol uses protobuf-encoded messages. This helper sends a RequestRelay
// message to detect active HBBR servers.
package rustdesk

import (
	"github.com/allanpk716/go-protocol-detector/internal/common"
)

type HBBRHelper struct {
	SenderPackage    []byte
	ReceiverFeatures []common.ReceiverFeature
	version          string
}

// NewHBBRHelper creates a new HBBR protocol detection helper
//
// HBBR (relay server) detection works by sending a RequestRelay message.
// The server will accept the connection and keep it open waiting for relay pairing.
// This is reliable protocol-based detection with minimal false positive risk.
func NewHBBRHelper() *HBBRHelper {
	// Create a RequestRelay message with empty uuid and licence_key
	//
	// Protobuf structure:
	// message RequestRelay {
	//   string uuid = 1;
	//   string licence_key = 2;
	// }
	//
	// Empty strings don't encode any data in protobuf, so an empty RequestRelay
	// message is 0 bytes.
	//
	// Encoding for field 23 (RequestRelay) with empty message:
	// - Tag: (23 << 3) | 2 = 0xBA (field number + wire type 2 for length-delimited)
	// - Length: 0 (empty message)
	// - Data: none
	//
	// So the protobuf message is just: 0xBA 0x00
	protobufMsg := []byte{0xBA, 0x00}

	// hbb_common's BytesCodec uses variable-length encoding:
	// - For length <= 0x3F: 1 byte header = (length << 2)
	// Our message is 2 bytes, which uses 1-byte header: (2 << 2) = 0x08
	length := len(protobufMsg)
	header := []byte{byte(length << 2)}

	result := append(header, protobufMsg...)

	hbbr := &HBBRHelper{
		SenderPackage:    result,
		ReceiverFeatures: []common.ReceiverFeature{}, // No response expected
		version:          "v0.2",
	}
	return hbbr
}

// GetVersion returns the helper version
func (h HBBRHelper) GetVersion() string {
	return h.version
}
