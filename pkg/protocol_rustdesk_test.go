package pkg

import (
	"testing"
)

func TestProtocolType_RustDesk(t *testing.T) {
	tests := []struct {
		name     string
		proto    ProtocolType
		expected string
	}{
		{"RustDeskHBBS", RustDeskHBBS, "rustdesk-hbbs"},
		{"RustDeskHBBR", RustDeskHBBR, "rustdesk-hbbr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.proto.String(); got != tt.expected {
				t.Errorf("ProtocolType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestString2ProtocolType_RustDesk(t *testing.T) {
	tests := []struct {
		input    string
		expected ProtocolType
	}{
		{"rustdesk-hbbs", RustDeskHBBS},
		{"rustdesk-hbbr", RustDeskHBBR},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := String2ProtocolType(tt.input); got != tt.expected {
				t.Errorf("String2ProtocolType(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
