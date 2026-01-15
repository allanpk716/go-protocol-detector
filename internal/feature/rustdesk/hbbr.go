package rustdesk

// HBBRHelper implements detection for RustDesk HBBR (relay server)
// Port: 21117
// Uses connection-based detection (server accepts connections)
type HBBRHelper struct {
	version string
}

// NewHBBRHelper creates a new HBBR protocol detection helper
func NewHBBRHelper() *HBBRHelper {
	hbbr := &HBBRHelper{
		version: "v0.1",
	}
	return hbbr
}

// GetVersion returns the helper version
func (h HBBRHelper) GetVersion() string {
	return h.version
}
