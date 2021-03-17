package SSHFeature

type ReceiverFeature struct {
	StartIndex		int
	FeatureBytes	[]byte
}

type SSHHelper struct {
	SenderPackage		[]byte
	ReceiverFeatures	[]ReceiverFeature
	version				string
}

func NewSSHHelper() *SSHHelper {
	ssh := SSHHelper{
		SenderPackage: []byte("\x53\x53\x48\x2d\x32\x2e\x30\x2d\x4f\x70\x65\x6e\x53\x53\x48\x5f\x66\x6f\x72\x5f\x57\x69\x6e\x64\x6f\x77\x73\x5f\x37\x2e\x37\x0d\x0a"),
		ReceiverFeatures: []ReceiverFeature{
			ReceiverFeature{
				StartIndex: 0,
				FeatureBytes: []byte("\x53\x53\x48\x2d"),
			},
			ReceiverFeature{
				StartIndex: 7,
				FeatureBytes: []byte("\x2d"),
			},
		},
		version: "v0.1",
	}

	return &ssh
}

func (s SSHHelper) GetVersion() string {
	return s.version
}