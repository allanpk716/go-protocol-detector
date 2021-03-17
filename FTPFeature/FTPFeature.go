package FTPFeature

import (
	"github.com/allanpk716/go-protocol-detector/Model"
)

type FTPHelper struct {
	SenderPackage		[]byte
	ReceiverFeatures	[]Model.ReceiverFeature
	version				string
}

func NewFTPHelper() *FTPHelper {
	ftp := FTPHelper{
		SenderPackage: []byte("\r\nUSER wjfR22nDtsd33123Ks36o3q12YJ9rPRrq"),
		ReceiverFeatures: []Model.ReceiverFeature{
			{
				StartIndex:   0,
				FeatureBytes: []byte("220"),
			},
		},
		version: "v0.1",
	}

	return &ftp
}

func (f FTPHelper) GetVersion() string {
	return f.version
}