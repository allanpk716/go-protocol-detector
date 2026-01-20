package ftp

import (
	"github.com/allanpk716/go-protocol-detector/internal/common"
)

type FTPHelper struct {
	SenderPackage    []byte
	ReceiverFeatures []common.ReceiverFeature
}

func NewFTPHelper() *FTPHelper {
	return &FTPHelper{
		SenderPackage: []byte("\r\nUSER wjfR22nDtsd33123Ks36o3q12YJ9rPRrq"),
		ReceiverFeatures: []common.ReceiverFeature{
			{
				StartIndex:   0,
				FeatureBytes: []byte("220"),
			},
		},
	}
}
