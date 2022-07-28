package pkg

import (
	"testing"
	"time"
)

func TestScanTools_Scan(t *testing.T) {
	type fields struct {
		threads int
		timeOut time.Duration
	}
	type args struct {
		protocolType ProtocolType
		inputInfo    InputInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *OutputInfo
		wantErr bool
	}{
		{
			name: "TestScanTools_Scan",
			fields: fields{
				threads: 20,
				timeOut: time.Second * 2,
			},
			args: args{
				protocolType: RDP,
				inputInfo: InputInfo{
					Host: "172.20.65.100-101",
					Port: "3300-3400",
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ScanTools{
				threads: tt.fields.threads,
				timeOut: tt.fields.timeOut,
			}
			got, err := s.Scan(tt.args.protocolType, tt.args.inputInfo)
			if err != nil {
				t.Fatal(err)
			}
			println("Found", tt.args.protocolType.String(), got.Info)
		})
	}
}
