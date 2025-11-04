package pkg

import (
	"log"
	"strings"
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
			name: "TestScanTools_Scan_Range",
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
		{
			name: "TestScanTools_Scan_Single",
			fields: fields{
				threads: 20,
				timeOut: time.Second * 2,
			},
			args: args{
				protocolType: RDP,
				inputInfo: InputInfo{
					Host: "172.20.65.100",
					Port: "3300,3389",
				},
			},
			want: nil,
		},
		{
			name: "TestScanTools_Scan_Mix",
			fields: fields{
				threads: 20,
				timeOut: time.Second * 2,
			},
			args: args{
				protocolType: RDP,
				inputInfo: InputInfo{
					Host: "172.20.65.2-254",
					Port: "3389",
				},
			},
			want: nil,
		},
		{
			name: "TestScanTools_Scan_2_IP",
			fields: fields{
				threads: 20,
				timeOut: time.Second * 2,
			},
			args: args{
				protocolType: RDP,
				inputInfo: InputInfo{
					Host: "172.20.65.89,172.20.65.101",
					Port: "3389",
				},
			},
			want: nil,
		},
		{
			name: "TestScanTools_Scan_CICR",
			fields: fields{
				threads: 20,
				timeOut: time.Second * 2,
			},
			args: args{
				protocolType: RDP,
				inputInfo: InputInfo{
					Host: "172.20.65.0/24",
					Port: "3389",
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
			got, err := s.Scan(tt.args.protocolType, tt.args.inputInfo, true)
			if err != nil {
				t.Fatal(err)
			}
			info := ""
			for s2, i := range got.SuccessMapString {
				info += s2 + ":" + strings.Join(i, ",") + "\r\n"
			}

			log.Printf("Found %s %s", tt.args.protocolType.String(), info)
		})
	}
}
