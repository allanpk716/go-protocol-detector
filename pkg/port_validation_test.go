package pkg

import (
	"testing"
)

func TestParsePort_Validation(t *testing.T) {
	scan := ScanTools{}

	// 测试用例
	testCases := []struct {
		name        string
		input       string
		expectError bool
		expectedLen int
	}{
		{
			name:        "valid single port",
			input:       "80",
			expectError: false,
			expectedLen: 1,
		},
		{
			name:        "valid multiple ports",
			input:       "80,443,8080",
			expectError: false,
			expectedLen: 3,
		},
		{
			name:        "valid port range",
			input:       "8000-8010",
			expectError: false,
			expectedLen: 11,
		},
		{
			name:        "valid mixed ports and ranges",
			input:       "80,443,8000-8010,9000",
			expectError: false,
			expectedLen: 14,
		},
		{
			name:        "port 0 valid",
			input:       "0",
			expectError: false,
			expectedLen: 1,
		},
		{
			name:        "port too high",
			input:       "65536",
			expectError: true,
			expectedLen: 0,
		},
		{
			name:        "range with port 0 valid",
			input:       "0-100",
			expectError: false,
			expectedLen: 101,
		},
		{
			name:        "range with port too high",
			input:       "65500-65536",
			expectError: true,
			expectedLen: 0,
		},
		{
			name:        "start port greater than end port",
			input:       "8080-8000",
			expectError: true,
			expectedLen: 0,
		},
		{
			name:        "too many ports (should fail)",
			input:       "1-10001",
			expectError: true,
			expectedLen: 0,
		},
		{
			name:        "boundary valid ports",
			input:       "1,65535",
			expectError: false,
			expectedLen: 2,
		},
		{
			name:        "invalid port format",
			input:       "abc",
			expectError: true,
			expectedLen: 0,
		},
		{
			name:        "invalid range format",
			input:       "80-443-8080",
			expectError: true,
			expectedLen: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ports, err := scan.parsePort(tc.input)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for input %s, but got none", tc.input)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for input %s: %v", tc.input, err)
				}
				if len(ports) != tc.expectedLen {
					t.Errorf("Expected %d ports for input %s, got %d", tc.expectedLen, tc.input, len(ports))
				}
			}
		})
	}
}

func TestParsePort_LargeRange(t *testing.T) {
	scan := ScanTools{}

	// 测试接近限制的大端口范围
	ports, err := scan.parsePort("8000-8999") // 1000 ports
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(ports) != 1000 {
		t.Errorf("Expected 1000 ports, got %d", len(ports))
	}

	// 测试刚好在限制内的端口范围
	ports, err = scan.parsePort("1-10000") // 10000 ports - should work
	if err != nil {
		t.Fatalf("Unexpected error for 10000 ports: %v", err)
	}
	if len(ports) != 10000 {
		t.Errorf("Expected 10000 ports, got %d", len(ports))
	}

	// 测试超过限制的端口范围
	_, err = scan.parsePort("1-10001") // 10001 ports - should fail
	if err == nil {
		t.Error("Expected error for port range exceeding 10000 ports")
	}
}