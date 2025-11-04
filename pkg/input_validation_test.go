package pkg

import (
	"testing"
	"time"
)

// TestIPBoundaryValidation 测试IP边界检查逻辑
func TestIPBoundaryValidation(t *testing.T) {
	scan := NewScanTools(10, 3*time.Second)

	testCases := []struct {
		name        string
		host        string
		shouldError bool
		errorMsg    string
	}{
		// 边界值测试
		{"Valid IP boundary 0", "192.168.1.0", false, ""},
		{"Valid IP boundary 255", "192.168.1.255", false, ""},
		{"Invalid IP -1", "192.168.1.-1", true, "ParseIP Error"},
		{"Invalid IP 256", "192.168.1.256", true, "ParseIP Error"},
		{"Invalid IP 257", "192.168.1.257", true, "ParseIP Error"},

		// 范围边界测试
		{"Valid range 0-10", "192.168.1.0-10", false, ""},
		{"Valid range 245-255", "192.168.1.245-255", false, ""},
		{"Invalid range -1-10", "192.168.1.-1-10", true, "Split Error"},
		{"Invalid range 250-256", "192.168.1.250-256", true, "end index out of range [0-255]"},
		{"Invalid range 260-300", "192.168.1.260-300", true, "ParseIP Error"},

		// 范围大小限制测试 - 考虑到IP地址最后一段最大255
		{"Valid max range", "192.168.1.1-255", false, ""},
		{"Invalid range exceed 255", "192.168.1.1-256", true, "end index out of range [0-255]"},
		{"Invalid very large range", "192.168.1.1-5000", true, "end index out of range [0-255]"},

		// 逻辑错误测试
		{"Start > End", "192.168.1.100-50", true, "start index (100) cannot be greater than end index (50)"},
		{"Same range", "192.168.1.100-100", false, ""}, // 单个IP应该有效

		// 格式错误测试
		{"Multiple dashes", "192.168.1.1-10-20", true, "Split Error"},
		{"Invalid IP format", "300.400.500.600", true, "ParseIP Error"},
		{"Incomplete IP", "192.168.1", true, "ParseIP Error"},
		{"Text instead of IP", "not.an.ip.address", true, "ParseIP Error"},
		{"Empty string", "", true, "ParseIP Error"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scan.parseHost(tc.host)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for input '%s', but got none", tc.host)
				} else if tc.errorMsg != "" && !contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error containing '%s' for input '%s', but got: %v", tc.errorMsg, tc.host, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid input '%s': %v", tc.host, err)
				}
			}
		})
	}
}

// TestPortValidation 测试端口解析验证
func TestPortValidation(t *testing.T) {
	scan := NewScanTools(10, 3*time.Second)

	testCases := []struct {
		name        string
		port        string
		shouldError bool
		expectedLen int // 预期的端口数量
	}{
		{"Single port", "80", false, 1},
		{"Multiple ports", "80,443,3389", false, 3},
		{"Valid range", "8000-8010", false, 11},
		{"Mixed format", "80,443,8000-8010,3389", false, 14},

		{"Port 0", "0", false, 1}, // 端口0在技术上是有效的
		{"Port 65535", "65535", false, 1},
		{"Invalid port -1", "-1", true, 0},
		{"Invalid port 65536", "65536", true, 0},
		{"Invalid port text", "http", true, 0},

		{"Invalid range - start > end", "8080-80", true, 0},
		{"Invalid range - multiple dashes", "8080-8090-8100", true, 0},
		{"Empty port", "", true, 0},
		{"Invalid comma", "80,,443", true, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ports, err := scan.parsePort(tc.port)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for port '%s', but got none", tc.port)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid port '%s': %v", tc.port, err)
				}
				if len(ports) != tc.expectedLen {
					t.Errorf("Expected %d ports for '%s', but got %d", tc.expectedLen, tc.port, len(ports))
				}
			}
		})
	}
}

// TestThreadLimitValidation 测试线程数限制验证
func TestThreadLimitValidation(t *testing.T) {
	testCases := []struct {
		name          string
		inputThreads  int
		expectedThreads int
	}{
		{"Normal threads", 10, 10},
		{"Zero threads", 0, 1}, // 默认应该是1
		{"Max allowed threads", 1000, 1000},
		{"Exceeds max threads", 2000, 1000}, // 应该被限制到1000
		{"Negative threads", -5, 1}, // 应该被处理为默认值
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scan := NewScanTools(tc.inputThreads, 3*time.Second)
			if scan.threads != tc.expectedThreads {
				t.Errorf("Expected threads=%d for input %d, but got %d",
					tc.expectedThreads, tc.inputThreads, scan.threads)
			}
		})
	}
}

// TestInputInfoValidation 测试完整的InputInfo验证
func TestInputInfoValidation(t *testing.T) {
	scan := NewScanTools(10, 3*time.Second)

	testCases := []struct {
		name        string
		inputInfo   InputInfo
		shouldError bool
	}{
		{
			name: "Valid complete input",
			inputInfo: InputInfo{
				Host:     "192.168.1.1-10",
				Port:     "22,80,443",
				User:     "testuser",
				Password: "testpass",
			},
			shouldError: false,
		},
		{
			name: "Empty host",
			inputInfo: InputInfo{
				Host:     "",
				Port:     "22",
				User:     "testuser",
				Password: "testpass",
			},
			shouldError: true,
		},
		{
			name: "Empty port",
			inputInfo: InputInfo{
				Host:     "192.168.1.1",
				Port:     "",
				User:     "testuser",
				Password: "testpass",
			},
			shouldError: true,
		},
		{
			name: "Invalid host range",
			inputInfo: InputInfo{
				Host:     "192.168.1.1-2000",
				Port:     "22",
				User:     "testuser",
				Password: "testpass",
			},
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 测试parseHost
			_, err := scan.parseHost(tc.inputInfo.Host)
			if tc.inputInfo.Host == "" {
				if err == nil {
					t.Error("Expected error for empty host, but got none")
				}
			} else if tc.shouldError && err == nil {
				t.Errorf("Expected error for input '%+v', but got none", tc.inputInfo)
			}

			// 测试parsePort
			_, err = scan.parsePort(tc.inputInfo.Port)
			if tc.inputInfo.Port == "" {
				if err == nil {
					t.Error("Expected error for empty port, but got none")
				}
			} else if tc.inputInfo.Host != "" && tc.shouldError && err == nil {
				// Only check shouldError for port if host is valid (not empty)
				// This prevents false failures when host is empty but port is valid
				t.Errorf("Expected error for input '%+v', but got none", tc.inputInfo)
			}
		})
	}
}

// 辅助函数：检查字符串是否包含子字符串
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		   (len(substr) == 0 ||
		   (len(s) > 0 && (s == substr ||
		   (len(s) > len(substr) &&
		   (s[:len(substr)] == substr ||
		   s[len(s)-len(substr):] == substr ||
		   containsInMiddle(s, substr))))))
}

func containsInMiddle(s, substr string) bool {
	for i := 1; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}