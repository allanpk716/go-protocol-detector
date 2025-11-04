package pkg

import (
	"github.com/allanpk716/go-protocol-detector/internal/custom_error"
	"os"
	"strconv"
	"testing"
	"time"
)

var (
	timeOut = 3 * time.Second
)

// getTestEnv 从环境变量获取测试配置，如果不存在则跳过测试
func getTestEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		return ""
	}
	return value
}

// requireTestEnv 如果环境变量不存在则跳过测试
func requireTestEnv(t *testing.T, keys ...string) {
	for _, key := range keys {
		if os.Getenv(key) == "" {
			t.Skipf("Skipping test: environment variable %s is not set", key)
		}
	}
}

// getOptionalTestEnv 获取可选的环境变量，如果不存在则返回默认值
func getOptionalTestEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getOptionalTestEnvInt 获取可选的整数环境变量
func getOptionalTestEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	if intValue, err := strconv.Atoi(value); err == nil {
		return intValue
	}
	return defaultValue
}

func TestNewDetector(t *testing.T) {
	NewDetector(timeOut)
}

func TestDetector_RDPCheck(t *testing.T) {
	det := NewDetector(timeOut)
	if det.rdp.GetVersion() == "" {
		t.Fatal("rdp version is empty")
	}
	if len(det.rdp.GetSupportOSVersion()) == 0 {
		t.Fatal("rdp Support OS Version is empty")
	}

	// 测试有效的RDP服务（需要设置环境变量 TEST_RDP_HOST 和 TEST_RDP_PORT）
	testHost := getTestEnv("TEST_RDP_HOST")
	testPort := getTestEnv("TEST_RDP_PORT")
	if testHost != "" && testPort != "" {
		err := det.RDPCheck(testHost, testPort)
		if err != nil {
			t.Logf("RDP check failed for %s:%s - %v", testHost, testPort, err)
		}
	}

	// 测试无效的RDP服务
	err := det.RDPCheck("192.168.200.1", "1")
	if err != custom_error.ErrRDPNotFound {
		t.Fatal(err)
	}
}

func TestDetector_SSHCheck(t *testing.T) {
	det := NewDetector(timeOut)
	if det.ssh.GetVersion() == "" {
		t.Fatal("ssh version is empty")
	}

	// 测试有效的SSH服务（需要设置环境变量 TEST_SSH_HOST 和 TEST_SSH_PORT）
	testHost := getTestEnv("TEST_SSH_HOST")
	testPort := getTestEnv("TEST_SSH_PORT")
	if testHost != "" && testPort != "" {
		err := det.SSHCheck(testHost, testPort)
		if err != nil {
			t.Logf("SSH check failed for %s:%s - %v", testHost, testPort, err)
		}
	}

	// 测试无效的SSH服务
	err := det.SSHCheck("192.168.200.1", "1")
	if err != custom_error.ErrSSHNotFound {
		t.Fatal(err)
	}
}

func TestDetector_FTPCheck(t *testing.T) {
	det := NewDetector(timeOut)
	if det.ftp.GetVersion() == "" {
		t.Fatal("ftp version is empty")
	}

	// 测试有效的FTP服务（需要设置环境变量 TEST_FTP_HOST 和 TEST_FTP_PORT）
	// 如果没有设置，使用公共FTP服务器进行测试
	testHost := getOptionalTestEnv("TEST_FTP_HOST", "cdimage.debian.org")
	testPort := getOptionalTestEnv("TEST_FTP_PORT", "21")

	err := det.FTPCheck(testHost, testPort)
	if err != nil {
		t.Logf("FTP check failed for %s:%s - %v", testHost, testPort, err)
	}

	// 测试无效的FTP服务
	err = det.FTPCheck("192.168.200.1", "1")
	if err != custom_error.ErrFTPNotFound {
		t.Fatal(err)
	}
}

func TestDetector_SFTPCheck(t *testing.T) {
	det := NewDetector(timeOut)

	// 测试SFTP密码登录（需要设置相关环境变量）
	testHost := getTestEnv("TEST_SFTP_HOST")
	testPort := getTestEnv("TEST_SFTP_PORT")
	testUser := getTestEnv("TEST_SFTP_USER")
	testPass := getTestEnv("TEST_SFTP_PASSWORD")

	if testHost != "" && testPort != "" && testUser != "" && testPass != "" {
		err := det.SFTPCheck(testHost, testPort, testUser, testPass, "")
		if err != nil {
			t.Logf("SFTP password check failed for %s:%s - %v", testHost, testPort, err)
		}

		// 测试私钥登录（需要额外的环境变量）
		testKeyFile := getTestEnv("TEST_SFTP_KEYFILE")
		testKeyPass := getTestEnv("TEST_SFTP_KEY_PASSWORD")

		if testKeyFile != "" {
			err = det.SFTPCheck(testHost, testPort, testUser, testKeyPass, testKeyFile)
			if err != nil {
				t.Logf("SFTP key check failed for %s:%s - %v", testHost, testPort, err)
			}
		}
	} else {
		t.Skip("Skipping SFTP tests: environment variables TEST_SFTP_HOST, TEST_SFTP_PORT, TEST_SFTP_USER, TEST_SFTP_PASSWORD are not set")
	}
}

func TestDetector_TelnetCheck(t *testing.T) {
	det := NewDetector(timeOut)

	// 测试有效的Telnet服务（需要设置环境变量 TEST_TELNET_HOST 和 TEST_TELNET_PORT）
	testHost := getTestEnv("TEST_TELNET_HOST")
	testPort := getTestEnv("TEST_TELNET_PORT")
	if testHost != "" && testPort != "" {
		err := det.TelnetCheck(testHost, testPort)
		if err != nil {
			t.Logf("Telnet check failed for %s:%s - %v", testHost, testPort, err)
		}
	}

	// 测试无效的Telnet服务
	err := det.TelnetCheck("192.168.200.1", "1")
	if err != custom_error.ErrTelnetNotFound {
		t.Fatal(err)
	}
}

func TestDetector_VNCCheck(t *testing.T) {
	det := NewDetector(timeOut)

	// 测试有效的VNC服务（需要设置环境变量 TEST_VNC_HOST 和 TEST_VNC_PORT）
	testHost := getTestEnv("TEST_VNC_HOST")
	testPort := getTestEnv("TEST_VNC_PORT")
	if testHost != "" && testPort != "" {
		err := det.VNCCheck(testHost, testPort)
		if err != nil {
			t.Logf("VNC check failed for %s:%s - %v", testHost, testPort, err)
		}
	}

	// 测试无效的VNC服务
	err := det.VNCCheck("192.168.200.1", "1")
	if err != custom_error.ErrVNCNotFound {
		t.Fatal(err)
	}
}

func TestDetector_CommonPortCheck(t *testing.T) {
	det := NewDetector(timeOut)

	// 测试有效的通用端口（需要设置环境变量 TEST_COMMON_HOST 和 TEST_COMMON_PORT）
	testHost := getTestEnv("TEST_COMMON_HOST")
	testPort := getTestEnv("TEST_COMMON_PORT")
	if testHost != "" && testPort != "" {
		err := det.CommonPortCheck(testHost, testPort)
		if err != nil {
			t.Logf("Common port check failed for %s:%s - %v", testHost, testPort, err)
		}
	}

	// 测试无效的通用端口
	err := det.CommonPortCheck("192.168.200.1", "1")
	if err != custom_error.ErrCommontPortCheckError {
		t.Fatal(err)
	}
}
