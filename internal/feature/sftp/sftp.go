package sftp

import (
	"fmt"
	"net"
	"bufio"
	"github.com/allanpk716/go-protocol-detector/internal/custom_error"
	"github.com/allanpk716/go-protocol-detector/internal/utils"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"time"
	"strings"
)

type SFTPHelper struct {
	uri     string
	timeout time.Duration
}

// SFTPDiagnostics 包含SFTP检测的详细诊断信息
type SFTPDiagnostics struct {
	TCPConnected       bool          `json:"tcp_connected"`       // TCP连接是否成功
	SSHBanner          string        `json:"ssh_banner"`          // SSH服务器banner信息
	SSHVersion         string        `json:"ssh_version"`         // SSH版本信息
	SFTPSupported      bool          `json:"sftp_supported"`      // SFTP subsystem是否支持
	SubsystemResponse  string        `json:"subsystem_response"`  // subsystem响应信息
	ElapsedTime        int64         `json:"elapsed_time_ms"`     // 检测耗时（毫秒）
	ErrorMsg           string        `json:"error_msg"`           // 错误信息
}

func NewSFTPHelper(host, port string, timeout time.Duration) *SFTPHelper {
	uri := net.JoinHostPort(host, port)
	sftpHelper := SFTPHelper{
		uri:     uri,
		timeout: timeout,
	}
	return &sftpHelper
}

func (s SFTPHelper) Check(user, password, priKeyFullPath string) error {
	// SFTP协议检测：不使用认证信息，专注于协议识别
	_, err := s.checkSFTPProtocolWithDiagnostics()
	return err
}

// CheckWithDiagnostics 执行SFTP检测并返回详细的诊断信息
func (s SFTPHelper) CheckWithDiagnostics() (*SFTPDiagnostics, error) {
	return s.checkSFTPProtocolWithDiagnostics()
}

// 保留认证检测方法作为备用（仅在用户提供认证信息时使用）
func (s SFTPHelper) CheckWithAuth(user, password, priKeyFullPath string) error {
	if user == "" || (password == "" && priKeyFullPath == "") {
		// 如果没有提供认证信息，使用协议检测方式
		_, err := s.checkSFTPProtocolWithDiagnostics()
		return err
	}

	// 用户提供了认证信息，使用传统的认证检测方式
	var authMethod ssh.AuthMethod
	if priKeyFullPath == "" {
		authMethod = ssh.Password(password)
	} else {
		// 验证私钥文件路径是否安全
		if err := utils.ValidatePrivateKeyPath(priKeyFullPath); err != nil {
			return fmt.Errorf("invalid private key path: %w", err)
		}

		// use private key login, password belong to private key
		keyData, err := os.ReadFile(priKeyFullPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file %s: %w", filepath.Base(priKeyFullPath), err)
		}

		var signer ssh.Signer
		if password != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(password))
			if err != nil {
				return fmt.Errorf("failed to parse private key with passphrase: %w", err)
			}
		} else {
			signer, err = ssh.ParsePrivateKey(keyData)
			if err != nil {
				return fmt.Errorf("failed to parse private key: %w", err)
			}
		}
		authMethod = ssh.PublicKeys(signer)
	}

	return s.checkWithAuth(user, authMethod)
}

// 带诊断信息的SFTP协议检测方法 - 简化为3层检测
func (s SFTPHelper) checkSFTPProtocolWithDiagnostics() (*SFTPDiagnostics, error) {
	startTime := time.Now()
	diagnostics := &SFTPDiagnostics{
		TCPConnected: false,
	}

	// Layer 1: TCP连接测试
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout)
	if err != nil {
		diagnostics.ErrorMsg = fmt.Sprintf("TCP连接失败: %v", err)
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, custom_error.ErrSFTPNotFound
	}
	defer netConn.Close()
	diagnostics.TCPConnected = true

	// Layer 2: SSH协议识别 - 读取SSH Banner
	netConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(netConn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		diagnostics.ErrorMsg = fmt.Sprintf("读取SSH Banner失败: %v", err)
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, custom_error.ErrSFTPNotFound
	}

	diagnostics.SSHBanner = strings.TrimSpace(banner)
	if !strings.HasPrefix(diagnostics.SSHBanner, "SSH-") {
		diagnostics.ErrorMsg = "非SSH协议服务"
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, custom_error.ErrSFTPNotFound
	}

	// 提取SSH版本信息
	parts := strings.Split(diagnostics.SSHBanner, "-")
	if len(parts) >= 2 {
		diagnostics.SSHVersion = parts[1]
	}

	// Layer 3: SFTP子系统支持检测
	sftpSupported, subsystemResponse, err := s.detectSFTPSupport(netConn)
	if err != nil {
		diagnostics.ErrorMsg = fmt.Sprintf("SFTP子系统检测失败: %v", err)
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, err
	}

	diagnostics.SFTPSupported = sftpSupported
	diagnostics.SubsystemResponse = subsystemResponse
	diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()

	if !sftpSupported {
		return diagnostics, custom_error.ErrSFTPNotFound
	}

	return diagnostics, nil
}

// detectSFTPSupport 检测SSH服务是否支持SFTP子系统
func (s SFTPHelper) detectSFTPSupport(netConn net.Conn) (bool, string, error) {
	// 为SSH连接建立新的连接（复用现有连接可能导致状态混乱）
	sshConn, err := net.DialTimeout("tcp", s.uri, s.timeout/2)
	if err != nil {
		return false, "", fmt.Errorf("建立SSH连接失败: %w", err)
	}
	defer sshConn.Close()

	// 配置SSH客户端 - 使用协议检测专用的用户名和空认证
	config := &ssh.ClientConfig{
		User:            "protocol-detector", // 专用于协议检测的用户名
		Auth:            []ssh.AuthMethod{},   // 空认证数组
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.timeout / 2,
		ClientVersion:   "SSH-2.0-ProtocolDetector",
	}

	// 建立SSH客户端连接
	sshClientConn, _, requests, err := ssh.NewClientConn(sshConn, s.uri, config)
	if err != nil {
		// 如果连接失败，说明SSH服务需要认证，但这不影响SFTP支持检测
		return false, "SSH连接需要认证", nil
	}
	defer sshClientConn.Close()

	// 丢弃 incoming requests
	go ssh.DiscardRequests(requests)

	// 尝试打开session通道
	channel, _, err := sshClientConn.OpenChannel("session", nil)
	if err != nil {
		return false, "", fmt.Errorf("打开session通道失败: %w", err)
	}
	defer channel.Close()

	// 发送subsystem请求尝试启动SFTP
	ok, err := channel.SendRequest("subsystem", true, ssh.Marshal(&struct{ Name string }{"sftp"}))
	if err != nil {
		return false, "", fmt.Errorf("发送subsystem请求失败: %w", err)
	}

	if ok {
		return true, "SFTP子系统支持", nil
	} else {
		return false, "SFTP子系统不支持", nil
	}
}

// === 已移除的认证相关方法 ===
// 原来的 trySFTPUserWithDiagnostics, trySFTPWithCredentials,
// checkSFTPSubsystem, tryWithAlternativeUsers, trySFTPWithUser
// 等方法已被移除，因为它们包含了密码认证逻辑，不符合协议检测器的定位

// 基于认证的检测方法（仅在用户提供有效认证信息时使用）
func (s SFTPHelper) checkWithAuth(user string, authMethod ssh.AuthMethod) error {
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	defer netConn.Close()

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.timeout,
	}

	sshCon, channel, req, err := ssh.NewClientConn(netConn, s.uri, config)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	defer sshCon.Close()

	sshClient := ssh.NewClient(sshCon, channel, req)
	ftp, err := sftp.NewClient(sshClient)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	defer ftp.Close()

	// 验证SFTP功能 - 尝试读取根目录
	_, err = ftp.ReadDir("/")
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}

	return nil
}
