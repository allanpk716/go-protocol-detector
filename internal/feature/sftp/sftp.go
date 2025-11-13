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
	TCPOK            bool     // TCP连接是否成功
	SSHBanner        string   // SSH服务器banner信息
	SSHVersion       string   // SSH版本信息
	AuthRequired     bool     // 是否需要认证
	TriedUsers       []string // 尝试的用户名列表
	SubsystemOK      bool     // SFTP subsystem是否成功
	DetailedErrors   []string // 详细错误信息
	TotalTime        time.Duration // 总检测时间
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
	// 新的SFTP检测逻辑：使用分层检测策略进行SFTP子系统探测
	_, err := s.checkSFTPSubsystemWithDiagnostics()
	return err
}

// CheckWithDiagnostics 执行SFTP检测并返回详细的诊断信息
func (s SFTPHelper) CheckWithDiagnostics() (*SFTPDiagnostics, error) {
	return s.checkSFTPSubsystemWithDiagnostics()
}

// 保留原有的认证检测方法作为备用
func (s SFTPHelper) CheckWithAuth(user, password, priKeyFullPath string) error {
	var authMethod ssh.AuthMethod
	// use password login
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

	return s.check(user, authMethod)
}

// 带诊断信息的SFTP子系统检测方法
func (s SFTPHelper) checkSFTPSubsystemWithDiagnostics() (*SFTPDiagnostics, error) {
	startTime := time.Now()
	diagnostics := &SFTPDiagnostics{
		TriedUsers:     []string{},
		DetailedErrors: []string{},
	}

	// 1. TCP连接测试
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout)
	if err != nil {
		diagnostics.TCPOK = false
		diagnostics.DetailedErrors = append(diagnostics.DetailedErrors, fmt.Sprintf("TCP连接失败: %v", err))
		diagnostics.TotalTime = time.Since(startTime)
		return diagnostics, custom_error.ErrSFTPNotFound
	}
	defer netConn.Close()
	diagnostics.TCPOK = true

	// 2. 读取SSH Banner
	netConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(netConn)
	banner, err := reader.ReadString('\n')
	if err == nil {
		diagnostics.SSHBanner = strings.TrimSpace(banner)
		if strings.HasPrefix(diagnostics.SSHBanner, "SSH-") {
			parts := strings.Split(diagnostics.SSHBanner, "-")
			if len(parts) >= 2 {
				diagnostics.SSHVersion = parts[1]
			}
		}
	}

	// 3. 尝试SSH连接和SFTP子系统探测
	err = s.trySFTPWithDiagnostics(netConn, diagnostics)
	if err != nil {
		diagnostics.DetailedErrors = append(diagnostics.DetailedErrors, fmt.Sprintf("SFTP子系统检测失败: %v", err))
		diagnostics.TotalTime = time.Since(startTime)
		return diagnostics, err
	}

	diagnostics.TotalTime = time.Since(startTime)
	return diagnostics, nil
}

// 尝试SFTP检测（带诊断信息）
func (s SFTPHelper) trySFTPWithDiagnostics(netConn net.Conn, diagnostics *SFTPDiagnostics) error {
	// 分层检测策略：
	// 1. 首先尝试无认证连接
	// 2. 然后尝试常见弱凭据
	// 3. 最后尝试默认用户名+无认证

	// 策略1: 尝试无认证连接
	err := s.trySFTPUserWithDiagnostics("sftp-check", s.uri, diagnostics)
	if err == nil {
		diagnostics.SubsystemOK = true
		return nil
	}

	// 策略2: 尝试常见弱凭据组合
	commonCredentials := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"root", "root"},
		{"root", "password"},
		{"user", "user"},
		{"demo", "password"}, // 公开测试服务器凭据
		{"demo", "demo"},
		{"test", "test"},
		{"guest", "guest"},
		{"testuser", "testpass"}, // Docker SFTP常用凭据
		{"foo", "bar"}, // 另一个常见测试凭据
		{"", ""}, // 匿名登录
	}

	for _, cred := range commonCredentials {
		diagnostics.TriedUsers = append(diagnostics.TriedUsers,
			fmt.Sprintf("%s:%s", cred.username, cred.password))

		err := s.trySFTPWithCredentials(cred.username, cred.password, s.uri, diagnostics)
		if err == nil {
			diagnostics.SubsystemOK = true
			return nil
		}

		diagnostics.DetailedErrors = append(diagnostics.DetailedErrors,
			fmt.Sprintf("凭据 '%s:%s' 检测失败: %v", cred.username, cred.password, err))
	}

	// 策略3: 尝试常见用户名+无认证
	users := []string{"root", "admin", "user", "guest", "test", "ftp", "sftp"}

	for _, username := range users {
		diagnostics.TriedUsers = append(diagnostics.TriedUsers, username+"(无认证)")

		err := s.trySFTPUserWithDiagnostics(username, s.uri, diagnostics)
		if err == nil {
			diagnostics.SubsystemOK = true
			return nil
		}

		diagnostics.DetailedErrors = append(diagnostics.DetailedErrors,
			fmt.Sprintf("用户名 '%s'(无认证) 检测失败: %v", username, err))
	}

	// 所有策略都失败
	diagnostics.AuthRequired = true
	return custom_error.ErrSFTPNotFound
}

// 使用特定用户名尝试SFTP检测（带诊断信息）
func (s SFTPHelper) trySFTPUserWithDiagnostics(username string, uri string, diagnostics *SFTPDiagnostics) error {
	// 为每次尝试建立新的TCP连接
	netConn, err := net.DialTimeout("tcp", uri, s.timeout/2)
	if err != nil {
		return fmt.Errorf("TCP连接失败: %w", err)
	}
	defer netConn.Close()

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{}, // 空认证数组
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.timeout / 2,
		ClientVersion:   "SSH-2.0-ProtocolDetector",
	}

	// 建立SSH连接
	sshConn, _, reqs, err := ssh.NewClientConn(netConn, uri, config)
	if err != nil {
		return fmt.Errorf("SSH连接失败: %w", err)
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	// 尝试打开session通道
	session, _, err := sshConn.OpenChannel("session", nil)
	if err != nil {
		return fmt.Errorf("打开session通道失败: %w", err)
	}
	defer session.Close()

	// 发送subsystem请求尝试启动SFTP
	ok, err := session.SendRequest("subsystem", true, ssh.Marshal(&struct{ Name string }{"sftp"}))
	if err != nil {
		return fmt.Errorf("发送subsystem请求失败: %w", err)
	}

	if !ok {
		return fmt.Errorf("SFTP subsystem请求被拒绝")
	}

	return nil
}

// 使用用户名密码尝试SFTP检测
func (s SFTPHelper) trySFTPWithCredentials(username, password, uri string, diagnostics *SFTPDiagnostics) error {
	// 为每次尝试建立新的TCP连接
	netConn, err := net.DialTimeout("tcp", uri, s.timeout/4) // 使用更短的超时
	if err != nil {
		return fmt.Errorf("TCP连接失败: %w", err)
	}
	defer netConn.Close()

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.timeout / 4,
		ClientVersion:   "SSH-2.0-ProtocolDetector",
	}

	// 建立SSH连接
	sshConn, _, reqs, err := ssh.NewClientConn(netConn, uri, config)
	if err != nil {
		return fmt.Errorf("SSH连接失败: %w", err)
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	// 尝试打开session通道
	session, _, err := sshConn.OpenChannel("session", nil)
	if err != nil {
		return fmt.Errorf("打开session通道失败: %w", err)
	}
	defer session.Close()

	// 发送subsystem请求尝试启动SFTP
	ok, err := session.SendRequest("subsystem", true, ssh.Marshal(&struct{ Name string }{"sftp"}))
	if err != nil {
		return fmt.Errorf("发送subsystem请求失败: %w", err)
	}

	if !ok {
		return fmt.Errorf("SFTP subsystem请求被拒绝")
	}

	return nil
}

// 新的SFTP子系统检测方法：无需认证，直接探测SFTP支持
func (s SFTPHelper) checkSFTPSubsystem() error {
	// 建立TCP连接
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	defer netConn.Close()

	// 创建SSH客户端配置，使用空认证方法（无密码）
	config := &ssh.ClientConfig{
		User:            "sftp-check", // 使用通用用户名
		Auth:            []ssh.AuthMethod{}, // 空认证数组
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.timeout,
		ClientVersion:   "SSH-2.0-ProtocolDetector",
	}

	// 建立SSH连接
	sshConn, _, reqs, err := ssh.NewClientConn(netConn, s.uri, config)
	if err != nil {
		// 如果连接失败，尝试其他常见用户名
		return s.tryWithAlternativeUsers()
	}
	defer sshConn.Close()

	// 关闭不需要的通道
	go ssh.DiscardRequests(reqs)

	// 尝试打开session通道
	session, _, err := sshConn.OpenChannel("session", nil)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	defer session.Close()

	// 发送subsystem请求尝试启动SFTP
	ok, err := session.SendRequest("subsystem", true, ssh.Marshal(&struct{ Name string }{"sftp"}))
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}

	if !ok {
		// subsystem请求被拒绝，说明不支持SFTP
		return custom_error.ErrSFTPNotFound
	}

	// 如果到达这里，说明SFTP子系统请求成功
	return nil
}

// 尝试使用其他常见用户名进行检测
func (s SFTPHelper) tryWithAlternativeUsers() error {
	commonUsers := []string{"root", "admin", "user", "guest", "test"}

	for _, username := range commonUsers {
		if s.trySFTPWithUser(username) == nil {
			return nil
		}
	}

	return custom_error.ErrSFTPNotFound
}

// 使用指定用户名尝试SFTP检测
func (s SFTPHelper) trySFTPWithUser(username string) error {
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout/2) // 使用较短超时
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	defer netConn.Close()

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{}, // 空认证数组
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.timeout / 2,
		ClientVersion:   "SSH-2.0-ProtocolDetector",
	}

	sshConn, _, reqs, err := ssh.NewClientConn(netConn, s.uri, config)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	session, _, err := sshConn.OpenChannel("session", nil)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	defer session.Close()

	ok, err := session.SendRequest("subsystem", true, ssh.Marshal(&struct{ Name string }{"sftp"}))
	if err != nil || !ok {
		return custom_error.ErrSFTPNotFound
	}

	return nil
}

// 保留原有的认证检测方法
func (s SFTPHelper) check(user string, authMethod ssh.AuthMethod) error {
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
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
	sshClient := ssh.NewClient(sshCon, channel, req)
	ftp, err := sftp.NewClient(sshClient)
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	// read a directory
	_, err = ftp.ReadDir("/")
	if err != nil {
		return custom_error.ErrSFTPNotFound
	}
	return nil
}
