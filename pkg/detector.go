package pkg

import (
	"bytes"
	"io"
	"github.com/allanpk716/go-protocol-detector/internal/common"
	"github.com/allanpk716/go-protocol-detector/internal/custom_error"
	"github.com/allanpk716/go-protocol-detector/internal/feature/ftp"
	"github.com/allanpk716/go-protocol-detector/internal/feature/rdp"
	"github.com/allanpk716/go-protocol-detector/internal/feature/sftp"
	"github.com/allanpk716/go-protocol-detector/internal/feature/ssh"
	"github.com/allanpk716/go-protocol-detector/internal/feature/telnet"
	"github.com/allanpk716/go-protocol-detector/internal/feature/vnc"
	"github.com/allanpk716/go-protocol-detector/internal/feature/rustdesk"
	"github.com/allanpk716/go-protocol-detector/internal/utils"
	"net"
	"time"
)

const (
	// MaxReadSize 是从网络读取的最大字节数
	MaxReadSize = 4096
	// ReadTimeout 是网络读取的超时时间
	ReadTimeout = 5 * time.Second
)

type Detector struct {
	rdp               *rdp.RDPHelper
	ssh               *ssh.SSHHelper
	ftp               *ftp.FTPHelper
	rustdeskHBBS      *rustdesk.HBBSHelper
	rustdeskHBBR      *rustdesk.HBBRHelper
	rustdeskHBBS21116 *rustdesk.HBBS21116Helper
	timeOut           time.Duration
}

func NewDetector(timeOut time.Duration) *Detector {
	d := Detector{
		rdp:               rdp.NewRDPHelper(),
		ssh:               ssh.NewSSHHelper(),
		ftp:               ftp.NewFTPHelper(),
		rustdeskHBBS:      rustdesk.NewHBBSHelper(),
		rustdeskHBBR:      rustdesk.NewHBBRHelper(),
		rustdeskHBBS21116: rustdesk.NewHBBS21116Helper(),
		timeOut:           timeOut,
	}
	return &d
}

// CheckDetail carries per-target extra info for agent mode.
// Banner: sanitized raw-response prefix of a hit (may be empty).
// Reason: negative reason of a failure ("closed|timeout|protocol_mismatch|unreachable|unknown").
type CheckDetail struct {
	Banner string
	Reason string
}

// CheckDetailed runs the protocol check for pt and returns extra detail.
// It is the agent-mode entry point; the plain XxxCheck methods stay for tests
// and backward compatibility.
//
// Banner capture scope is fixed by decision D7: only ssh/ftp/vnc/sftp return
// a banner; rdp/rustdesk/common never do (captureBanner=false).
func (d Detector) CheckDetailed(pt ProtocolType, host, port, user, password, privateKeyFullPath string) (CheckDetail, error) {
	switch pt {
	case RDP:
		return d.commonCheckDetailed(host, port, d.rdp.SenderPackage, d.rdp.ReceiverFeatures, custom_error.ErrRDPNotFound, false)
	case SSH:
		return d.commonCheckDetailed(host, port, d.ssh.SenderPackage, d.ssh.ReceiverFeatures, custom_error.ErrSSHNotFound, true)
	case FTP:
		return d.commonCheckDetailed(host, port, d.ftp.SenderPackage, d.ftp.ReceiverFeatures, custom_error.ErrFTPNotFound, true)
	case SFTP:
		return d.sftpCheckDetailed(host, port)
	case Telnet:
		return d.telnetCheckDetailed(host, port)
	case VNC:
		return d.vncCheckDetailed(host, port)
	case RustDeskHBBS:
		// HBBS uses the RegisterPk probe, same as the old HBBSCheck (see its
		// comment); the sentinel must match too so scan results stay identical.
		return d.commonCheckDetailed(host, port, d.rustdeskHBBS21116.SenderPackage, d.rustdeskHBBS21116.ReceiverFeatures, custom_error.ErrRustDeskHBBS21116NotFound, false)
	case RustDeskHBBR:
		return d.hbbrCheckDetailed(host, port)
	case RustDeskHBBS21116:
		return d.commonCheckDetailed(host, port, d.rustdeskHBBS21116.SenderPackage, d.rustdeskHBBS21116.ReceiverFeatures, custom_error.ErrRustDeskHBBS21116NotFound, false)
	default:
		return d.commonPortCheckDetailed(host, port)
	}
}

func (d Detector) RDPCheck(host, port string) error {
	return d.commonCheck(host, port, d.rdp.SenderPackage, d.rdp.ReceiverFeatures, custom_error.ErrRDPNotFound)
}

func (d Detector) SSHCheck(host, port string) error {
	return d.commonCheck(host, port, d.ssh.SenderPackage, d.ssh.ReceiverFeatures, custom_error.ErrSSHNotFound)
}

func (d Detector) FTPCheck(host, port string) error {
	return d.commonCheck(host, port, d.ftp.SenderPackage, d.ftp.ReceiverFeatures, custom_error.ErrFTPNotFound)
}

func (d Detector) SFTPCheck(host, port, user, password, privateKeyFullPath string) error {
	// 新的SFTP检测逻辑：无需认证凭据，直接进行SFTP子系统探测
	return sftp.NewSFTPHelper(host, port, d.timeOut).Check("", "", "")
}

// 保留原有的认证式SFTP检测方法（向后兼容）
func (d Detector) SFTPCheckWithAuth(host, port, user, password, privateKeyFullPath string) error {
	return sftp.NewSFTPHelper(host, port, d.timeOut).CheckWithAuth(user, password, privateKeyFullPath)
}

func (d Detector) TelnetCheck(host, port string) error {

	tel, err := telnet.NewTelnetHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return custom_error.ErrTelnetNotFound
	}
	n, err := tel.Check()
	if err != nil || n <= 0 {
		return custom_error.ErrTelnetNotFound
	}
	return nil
}

func (d Detector) VNCCheck(host, port string) error {

	vnc, err := vnc.NewVNCHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return custom_error.ErrVNCNotFound
	}
	return vnc.Check()
}

func (d Detector) CommonPortCheck(host, port string) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return custom_error.ErrCommontPortCheckError
	}
	defer conn.Close()
	return nil
}

func (d Detector) HBBSCheck(host, port string) error {
	// HBBS 21116 uses RegisterPk message for reliable detection
	// Note: Port 21115 (NAT test) is NOT detected - see internal/feature/rustdesk/README.md
	return d.commonCheck(host, port, d.rustdeskHBBS21116.SenderPackage, d.rustdeskHBBS21116.ReceiverFeatures, custom_error.ErrRustDeskHBBS21116NotFound)
}

func (d Detector) HBBRCheck(host, port string) error {
	// HBBR uses protocol-based detection with RequestRelay message
	// The server will accept the message and keep the connection open,
	// waiting for relay pairing. No response is sent immediately.
	//
	// Detection strategy:
	// 1. Send RequestRelay message (with empty uuid)
	// 2. Server accepts the message (doesn't close connection)
	// 3. We close the connection (detection complete)
	//
	// This is reliable protocol-based detection - only HBBR servers
	// will understand the RequestRelay message and accept it.

	// Special handling for HBBR: no response expected, just send message
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return custom_error.ErrRustDeskHBBRNotFound
	}
	defer conn.Close()

	// Send the RequestRelay message
	_, err = conn.Write(d.rustdeskHBBR.SenderPackage)
	if err != nil {
		return custom_error.ErrRustDeskHBBRNotFound
	}

	// Message sent successfully - server accepted it
	// (HBBR servers keep connection open waiting for relay pairing)
	return nil
}

func (d Detector) HBBS21116Check(host, port string) error {
	// HBBS 21116 detection using RegisterPk message
	//
	// Port 21116 serves multiple functions:
	// - UDP: ID registration and heartbeat services
	// - TCP: TCP hole punching and connection services
	//
	// Detection strategy:
	// 1. Send RegisterPk message with no_register_device=true
	// 2. Server responds with RegisterPkResponse
	// 3. Verify response contains RegisterPkResponse field (field 16)
	//
	// This works reliably because:
	// - no_register_device=true doesn't require valid keys
	// - Server always responds to RegisterPk messages
	// - Protocol-specific detection eliminates false positives
	return d.commonCheck(host, port, d.rustdeskHBBS21116.SenderPackage,
		d.rustdeskHBBS21116.ReceiverFeatures, custom_error.ErrRustDeskHBBS21116NotFound)
}

func (d Detector) commonCheck(host string, port string,
	senderPackage []byte, recFeatures []common.ReceiverFeature, outErr error) error {
	_, err := d.commonCheckDetailed(host, port, senderPackage, recFeatures, outErr, false)
	return err
}

func (d Detector) commonCheckDetailed(host string, port string,
	senderPackage []byte, recFeatures []common.ReceiverFeature, outErr error, captureBanner bool) (CheckDetail, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, outErr
	}
	defer conn.Close()

	if _, err = conn.Write(senderPackage); err != nil {
		return CheckDetail{Reason: utils.ReasonClosed}, outErr
	}
	lastFeature := recFeatures[len(recFeatures)-1]
	readBytesLen := lastFeature.StartIndex + len(lastFeature.FeatureBytes)

	// 添加网络读取安全限制
	if readBytesLen > MaxReadSize {
		return CheckDetail{Reason: utils.ReasonUnknown}, outErr
	}
	if readBytesLen <= 0 {
		return CheckDetail{Reason: utils.ReasonUnknown}, outErr
	}

	var readBuf = make([]byte, readBytesLen)

	// 设置读取超时，防止阻塞
	if err = conn.SetReadDeadline(time.Now().Add(ReadTimeout)); err != nil {
		return CheckDetail{Reason: utils.ReasonUnknown}, outErr
	}

	// 使用io.ReadFull确保读取指定大小的数据或返回错误
	if _, err = io.ReadFull(conn, readBuf); err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, outErr
	}
	// according to the features
	for _, feature := range recFeatures {
		if bytes.Equal(readBuf[feature.StartIndex:feature.StartIndex+len(feature.FeatureBytes)], feature.FeatureBytes) == false {
			return CheckDetail{Reason: utils.ReasonProtocolMismatch}, outErr
		}
	}
	if captureBanner {
		return CheckDetail{Banner: utils.SanitizeBanner(d.readBannerTail(conn, readBuf))}, nil
	}
	return CheckDetail{}, nil
}

// readBannerTail best-effort drains what the peer already sent beyond the
// match window (SSH/FTP greeting lines are longer than the matched bytes).
// The match-sized io.ReadFull above usually stops short of the full line, e.g.
// SSH only reads 8 bytes ("SSH-2.0-"). The tail read is bounded (500ms) and
// NEVER affects the check outcome — it runs only after a successful match.
func (d Detector) readBannerTail(conn net.Conn, head []byte) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	tail := make([]byte, 512)
	n, _ := conn.Read(tail)
	if n <= 0 {
		return head
	}
	return append(head, tail[:n]...)
}

func (d Detector) telnetCheckDetailed(host, port string) (CheckDetail, error) {
	tel, err := telnet.NewTelnetHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrTelnetNotFound
	}
	n, err := tel.Check()
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrTelnetNotFound
	}
	if n <= 0 {
		return CheckDetail{Reason: utils.ReasonProtocolMismatch}, custom_error.ErrTelnetNotFound
	}
	return CheckDetail{}, nil
}

func (d Detector) vncCheckDetailed(host, port string) (CheckDetail, error) {
	v, err := vnc.NewVNCHelper("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrVNCNotFound
	}
	banner, reason, err := v.CheckDetailed()
	if err != nil {
		return CheckDetail{Reason: reason}, custom_error.ErrVNCNotFound
	}
	return CheckDetail{Banner: banner}, nil
}

func (d Detector) sftpCheckDetailed(host, port string) (CheckDetail, error) {
	diag, err := sftp.NewSFTPHelper(host, port, d.timeOut).CheckWithDiagnostics()
	if err == nil {
		return CheckDetail{Banner: utils.SanitizeBanner([]byte(diag.SSHBanner))}, nil
	}
	// TCP ok and a banner came back, but not a usable SSH/SFTP service
	if diag != nil && diag.TCPConnected && diag.SSHBanner != "" {
		return CheckDetail{Reason: utils.ReasonProtocolMismatch}, err
	}
	return CheckDetail{Reason: utils.ClassifyNetError(err)}, err
}

func (d Detector) hbbrCheckDetailed(host, port string) (CheckDetail, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrRustDeskHBBRNotFound
	}
	defer conn.Close()
	if _, err = conn.Write(d.rustdeskHBBR.SenderPackage); err != nil {
		return CheckDetail{Reason: utils.ReasonClosed}, custom_error.ErrRustDeskHBBRNotFound
	}
	return CheckDetail{}, nil
}

func (d Detector) commonPortCheckDetailed(host, port string) (CheckDetail, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), d.timeOut)
	if err != nil {
		return CheckDetail{Reason: utils.ClassifyNetError(err)}, custom_error.ErrCommontPortCheckError
	}
	_ = conn.Close()
	return CheckDetail{}, nil
}
