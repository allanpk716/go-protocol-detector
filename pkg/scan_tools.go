package pkg

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/3th1nk/cidr"
	"github.com/allanpk716/go-protocol-detector/internal/errors"
	"github.com/allanpk716/go-protocol-detector/internal/utils"
)

type ScanTools struct {
	threads         int                    // 同时扫描的并发数
	timeOut         time.Duration          // 超时时间
	resourceLimiter *utils.ResourceLimiter // 资源限制器
}

func NewScanTools(threads int, timeOut time.Duration) *ScanTools {
	// 限制最大线程数
	if threads <= 0 {
		threads = 1
	}
	if threads > 1000 {
		threads = 1000
		log.Println("threads is set to 1000")
	}

	// 设置默认超时
	if timeOut == 0 {
		timeOut = time.Second * 2
	}

	// 创建资源限制器：最大连接数为线程数的2倍，内存限制512MB
	maxConnections := threads * 2
	if maxConnections > 500 {
		maxConnections = 500
	}

	scan := &ScanTools{
		threads:         threads,
		timeOut:         timeOut,
		resourceLimiter: utils.NewResourceLimiter(maxConnections, 512),
	}

	return scan
}

func (s ScanTools) Scan(protocolType ProtocolType, inputInfo InputInfo, showProgressStep bool) (*OutputInfo, error) {
	// Input validation
	if inputInfo.Host == "" {
		return nil, fmt.Errorf("scan - Host is empty")
	}
	if inputInfo.Port == "" {
		return nil, fmt.Errorf("scan - InputInfo Port is empty")
	}

	// Parse hosts and ports
	ipRangeInfos, err := s.parseHost(inputInfo.Host)
	if err != nil {
		return nil, err
	}
	ports, err := s.parsePort(inputInfo.Port)
	if err != nil {
		return nil, errors.NewValidationError("failed to parse ports", err)
	}

	// Create scan core with shared state
	core := newScanCore(&s, protocolType, inputInfo, showProgressStep, false)

	// Create channel for results
	channelSize := calculateChannelSize(s.threads)
	checkResultChan := make(chan CheckResult, channelSize)

	// Create output info and wait group
	outputInfo := OutputInfo{
		ProtocolType:     protocolType,
		SuccessMapString: make(map[string][]string, 100),
		FailedMapString:  make(map[string][]string, 100),
	}
	wg := &sync.WaitGroup{}

	// Start result collector goroutine
	revDone := core.startResultCollector(checkResultChan, &outputInfo, nil)

	// Create goroutine pool
	p, err := core.createGoroutinePoolWithCallback(checkResultChan, wg, nil)
	if err != nil {
		return nil, err
	}
	defer p.Release()

	// Execute scan - iterate through IP ranges and ports
	if err := s.scanIPRanges(core, p, ipRangeInfos, ports, checkResultChan, wg, nil); err != nil {
		return nil, err
	}

	// Wait for completion
	wg.Wait()
	close(checkResultChan)
	<-revDone

	// Log resource usage statistics
	stats := s.resourceLimiter.GetStats()
	log.Printf("Scan completed - %s", stats.String())

	return &outputInfo, nil
}

// ScanWithOutput scans with enhanced CSV logging and progress tracking
func (s ScanTools) ScanWithOutput(protocolType ProtocolType, inputInfo InputInfo, showProgressStep bool, csvOutputPath string, enableProgress bool) (*OutputInfo, *ScanContext, error) {
	// Input validation
	if inputInfo.Host == "" {
		return nil, nil, fmt.Errorf("scan - Host is empty")
	}
	if inputInfo.Port == "" {
		return nil, nil, fmt.Errorf("scan - InputInfo Port is empty")
	}

	// Create scan context for tracking
	scanContext := NewScanContext(protocolType, inputInfo.Host, inputInfo.Port, s.threads, int(s.timeOut.Milliseconds()))

	// Create progress manager (will be initialized after parsing hosts/ports)
	var progressManager *ProgressManager

	// Create resume manager if output path is provided
	var resumeManager *ResumeManager
	if csvOutputPath != "" {
		resumeManager = NewResumeManager(filepath.Dir(csvOutputPath))

		// Setup signal handlers for graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigChan
			log.Printf("Received interrupt signal, shutting down gracefully...")

			// Cancel scan context to signal all goroutines to stop
			if scanContext.Cancel != nil {
				scanContext.Cancel()
			}

			// Save state before exit
			if resumeManager != nil && csvOutputPath != "" {
				if err := resumeManager.SaveScanState(scanContext, inputInfo, csvOutputPath); err != nil {
					log.Printf("Failed to save scan state: %v", err)
				} else {
					log.Printf("Scan state saved. Use --resume=%s to continue.", scanContext.ScanID)
				}
			}

			// Note: Not using os.Exit(0) to allow defer statements to execute
			// The scan will naturally exit after all goroutines complete
		}()
	}

	// Parse hosts and ports
	ipRangeInfos, err := s.parseHost(inputInfo.Host)
	if err != nil {
		return nil, nil, err
	}
	ports, err := s.parsePort(inputInfo.Port)
	if err != nil {
		return nil, nil, errors.NewValidationError("failed to parse ports", err)
	}

	// Calculate total IPs for progress bar
	totalIPs := 0
	for _, ipRangeInfo := range ipRangeInfos {
		if ipRangeInfo.CICR != nil {
			// Get IP count from CIDR
			totalIPs += int(ipRangeInfo.CICR.IPCount().Int64())
		} else {
			totalIPs += ipRangeInfo.CountNextTime
		}
	}

	// Initialize progress manager if enabled (independent of showProgressStep)
	if enableProgress {
		progressManager = NewProgressManager(totalIPs, len(ports))
		defer progressManager.Finish()
	}

	// Generate target list for scan context
	var allTargets []string
	for _, ipRangeInfo := range ipRangeInfos {
		if ipRangeInfo.CICR != nil {
			err = ipRangeInfo.CICR.ForEachIP(func(ip string) error {
				for _, port := range ports {
					allTargets = append(allTargets, fmt.Sprintf("%s:%d", ip, port))
				}
				return nil
			})
			if err != nil {
				return nil, nil, fmt.Errorf("scan - ForEachIP error: %w", err)
			}
		} else {
			baseIP := ipRangeInfo.Begin.To4()
			for i := 0; i < ipRangeInfo.CountNextTime; i++ {
				currentIP := make(net.IP, len(baseIP))
				copy(currentIP, baseIP)
				currentIP[3] += uint8(i)
				for _, port := range ports {
					allTargets = append(allTargets, fmt.Sprintf("%s:%d", currentIP.String(), port))
				}
			}
		}
	}

	// Set targets in scan context
	scanContext.SetTargets(allTargets)

	log.Printf("Starting scan %s: %d targets, %d threads", scanContext.ScanID, scanContext.TotalTargets, s.threads)

	// Create scan core with shared state
	core := newScanCore(&s, protocolType, inputInfo, showProgressStep, enableProgress)

	// Create channel for results
	channelSize := calculateChannelSize(s.threads)
	checkResultChan := make(chan CheckResult, channelSize)

	// Create output info and wait group
	outputInfo := OutputInfo{
		ProtocolType:     protocolType,
		SuccessMapString: make(map[string][]string, 100),
		FailedMapString:  make(map[string][]string, 100),
	}
	wg := &sync.WaitGroup{}

	// Start result collector goroutine (with scanContext for tracking)
	revDone := core.startResultCollector(checkResultChan, &outputInfo, scanContext)

	// Create goroutine pool
	p, err := core.createGoroutinePoolWithCallback(checkResultChan, wg, scanContext)
	if err != nil {
		return nil, nil, err
	}
	defer p.Release()

	// Progress reporting goroutine
	progressTicker := time.NewTicker(10 * time.Second)
	defer progressTicker.Stop()

	stopProgress := make(chan struct{})
	go func() {
		for {
			select {
			case <-progressTicker.C:
				if showProgressStep {
					stats := scanContext.GetStats()
					log.Printf("Progress: %s - %.1f%% (%d/%d) - Success: %d, Failed: %d, Elapsed: %v",
						scanContext.ScanID, stats.ProgressPercent, stats.ScannedTargets, stats.TotalTargets,
						stats.SuccessCount, stats.FailureCount, stats.ScanDuration)
				}
			case <-stopProgress:
				return
			}
		}
	}()

	cleanup := func() {
		close(stopProgress)
		close(checkResultChan)
		<-revDone
	}

	// Execute scan - iterate through IP ranges and ports
	if err := s.scanIPRanges(core, p, ipRangeInfos, ports, checkResultChan, wg, progressManager); err != nil {
		cleanup()
		return nil, nil, err
	}

	// Wait for completion
	wg.Wait()
	cleanup()

	// Final progress update
	finalStats := scanContext.GetStats()
	log.Printf("Scan completed %s: %.1f%% (%d/%d) - Success: %d, Failed: %d, Duration: %v",
		scanContext.ScanID, finalStats.ProgressPercent, finalStats.ScannedTargets, finalStats.TotalTargets,
		finalStats.SuccessCount, finalStats.FailureCount, finalStats.ScanDuration)

	// Write CSV output
	if csvOutputPath != "" {
		if err := s.writeResultsToCSV(&outputInfo, scanContext.ScanID, csvOutputPath); err != nil {
			log.Printf("Warning: Failed to write CSV results: %v", err)
		} else {
			log.Printf("CSV results written to: %s", csvOutputPath)
		}
	}

	// Remove from incomplete scans index if scan completed successfully
	if resumeManager != nil && scanContext.IsComplete() {
		if err := resumeManager.RemoveIncompleteScan(scanContext.ScanID); err != nil {
			log.Printf("Warning: Failed to remove scan from incomplete index: %v", err)
		}
	}

	// Log resource usage statistics
	stats := s.resourceLimiter.GetStats()
	log.Printf("Scan completed - %s", stats.String())

	return &outputInfo, scanContext, nil
}

// ResumeScan resumes a previously interrupted scan
// TODO: Implement this method to avoid circular imports
func (s ScanTools) ResumeScan(scanID string, showProgressStep bool) (*OutputInfo, *ScanContext, error) {
	return nil, nil, fmt.Errorf("ResumeScan not implemented yet")
}

// parseHostPort parses a host:port string into host and port
func parseHostPort(target string) (string, int) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 {
		return "", 0
	}

	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return host, 0
	}

	return host, port
}

// parseHost 解析 Host 输入的信息 192.168.0.1,192.168.50.1-254,192.168.31.0/24
func (s ScanTools) parseHost(inputHostString string) ([]IPRangeInfo, error) {

	// Check for empty input
	if inputHostString == "" {
		return nil, fmt.Errorf("parseHost - input host string is empty")
	}

	var err error
	parsedHostList := make([]IPRangeInfo, 0)
	// 先使用 , 进行分割
	hostList := strings.Split(inputHostString, ",")
	for _, oneHostString := range hostList {

		ipRangeInfo := IPRangeInfo{}
		if strings.Contains(oneHostString, "/") {
			// CICR 地址类型
			ipRangeInfo.CICR, err = cidr.ParseCIDR(oneHostString)
			if err != nil {
				return nil, fmt.Errorf("parseHost - ParseCIDR Error: %v", err)
			}

			parsedHostList = append(parsedHostList, ipRangeInfo)

		} else if strings.Contains(oneHostString, "-") {
			// 简易的 192.168.1.1-254

			ipSplit := strings.Split(oneHostString, "-")
			if len(ipSplit) > 2 {
				return nil, fmt.Errorf("scan - InputInfo Host Split Error: %s", inputHostString)
			} else if len(ipSplit) == 2 {
				// 说明是 192.168.50.123-200 格式
				address := net.ParseIP(ipSplit[0])
				if address == nil {
					return nil, fmt.Errorf("scan - InputInfo Host ParseIP Error: %v", ipSplit[0])
				}
				parts := strings.Split(ipSplit[0], ".")
				if len(parts) != 4 {
					return nil, fmt.Errorf("scan - InputInfo Host Split Error: %v", ipSplit[0])
				}
				var startIndex, endIndex int
				startIndex, err = strconv.Atoi(parts[3])
				if err != nil {
					return nil, fmt.Errorf("scan - InputInfo Host Atoi Error: %v", ipSplit[0])
				}

				endIndex, err = strconv.Atoi(ipSplit[1])
				if err != nil {
					return nil, fmt.Errorf("scan - InputInfo Host Atoi Error: %v", ipSplit[1])
				}

				// 添加输入验证：边界检查
				if startIndex < 0 || startIndex > 255 {
					return nil, fmt.Errorf("scan - InputInfo Host start index out of range [0-255]: %d", startIndex)
				}
				if endIndex < 0 || endIndex > 255 {
					return nil, fmt.Errorf("scan - InputInfo Host end index out of range [0-255]: %d", endIndex)
				}
				if startIndex > endIndex {
					return nil, fmt.Errorf("scan - InputInfo Host start index (%d) cannot be greater than end index (%d)", startIndex, endIndex)
				}

				// 防止大范围导致的资源耗尽
				maxRangeSize := 1000
				rangeSize := endIndex - startIndex + 1
				if rangeSize > maxRangeSize {
					return nil, fmt.Errorf("scan - InputInfo Host range size (%d) exceeds maximum allowed (%d)", rangeSize, maxRangeSize)
				}

				// 显式的 IP 字节溢出检查
				// 确保 baseIP[3] + rangeSize - 1 不会超过 255（uint8 的最大值）
				// 虽然 endIndex <= 255 已覆盖此情况，但显式检查使代码意图更明确
				if startIndex+rangeSize-1 > 255 {
					return nil, fmt.Errorf("scan - InputInfo Host range would cause octet overflow: %s (start=%d, size=%d, max=255)", oneHostString, startIndex, rangeSize)
				}

				ipRangeInfo.Begin = address
				ipRangeInfo.CountNextTime = rangeSize
			}
			parsedHostList = append(parsedHostList, ipRangeInfo)

		} else {
			// 单个 IP 地址
			address := net.ParseIP(oneHostString)
			if address == nil {
				return nil, fmt.Errorf("scan - InputInfo Host ParseIP Error")
			}
			ipRangeInfo.Begin = address
			ipRangeInfo.CountNextTime = 1
			parsedHostList = append(parsedHostList, ipRangeInfo)

		}
	}

	return parsedHostList, nil
}

// parsePort 解析 Port 输入的信息 80,8080,8000-8100
func (s ScanTools) parsePort(inputPortString string) ([]int, error) {

	// Check for empty input
	if inputPortString == "" {
		return nil, fmt.Errorf("parsePort - input port string is empty")
	}

	const (
		MinPort = 0
		MaxPort = 65535
	)

	portList := make([]int, 0)
	tmpPorts := make([]string, 0)
	tmpPorts = strings.Split(inputPortString, ",")

	// 检查端口数量限制，防止创建过大的端口列表
	totalPortCount := 0
	for _, port := range tmpPorts {
		portSplit := strings.Split(port, "-")
		if len(portSplit) > 2 {
			return nil, fmt.Errorf("scan - InputInfo Port Split Error: %s", port)
		} else if len(portSplit) == 2 {
			// 说明是 20-30 这样的格式
			startPort, err := strconv.Atoi(portSplit[0])
			if err != nil {
				return nil, fmt.Errorf("scan - InputInfo Port Atoi Error: %w", err)
			}
			endPort, err := strconv.Atoi(portSplit[1])
			if err != nil {
				return nil, fmt.Errorf("scan - InputInfo Port Atoi Error: %w", err)
			}

			// 验证端口边界
			if startPort < MinPort || startPort > MaxPort {
				return nil, errors.NewValidationError(
					fmt.Sprintf("port out of range: %d (valid range: %d-%d)", startPort, MinPort, MaxPort),
					nil,
				)
			}
			if endPort < MinPort || endPort > MaxPort {
				return nil, errors.NewValidationError(
					fmt.Sprintf("port out of range: %d (valid range: %d-%d)", endPort, MinPort, MaxPort),
					nil,
				)
			}

			if startPort > endPort {
				return nil, errors.NewValidationError(
					fmt.Sprintf("invalid port range: start port %d > end port %d", startPort, endPort),
					nil,
				)
			}

			// 计算这个范围的端口数量
			rangePortCount := endPort - startPort + 1
			totalPortCount += rangePortCount

			// 防止创建过大的端口列表（资源保护）
			if totalPortCount > 65536 {
				return nil, errors.NewResourceLimitError(
					fmt.Sprintf("too many ports specified (max 65536 allowed, got %d)", totalPortCount),
					nil,
				)
			}

			for i := startPort; i <= endPort; i++ {
				portList = append(portList, i)
			}
		} else {
			// 说明是单个端口格式
			portInt, err := strconv.Atoi(port)
			if err != nil {
				return nil, fmt.Errorf("scan - InputInfo Port Atoi Error: %w", err)
			}

			// 验证端口边界
			if portInt < MinPort || portInt > MaxPort {
				return nil, errors.NewValidationError(
					fmt.Sprintf("port out of range: %d (valid range: %d-%d)", portInt, MinPort, MaxPort),
					nil,
				)
			}

			totalPortCount++
			if totalPortCount > 65536 {
				return nil, errors.NewResourceLimitError(
					fmt.Sprintf("too many ports specified (max 65536 allowed, got %d)", totalPortCount),
					nil,
				)
			}

			portList = append(portList, portInt)
		}
	}

	return portList, nil
}

type IPRangeInfo struct {
	Begin         net.IP
	CountNextTime int
	CICR          *cidr.CIDR
}

type DeliveryInfo struct {
	ProtocolType       ProtocolType
	Host               string
	Port               string
	User               string
	Password           string
	PrivateKeyFullPath string
	Detector           *Detector
	CheckResultChan    chan CheckResult
	Wg                 *sync.WaitGroup
	ProgressManager    *ProgressManager // Added for progress tracking
	ScanContext        *ScanContext    // Added for cancellation support
}

type CheckResult struct {
	Success      bool
	ProtocolType ProtocolType
	Host         string
	Port         string
	Timestamp    time.Time
	ResponseTime time.Duration
	ErrorMessage string
}

type InputInfo struct {
	Host               string // 192.168.50.123-200
	Port               string // 80,90,100,101-120
	User               string
	Password           string
	PrivateKeyFullPath string
}

type OutputInfo struct {
	ProtocolType     ProtocolType
	SuccessMapString map[string][]string
	FailedMapString  map[string][]string
}

type ProtocolType int

const (
	RDP ProtocolType = iota + 1
	SSH
	FTP
	SFTP
	Telnet
	VNC
	Common
	RustDeskHBBS
	RustDeskHBBR
	RustDeskHBBS21116
)

func (p ProtocolType) String() string {
	switch p {
	case RDP:
		return "rdp"
	case SSH:
		return "ssh"
	case FTP:
		return "ftp"
	case SFTP:
		return "sftp"
	case Telnet:
		return "telnet"
	case VNC:
		return "vnc"
	case Common:
		return "common"
	case RustDeskHBBS:
		return "rustdesk-hbbs"
	case RustDeskHBBR:
		return "rustdesk-hbbr"
	case RustDeskHBBS21116:
		return "rustdesk-hbbs-21116"
	default:
		return "unknown"
	}
}

func String2ProtocolType(input string) ProtocolType {
	switch input {
	case "rdp":
		return RDP
	case "ssh":
		return SSH
	case "ftp":
		return FTP
	case "sftp":
		return SFTP
	case "telnet":
		return Telnet
	case "vnc":
		return VNC
	case "common":
		return Common
	case "rustdesk-hbbs":
		return RustDeskHBBS
	case "rustdesk-hbbr":
		return RustDeskHBBR
	case "rustdesk-hbbs-21116":
		return RustDeskHBBS21116
	default:
		return Common
	}
}

// writeResultsToCSV writes scan results to a CSV file
func (s ScanTools) writeResultsToCSV(outputInfo *OutputInfo, scanID string, csvPath string) error {
	// Create CSV writer
	csvWriter, err := NewCSVWriter(csvPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV writer: %w", err)
	}
	defer csvWriter.Close()

	// Write successful results
	for host, ports := range outputInfo.SuccessMapString {
		for _, portStr := range ports {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue // Skip invalid port numbers
			}

			csvResult := CSVResult{
				Timestamp:    time.Now(),
				ScanID:       scanID,
				Protocol:     outputInfo.ProtocolType.String(),
				Host:         host,
				Port:         port,
				Status:       "success",
				ResponseTime: "", // We don't have response time in OutputInfo
				ErrorMessage: "",
			}
			if err := csvWriter.WriteResult(csvResult); err != nil {
				return fmt.Errorf("failed to write successful result: %w", err)
			}
		}
	}

	// Write failed results
	for host, ports := range outputInfo.FailedMapString {
		for _, portStr := range ports {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue // Skip invalid port numbers
			}

			csvResult := CSVResult{
				Timestamp:    time.Now(),
				ScanID:       scanID,
				Protocol:     outputInfo.ProtocolType.String(),
				Host:         host,
				Port:         port,
				Status:       "failed",
				ResponseTime: "",
				ErrorMessage: "", // We don't have error messages in OutputInfo
			}
			if err := csvWriter.WriteResult(csvResult); err != nil {
				return fmt.Errorf("failed to write failed result: %w", err)
			}
		}
	}

	// Flush all data to disk
	if err := csvWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush CSV data: %w", err)
	}

	return nil
}
