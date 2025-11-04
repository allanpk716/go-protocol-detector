package pkg

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/3th1nk/cidr"
	"github.com/allanpk716/go-protocol-detector/internal/errors"
	"github.com/allanpk716/go-protocol-detector/internal/utils"
	"github.com/panjf2000/ants/v2"
)

type ScanTools struct {
	threads        int                    // 同时扫描的并发数
	timeOut        time.Duration          // 超时时间
	resourceLimiter *utils.ResourceLimiter // 资源限制器
	rateLimiter    *utils.RateLimiter     // 速率限制器
}

func NewScanTools(threads int, timeOut time.Duration) *ScanTools {
	// 限制最大线程数
	if threads <= 0 {
		threads = 10
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
		rateLimiter:     utils.NewRateLimiter(maxConnections), // 每秒最多maxConnections个请求
	}

	return scan
}

func (s ScanTools) Scan(protocolType ProtocolType, inputInfo InputInfo, showProgressStep bool) (*OutputInfo, error) {

	d := NewDetector(s.timeOut)

	// 创建连接守卫
	connGuard := utils.NewConnectionGuard(s.resourceLimiter)

	p, err := ants.NewPoolWithFunc(s.threads, func(inData interface{}) {
		// 添加panic恢复机制，防止单个goroutine的panic影响整个程序
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic in goroutine: %v", r)
			}
		}()

		deliveryInfo := inData.(DeliveryInfo)
		checkResult := CheckResult{
			Success:      false,
			ProtocolType: deliveryInfo.ProtocolType,
			Host:         deliveryInfo.Host,
			Port:         deliveryInfo.Port,
		}

		// 获取连接许可，带超时控制
		ctx, cancel := context.WithTimeout(context.Background(), s.timeOut)
		defer cancel()

		releaseConn, err := connGuard.Acquire(ctx)
		if err != nil {
			log.Printf("Failed to acquire connection for %s:%s: %v", deliveryInfo.Host, deliveryInfo.Port, err)
			checkResult.Success = false
			// 即使获取连接失败也要确保WaitGroup被正确处理
			defer func() {
				if showProgressStep {
					log.Printf("%s %s:%s %v (connection denied)", protocolType.String(), deliveryInfo.Host, deliveryInfo.Port, checkResult.Success)
				}
				select {
				case deliveryInfo.CheckResultChan <- checkResult:
				default:
					log.Printf("Warning: result channel is full, dropping result for %s:%s", deliveryInfo.Host, deliveryInfo.Port)
				}
				deliveryInfo.Wg.Done()
			}()
			return
		}

		// 确保释放连接
		defer releaseConn()

		// 应用速率限制
		if err := s.rateLimiter.Wait(ctx); err != nil {
			log.Printf("Rate limit exceeded for %s:%s: %v", deliveryInfo.Host, deliveryInfo.Port, err)
			checkResult.Success = false
			defer func() {
				if showProgressStep {
					log.Printf("%s %s:%s %v (rate limited)", protocolType.String(), deliveryInfo.Host, deliveryInfo.Port, checkResult.Success)
				}
				select {
				case deliveryInfo.CheckResultChan <- checkResult:
				default:
					log.Printf("Warning: result channel is full, dropping result for %s:%s", deliveryInfo.Host, deliveryInfo.Port)
				}
				deliveryInfo.Wg.Done()
			}()
			return
		}

		defer func() {
			// 确保在所有情况下都正确处理资源清理
			if showProgressStep == true {
				log.Printf("%s %s:%s %v", protocolType.String(), deliveryInfo.Host, deliveryInfo.Port, checkResult.Success)
			}
			// 使用select防止channel阻塞
			select {
			case deliveryInfo.CheckResultChan <- checkResult:
			default:
				log.Printf("Warning: result channel is full, dropping result for %s:%s", deliveryInfo.Host, deliveryInfo.Port)
			}
			deliveryInfo.Wg.Done() // 确保在所有情况下都调用Done()，防止goroutine泄漏
		}()

		switch protocolType {
		case RDP:
			if deliveryInfo.Detector.RDPCheck(deliveryInfo.Host, deliveryInfo.Port) == nil {
				// 检测到了，那么就提交出来
				checkResult.Success = true
			}
			break
		case SSH:
			if deliveryInfo.Detector.SSHCheck(deliveryInfo.Host, deliveryInfo.Port) == nil {
				// 检测到了，那么就提交出来
				checkResult.Success = true
			}
			break
		case FTP:
			if deliveryInfo.Detector.FTPCheck(deliveryInfo.Host, deliveryInfo.Port) == nil {
				// 检测到了，那么就提交出来
				checkResult.Success = true
			}
			break
		case SFTP:
			if deliveryInfo.Detector.SFTPCheck(deliveryInfo.Host, deliveryInfo.Port,
				deliveryInfo.User, deliveryInfo.Password, deliveryInfo.PrivateKeyFullPath) == nil {
				// 检测到了，那么就提交出来
				checkResult.Success = true
			}
			break
		case Telnet:
			if deliveryInfo.Detector.TelnetCheck(deliveryInfo.Host, deliveryInfo.Port) == nil {
				// 检测到了，那么就提交出来
				checkResult.Success = true
			}
			break
		case VNC:
			if deliveryInfo.Detector.VNCCheck(deliveryInfo.Host, deliveryInfo.Port) == nil {
				// 检测到了，那么就提交出来
				checkResult.Success = true
			}
			break
		default:
			// 默认就当常规的端口来检测
			if deliveryInfo.Detector.CommonPortCheck(deliveryInfo.Host, deliveryInfo.Port) == nil {
				// 检测到了，那么就提交出来
				checkResult.Success = true
			}
			break
		}

	})
	if err != nil {
		return nil, err
	}
	defer p.Release()
	// --------------------------------------------------
	// 解析 InputInfo Host
	if inputInfo.Host == "" {
		return nil, fmt.Errorf("scan - Host is empty")
	}
	ipRangeInfos, err := s.parseHost(inputInfo.Host)
	if err != nil {
		return nil, err
	}
	// --------------------------------------------------
	// 解析 InputInfo Port 的信息
	if inputInfo.Port == "" {
		return nil, fmt.Errorf("scan - InputInfo Port is empty")
	}
	ports, err := s.parsePort(inputInfo.Port)
	if err != nil {
		return nil, errors.NewValidationError("failed to parse ports", err)
	}
	// --------------------------------------------------
	// 开始扫描
	checkResultChan := make(chan CheckResult, 1)
	defer close(checkResultChan)
	exitRevResultChan := make(chan bool, 1)
	defer close(exitRevResultChan)
	// --------------------------------------------------
	// 使用管道去接收
	// Host -- {"10, 20"}
	outputInfo := OutputInfo{
		ProtocolType: protocolType,
	}
	wg := &sync.WaitGroup{}
	outputInfo.SuccessMapString = make(map[string][]string, 0)
	outputInfo.FailedMapString = make(map[string][]string, 0)

	// 互斥锁保护map操作
	var resultMapMutex sync.RWMutex
	go func() {
		for {
			select {
			case revCheckResult := <-checkResultChan:
				// 使用写锁保护map操作，防止并发写入时的竞态条件
				resultMapMutex.Lock()
				if revCheckResult.Success == false {
					if _, ok := outputInfo.FailedMapString[revCheckResult.Host]; ok {
						outputInfo.FailedMapString[revCheckResult.Host] = append(outputInfo.FailedMapString[revCheckResult.Host], revCheckResult.Port)
					} else {
						outputInfo.FailedMapString[revCheckResult.Host] = []string{revCheckResult.Port}
					}
				} else {
					if _, ok := outputInfo.SuccessMapString[revCheckResult.Host]; ok {
						outputInfo.SuccessMapString[revCheckResult.Host] = append(outputInfo.SuccessMapString[revCheckResult.Host], revCheckResult.Port)
					} else {
						outputInfo.SuccessMapString[revCheckResult.Host] = []string{revCheckResult.Port}
					}
				}
				resultMapMutex.Unlock()
			case <-exitRevResultChan:
				return
			}
		}
	}()
	// --------------------------------------------------
	for _, ipRangeInfo := range ipRangeInfos {

		if ipRangeInfo.CICR != nil {
			// 使用 CICR 去遍历
			err = ipRangeInfo.CICR.ForEachIP(func(ip string) error {
				for _, port := range ports {
					// 创建deliveryInfo
					deliveryInfo := DeliveryInfo{
						Detector:           d,
						ProtocolType:       protocolType,
						Host:               ip,
						Port:               fmt.Sprintf("%d", port),
						User:               inputInfo.User,
						Password:           inputInfo.Password,
						PrivateKeyFullPath: inputInfo.PrivateKeyFullPath,
						CheckResultChan:    checkResultChan,
						Wg:                 wg,
					}

					// 先增加WaitGroup计数器
					wg.Add(1)
					// 使用defer确保在出错时正确减少计数器
					err = p.Invoke(deliveryInfo)
					if err != nil {
						// 如果Invoke失败，我们需要确保goroutine不会启动
						// 所以在这里减少计数器并返回错误
						wg.Done()
						return errors.NewResourceLimitError("failed to invoke scan task", err)
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("scan - ForEachIP error: %w", err)
			}
		} else {
			// 使用内置的段规则去遍历
			startIP := ipRangeInfo.Begin
			for i := 0; i < ipRangeInfo.CountNextTime; i++ {

				if i != 0 {
					startIP.To4()[3] += uint8(1)
				}
				for _, port := range ports {
					// 创建deliveryInfo
					deliveryInfo := DeliveryInfo{
						Detector:           d,
						ProtocolType:       protocolType,
						Host:               startIP.String(),
						Port:               fmt.Sprintf("%d", port),
						User:               inputInfo.User,
						Password:           inputInfo.Password,
						PrivateKeyFullPath: inputInfo.PrivateKeyFullPath,
						CheckResultChan:    checkResultChan,
						Wg:                 wg,
					}

					// 先增加WaitGroup计数器
					wg.Add(1)
					// 使用defer确保在出错时正确减少计数器
					err = p.Invoke(deliveryInfo)
					if err != nil {
						// 如果Invoke失败，我们需要确保goroutine不会启动
						// 所以在这里减少计数器并返回错误
						wg.Done()
						return nil, errors.NewResourceLimitError("failed to invoke scan task", err)
					}
				}
			}
		}
	}
	wg.Wait()
	exitRevResultChan <- true

	// 记录资源使用统计
	stats := s.resourceLimiter.GetStats()
	log.Printf("Scan completed - %s", stats.String())

	// 停止速率限制器
	s.rateLimiter.Stop()

	return &outputInfo, nil
}

// parseHost 解析 Host 输入的信息 192.168.0.1,192.168.50.1-254,192.168.31.0/24
func (s ScanTools) parseHost(inputHostString string) ([]IPRangeInfo, error) {

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

	const (
		MinPort = 1
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
			if totalPortCount > 10000 {
				return nil, errors.NewResourceLimitError(
					fmt.Sprintf("too many ports specified (max 10000 allowed, got %d)", totalPortCount),
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
			if totalPortCount > 10000 {
				return nil, errors.NewResourceLimitError(
					fmt.Sprintf("too many ports specified (max 10000 allowed, got %d)", totalPortCount),
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
}

type CheckResult struct {
	Success      bool
	ProtocolType ProtocolType
	Host         string
	Port         string
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
	default:
		return Common
	}
}
