package pkg

import (
	"fmt"
	"github.com/3th1nk/cidr"
	"github.com/panjf2000/ants/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanTools struct {
	threads int           // 同时扫描的并发数
	timeOut time.Duration // 超时时间
}

func NewScanTools(threads int, timeOut time.Duration) *ScanTools {

	scan := &ScanTools{threads: threads, timeOut: timeOut}
	if scan.threads > 10 {
		scan.threads = 10
	}
	if scan.timeOut == 0 {
		scan.timeOut = time.Second * 2
	}
	return scan
}

func (s ScanTools) Scan(protocolType ProtocolType, inputInfo InputInfo, showProgressStep bool) (*OutputInfo, error) {

	d := NewDetector(s.timeOut)
	p, err := ants.NewPoolWithFunc(s.threads, func(inData interface{}) {

		deliveryInfo := inData.(DeliveryInfo)
		checkResult := CheckResult{
			Success:      false,
			ProtocolType: deliveryInfo.ProtocolType,
			Host:         deliveryInfo.Host,
			Port:         deliveryInfo.Port,
		}
		defer func() {

			if showProgressStep == true {
				println(protocolType.String(), deliveryInfo.Host, deliveryInfo.Port, checkResult.Success)
			}
			deliveryInfo.CheckResultChan <- checkResult
			deliveryInfo.Wg.Done()
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
		return nil, err
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
	outputInfo.SuccessMapString = make(map[string][]string, 0)
	go func() {
		for {
			select {
			case revCheckResult := <-checkResultChan:
				if revCheckResult.Success == false {
					continue
				}
				if _, ok := outputInfo.SuccessMapString[revCheckResult.Host]; ok {
					outputInfo.SuccessMapString[revCheckResult.Host] = append(outputInfo.SuccessMapString[revCheckResult.Host], revCheckResult.Port)
				} else {
					outputInfo.SuccessMapString[revCheckResult.Host] = []string{revCheckResult.Port}
				}
			case <-exitRevResultChan:
				return
			}
		}
	}()
	// --------------------------------------------------
	wg := &sync.WaitGroup{}

	for _, ipRangeInfo := range ipRangeInfos {

		if ipRangeInfo.CICR != nil {
			// 使用 CICR 去遍历
			err = ipRangeInfo.CICR.ForEachIP(func(ip string) error {
				for _, port := range ports {

					wg.Add(1)
					// 单个 port 格式
					err = p.Invoke(DeliveryInfo{
						Detector:           d,
						ProtocolType:       protocolType,
						Host:               ip,
						Port:               fmt.Sprintf("%d", port),
						User:               inputInfo.User,
						Password:           inputInfo.Password,
						PrivateKeyFullPath: inputInfo.PrivateKeyFullPath,
						CheckResultChan:    checkResultChan,
						Wg:                 wg,
					})
					if err != nil {
						wg.Done()
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("scan - ForEachIP error: %s", err.Error())
			}
		} else {
			// 使用内置的段规则去遍历
			startIP := ipRangeInfo.Begin
			for i := 0; i < ipRangeInfo.CountNextTime; i++ {

				if i != 0 {
					startIP.To4()[3] += uint8(1)
				}
				for _, port := range ports {

					wg.Add(1)
					// 单个 port 格式
					err = p.Invoke(DeliveryInfo{
						Detector:           d,
						ProtocolType:       protocolType,
						Host:               startIP.String(),
						Port:               fmt.Sprintf("%d", port),
						User:               inputInfo.User,
						Password:           inputInfo.Password,
						PrivateKeyFullPath: inputInfo.PrivateKeyFullPath,
						CheckResultChan:    checkResultChan,
						Wg:                 wg,
					})
					if err != nil {
						wg.Done()
						return nil, fmt.Errorf("scan - Invoke Error: %v", err)
					}
				}
			}
		}
	}
	wg.Wait()
	exitRevResultChan <- true

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

			ipSplit := strings.Split(inputHostString, "-")
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
				ipRangeInfo.Begin = address
				ipRangeInfo.CountNextTime = endIndex - startIndex + 1
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

	portList := make([]int, 0)
	tmpPorts := make([]string, 0)
	tmpPorts = strings.Split(inputPortString, ",")
	for _, port := range tmpPorts {
		portSplit := strings.Split(port, "-")
		if len(portSplit) > 2 {
			return nil, fmt.Errorf("scan - InputInfo Port Split Error: %s", port)
		} else if len(portSplit) == 2 {
			// 说明是 20-30 这样的格式
			startPort, err := strconv.Atoi(portSplit[0])
			if err != nil {
				return nil, fmt.Errorf("scan - InputInfo Port Atoi Error: %v", portSplit[0])
			}
			endPort, err := strconv.Atoi(portSplit[1])
			if err != nil {
				return nil, fmt.Errorf("scan - InputInfo Port Atoi Error: %v", portSplit[1])
			}
			if startPort > endPort {
				return nil, fmt.Errorf("scan - InputInfo Port Error: %v", portSplit[0])
			}
			for i := startPort; i <= endPort; i++ {
				portList = append(portList, i)
			}
		} else {
			// 说明是单个端口格式
			portInt, err := strconv.Atoi(port)
			if err != nil {
				return nil, fmt.Errorf("scan - InputInfo Port Atoi Error: %v", port)
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

func String2ProcotolType(input string) ProtocolType {
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
