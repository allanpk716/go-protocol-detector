package pkg

import (
	"fmt"
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

func (s ScanTools) Scan(protocolType ProtocolType, inputInfo InputInfo) (*OutputInfo, error) {

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
			println(protocolType.String(), deliveryInfo.Host, deliveryInfo.Port, checkResult.Success)
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
	// 解析 InputInfo Host 和 Port 的信息
	if inputInfo.Host == "" {
		return nil, fmt.Errorf("scan - Host is empty")
	}
	ipRangeInfo := IPRangeInfo{}
	{
		ipSplit := strings.Split(inputInfo.Host, "-")
		if len(ipSplit) > 2 {
			return nil, fmt.Errorf("scan - InputInfo Host Split Error: %s", inputInfo.Host)
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
		} else {
			// 说明是单个 IP 格式
			address := net.ParseIP(ipSplit[0])
			if address == nil {
				return nil, fmt.Errorf("scan - InputInfo Host ParseIP Error")
			}
			ipRangeInfo.Begin = address
			ipRangeInfo.CountNextTime = 1
		}
	}
	// --------------------------------------------------
	// 解析 InputInfo Port 的信息
	// 可能切割出来的 port 是 20-30 这样的格式，需要在内部再次判断
	portList := make([]int, 0)
	{
		tmpPorts := make([]string, 0)
		if inputInfo.Port == "" {
			return nil, fmt.Errorf("scan - InputInfo Port is empty")
		}
		tmpPorts = strings.Split(inputInfo.Port, ",")
		for _, port := range tmpPorts {
			portSplit := strings.Split(port, "-")
			if len(portSplit) > 2 {
				return nil, fmt.Errorf("scan - InputInfo Port Split Error: %s", inputInfo.Port)
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
	}
	// --------------------------------------------------
	// 开始扫描
	checkResultChan := make(chan CheckResult, 1)
	defer close(checkResultChan)
	exitRevResultChan := make(chan bool, 1)
	defer close(exitRevResultChan)
	// 使用管道去接收
	// Host -- {"10, 20"}
	successMapString := make(map[string][]string, 0)
	go func() {
		for {
			select {
			case revCheckResult := <-checkResultChan:
				if revCheckResult.Success == false {
					continue
				}

				if _, ok := successMapString[revCheckResult.Host]; ok {
					successMapString[revCheckResult.Host] = append(successMapString[revCheckResult.Host], revCheckResult.Port)
				} else {
					successMapString[revCheckResult.Host] = []string{revCheckResult.Port}
				}
			case <-exitRevResultChan:
				return
			}
		}
	}()
	// --------------------------------------------------
	wg := &sync.WaitGroup{}
	startIP := ipRangeInfo.Begin
	for i := 0; i < ipRangeInfo.CountNextTime; i++ {

		if i != 0 {
			startIP.To4()[3] += uint8(1)
		}
		for _, port := range portList {

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

	wg.Wait()
	exitRevResultChan <- true

	outputInfo := OutputInfo{
		ProtocolType: protocolType,
		Info:         "",
	}
	for s2, i := range successMapString {
		outputInfo.Info += s2 + ":" + strings.Join(i, ",") + "\r\n"
	}

	return &outputInfo, nil
}

type IPRangeInfo struct {
	Begin         net.IP
	CountNextTime int
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
	ProtocolType ProtocolType
	Info         string
}

type ProtocolType int

const (
	RDP ProtocolType = iota + 1
	SSH
	FTP
	SFTP
	Telnet
	VNC
	CommonPort
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
	case CommonPort:
		return "commonPort"
	default:
		return "unknown"
	}
}
