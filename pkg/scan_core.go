package pkg

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/allanpk716/go-protocol-detector/internal/errors"
	"github.com/allanpk716/go-protocol-detector/internal/utils"
	"github.com/panjf2000/ants/v2"
)

// scanCore 包含 Scan 和 ScanWithOutput 的公共逻辑
type scanCore struct {
	scanTools        *ScanTools
	detector         *Detector
	connGuard        *utils.ConnectionGuard
	protocol         ProtocolType
	inputInfo        InputInfo
	enableProgress   bool
	showProgressStep bool
}

func newScanCore(st *ScanTools, pt ProtocolType, ii InputInfo, showProgress, enableProgress bool) *scanCore {
	return &scanCore{
		scanTools:        st,
		detector:         NewDetector(st.timeOut),
		connGuard:        utils.NewConnectionGuard(st.resourceLimiter),
		protocol:         pt,
		inputInfo:        ii,
		showProgressStep: showProgress,
		enableProgress:   enableProgress,
	}
}

// performProtocolCheck 执行特定协议的检测
func (sc *scanCore) performProtocolCheck(deliveryInfo DeliveryInfo) (bool, string) {
	var err error

	switch sc.protocol {
	case RDP:
		err = deliveryInfo.Detector.RDPCheck(deliveryInfo.Host, deliveryInfo.Port)
	case SSH:
		err = deliveryInfo.Detector.SSHCheck(deliveryInfo.Host, deliveryInfo.Port)
	case FTP:
		err = deliveryInfo.Detector.FTPCheck(deliveryInfo.Host, deliveryInfo.Port)
	case SFTP:
		err = deliveryInfo.Detector.SFTPCheck(deliveryInfo.Host, deliveryInfo.Port,
			deliveryInfo.User, deliveryInfo.Password, deliveryInfo.PrivateKeyFullPath)
	case Telnet:
		err = deliveryInfo.Detector.TelnetCheck(deliveryInfo.Host, deliveryInfo.Port)
	case VNC:
		err = deliveryInfo.Detector.VNCCheck(deliveryInfo.Host, deliveryInfo.Port)
	case RustDeskHBBS:
		err = deliveryInfo.Detector.HBBSCheck(deliveryInfo.Host, deliveryInfo.Port)
	case RustDeskHBBR:
		err = deliveryInfo.Detector.HBBRCheck(deliveryInfo.Host, deliveryInfo.Port)
	case RustDeskHBBS21116:
		err = deliveryInfo.Detector.HBBS21116Check(deliveryInfo.Host, deliveryInfo.Port)
	default:
		err = deliveryInfo.Detector.CommonPortCheck(deliveryInfo.Host, deliveryInfo.Port)
	}

	if err != nil {
		return false, err.Error()
	}
	return true, ""
}

// startResultCollector 启动结果收集 goroutine
func (sc *scanCore) startResultCollector(checkResultChan chan CheckResult, outputInfo *OutputInfo, scanContext *ScanContext) chan struct{} {
	var resultMapMutex sync.RWMutex
	revDone := make(chan struct{})

	go func() {
		defer close(revDone)
		for revCheckResult := range checkResultChan {
			resultMapMutex.Lock()

			portInt := 0
			if p, err := strconv.Atoi(revCheckResult.Port); err == nil {
				portInt = p
			}

			if !revCheckResult.Success {
				if _, ok := outputInfo.FailedMapString[revCheckResult.Host]; ok {
					outputInfo.FailedMapString[revCheckResult.Host] = append(outputInfo.FailedMapString[revCheckResult.Host], revCheckResult.Port)
				} else {
					outputInfo.FailedMapString[revCheckResult.Host] = []string{revCheckResult.Port}
				}
				if scanContext != nil {
					scanContext.MarkFailed(revCheckResult.Host, portInt)
				}
			} else {
				if _, ok := outputInfo.SuccessMapString[revCheckResult.Host]; ok {
					outputInfo.SuccessMapString[revCheckResult.Host] = append(outputInfo.SuccessMapString[revCheckResult.Host], revCheckResult.Port)
				} else {
					outputInfo.SuccessMapString[revCheckResult.Host] = []string{revCheckResult.Port}
				}
				if scanContext != nil {
					scanContext.MarkCompleted(revCheckResult.Host, portInt, revCheckResult.ResponseTime)
				}
			}
			resultMapMutex.Unlock()
		}
	}()

	return revDone
}

// createGoroutinePoolWithCallback 创建 goroutine 池并返回任务函数
func (sc *scanCore) createGoroutinePoolWithCallback(checkResultChan chan CheckResult, wg *sync.WaitGroup, scanContext *ScanContext) (*ants.PoolWithFunc, error) {
	p, err := ants.NewPoolWithFunc(sc.scanTools.threads, func(inData interface{}) {
		deliveryInfo := inData.(DeliveryInfo)
		startTime := time.Now()
		checkResult := CheckResult{
			Success:      false,
			ProtocolType: deliveryInfo.ProtocolType,
			Host:         deliveryInfo.Host,
			Port:         deliveryInfo.Port,
			Timestamp:    startTime,
		}

		portInt, _ := strconv.Atoi(deliveryInfo.Port)
		var releaseConn func()
		acquiredConn := false

		defer func() {
			if r := recover(); r != nil {
				checkResult.ErrorMessage = fmt.Sprintf("panic: %v", r)
			}
			checkResult.ResponseTime = time.Since(startTime)

			if acquiredConn && releaseConn != nil {
				releaseConn()
			}

			if deliveryInfo.ProgressManager != nil {
				deliveryInfo.ProgressManager.IncrementPort(portInt)
			}

			if sc.showProgressStep {
				log.Printf("%s %s:%s %v (%v)", sc.protocol.String(), deliveryInfo.Host, deliveryInfo.Port, checkResult.Success, checkResult.ResponseTime)
			}
			checkResultChan <- checkResult
			deliveryInfo.Wg.Done()
		}()

		// Check if scan has been cancelled
		if deliveryInfo.ScanContext != nil {
			select {
			case <-deliveryInfo.ScanContext.Ctx.Done():
				checkResult.ErrorMessage = "scan cancelled"
				return
			default:
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), sc.scanTools.timeOut)
		defer cancel()

		releaseConn, err := sc.connGuard.Acquire(ctx)
		if err != nil {
			checkResult.ErrorMessage = fmt.Sprintf("Connection denied: %v", err)
			return
		}
		acquiredConn = true

		checkResult.Success, checkResult.ErrorMessage = sc.performProtocolCheck(deliveryInfo)
	})

	return p, err
}

// scanIPRanges 遍历 IP 范围并提交扫描任务
func (s ScanTools) scanIPRanges(core *scanCore, p *ants.PoolWithFunc, ipRangeInfos []IPRangeInfo, ports []int, checkResultChan chan CheckResult, wg *sync.WaitGroup, progressManager *ProgressManager) error {
	for _, ipRangeInfo := range ipRangeInfos {
		if ipRangeInfo.CICR != nil {
			err := ipRangeInfo.CICR.ForEachIP(func(ip string) error {
				return s.scanIPPorts(core, p, ip, ports, checkResultChan, wg, progressManager)
			})
			if err != nil {
				return fmt.Errorf("scan - ForEachIP error: %w", err)
			}
		} else {
			baseIP := ipRangeInfo.Begin.To4()
			for i := 0; i < ipRangeInfo.CountNextTime; i++ {
				currentIP := make(net.IP, len(baseIP))
				copy(currentIP, baseIP)
				currentIP[3] += uint8(i)

				if err := s.scanIPPorts(core, p, currentIP.String(), ports, checkResultChan, wg, progressManager); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// scanIPPorts 扫描单个 IP 的所有端口
func (s ScanTools) scanIPPorts(core *scanCore, p *ants.PoolWithFunc, ip string, ports []int, checkResultChan chan CheckResult, wg *sync.WaitGroup, progressManager *ProgressManager) error {
	if progressManager != nil {
		progressManager.StartNewIP(ip)
	}

	for _, port := range ports {
		deliveryInfo := DeliveryInfo{
			Detector:           core.detector,
			ProtocolType:       core.protocol,
			Host:               ip,
			Port:               fmt.Sprintf("%d", port),
			User:               core.inputInfo.User,
			Password:           core.inputInfo.Password,
			PrivateKeyFullPath: core.inputInfo.PrivateKeyFullPath,
			CheckResultChan:    checkResultChan,
			Wg:                 wg,
			ProgressManager:    progressManager,
		}

		wg.Add(1)
		if err := p.Invoke(deliveryInfo); err != nil {
			wg.Done()
			return errors.NewResourceLimitError("failed to invoke scan task", err)
		}
	}

	if progressManager != nil {
		progressManager.IncrementIP(ip)
	}
	return nil
}

// calculateChannelSize 计算合适的通道缓冲区大小
func calculateChannelSize(threads int) int {
	channelSize := threads * 100
	if channelSize < 10000 {
		channelSize = 10000
	}
	return channelSize
}
