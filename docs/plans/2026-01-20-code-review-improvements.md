# 代码审查改进实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 修复代码审查中发现的问题，提高代码质量、稳定性和可维护性。

**架构：** 改进分为三个优先级层级：
1. 高优先级：修复影响正确性和稳定性的问题
2. 中优先级：改进代码质量和结构
3. 低优先级：代码清理和优化

**Tech Stack:** Go 1.x, github.com/panjf2000/ants/v2, github.com/vbauerster/mpb/v8

---

## 高优先级任务

### Task 1: 修复 IP 递增逻辑问题

> **Status:** completed

**问题描述：** 在 `scan_tools.go:289-295` 和 `690-695` 中，通过递增最后一个字节生成 IP 可能导致跨网段时产生错误的 IP 地址。

**Files:**
- Modify: `pkg/scan_tools.go:289-323` (Scan 方法中的 IP 遍历)
- Modify: `pkg/scan_tools.go:688-733` (ScanWithOutput 方法中的 IP 遍历)
- Create: `pkg/ip_range_test.go` (新的测试文件)

**Step 1: 编写失败测试 - 验证 IP 范围边界检查**

```go
// pkg/ip_range_test.go
package pkg

import (
	"testing"
)

func TestParseHost_IPRangeValidation(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		description string
	}{
		{
			name:        "valid_single_ip",
			input:       "192.168.1.100",
			expectError: false,
			description: "单个 IP 应该有效",
		},
		{
			name:        "valid_range_within_octet",
			input:       "192.168.1.100-150",
			expectError: false,
			description: "同一网段内的范围应该有效",
		},
		{
			name:        "invalid_range_cross_octet_boundary",
			input:       "192.168.1.250-10",
			expectError: true,
			description: "跨字节边界的范围应该失败（会溢出到下一字节）",
		},
		{
			name:        "invalid_range_exceeds_max",
			input:       "192.168.1.200-300",
			expectError: true,
			description: "超过 255 的范围应该失败",
		},
		{
			name:        "invalid_start_greater_than_end",
			input:       "192.168.1.200-100",
			expectError: true,
			description: "起始值大于结束值应该失败",
		},
		{
			name:        "valid_cidr",
			input:       "192.168.1.0/24",
			expectError: false,
			description: "CIDR 格式应该有效",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanTools := NewScanTools(10, 1000)
			_, err := scanTools.parseHost(tt.input)

			if tt.expectError && err == nil {
				t.Errorf("%s: 预期错误但未收到错误", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("%s: 预期成功但收到错误: %v", tt.description, err)
			}
		})
	}
}
```

**Step 2: 运行测试验证失败**

```bash
cd /c/WorkSpace/Go2Hell/src/github.com/allanpk716/go-protocol-detector
go test ./pkg -run TestParseHost_IPRangeValidation -v
```

预期: FAIL（测试会通过，但我们需要确保边界检查正确）

**Step 3: 改进 parseHost 方法中的 IP 范围验证**

在 `pkg/scan_tools.go` 的 `parseHost` 方法中，更新范围验证逻辑（约 840-850 行）：

```go
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

// 新增：验证 IP 前缀是否一致
// 确保范围在同一个网段内（前三个字节相同）
prefix := ipSplit[0] // 例如 "192.168.1"
if startIndex > 255-((endIndex-startIndex)%256) {
	// 计算是否会溢出到下一字节
	// 简化检查：确保起始和结束都在 0-255 范围内且不会跨网段
	// 实际上，由于我们只递增最后一个字节，需要确保
	// baseIP[3] + (endIndex - startIndex) 不会溢出
	baseLastByte, _ := strconv.Atoi(parts[3])
	if baseLastByte+rangeSize-1 > 255 {
		return nil, fmt.Errorf("scan - InputInfo Host range crosses octet boundary: %s", inputHostString)
	}
}
```

**Step 4: 运行测试验证通过**

```bash
go test ./pkg -run TestParseHost_IPRangeValidation -v
```

预期: PASS

**Step 5: 提交**

```bash
git add pkg/scan_tools.go pkg/ip_range_test.go
git commit -m "fix(scan): 添加 IP 范围边界验证防止跨网段溢出"
```

---

### Task 2: 修复 ResourceLimiter 连接计数问题

> **Status:** completed

**问题描述：** `resource_limiter.go:41-56` 中，连接计数在通道操作前递增，超时后计数不准确。

**Files:**
- Modify: `internal/utils/resource_limiter.go:41-56`
- Modify: `internal/utils/resource_limiter_test.go` (如果存在则修改，否则创建)

**Step 1: 编写失败测试 - 验证超时情况下的计数**

```go
// internal/utils/resource_limiter_test.go
package utils

import (
	"context"
	"testing"
	"time"
)

func TestResourceLimiter_AcquireTimeout(t *testing.T) {
	limiter := NewResourceLimiter(1, 100)

	// 第一次获取应该成功
	ctx1 := context.Background()
	release1, err := limiter.AcquireConnection(ctx1)
	if err != nil {
		t.Fatalf("第一次获取不应该失败: %v", err)
	}
	defer release1()

	// 第二次获取应该超时（因为已达到最大连接数）
	ctx2, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	startCount := limiter.GetStats().TotalConnections
	err = limiter.AcquireConnection(ctx2)

	// 应该超时
	if err == nil {
		t.Error("预期超时错误但获取成功")
	}

	// 验证计数器没有递增（因为超时）
	endCount := limiter.GetStats().TotalConnections
	if endCount != startCount {
		t.Errorf("超时时不应递增计数器: 开始=%d, 结束=%d", startCount, endCount)
	}
}
```

**Step 2: 运行测试验证失败**

```bash
cd /c/WorkSpace/Go2Hell/src/github.com/allanpk716/go-protocol-detector
go test ./internal/utils -run TestResourceLimiter_AcquireTimeout -v
```

预期: FAIL（测试会显示计数器在超时后被错误递增）

**Step 3: 修复连接计数逻辑**

修改 `internal/utils/resource_limiter.go` 的 `AcquireConnection` 方法：

```go
// AcquireConnection 获取连接许可
func (rl *ResourceLimiter) AcquireConnection(ctx context.Context) error {
	// 检查是否超过最大连接数
	select {
	case rl.connLimiter <- struct{}{}:
		// 只在成功获取许可后才递增计数器
		rl.mu.Lock()
		rl.connectionCounter++
		rl.currentConnections++
		rl.mu.Unlock()
		return nil
	case <-ctx.Done():
		// 超时时不递增计数器
		return fmt.Errorf("connection acquisition timeout: %w", ctx.Err())
	}
}
```

**Step 4: 运行测试验证通过**

```bash
go test ./internal/utils -run TestResourceLimiter_AcquireTimeout -v
go test ./internal/utils -v
```

预期: PASS

**Step 5: 提交**

```bash
git add internal/utils/resource_limiter.go internal/utils/resource_limiter_test.go
git commit -m "fix(utils): 修复 ResourceLimiter 超时时计数器错误递增"
```

---

### Task 3: 修复信号处理中的资源泄漏

> **Status:** completed

**问题描述：** `scan_tools.go:352-367` 中，信号处理使用 `os.Exit(0)` 跳过所有 defer 语句。

**Files:**
- Modify: `pkg/scan_tools.go:337-368` (ScanWithOutput 方法)
- Modify: `pkg/scan_context.go` (添加取消机制)
- Modify: `cmd/go-protocol-detector/main.go:94-139` (使用 context)

**Step 1: 编写测试 - 验证信号处理时的资源清理**

```go
// pkg/signal_test.go
package pkg

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestSignalHandling_ResourceCleanup(t *testing.T) {
	// 这个测试验证收到 SIGINT 时资源被正确清理
	// 由于难以在测试中模拟真实信号，我们测试取消机制

	scanTools := NewScanTools(10, 1000)
	ctx, cancel := context.WithCancel(context.Background())

	// 模拟快速取消
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// 使用 context 启动扫描（需要先修改 ScanWithOutput 接受 context）
	_, _, err := scanTools.ScanWithContext(ctx, Common, InputInfo{
		Host: "127.0.0.1",
		Port: "9999", // 使用不太可能开放的端口
	}, false, "", false)

	if err == nil {
		t.Log("扫描被取消（预期行为）")
	}
	// 验证资源已释放
	stats := scanTools.resourceLimiter.GetStats()
	if stats.CurrentConnections > 0 {
		t.Errorf("取消后仍有连接未释放: %d", stats.CurrentConnections)
	}
}
```

**Step 2: 修改 ScanContext 添加取消机制**

在 `pkg/scan_context.go` 中添加 context 支持：

```go
type ScanContext struct {
	// ... 现有字段 ...
	Ctx        context.Context
	Cancel     context.CancelFunc
}

func NewScanContext(protocolType ProtocolType, hosts, ports string, threads, timeout int) *ScanContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &ScanContext{
		// ... 现有初始化 ...
		Ctx:    ctx,
		Cancel: cancel,
	}
}
```

**Step 3: 修改 ScanWithOutput 使用优雅退出**

在 `pkg/scan_tools.go` 中修改信号处理：

```go
// ScanWithOutput scans with enhanced CSV logging and progress tracking
func (s ScanTools) ScanWithOutput(protocolType ProtocolType, inputInfo InputInfo, showProgressStep bool, csvOutputPath string, enableProgress bool) (*OutputInfo, *ScanContext, error) {
	// Create scan context for tracking
	scanContext := NewScanContext(protocolType, inputInfo.Host, inputInfo.Port, s.threads, int(s.timeOut.Milliseconds()))

	// ... 现有代码 ...

	// Setup signal handlers for graceful shutdown
	if csvOutputPath != "" {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigChan
			log.Printf("Received interrupt signal, shutting down gracefully...")

			// 取消扫描 context
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

			// 不再使用 os.Exit，让程序自然退出
			// 所有 defer 语句会被正确执行
		}()
	}

	// ... 其余代码保持不变，但在 goroutine 中检查 scanContext.Ctx.Done() ...
}
```

**Step 4: 在 goroutine 中检查 context 取消**

修改 goroutine 函数添加 context 检查：

```go
// 在 goroutine 函数开始处添加
select {
case <-deliveryInfo.ScanContext.Ctx.Done():
	checkResult.ErrorMessage = "scan cancelled"
	return
default:
}
```

**Step 5: 运行测试验证**

```bash
go test ./pkg -run TestSignalHandling_ResourceCleanup -v
```

**Step 6: 提交**

```bash
git add pkg/scan_tools.go pkg/scan_context.go pkg/signal_test.go
git commit -m "fix(scan): 使用 context cancel 替代 os.Exit 实现优雅退出"
```

---

### Task 4: 重构消除 Scan 和 ScanWithOutput 的重复代码

> **Status:** completed

**问题描述：** 两个方法有超过 300 行的重复代码。

**Files:**
- Create: `pkg/scan_core.go` (新的核心逻辑文件)
- Modify: `pkg/scan_tools.go:59-766`

**Step 1: 创建核心扫描逻辑**

```go
// pkg/scan_core.go
package pkg

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/allanpk716/go-protocol-detector/internal/errors"
	"github.com/allanpk716/go-protocol-detector/internal/utils"
	"github.com/panjf2000/ants/v2"
)

// scanCore 包含 Scan 和 ScanWithOutput 的公共逻辑
type scanCore struct {
	scanTools  *ScanTools
	detector   *Detector
	connGuard  *utils.ConnectionGuard
	protocol   ProtocolType
	inputInfo  InputInfo
	enableProgress bool
	showProgressStep bool
}

func newScanCore(st *ScanTools, pt ProtocolType, ii InputInfo, showProgress bool, enableProgress bool) *scanCore {
	return &scanCore{
		scanTools:       st,
		detector:        NewDetector(st.timeOut),
		connGuard:       utils.NewConnectionGuard(st.resourceLimiter),
		protocol:        pt,
		inputInfo:       ii,
		showProgressStep: showProgress,
		enableProgress:  enableProgress,
	}
}

// createGoroutinePool 创建并返回 goroutine 池和结果通道
func (sc *scanCore) createGoroutinePool(progressManager *ProgressManager, checkResultChan chan CheckResult) (*ants.PoolWithFunc, error) {
	p, err := ants.NewPoolWithFunc(sc.scanTools.threads, func(inData interface{}) {
		sc.handleScanTask(inData.(DeliveryInfo))
	})
	return p, err
}

// handleScanTask 处理单个扫描任务
func (sc *scanCore) handleScanTask(deliveryInfo DeliveryInfo) {
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
		deliveryInfo.CheckResultChan <- checkResult
		deliveryInfo.Wg.Done()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), sc.scanTools.timeOut)
	defer cancel()

	releaseConn, err := sc.connGuard.Acquire(ctx)
	if err != nil {
		checkResult.ErrorMessage = fmt.Sprintf("Connection denied: %v", err)
		return
	}
	acquiredConn = true

	// 执行协议检测
	checkResult.Success, checkResult.ErrorMessage = sc.performProtocolCheck(deliveryInfo)
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
```

**Step 2: 重构 Scan 方法使用 scanCore**

```go
func (s ScanTools) Scan(protocolType ProtocolType, inputInfo InputInfo, showProgressStep bool) (*OutputInfo, error) {
	core := newScanCore(&s, protocolType, inputInfo, showProgressStep, false)

	// 解析输入
	if inputInfo.Host == "" {
		return nil, fmt.Errorf("scan - Host is empty")
	}
	ipRangeInfos, err := s.parseHost(inputInfo.Host)
	if err != nil {
		return nil, err
	}

	if inputInfo.Port == "" {
		return nil, fmt.Errorf("scan - InputInfo Port is empty")
	}
	ports, err := s.parsePort(inputInfo.Port)
	if err != nil {
		return nil, errors.NewValidationError("failed to parse ports", err)
	}

	// 创建通道和输出
	channelSize := calculateChannelSize(s.threads)
	checkResultChan := make(chan CheckResult, channelSize)
	outputInfo := &OutputInfo{
		ProtocolType:     protocolType,
		SuccessMapString: make(map[string][]string, 100),
		FailedMapString:  make(map[string][]string, 100),
	}
	wg := &sync.WaitGroup{}

	// 启动结果收集器
	revDone := core.startResultCollector(checkResultChan, outputInfo, nil)

	// 创建 goroutine 池
	p, err := core.createGoroutinePool(nil, checkResultChan)
	if err != nil {
		return nil, err
	}
	defer p.Release()

	// 执行扫描
	s.scanIPRanges(core, p, ipRangeInfos, ports, checkResultChan, wg, nil)

	// 等待完成
	wg.Wait()
	close(checkResultChan)
	<-revDone

	stats := s.resourceLimiter.GetStats()
	log.Printf("Scan completed - %s", stats.String())

	return outputInfo, nil
}

// 辅助函数
func calculateChannelSize(threads int) int {
	channelSize := threads * 100
	if channelSize < 10000 {
		channelSize = 10000
	}
	return channelSize
}
```

**Step 3: 重构 ScanWithOutput 方法使用 scanCore**

类似地重构 ScanWithOutput。

**Step 4: 添加 scanIPRanges 辅助方法**

```go
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
```

**Step 5: 运行测试验证重构未破坏功能**

```bash
go test ./pkg -v
```

**Step 6: 提交**

```bash
git add pkg/scan_core.go pkg/scan_tools.go
git commit -m "refactor(scan): 提取公共逻辑到 scanCore 消除重复代码"
```

---

### Task 5: ~~修复 SFTP 重复连接问题~~ (已撤回 - 设计正确)

> **Status:** withdrawn

**说明：** 经过代码审查，SFTP 检测中的两次连接是**必要的设计**：
1. 第一次连接：读取 SSH Banner（使用原始 TCP 连接）
2. 第二次连接：建立 SSH 客户端连接（需要全新连接进行握手）

SSH 客户端库 (`ssh.NewClientConn`) 要求从连接开始就控制整个握手过程，不能复用已读取过 Banner 的连接。

**此任务已从改进计划中移除。**

**Step 1: 编写性能测试**

```go
// internal/feature/sftp/sftp_bench_test.go
package sftp

import (
	"testing"
	"time"
)

func BenchmarkSFTPCheck(b *testing.B) {
	helper := NewSFTPHelper("127.0.0.1", "22", 2*time.Second)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		helper.Check("", "", "")
	}
}
```

**Step 2: 运行基准测试记录当前性能**

```bash
go test ./internal/feature/sftp -bench=BenchmarkSFTPCheck -benchmem
```

**Step 3: 重构 SFTP 检测复用连接**

```go
// checkSFTPProtocolWithDiagnostics - 简化为复用连接的检测
func (s SFTPHelper) checkSFTPProtocolWithDiagnostics() (*SFTPDiagnostics, error) {
	startTime := time.Now()
	diagnostics := &SFTPDiagnostics{
		TCPConnected: false,
	}

	// Layer 1+2: TCP连接 + SSH协议识别
	netConn, err := net.DialTimeout("tcp", s.uri, s.timeout)
	if err != nil {
		diagnostics.ErrorMsg = fmt.Sprintf("TCP连接失败: %v", err)
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, custom_error.ErrSFTPNotFound
	}
	diagnostics.TCPConnected = true

	// 读取 SSH Banner
	netConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(netConn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		netConn.Close()
		diagnostics.ErrorMsg = fmt.Sprintf("读取SSH Banner失败: %v", err)
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, custom_error.ErrSFTPNotFound
	}

	diagnostics.SSHBanner = strings.TrimSpace(banner)
	if !strings.HasPrefix(diagnostics.SSHBanner, "SSH-") {
		netConn.Close()
		diagnostics.ErrorMsg = "非SSH协议服务"
		diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()
		return diagnostics, custom_error.ErrSFTPNotFound
	}

	parts := strings.Split(diagnostics.SSHBanner, "-")
	if len(parts) >= 2 {
		diagnostics.SSHVersion = parts[1]
	}

	// Layer 3: 使用新连接检测 SFTP（因为 SSH 客户端需要全新连接）
	// 这是必要的，因为读取 Banner 后连接状态已改变
	sftpSupported, subsystemResponse, err := s.detectSFTPSupport(netConn)

	// 关闭初始连接
	netConn.Close()

	diagnostics.SFTPSupported = sftpSupported
	diagnostics.SubsystemResponse = subsystemResponse
	diagnostics.ElapsedTime = time.Since(startTime).Milliseconds()

	if !sftpSupported {
		return diagnostics, custom_error.ErrSFTPNotFound
	}

	return diagnostics, nil
}

// detectSFTPSupport 检测SSH服务是否支持SFTP子系统
func (s SFTPHelper) detectSFTPSupport(initialConn net.Conn) (bool, string, error) {
	// 注意：由于 initialConn 已经读取了 Banner，我们需要一个新连接
	initialConn.Close() // 关闭旧连接

	// 建立新的 SSH 连接
	sshConn, err := net.DialTimeout("tcp", s.uri, s.timeout/2)
	if err != nil {
		return false, "", fmt.Errorf("建立SSH连接失败: %w", err)
	}
	defer sshConn.Close()

	// ... 其余代码保持不变 ...
}
```

**Step 4: 运行测试验证**

```bash
go test ./internal/feature/sftp -v
go test ./internal/feature/sftp -bench=BenchmarkSFTPCheck -benchmem
```

**Step 5: 提交**

```bash
git add internal/feature/sftp/sftp.go internal/feature/sftp/sftp_bench_test.go
git commit -m "refactor(sftp): 改进连接管理并添加性能测试"
```

---

## 中优先级任务

### Task 6: 分解巨大函数

> **Status:** completed

**Files:**
- Modify: `pkg/scan_tools.go`

已在 Task 4 中部分完成。

---

### Task 7: 使用合理的 map 初始容量

> **Status:** completed

**Files:**
- Modify: `pkg/scan_tools.go:224-225, 581-582`

**Step 1: 修改 map 初始化**

```go
// 在 Scan 方法中
outputInfo.SuccessMapString = make(map[string][]string, 100)
outputInfo.FailedMapString = make(map[string][]string, 100)

// 在 ScanWithOutput 方法中
outputInfo.SuccessMapString = make(map[string][]string, 100)
outputInfo.FailedMapString = make(map[string][]string, 100)
```

**Step 2: 运行测试验证**

```bash
go test ./pkg -v
```

**Step 3: 提交**

```bash
git add pkg/scan_tools.go
git commit -m "perf(scan): 使用合理的 map 初始容量减少扩容"
```

---

### Task 8: 移除全局变量

> **Status:** completed

**Files:**
- Modify: `cmd/go-protocol-detector/main.go:13-24, 94-139`

**Step 1: 重构 main.go 移除全局变量**

```go
package main

import (
	// ... imports ...
)

var AppVersion = "unknown" // 修正拼写

func main() {
	app := &cli.App{
		Name:        "go-protocol-detector",
		Usage:       "use like: go-protocol-detector --protocol=rdp --host=172.20.65.89-101 --port=3389",
		Description: "Multi-protocol scan tool",
		Version:     AppVersion,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "protocol",
				Usage:   "select only one protocol: common | ftp | rdp | rustdesk-hbbs | rustdesk-hbbr | rustdesk-hbbs-21116 | sftp | ssh | telnet | vnc",
				Value:   "common",
			},
			// ... 其他 flags 保持不变，但移除 Destination ...
		},
		Action: func(c *cli.Context) error {
			// 检查是否没有任何参数被传递
			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return nil
			}

			// 直接从 context 获取参数
			protocol := c.String("protocol")
			host := c.String("host")
			port := c.String("port")
			thread := c.Int("thread")
			timeOut := c.Int("timeout")
			user := c.String("user")
			password := c.String("password")
			priKeyFullPath := c.String("prikey")
			csvOutput := c.String("csv-output")
			noProgress := c.Bool("no-progress")

			nowProtocol := pkg.String2ProtocolType(protocol)
			scanTools := pkg.NewScanTools(thread, time.Duration(timeOut)*time.Millisecond)

			var outputInfo *pkg.OutputInfo
			var err error

			outputInfo, _, err = scanTools.ScanWithOutput(nowProtocol, pkg.InputInfo{
				Host:               host,
				Port:               port,
				User:               user,
				Password:           password,
				PrivateKeyFullPath: priKeyFullPath,
			}, false, csvOutput, !noProgress)

			if err != nil {
				return err
			}

			// ... 其余代码保持不变 ...
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
```

**Step 2: 运行测试验证**

```bash
go build -o go-protocol-detector.exe ./cmd/go-protocol-detector
./go-protocol-detector.exe --help
```

**Step 3: 提交**

```bash
git add cmd/go-protocol-detector/main.go
git commit -m "refactor(main): 移除全局变量直接从 context 获取参数"
```

---

### Task 9: 移除未使用的 RateLimiter

> **Status:** completed

**Files:**
- Modify: `internal/utils/resource_limiter.go:149-206`

**Step 1: 确认 RateLimiter 未被使用**

```bash
cd /c/WorkSpace/Go2Hell/src/github.com/allanpk716/go-protocol-detector
grep -r "RateLimiter" --include="*.go" | grep -v "resource_limiter.go"
```

确认没有其他地方使用 RateLimiter。

**Step 2: 移除 RateLimiter 代码**

从 `internal/utils/resource_limiter.go` 中删除整个 RateLimiter 相关代码。

**Step 3: 运行测试验证**

```bash
go test ./internal/utils -v
go test ./...
```

**Step 4: 提交**

```bash
git add internal/utils/resource_limiter.go
git commit -m "chore(utils): 移除未使用的 RateLimiter 代码"
```

---

### Task 10: 改进错误处理优先使用类型断言

> **Status:** completed

**Files:**
- Modify: `internal/errors/errors.go:138-180`

**Step 1: 改进错误检测函数**

```go
// isNetTimeoutError 检查是否为网络超时错误
func isNetTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// 优先使用类型断言
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	// 检查包装的错误
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		if netErr, ok := unwrapped.(net.Error); ok && netErr.Timeout() {
			return true
		}
	}

	// 字符串匹配仅作为最后的后备手段
	errMsg := err.Error()
	return strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "deadline") ||
		strings.Contains(errMsg, "timed out")
}

// isNetError 检查是否为网络错误
func isNetError(err error) bool {
	if err == nil {
		return false
	}

	// 优先使用类型断言
	if _, ok := err.(net.Error); ok {
		return true
	}

	// 检查包装的错误
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		if _, ok := unwrapped.(net.Error); ok {
			return true
		}
	}

	// 字符串匹配仅作为后备
	errMsg := err.Error()
	return strings.Contains(errMsg, "connection") ||
		strings.Contains(errMsg, "network") ||
		strings.Contains(errMsg, "dial") ||
		strings.Contains(errMsg, "refused") ||
		strings.Contains(errMsg, "unreachable")
}
```

**Step 2: 移除手动的 contains 函数**

由于现在使用 `strings.Contains`，可以删除 `contains` 函数。

**Step 3: 运行测试验证**

```bash
go test ./internal/errors -v
```

**Step 4: 提交**

```bash
git add internal/errors/errors.go
git commit -m "refactor(errors): 优先使用类型断言改进错误检测"
```

---

## 低优先级任务

### Task 11: 移除未使用的字段和方法

> **Status:** pending

**Files:**
- Modify: `internal/feature/ssh/ssh.go`
- Modify: `internal/feature/rdp/rdp.go`
- Modify: `internal/feature/rustdesk/hbbs.go`

**Step 1: 移除未使用的字段**

```go
// internal/feature/ssh/ssh.go
type SSHHelper struct {
	SenderPackage    []byte
	ReceiverFeatures []common.ReceiverFeature
	// 移除 version 字段
}

func NewSSHHelper() *SSHHelper {
	return &SSHHelper{
		SenderPackage:    []byte("\x53\x53\x48\x2d\x32\x2e\x30\x2d\x4f\x70\x65\x6e\x53\x53\x48\x5f\x66\x6f\x72\x5f\x57\x69\x6e\x64\x6f\x77\x73\x5f\x37\x2e\x37\x0d\x0a"),
		ReceiverFeatures: []common.ReceiverFeature{
			{StartIndex: 0, FeatureBytes: []byte("\x53\x53\x48\x2d")},
			{StartIndex: 7, FeatureBytes: []byte("\x2d")},
		},
	}
}

// 移除 GetVersion 方法
```

类似地修改 RDP 和 RustDesk helpers。

**Step 2: 提交**

```bash
git add internal/feature/ssh/ssh.go internal/feature/rdp/rdp.go internal/feature/rustdesk/hbbs.go
git commit -m "chore(feature): 移除未使用的 version 字段和 GetVersion 方法"
```

---

### Task 12: 使用常量替代魔法数字

> **Status:** completed

**Files:**
- Modify: `pkg/detector.go:168, 179`

**Step 1: 添加常量定义**

```go
// pkg/detector.go
package pkg

import (
	// ... existing imports ...
)

const (
	// MaxReadSize 是从网络读取的最大字节数
	MaxReadSize = 4096
	// ReadTimeout 是网络读取的超时时间
	ReadTimeout = 5 * time.Second
)

// ... 其余代码 ...
```

**Step 2: 使用常量**

```go
// 添加网络读取安全限制
maxReadSize := MaxReadSize
if readBytesLen > maxReadSize {
	return outErr
}
if readBytesLen <= 0 {
	return outErr
}

// 设置读取超时，防止阻塞
err = conn.SetReadDeadline(time.Now().Add(ReadTimeout))
```

**Step 3: 提交**

```bash
git add pkg/detector.go
git commit -m "refactor(detector): 使用常量替代魔法数字"
```

---

### Task 13: 修正版本号拼写错误

> **Status:** completed

**Files:**
- Modify: `cmd/go-protocol-detector/main.go:26`

**Step 1: 修正拼写**

```go
var AppVersion = "unknown" // 修正: unknow -> unknown
```

**Step 2: 提交**

```bash
git add cmd/go-protocol-detector/main.go
git commit -m "fix(main): 修正版本号拼写错误 (unknow -> unknown)"
```

---

## 测试验证

在完成所有任务后，运行完整的测试套件：

```bash
# 运行所有测试
go test ./... -v

# 运行基准测试
go test ./... -bench=. -benchmem

# 检查测试覆盖率
go test ./... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out

# 运行 go vet
go vet ./...

# 构建
go build -o go-protocol-detector.exe ./cmd/go-protocol-detector

# 功能测试
./go-protocol-detector.exe --protocol=ssh --host=127.0.0.1 --port=22
```

---

## 执行顺序建议

1. 先完成高优先级任务（Task 1-5）
2. 再完成中优先级任务（Task 6-10）
3. 最后完成低优先级任务（Task 11-13）

每个任务都应独立完成、测试、提交后再进行下一个任务。
