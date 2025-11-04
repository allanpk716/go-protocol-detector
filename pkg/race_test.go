package pkg

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestRaceConditionSafety 测试互斥锁是否正确防止了竞态条件
func TestRaceConditionSafety(t *testing.T) {
	// 创建一个模拟的OutputInfo来测试并发安全性
	outputInfo := &OutputInfo{
		SuccessMapString: make(map[string][]string),
		FailedMapString:  make(map[string][]string),
	}

	// 模拟ScanTools中的resultMapMutex
	var resultMapMutex sync.RWMutex
	var wg sync.WaitGroup
	numGoroutines := 50

	// 测试SuccessMapString的并发访问
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// 模拟ScanTools中的并发写入操作
			resultMapMutex.Lock()
			host := fmt.Sprintf("192.168.1.%d", id%254+1)
			port := fmt.Sprintf("%d", id%65535+1)
			if _, ok := outputInfo.SuccessMapString[host]; ok {
				outputInfo.SuccessMapString[host] = append(outputInfo.SuccessMapString[host], port)
			} else {
				outputInfo.SuccessMapString[host] = []string{port}
			}
			resultMapMutex.Unlock()
		}(i)
	}

	// 测试FailedMapString的并发访问
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// 模拟ScanTools中的并发写入操作
			resultMapMutex.Lock()
			host := fmt.Sprintf("10.0.0.%d", id%254+1)
			port := fmt.Sprintf("%d", id%65535+1)
			if _, ok := outputInfo.FailedMapString[host]; ok {
				outputInfo.FailedMapString[host] = append(outputInfo.FailedMapString[host], port)
			} else {
				outputInfo.FailedMapString[host] = []string{port}
			}
			resultMapMutex.Unlock()
		}(i)
	}

	wg.Wait()

	// 验证数据完整性
	totalSuccessEntries := 0
	for _, ports := range outputInfo.SuccessMapString {
		totalSuccessEntries += len(ports)
	}

	totalFailedEntries := 0
	for _, ports := range outputInfo.FailedMapString {
		totalFailedEntries += len(ports)
	}

	if totalSuccessEntries != numGoroutines {
		t.Errorf("Expected %d entries in SuccessMapString, got %d", numGoroutines, totalSuccessEntries)
	}

	if totalFailedEntries != numGoroutines {
		t.Errorf("Expected %d entries in FailedMapString, got %d", numGoroutines, totalFailedEntries)
	}

	t.Logf("Race condition safety test passed with %d concurrent goroutines", numGoroutines*2)
}

// TestInputValidationBoundary 测试输入验证的边界条件
func TestInputValidationBoundary(t *testing.T) {
	scan := NewScanTools(10, 3*time.Second)

	testCases := []struct {
		name        string
		host        string
		shouldError bool
	}{
		{"Valid single IP", "192.168.1.1", false},
		{"Valid IP range", "192.168.1.1-5", false},
		{"Valid CIDR", "192.168.1.0/24", false},
		{"Invalid IP - too high", "192.168.1.256", true},
		{"Invalid IP - negative", "192.168.1.-1", true},
		{"Invalid IP - out of range", "999.999.999.999", true},
		{"Empty string", "", true},
		{"Invalid format", "not.an.ip.address", true},
		{"Start index > end index", "192.168.1.10-5", true},
		{"Range too large", "192.168.1.1-1500", true}, // 超过1000的限制
		{"Invalid range boundary", "192.168.1.300-400", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 测试parseHost函数的输入验证
			_, err := scan.parseHost(tc.host)
			if tc.shouldError && err == nil {
				t.Errorf("Expected error for invalid input: %s", tc.host)
			}
			if !tc.shouldError && err != nil {
				t.Errorf("Unexpected error for valid input: %s, error: %v", tc.host, err)
			}
		})
	}
}

// BenchmarkConcurrentMapOperations 并发map操作的性能基准测试
func BenchmarkConcurrentMapOperations(b *testing.B) {
	outputInfo := &OutputInfo{
		SuccessMapString: make(map[string][]string),
		FailedMapString:  make(map[string][]string),
	}
	var resultMapMutex sync.RWMutex

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		numGoroutines := 10

		for j := 0; j < numGoroutines; j++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				resultMapMutex.Lock()
				host := fmt.Sprintf("benchmark.host.%d", id)
				port := fmt.Sprintf("%d", id)
				if _, ok := outputInfo.SuccessMapString[host]; ok {
					outputInfo.SuccessMapString[host] = append(outputInfo.SuccessMapString[host], port)
				} else {
					outputInfo.SuccessMapString[host] = []string{port}
				}
				resultMapMutex.Unlock()
			}(j)
		}

		wg.Wait()
	}
}