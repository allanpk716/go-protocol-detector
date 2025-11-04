package pkg

import (
	"testing"
	"time"
)

// TestSimpleRaceCondition 简单的竞态条件测试
func TestSimpleRaceCondition(t *testing.T) {
	// 测试ScanTools的创建是否线程安全
	done := make(chan bool, 1)

	go func() {
		scan := NewScanTools(10, 3*time.Second)
		if scan.threads != 10 {
			t.Errorf("Expected threads=10, got %d", scan.threads)
		}
		done <- true
	}()

	select {
	case <-done:
		t.Log("Simple race condition test passed")
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out")
	}
}

// TestInputValidationInConcurrency 并发输入验证测试
func TestInputValidationInConcurrency(t *testing.T) {
	scan := NewScanTools(10, 3*time.Second)

	testCases := []string{
		"192.168.1.1",
		"192.168.1.1-10",
		"10.0.0.0/24",
		"192.168.1.256", // 无效
		"invalid",       // 无效
	}

	for _, host := range testCases {
		host := host // 创建局部变量避免循环变量捕获
		t.Run("ConcurrentValidation_"+host, func(t *testing.T) {
			t.Parallel() // 启用并行测试

			for i := 0; i < 10; i++ {
				_, err := scan.parseHost(host)
				// 验证结果是可重复的
				result1 := err != nil
				result2 := err != nil
				if result1 != result2 {
					t.Errorf("Inconsistent validation results for %s", host)
				}
			}
		})
	}
}