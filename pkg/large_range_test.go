package pkg

import (
	"testing"
	"time"
)

// TestLargeIPRangePerformance 测试大IP范围的性能表现
func TestLargeIPRangePerformance(t *testing.T) {
	scan := NewScanTools(10, 3*time.Second)

	// 测试接近最大限制的IP范围 (254个IP，这是单个C类网段的最大有效范围)
	t.Run("LargeRange_254_IPs", func(t *testing.T) {
		start := time.Now()

		ipRanges, err := scan.parseHost("192.168.1.1-254")
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Unexpected error parsing large range: %v", err)
		}

		// 验证返回的IP范围数量
		if len(ipRanges) != 1 {
			t.Errorf("Expected 1 IP range, got %d", len(ipRanges))
		}

		if ipRanges[0].CountNextTime != 254 {
			t.Errorf("Expected 254 IPs, got %d", ipRanges[0].CountNextTime)
		}

		t.Logf("Parsed 254 IPs in %v", duration)

		// 验证解析时间合理（应该在毫秒级别）
		if duration > 100*time.Millisecond {
			t.Logf("Warning: Large range parsing took %v, which might be too slow", duration)
		}
	})

	// 测试多个IP范围
	t.Run("MultipleRanges", func(t *testing.T) {
		start := time.Now()

		hostString := "192.168.1.1-100,192.168.2.1-100,192.168.3.1-54"
		ipRanges, err := scan.parseHost(hostString)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Unexpected error parsing multiple ranges: %v", err)
		}

		// 验证返回的IP范围数量
		if len(ipRanges) != 3 {
			t.Errorf("Expected 3 IP ranges, got %d", len(ipRanges))
		}

		totalIPs := 0
		for _, ipRange := range ipRanges {
			totalIPs += ipRange.CountNextTime
		}

		expectedTotal := 100 + 100 + 54 // 254 total
		if totalIPs != expectedTotal {
			t.Errorf("Expected %d total IPs, got %d", expectedTotal, totalIPs)
		}

		t.Logf("Parsed %d IPs across 3 ranges in %v", totalIPs, duration)
	})

	// 测试边界情况 - 刚好1000个IP的组合
	t.Run("Exactly1000IPs", func(t *testing.T) {
		start := time.Now()

		// 创建多个范围，总共1000个IP
		hostString := "10.0.0.1-250,10.0.1.1-250,10.0.2.1-250,10.0.3.1-250"
		ipRanges, err := scan.parseHost(hostString)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Unexpected error parsing 1000 IP ranges: %v", err)
		}

		totalIPs := 0
		for _, ipRange := range ipRanges {
			totalIPs += ipRange.CountNextTime
		}

		if totalIPs != 1000 {
			t.Errorf("Expected 1000 total IPs, got %d", totalIPs)
		}

		t.Logf("Parsed exactly 1000 IPs in %v", duration)
	})
}

// TestRangeSizeLimit 测试范围大小限制
func TestRangeSizeLimit(t *testing.T) {
	scan := NewScanTools(10, 3*time.Second)

	// 这个测试应该失败，因为单个范围超过了1000个IP的限制
	t.Run("SingleRangeExceed1000IPs", func(t *testing.T) {
		// 注意：由于IP地址最后一段最大是255，我们需要一个不同的方法来测试1000+的范围
		// 但实际上这个限制在单个IP段内是无法达到的，因为最大就是254个IP
		// 所以这个测试验证的是边界情况
		hostString := "192.168.1.1-999" // 这会在ParseIP阶段失败
		_, err := scan.parseHost(hostString)

		if err == nil {
			t.Error("Expected error for invalid range, but got none")
		} else {
			t.Logf("Correctly detected invalid range: %v", err)
		}
	})

	// 测试实际能达到的最大范围
	t.Run("MaxValidSingleRange", func(t *testing.T) {
		hostString := "192.168.1.1-254" // 254个IP，这是单个范围的最大值
		_, err := scan.parseHost(hostString)

		if err != nil {
			t.Errorf("Unexpected error for max valid range: %v", err)
		}
	})
}

// BenchmarkIPRangeParsing IP范围解析性能基准测试
func BenchmarkIPRangeParsing(b *testing.B) {
	scan := NewScanTools(10, 3*time.Second)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 基准测试：解析中等大小的IP范围
		_, _ = scan.parseHost("192.168.1.1-100")
	}
}

// BenchmarkLargeIPRangeParsing 大IP范围解析性能基准测试
func BenchmarkLargeIPRangeParsing(b *testing.B) {
	scan := NewScanTools(10, 3*time.Second)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 基准测试：解析大IP范围
		_, _ = scan.parseHost("192.168.1.1-254")
	}
}

// BenchmarkMultipleIPRanges 多个IP范围解析性能基准测试
func BenchmarkMultipleIPRanges(b *testing.B) {
	scan := NewScanTools(10, 3*time.Second)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 基准测试：解析多个IP范围
		_, _ = scan.parseHost("192.168.1.1-50,192.168.2.1-50,192.168.3.1-50")
	}
}

// TestPortRangePerformance 测试端口范围解析性能
func TestPortRangePerformance(t *testing.T) {
	scan := NewScanTools(10, 3*time.Second)

	// 测试大端口范围
	t.Run("LargePortRange", func(t *testing.T) {
		start := time.Now()

		ports, err := scan.parsePort("1000-2000")
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Unexpected error parsing large port range: %v", err)
		}

		expectedPorts := 1001 // 1000 to 2000 inclusive
		if len(ports) != expectedPorts {
			t.Errorf("Expected %d ports, got %d", expectedPorts, len(ports))
		}

		t.Logf("Parsed %d ports in %v", len(ports), duration)

		// 验证解析时间合理
		if duration > 50*time.Millisecond {
			t.Logf("Warning: Large port range parsing took %v", duration)
		}
	})

	// 测试多个端口范围
	t.Run("MultiplePortRanges", func(t *testing.T) {
		start := time.Now()

		ports, err := scan.parsePort("80,443,8080-8090,9000-9100")
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Unexpected error parsing multiple port ranges: %v", err)
		}

		expectedPorts := 2 + (8090-8080+1) + (9100-9000+1) // 2 + 11 + 101 = 114
		if len(ports) != expectedPorts {
			t.Errorf("Expected %d ports, got %d", expectedPorts, len(ports))
		}

		t.Logf("Parsed %d ports across multiple ranges in %v", len(ports), duration)
	})
}