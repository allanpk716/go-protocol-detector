package pkg

import (
	"testing"
)

// BenchmarkProgressManager_Increment benchmarks single-threaded port increments
func BenchmarkProgressManager_Increment(b *testing.B) {
	pm := NewProgressManager(1000000, 1000000)
	defer pm.Finish()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.IncrementPort(i % 1000)
	}
}

// BenchmarkProgressManager_Concurrent benchmarks concurrent port increments
func BenchmarkProgressManager_Concurrent(b *testing.B) {
	pm := NewProgressManager(1000000, 1000000)
	defer pm.Finish()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			pm.IncrementPort(i % 1000)
			i++
		}
	})
}

// BenchmarkProgressManager_IPPort benchmarks combined IP and port increments
func BenchmarkProgressManager_IPPort(b *testing.B) {
	pm := NewProgressManager(10000, 100)
	defer pm.Finish()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%100 == 0 {
			pm.StartNewIP("192.168.1.1")
		}
		pm.IncrementPort(i % 100)
		if i%100 == 99 {
			pm.IncrementIP("192.168.1.1")
		}
	}
}

// BenchmarkProgressManager_StartNewIP benchmarks starting new IP tracking
func BenchmarkProgressManager_StartNewIP(b *testing.B) {
	pm := NewProgressManager(1000000, 100)
	defer pm.Finish()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.StartNewIP("192.168.1.1")
	}
}

// BenchmarkProgressManager_IncrementIP benchmarks IP completion increments
func BenchmarkProgressManager_IncrementIP(b *testing.B) {
	pm := NewProgressManager(1000000, 100)
	defer pm.Finish()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.IncrementIP("192.168.1.1")
	}
}

// BenchmarkProgressManager_Disabled benchmarks disabled progress manager
func BenchmarkProgressManager_Disabled(b *testing.B) {
	pm := &ProgressManager{disabled: true}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.IncrementPort(i % 1000)
	}
}

// BenchmarkProgressManager_FullScan simulates a full scan workflow
func BenchmarkProgressManager_FullScan(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pm := NewProgressManager(100, 100)
		for ip := 0; ip < 100; ip++ {
			pm.StartNewIP("192.168.1.1")
			for port := 0; port < 100; port++ {
				pm.IncrementPort(port)
			}
			pm.IncrementIP("192.168.1.1")
		}
		pm.Finish()
	}
}
