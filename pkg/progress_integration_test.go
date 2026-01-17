package pkg

import (
	"testing"
	"time"
)

// TestProgressManager_Integration tests the progress manager with simulated scanning
func TestProgressManager_Integration(t *testing.T) {
	pm := NewProgressManager(5, 10)
	if pm == nil {
		t.Fatal("Failed to create ProgressManager")
	}
	defer pm.Finish()

	// Simulate scanning
	for i := 0; i < 5; i++ {
		ip := "192.168.1." + string(rune('1'+i))
		pm.StartNewIP(ip)

		for j := 0; j < 10; j++ {
			pm.IncrementPort(22 + j)
			time.Sleep(10 * time.Millisecond)
		}

		pm.IncrementIP(ip)
	}
}

// TestProgressManager_ConcurrentUpdates tests concurrent progress updates
func TestProgressManager_ConcurrentUpdates(t *testing.T) {
	pm := NewProgressManager(100, 100)
	if pm == nil {
		t.Fatal("Failed to create ProgressManager")
	}
	defer pm.Finish()

	// Concurrent updates
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				pm.IncrementPort(j)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestProgressManager_DisabledState tests disabled progress manager
func TestProgressManager_DisabledState(t *testing.T) {
	// Test with non-terminal output
	pm := &ProgressManager{disabled: true}

	// Should not panic
	pm.StartNewIP("192.168.1.1")
	pm.IncrementPort(22)
	pm.IncrementIP("192.168.1.1")
	pm.Finish()
}

// TestProgressManager_MultipleIPs tests scanning multiple IPs
func TestProgressManager_MultipleIPs(t *testing.T) {
	pm := NewProgressManager(3, 5)
	if pm == nil {
		t.Fatal("Failed to create ProgressManager")
	}
	defer pm.Finish()

	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}

	for _, ip := range ips {
		pm.StartNewIP(ip)
		for port := 22; port <= 26; port++ {
			pm.IncrementPort(port)
		}
		pm.IncrementIP(ip)
	}
}

// TestProgressManager_PartialCompletion tests partial scan completion
func TestProgressManager_PartialCompletion(t *testing.T) {
	pm := NewProgressManager(10, 100)
	if pm == nil {
		t.Fatal("Failed to create ProgressManager")
	}
	defer pm.Finish()

	// Only complete half the work
	for i := 0; i < 5; i++ {
		ip := "10.0.0." + string(rune('1'+i))
		pm.StartNewIP(ip)

		for j := 0; j < 50; j++ {
			pm.IncrementPort(j)
		}

		pm.IncrementIP(ip)
	}
}
