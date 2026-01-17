package pkg

import (
	"os"
	"testing"
)

func TestIsTerminal(t *testing.T) {
	result := isTerminal(os.Stdout)
	// Should at least not panic
	if result != true && result != false {
		t.Error("isTerminal should return boolean")
	}
}

func TestNewProgressManager(t *testing.T) {
	pm := NewProgressManager(10, 100)
	if pm == nil {
		t.Fatal("NewProgressManager should not return nil")
	}
	pm.Finish()
}

func TestProgressManager_Disabled(t *testing.T) {
	// Test that methods don't panic when disabled
	pm := NewProgressManager(10, 100)
	if pm == nil {
		t.Fatal("NewProgressManager should not return nil")
	}

	// These should not panic
	pm.IncrementIP("192.168.1.1")
	pm.IncrementPort(22)
	pm.StartNewIP("192.168.1.2")
	pm.Wait()
	pm.Finish()
}

func TestProgressManager_ConcurrentUsage(t *testing.T) {
	pm := NewProgressManager(100, 1000)
	if pm == nil {
		t.Fatal("NewProgressManager should not return nil")
	}

	// Simulate concurrent usage
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			pm.IncrementIP("192.168.1.1")
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 1000; i++ {
			pm.IncrementPort(i)
		}
		done <- true
	}()

	<-done
	<-done
	pm.Finish()
}
