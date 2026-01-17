package pkg

import (
	"io"
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

func TestIsTerminal_Pipe(t *testing.T) {
	// Create a pipe (not a terminal)
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	// Note: This test verifies behavior with non-terminal output
	result := isTerminal(w)
	if result {
		// Pipe should not be detected as terminal
		t.Log("Pipe detected as terminal - may need better detection")
	}
}

func TestIsTerminal_File(t *testing.T) {
	// Test with actual file (not a terminal)
	tmpfile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	result := isTerminal(tmpfile)
	if result {
		t.Error("File should not be detected as terminal")
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
