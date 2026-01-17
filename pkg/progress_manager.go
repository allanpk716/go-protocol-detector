package pkg

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

// ProgressManager manages dual progress bars for IP and port scanning
type ProgressManager struct {
	progress   *mpb.Progress
	ipBar      *mpb.Bar
	portBar    *mpb.Bar
	totalIPs   int64
	totalPorts int64
	currentIP  string
	ipMutex    sync.Mutex
	portMutex  sync.Mutex
	disabled   bool
	ipCount    int64
	portCount  int64
}

// NewProgressManager creates a new progress manager with dual progress bars
func NewProgressManager(totalIPs, totalPorts int) *ProgressManager {
	// Check if output is being redirected to a file (not a terminal)
	// If it's redirected to a file, disable progress bars
	fileInfo, _ := os.Stdout.Stat()
	if fileInfo == nil {
		// If we can't get file info, assume it's not a terminal and disable
		return &ProgressManager{disabled: true}
	}

	// Check if stdout is a regular file (output redirected)
	// In this case, we should disable progress bars
	if fileInfo.Mode()&os.ModeCharDevice == 0 {
		// Not a character device - likely a file or pipe
		// Only disable if it's explicitly a regular file
		if fileInfo.Mode().IsRegular() {
			return &ProgressManager{disabled: true}
		}
		// For pipes (like in Git Bash), fall back to simple text progress
		pm := &ProgressManager{
			progress:   nil,
			ipBar:      nil,
			portBar:    nil,
			totalIPs:   int64(totalIPs),
			totalPorts: int64(totalPorts),
			disabled:   false,
			ipCount:    0,
			portCount:  0,
		}
		return pm
	}

	// Enable platform-specific virtual terminal processing
	enableVirtualTerminalProcessing(os.Stdout)

	// Create progress container
	// Use mpb.WithOutput to explicitly set the output writer
	// Use mpb.WithManualRefresh to force rendering in all environments
	p := mpb.New(
		mpb.WithOutput(os.Stdout),
		mpb.WithWidth(60),
		mpb.WithRefreshRate(100*time.Millisecond),
	)

	// Create IP progress bar
	ipBar := p.AddBar(int64(totalIPs),
		mpb.PrependDecorators(
			decor.Name("Scanning IPs ", decor.WC{C: 20}),
			decor.CountersNoUnit(" %d / %d", decor.WC{C: 15}),
		),
		mpb.AppendDecorators(
			decor.Percentage(decor.WC{C: 5}),
		),
	)

	// Create port progress bar
	portBar := p.AddBar(int64(totalPorts),
		mpb.PrependDecorators(
			decor.Name("Current IP: ", decor.WC{C: 20}),
			decor.Name("scanning ports", decor.WC{C: 20}),
		),
		mpb.AppendDecorators(
			decor.CountersNoUnit(" %d / %d", decor.WC{C: 15}),
			decor.Percentage(decor.WC{C: 5}),
		),
	)

	return &ProgressManager{
		progress:   p,
		ipBar:      ipBar,
		portBar:    portBar,
		totalIPs:   int64(totalIPs),
		totalPorts: int64(totalPorts),
		disabled:   false,
		ipCount:    0,
		portCount:  0,
	}
}

// IncrementIP advances the IP progress bar by one
func (pm *ProgressManager) IncrementIP(ip string) {
	if pm.disabled {
		return
	}
	pm.ipMutex.Lock()
	defer pm.ipMutex.Unlock()
	if pm.progress != nil && pm.ipBar != nil {
		pm.ipBar.Increment()
	} else {
		pm.ipCount++
		// Fallback to simple text progress with carriage return for in-place update
		if pm.totalIPs > 0 {
			percent := float64(pm.ipCount) / float64(pm.totalIPs) * 100
			fmt.Printf("\rProgress: %.1f%% (%d/%d IPs)", percent, pm.ipCount, pm.totalIPs)
		}
	}
}

// IncrementPort advances the port progress bar by one
func (pm *ProgressManager) IncrementPort(port int) {
	if pm.disabled {
		return
	}
	pm.portMutex.Lock()
	defer pm.portMutex.Unlock()
	if pm.progress != nil && pm.portBar != nil {
		pm.portBar.Increment()
	} else {
		pm.portCount++
	}
}

// StartNewIP resets the port progress bar for a new IP
func (pm *ProgressManager) StartNewIP(ip string) {
	if pm.disabled {
		return
	}
	pm.portMutex.Lock()
	defer pm.portMutex.Unlock()
	pm.currentIP = ip
	if pm.portBar != nil {
		pm.portBar.SetTotal(0, false)
		pm.portBar.SetTotal(pm.totalPorts, false)
	}
	pm.portCount = 0 // Reset port counter for text fallback
}

// Wait waits for all progress bars to complete their rendering
func (pm *ProgressManager) Wait() {
	if pm.disabled {
		return
	}
	// Abort the bars to make them complete immediately
	if pm.ipBar != nil {
		pm.ipBar.Abort(true)
	}
	if pm.portBar != nil {
		pm.portBar.Abort(true)
	}
	if pm.progress != nil {
		pm.progress.Wait()
	}
}

// Finish marks all progress bars as complete
func (pm *ProgressManager) Finish() {
	if pm.disabled {
		return
	}
	// Print newline if using text fallback
	if pm.progress == nil || pm.ipBar == nil {
		fmt.Println() // Move to next line after progress text
		return
	}
	// Abort the bars to make them complete immediately
	pm.ipBar.Abort(true)
	pm.portBar.Abort(true)
	pm.progress.Wait()
}
