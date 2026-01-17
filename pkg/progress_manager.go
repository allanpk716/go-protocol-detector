package pkg

import (
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
}

// NewProgressManager creates a new progress manager with dual progress bars
func NewProgressManager(totalIPs, totalPorts int) *ProgressManager {
	// Check if output is a terminal
	if !isTerminal(os.Stdout) {
		return &ProgressManager{disabled: true}
	}

	// Enable platform-specific virtual terminal processing
	enableVirtualTerminalProcessing(os.Stdout)

	// Create progress container
	p := mpb.New(
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
	}
}

// IncrementIP advances the IP progress bar by one
func (pm *ProgressManager) IncrementIP(ip string) {
	if pm.disabled {
		return
	}
	pm.ipMutex.Lock()
	defer pm.ipMutex.Unlock()
	pm.ipBar.Increment()
}

// IncrementPort advances the port progress bar by one
func (pm *ProgressManager) IncrementPort(port int) {
	if pm.disabled {
		return
	}
	pm.portMutex.Lock()
	defer pm.portMutex.Unlock()
	pm.portBar.Increment()
}

// StartNewIP resets the port progress bar for a new IP
func (pm *ProgressManager) StartNewIP(ip string) {
	if pm.disabled {
		return
	}
	pm.portMutex.Lock()
	defer pm.portMutex.Unlock()
	pm.currentIP = ip
	pm.portBar.SetTotal(0, false)
	pm.portBar.SetTotal(pm.totalPorts, false)
}

// Wait waits for all progress bars to complete their rendering
func (pm *ProgressManager) Wait() {
	if pm.disabled {
		return
	}
	// Abort the bars to make them complete immediately
	pm.ipBar.Abort(true)
	pm.portBar.Abort(true)
	pm.progress.Wait()
}

// Finish marks all progress bars as complete
func (pm *ProgressManager) Finish() {
	if pm.disabled {
		return
	}
	// Abort the bars to make them complete immediately
	pm.ipBar.Abort(true)
	pm.portBar.Abort(true)
	pm.progress.Wait()
}
