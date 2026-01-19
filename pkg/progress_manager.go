package pkg

import (
	"fmt"
	"io"
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
	shutdownCh chan interface{}
	out        io.Writer
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
	}

	errInfo, _ := os.Stderr.Stat()
	if errInfo != nil && errInfo.Mode().IsRegular() {
		return &ProgressManager{disabled: true}
	}

	// Enable platform-specific virtual terminal processing BEFORE creating progress bars
	// This is critical for Windows PowerShell/CMD to support ANSI escape sequences
	enableVirtualTerminalProcessing(os.Stderr)

	// Create progress container
	shutdownCh := make(chan interface{}, 1)
	out := io.Writer(os.Stderr)
	p := mpb.New(
		mpb.WithOutput(out),
		mpb.WithWidth(60),
		mpb.WithShutdownNotifier(shutdownCh),
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

	pm := &ProgressManager{
		progress:   p,
		ipBar:      ipBar,
		portBar:    nil,
		totalIPs:   int64(totalIPs),
		totalPorts: int64(totalPorts),
		disabled:   false,
		ipCount:    0,
		portCount:  0,
		shutdownCh: shutdownCh,
		out:        out,
	}

	pm.portBar = pm.progress.AddBar(pm.totalPorts,
		mpb.PrependDecorators(
			decor.Any(func(_ decor.Statistics) string {
				pm.ipMutex.Lock()
				ip := pm.currentIP
				pm.ipMutex.Unlock()
				return fmt.Sprintf("IP: %-15s Ports: ", ip)
			}, decor.WC{C: 25}),
		),
		mpb.AppendDecorators(
			decor.CountersNoUnit(" %d / %d", decor.WC{C: 15}),
			decor.Percentage(decor.WC{C: 5}),
		),
		mpb.BarRemoveOnComplete(),
	)

	return pm
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
			fmt.Fprintf(pm.out, "\rProgress: %.1f%% (%d/%d IPs)", percent, pm.ipCount, pm.totalIPs)
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

// StartNewIP creates a new port progress bar for the current IP
func (pm *ProgressManager) StartNewIP(ip string) {
	if pm.disabled {
		return
	}
	pm.ipMutex.Lock()
	pm.currentIP = ip
	pm.ipMutex.Unlock()

	pm.portMutex.Lock()
	defer pm.portMutex.Unlock()

	if pm.portBar != nil {
		pm.portBar.SetCurrent(0)
		pm.portBar.SetTotal(pm.totalPorts, false)
	}
	pm.portCount = 0
}

// Wait waits for all progress bars to complete their rendering
func (pm *ProgressManager) Wait() {
	if pm.disabled {
		return
	}
	if pm.ipBar != nil {
		pm.ipBar.SetTotal(pm.totalIPs, true)
	}
	if pm.portBar != nil {
		pm.portBar.Abort(true)
		done := make(chan struct{})
		go func() {
			pm.portBar.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
	}
	if pm.progress != nil {
		pm.progress.Shutdown()
	}
	if pm.shutdownCh != nil {
		select {
		case <-pm.shutdownCh:
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Finish marks all progress bars as complete
func (pm *ProgressManager) Finish() {
	if pm.disabled {
		return
	}
	// Print newline if using text fallback
	if pm.progress == nil || pm.ipBar == nil {
		fmt.Fprintln(pm.out) // Move to next line after progress text
		return
	}
	// Complete the bars
	pm.ipBar.SetTotal(pm.totalIPs, true)
	if pm.portBar != nil {
		pm.portBar.Abort(true)
		done := make(chan struct{})
		go func() {
			pm.portBar.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
	}
	pm.progress.Shutdown()
	if pm.shutdownCh != nil {
		select {
		case <-pm.shutdownCh:
		case <-time.After(200 * time.Millisecond):
		}
	}
	// Print newlines to separate progress bars from subsequent output
	fmt.Fprintln(pm.out)
	fmt.Fprintln(pm.out)
}
