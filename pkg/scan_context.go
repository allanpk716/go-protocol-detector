package pkg

import (
	"fmt"
	"sync"
	"time"
)

// ScanContext tracks the state and progress of a scan operation
type ScanContext struct {
	// Basic scan information
	ScanID     string
	Protocol   ProtocolType
	StartTime  time.Time
	UpdateTime time.Time

	// Scan parameters
	HostRange string
	PortRange string
	Threads   int
	Timeout   int

	// Progress tracking
	TotalTargets   int
	ScannedTargets int
	SuccessCount   int
	FailureCount   int

	// Target tracking
	completedTargets map[string]bool // "host:port" -> completed
	failedTargets    map[string]bool // "host:port" -> failed
	pendingTargets   []string        // List of remaining targets

	// Statistics
	ResponseTimeSum time.Duration
	MinResponseTime time.Duration
	MaxResponseTime time.Duration

	// Thread safety
	mutex sync.RWMutex
}

// NewScanContext creates a new scan context with the given parameters
func NewScanContext(protocol ProtocolType, hostRange, portRange string, threads, timeout int) *ScanContext {
	now := time.Now()
	scanID := fmt.Sprintf("scan_%d", now.Unix())

	return &ScanContext{
		ScanID:          scanID,
		Protocol:        protocol,
		StartTime:       now,
		UpdateTime:      now,
		HostRange:       hostRange,
		PortRange:       portRange,
		Threads:         threads,
		Timeout:         timeout,
		completedTargets: make(map[string]bool),
		failedTargets:    make(map[string]bool),
		pendingTargets:   make([]string, 0),
		MinResponseTime:  time.Hour, // Initialize to a large value
	}
}

// SetTargets sets the total targets and initializes the pending list
func (sc *ScanContext) SetTargets(targets []string) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	sc.TotalTargets = len(targets)
	sc.pendingTargets = make([]string, len(targets))
	copy(sc.pendingTargets, targets)
}

// MarkCompleted marks a target as successfully scanned
func (sc *ScanContext) MarkCompleted(host string, port int, responseTime time.Duration) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	targetKey := fmt.Sprintf("%s:%d", host, port)

	// Remove from pending if exists
	for i, target := range sc.pendingTargets {
		if target == targetKey {
			sc.pendingTargets = append(sc.pendingTargets[:i], sc.pendingTargets[i+1:]...)
			break
		}
	}

	// Mark as completed
	sc.completedTargets[targetKey] = true
	sc.ScannedTargets++
	sc.SuccessCount++

	// Update statistics
	sc.ResponseTimeSum += responseTime
	if responseTime < sc.MinResponseTime {
		sc.MinResponseTime = responseTime
	}
	if responseTime > sc.MaxResponseTime {
		sc.MaxResponseTime = responseTime
	}

	sc.UpdateTime = time.Now()
}

// MarkFailed marks a target as failed
func (sc *ScanContext) MarkFailed(host string, port int) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	targetKey := fmt.Sprintf("%s:%d", host, port)

	// Remove from pending if exists
	for i, target := range sc.pendingTargets {
		if target == targetKey {
			sc.pendingTargets = append(sc.pendingTargets[:i], sc.pendingTargets[i+1:]...)
			break
		}
	}

	// Mark as failed
	sc.failedTargets[targetKey] = true
	sc.ScannedTargets++
	sc.FailureCount++

	sc.UpdateTime = time.Now()
}

// IsCompleted checks if a target has been completed (successfully or failed)
func (sc *ScanContext) IsCompleted(host string, port int) bool {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	targetKey := fmt.Sprintf("%s:%d", host, port)
	return sc.completedTargets[targetKey] || sc.failedTargets[targetKey]
}

// GetProgress returns the current progress as a percentage
func (sc *ScanContext) GetProgress() float64 {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	if sc.TotalTargets == 0 {
		return 0.0
	}
	return float64(sc.ScannedTargets) / float64(sc.TotalTargets) * 100.0
}

// GetPendingTargets returns a copy of the pending targets
func (sc *ScanContext) GetPendingTargets() []string {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	pending := make([]string, len(sc.pendingTargets))
	copy(pending, sc.pendingTargets)
	return pending
}

// GetCompletedTargets returns a copy of completed targets
func (sc *ScanContext) GetCompletedTargets() map[string]bool {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	completed := make(map[string]bool, len(sc.completedTargets))
	for k, v := range sc.completedTargets {
		completed[k] = v
	}
	return completed
}

// GetFailedTargets returns a copy of failed targets
func (sc *ScanContext) GetFailedTargets() map[string]bool {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	failed := make(map[string]bool, len(sc.failedTargets))
	for k, v := range sc.failedTargets {
		failed[k] = v
	}
	return failed
}

// GetStats returns current scan statistics
func (sc *ScanContext) GetStats() ScanStats {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	var avgResponseTime time.Duration
	if sc.SuccessCount > 0 {
		avgResponseTime = sc.ResponseTimeSum / time.Duration(sc.SuccessCount)
	}

	// Set min response time to 0 if no successful scans yet
	minResponseTime := sc.MinResponseTime
	if minResponseTime == time.Hour {
		minResponseTime = 0
	}

	return ScanStats{
		ScanID:           sc.ScanID,
		Protocol:         sc.Protocol,
		StartTime:        sc.StartTime,
		UpdateTime:       sc.UpdateTime,
		TotalTargets:     sc.TotalTargets,
		ScannedTargets:   sc.ScannedTargets,
		SuccessCount:     sc.SuccessCount,
		FailureCount:     sc.FailureCount,
		PendingCount:     len(sc.pendingTargets),
		ProgressPercent:  sc.GetProgress(),
		AvgResponseTime:  avgResponseTime,
		MinResponseTime:  minResponseTime,
		MaxResponseTime:  sc.MaxResponseTime,
		ScanDuration:     time.Since(sc.StartTime),
	}
}

// IsComplete returns true if all targets have been scanned
func (sc *ScanContext) IsComplete() bool {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	return sc.ScannedTargets >= sc.TotalTargets && len(sc.pendingTargets) == 0
}

// GetElapsedDuration returns the time elapsed since the scan started
func (sc *ScanContext) GetElapsedDuration() time.Duration {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	return time.Since(sc.StartTime)
}

// EstimateRemainingTime estimates the remaining time based on current progress
func (sc *ScanContext) EstimateRemainingTime() time.Duration {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	if sc.ScannedTargets == 0 {
		return 0
	}

	elapsed := time.Since(sc.StartTime)
	avgTimePerTarget := elapsed / time.Duration(sc.ScannedTargets)
	remainingTargets := sc.TotalTargets - sc.ScannedTargets

	return time.Duration(remainingTargets) * avgTimePerTarget
}

// ScanStats provides a snapshot of scan statistics
type ScanStats struct {
	ScanID           string
	Protocol         ProtocolType
	StartTime        time.Time
	UpdateTime       time.Time
	TotalTargets     int
	ScannedTargets   int
	SuccessCount     int
	FailureCount     int
	PendingCount     int
	ProgressPercent  float64
	AvgResponseTime  time.Duration
	MinResponseTime  time.Duration
	MaxResponseTime  time.Duration
	ScanDuration     time.Duration
}