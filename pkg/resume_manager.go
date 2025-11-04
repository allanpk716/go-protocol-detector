package pkg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScanState represents the persisted state of a scan
type ScanState struct {
	ScanID       string    `json:"scan_id"`
	Protocol     string    `json:"protocol"`
	HostRange    string    `json:"host_range"`
	PortRange    string    `json:"port_range"`
	Threads      int       `json:"threads"`
	Timeout      int       `json:"timeout"`
	User         string    `json:"user,omitempty"`
	Password     string    `json:"password,omitempty"`
	PrivateKey   string    `json:"private_key,omitempty"`
	StartTime    time.Time `json:"start_time"`
	LastUpdate   time.Time `json:"last_update"`
	TotalTargets int       `json:"total_targets"`
	ScannedCount int       `json:"scanned_count"`
	SuccessCount int       `json:"success_count"`
	FailureCount int       `json:"failure_count"`

	// Target tracking
	CompletedTargets []string `json:"completed_targets"`
	FailedTargets    []string `json:"failed_targets"`
	PendingTargets   []string `json:"pending_targets"`

	// File locations
	CSVFilePath string `json:"csv_file_path"`
	StatePath   string `json:"state_path"`
}

// ResumeManager handles the persistence and loading of scan states
type ResumeManager struct {
	storageDir string
	mutex      sync.RWMutex
}

// NewResumeManager creates a new resume manager
func NewResumeManager(storageDir string) *ResumeManager {
	if storageDir == "" {
		storageDir = "./logs/scans"
	}

	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		log.Printf("Warning: Failed to create resume storage directory: %v", err)
	}

	return &ResumeManager{
		storageDir: storageDir,
	}
}

// SaveScanState saves the current state of a scan
func (rm *ResumeManager) SaveScanState(scanContext *ScanContext, inputInfo InputInfo, csvFilePath string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	state := ScanState{
		ScanID:       scanContext.ScanID,
		Protocol:     scanContext.Protocol.String(),
		HostRange:    scanContext.HostRange,
		PortRange:    scanContext.PortRange,
		Threads:      scanContext.Threads,
		Timeout:      scanContext.Timeout,
		User:         inputInfo.User,
		Password:     inputInfo.Password,
		PrivateKey:   inputInfo.PrivateKeyFullPath,
		StartTime:    scanContext.StartTime,
		LastUpdate:   time.Now(),
		TotalTargets: scanContext.TotalTargets,
		ScannedCount: scanContext.ScannedTargets,
		SuccessCount: scanContext.SuccessCount,
		FailureCount: scanContext.FailureCount,
		CSVFilePath:  csvFilePath,
	}

	// Convert completed and failed targets maps to slices
	state.CompletedTargets = make([]string, 0, len(scanContext.completedTargets))
	for target := range scanContext.completedTargets {
		state.CompletedTargets = append(state.CompletedTargets, target)
	}
	sort.Strings(state.CompletedTargets)

	state.FailedTargets = make([]string, 0, len(scanContext.failedTargets))
	for target := range scanContext.failedTargets {
		state.FailedTargets = append(state.FailedTargets, target)
	}
	sort.Strings(state.FailedTargets)

	// Get pending targets
	state.PendingTargets = scanContext.GetPendingTargets()
	sort.Strings(state.PendingTargets)

	// Determine state file path
	stateFileName := fmt.Sprintf("%s.state", scanContext.ScanID)
	state.StatePath = filepath.Join(rm.storageDir, stateFileName)

	// Save state to file
	if err := rm.saveStateToFile(&state); err != nil {
		return fmt.Errorf("failed to save scan state: %w", err)
	}

	// Update incomplete scans index
	if err := rm.updateIncompleteScansIndex(&state); err != nil {
		log.Printf("Warning: Failed to update incomplete scans index: %v", err)
	}

	log.Printf("Saved scan state for %s: %d/%d targets scanned, %d pending",
		scanContext.ScanID, scanContext.ScannedTargets, scanContext.TotalTargets, len(state.PendingTargets))

	return nil
}

// LoadScanState loads a previously saved scan state
func (rm *ResumeManager) LoadScanState(scanID string) (*ScanState, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	stateFileName := fmt.Sprintf("%s.state", scanID)
	statePath := filepath.Join(rm.storageDir, stateFileName)

	data, err := ioutil.ReadFile(statePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read scan state file: %w", err)
	}

	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scan state: %w", err)
	}

	return &state, nil
}

// ListIncompleteScans returns a list of all incomplete scans
func (rm *ResumeManager) ListIncompleteScans() ([]*ScanState, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	indexPath := filepath.Join(rm.storageDir, "incomplete_scans.json")

	// Check if index exists
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		return []*ScanState{}, nil
	}

	data, err := ioutil.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read incomplete scans index: %w", err)
	}

	var index map[string]string // scanID -> stateFileName
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal incomplete scans index: %w", err)
	}

	var scans []*ScanState
	for scanID := range index {
		state, err := rm.LoadScanState(scanID)
		if err != nil {
			log.Printf("Warning: Failed to load scan state for %s: %v", scanID, err)
			continue
		}
		scans = append(scans, state)
	}

	// Sort by start time (newest first)
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].StartTime.After(scans[j].StartTime)
	})

	return scans, nil
}

// RemoveIncompleteScan removes a scan from the incomplete scans index
func (rm *ResumeManager) RemoveIncompleteScan(scanID string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	return rm.removeFromIncompleteScansIndex(scanID)
}

// CleanupOldStates removes scan state files older than the specified duration
func (rm *ResumeManager) CleanupOldStates(maxAge time.Duration) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	files, err := ioutil.ReadDir(rm.storageDir)
	if err != nil {
		return fmt.Errorf("failed to read storage directory: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	var removedCount int

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".state") {
			continue
		}

		if file.ModTime().Before(cutoff) {
			filePath := filepath.Join(rm.storageDir, file.Name())
			if err := os.Remove(filePath); err != nil {
				log.Printf("Warning: Failed to remove old state file %s: %v", file.Name(), err)
				continue
			}

			// Extract scan ID from filename
			scanID := strings.TrimSuffix(file.Name(), ".state")
			rm.removeFromIncompleteScansIndex(scanID)
			removedCount++
		}
	}

	log.Printf("Cleaned up %d old scan state files", removedCount)
	return nil
}

// saveStateToFile saves the scan state to a JSON file
func (rm *ResumeManager) saveStateToFile(state *ScanState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan state: %w", err)
	}

	// Write to temporary file first
	tempPath := state.StatePath + ".tmp"
	if err := ioutil.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary state file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, state.StatePath); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("failed to rename temporary state file: %w", err)
	}

	return nil
}

// updateIncompleteScansIndex updates the index of incomplete scans
func (rm *ResumeManager) updateIncompleteScansIndex(state *ScanState) error {
	if len(state.PendingTargets) == 0 {
		// Scan is complete, remove from index
		return rm.removeFromIncompleteScansIndex(state.ScanID)
	}

	indexPath := filepath.Join(rm.storageDir, "incomplete_scans.json")

	var index map[string]string
	if data, err := ioutil.ReadFile(indexPath); err == nil {
		json.Unmarshal(data, &index)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read incomplete scans index: %w", err)
	}

	if index == nil {
		index = make(map[string]string)
	}

	// Add or update the scan in the index
	index[state.ScanID] = fmt.Sprintf("%s.state", state.ScanID)

	// Save updated index
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal incomplete scans index: %w", err)
	}

	tempPath := indexPath + ".tmp"
	if err := ioutil.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary index file: %w", err)
	}

	if err := os.Rename(tempPath, indexPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temporary index file: %w", err)
	}

	return nil
}

// removeFromIncompleteScansIndex removes a scan from the incomplete scans index
func (rm *ResumeManager) removeFromIncompleteScansIndex(scanID string) error {
	indexPath := filepath.Join(rm.storageDir, "incomplete_scans.json")

	var index map[string]string
	if data, err := ioutil.ReadFile(indexPath); err == nil {
		json.Unmarshal(data, &index)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read incomplete scans index: %w", err)
	}

	if index == nil {
		return nil // Index doesn't exist, nothing to remove
	}

	delete(index, scanID)

	// If index is empty, remove the file
	if len(index) == 0 {
		if err := os.Remove(indexPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove empty index file: %w", err)
		}
		return nil
	}

	// Save updated index
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal incomplete scans index: %w", err)
	}

	tempPath := indexPath + ".tmp"
	if err := ioutil.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary index file: %w", err)
	}

	if err := os.Rename(tempPath, indexPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temporary index file: %w", err)
	}

	return nil
}

// ConvertToInputInfo converts a ScanState back to InputInfo
func (state *ScanState) ConvertToInputInfo() InputInfo {
	return InputInfo{
		Host:               state.HostRange,
		Port:               state.PortRange,
		User:               state.User,
		Password:           state.Password,
		PrivateKeyFullPath: state.PrivateKey,
	}
}

// ConvertToProtocolType converts protocol string back to ProtocolType
func (state *ScanState) ConvertToProtocolType() ProtocolType {
	return String2ProtocolType(state.Protocol)
}

// IsComplete returns true if the scan is complete (no pending targets)
func (state *ScanState) IsComplete() bool {
	return len(state.PendingTargets) == 0
}

// GetProgress returns the scan progress as a percentage
func (state *ScanState) GetProgress() float64 {
	if state.TotalTargets == 0 {
		return 0.0
	}
	return float64(state.ScannedCount) / float64(state.TotalTargets) * 100.0
}

// GetElapsedTime returns the time elapsed since the scan started
func (state *ScanState) GetElapsedTime() time.Duration {
	return time.Since(state.StartTime)
}