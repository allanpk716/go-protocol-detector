package pkg

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
)

// FullScanResults is the complete, non-truncated result set written by
// --output-file. The agent envelope carries only the file path.
type FullScanResults struct {
	Protocol  string          `json:"protocol"`
	ScanID    string          `json:"scan_id"`
	Timestamp string          `json:"timestamp"`
	Hits      []AgentHit      `json:"hits"`
	Negatives []AgentNegative `json:"negatives"`
	Errors    []AgentError    `json:"errors"`
}

// WriteFullResultsJSON writes every result (all negatives and errors included,
// no sample truncation) as indented JSON. Deterministic order: host, then port.
func WriteFullResultsJSON(path string, protocol string, scanID string, results []CheckResult) error {
	sorted := make([]CheckResult, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Host != sorted[j].Host {
			return sorted[i].Host < sorted[j].Host
		}
		pi, _ := strconv.Atoi(sorted[i].Port)
		pj, _ := strconv.Atoi(sorted[j].Port)
		return pi < pj
	})

	full := FullScanResults{
		Protocol:  protocol,
		ScanID:    scanID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hits:      []AgentHit{},
		Negatives: []AgentNegative{},
		Errors:    []AgentError{},
	}
	for _, r := range sorted {
		port, _ := strconv.Atoi(r.Port)
		switch {
		case r.Success:
			full.Hits = append(full.Hits, AgentHit{
				Host: r.Host, Port: port,
				ResponseTimeMs: r.ResponseTime.Milliseconds(),
				Banner:         r.Banner,
			})
		case r.Reason != "":
			full.Negatives = append(full.Negatives, AgentNegative{Host: r.Host, Port: port, Reason: r.Reason})
		default:
			full.Errors = append(full.Errors, AgentError{Host: r.Host, Port: port, Message: r.ErrorMessage})
		}
	}

	data, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal full results: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write full results file: %w", err)
	}
	return nil
}
