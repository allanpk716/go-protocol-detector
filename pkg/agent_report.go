package pkg

import (
	"sort"
	"strconv"
)

// DefaultSampleLimit caps negatives/errors samples in the agent envelope.
// Full data is available via --output-file.
const DefaultSampleLimit = 50

// AgentReportData is the `data` payload of the kind="scan-result" envelope.
// Schema is part of the agent contract — see AGENT_INSTRUCTION.md.
type AgentReportData struct {
	Protocol   string         `json:"protocol"`
	ScanID     string         `json:"scan_id"`
	Targets    AgentTargets   `json:"targets"`
	Stats      AgentStats     `json:"stats"`
	Hits       []AgentHit     `json:"hits"`
	Negatives  AgentNegatives `json:"negatives"`
	Errors     AgentErrors    `json:"errors"`
	OutputFile string         `json:"output_file,omitempty"`
}

type AgentTargets struct {
	Hosts       int `json:"hosts"`
	Ports       int `json:"ports"`
	TotalChecks int `json:"total_checks"`
}

type AgentStats struct {
	DurationMs int64 `json:"duration_ms"`
	Hits       int   `json:"hits"`
	Negatives  int   `json:"negatives"`
	Errors     int   `json:"errors"`
}

type AgentHit struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	ResponseTimeMs int64  `json:"response_time_ms"`
	Banner         string `json:"banner,omitempty"`
}

type AgentNegative struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Reason string `json:"reason"`
}

type AgentError struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Message string `json:"message"`
}

type AgentNegatives struct {
	Total           int             `json:"total"`
	ByReason        map[string]int  `json:"by_reason"`
	Sample          []AgentNegative `json:"sample"`
	SampleTruncated bool            `json:"sample_truncated"`
}

type AgentErrors struct {
	Total           int          `json:"total"`
	Sample          []AgentError `json:"sample"`
	SampleTruncated bool         `json:"sample_truncated"`
}

// BuildAgentReport assembles the machine report from raw scan results.
// Pure function: no I/O, deterministic ordering (host, then numeric port).
// Zero-entry samples are empty slices (never nil) so JSON emits [], not null.
func BuildAgentReport(protocol string, scanID string, results []CheckResult,
	hostsCount int, portsCount int, durationMs int64, sampleLimit int, outputFile string) AgentReportData {

	if sampleLimit <= 0 {
		sampleLimit = DefaultSampleLimit
	}

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

	report := AgentReportData{
		Protocol:  protocol,
		ScanID:    scanID,
		Targets:   AgentTargets{Hosts: hostsCount, Ports: portsCount, TotalChecks: len(results)},
		Stats:     AgentStats{DurationMs: durationMs},
		Hits:      []AgentHit{},
		Negatives: AgentNegatives{
			ByReason: map[string]int{},
			Sample:   []AgentNegative{},
		},
		Errors:     AgentErrors{Sample: []AgentError{}},
		OutputFile: outputFile,
	}

	negSample := []AgentNegative{}
	errSample := []AgentError{}

	for _, r := range sorted {
		port, _ := strconv.Atoi(r.Port)
		switch {
		case r.Success:
			report.Stats.Hits++
			report.Hits = append(report.Hits, AgentHit{
				Host:           r.Host,
				Port:           port,
				ResponseTimeMs: r.ResponseTime.Milliseconds(),
				Banner:         r.Banner,
			})
		case r.Reason != "":
			// negative result — data, not an error
			report.Stats.Negatives++
			report.Negatives.ByReason[r.Reason]++
			if len(negSample) < sampleLimit {
				negSample = append(negSample, AgentNegative{Host: r.Host, Port: port, Reason: r.Reason})
			}
		default:
			// scan-level failure — actionable error
			report.Stats.Errors++
			if len(errSample) < sampleLimit {
				errSample = append(errSample, AgentError{Host: r.Host, Port: port, Message: r.ErrorMessage})
			}
		}
	}

	report.Negatives.Total = report.Stats.Negatives
	report.Negatives.Sample = negSample
	report.Negatives.SampleTruncated = len(negSample) < report.Stats.Negatives
	report.Errors.Total = report.Stats.Errors
	report.Errors.Sample = errSample
	report.Errors.SampleTruncated = len(errSample) < report.Stats.Errors

	return report
}

// IsAllUnreachable reports the conservative NETWORK_ERROR condition:
// zero hits, zero errors, and every negative is unreachable.
func IsAllUnreachable(r AgentReportData) bool {
	return r.Stats.Hits == 0 &&
		r.Stats.Errors == 0 &&
		r.Stats.Negatives > 0 &&
		r.Negatives.ByReason["unreachable"] == r.Stats.Negatives
}
