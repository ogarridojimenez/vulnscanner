package models

import "time"

// ScanReport is the complete output of a scan
type ScanReport struct {
	ID          string         `json:"id"`
	Target      string         `json:"target"`
	Timestamp   time.Time      `json:"timestamp"`
	Duration    time.Duration  `json:"duration"`
	ModulesRun  []Module       `json:"modules_run"`
	Results     []Result       `json:"results"`
	Summary     Summary        `json:"summary"`
	RawOutput   string         `json:"raw_output,omitempty"`
	Status      string         `json:"status"`
}

// Summary aggregates findings
type Summary struct {
	TotalChecks     int            `json:"total_checks"`
	Vulnerabilities int            `json:"vulnerabilities"`
	High            int            `json:"high"`
	Medium          int            `json:"medium"`
	Low             int            `json:"low"`
	Info            int            `json:"info"`
	ByModule        map[string]int `json:"by_module"`
}

// BuildSummary computes a Summary from ResultList
func BuildSummary(results []Result) Summary {
	s := Summary{}
	byMod := make(map[string]int)
	for _, r := range results {
		s.TotalChecks++
		byMod[string(r.Module)]++
		switch r.Severity {
		case SeverityCritical, SeverityHigh:
			s.High++
			s.Vulnerabilities++
		case SeverityMedium:
			s.Medium++
			s.Vulnerabilities++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
	}
	s.ByModule = byMod
	return s
}

// ScanRecord is the DB representation
type ScanRecord struct {
	ID              string    `json:"id"`
	Target          string    `json:"target"`
	Timestamp       time.Time `json:"timestamp"`
	DurationSeconds float64   `json:"duration_seconds"`
	Modules         string    `json:"modules"`
	SummaryJSON     string    `json:"summary_json"`
	RawOutputJSON   string    `json:"raw_output_json"`
	Status          string    `json:"status"`
}
