package models

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Module represents a scanner module name
type Module string

const (
	ModulePort      Module = "port"
	ModuleHeaders   Module = "headers"
	ModuleTLS       Module = "tls"
	ModuleDirectory Module = "directory"
	ModuleSQLi      Module = "sqli"
	ModuleXSS       Module = "xss"
)

// Result is a single finding from any scanner module
type Result struct {
	Module         Module            `json:"module"`
	Name           string            `json:"name"`
	Severity       Severity          `json:"severity"`
	Description    string            `json:"description"`
	Recommendation string            `json:"recommendation,omitempty"`
	Evidence       string            `json:"evidence,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
}

// ResultList is a slice of results with helper methods
type ResultList []Result

func (rl ResultList) BySeverity(s Severity) []Result {
	var out []Result
	for _, r := range rl {
		if r.Severity == s {
			out = append(out, r)
		}
	}
	return out
}

func (rl ResultList) ByModule(m Module) []Result {
	var out []Result
	for _, r := range rl {
		if r.Module == m {
			out = append(out, r)
		}
	}
	return out
}

func (rl ResultList) Count() map[Severity]int {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}
	for _, r := range rl {
		counts[r.Severity]++
	}
	return counts
}
