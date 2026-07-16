package models

// Finding represents a vulnerability record for DB persistence
type Finding struct {
	ID             int64    `json:"id"`
	ScanID         string   `json:"scan_id"`
	Module         string   `json:"module"`
	Name           string   `json:"name"`
	Severity       Severity `json:"severity"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
}
