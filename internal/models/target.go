package models

// Target represents a scan target (domain or IP)
type Target struct {
	Host   string
	Ports  []int
	URL    string // Full URL if provided
	Cookie string
}
