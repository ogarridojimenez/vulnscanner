package storage

import (
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// Store interface for scan result persistence
type Store interface {
	// Init creates/initializes the database
	Init() error

	// SaveScan persists a completed scan report
	SaveScan(report *models.ScanReport) error

	// ListScans returns recent scans
	ListScans(limit int) ([]models.ScanRecord, error)

	// GetScan retrieves a single scan by ID
	GetScan(id string) (*models.ScanReport, error)

	// GetScanRecord retrieves the raw record
	GetScanRecord(id string) (*models.ScanRecord, error)

	// Summary returns aggregate vulnerability statistics
	Summary() ([]VulnStats, error)

	// Count returns number of stored scans
	Count() (int, error)

	// Health checks database connectivity
	Health() error
}

// VulnStats represents aggregated vulnerability stats
type VulnStats struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}
