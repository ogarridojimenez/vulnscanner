package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

func TestStorageIntegration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store := NewSQLiteStore(dbPath)
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()

	report := &models.ScanReport{
		ID:        "int_test_1",
		Target:    "http://example.com",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
		ModulesRun: []models.Module{
			models.ModulePort, models.ModuleHeaders,
		},
		Results: []models.Result{
			{
				Module:      models.ModuleHeaders,
				Name:        "Missing HSTS",
				Severity:    models.SeverityMedium,
				Description: "HSTS header not set",
			},
		},
		Summary: models.Summary{
			TotalChecks:     1,
			Vulnerabilities: 1,
			Medium:          1,
			ByModule: map[string]int{
				string(models.ModuleHeaders): 1,
			},
		},
		Status: "completed",
	}

	if err := store.SaveScan(report); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := store.GetScan("int_test_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Target != "http://example.com" {
		t.Errorf("target mismatch: %q", got.Target)
	}
	if len(got.Results) != 1 {
		t.Errorf("results count: %d", len(got.Results))
	}

	scans, err := store.ListScans(10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(scans) != 1 {
		t.Errorf("list count: %d", len(scans))
	}
}
