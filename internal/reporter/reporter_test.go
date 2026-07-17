package reporter

import (
	"testing"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

func TestReportsGenerate(t *testing.T) {
	report := &models.ScanReport{
		ID:      "test",
		Target:  "http://example.com",
		Results: []models.Result{{Module: models.ModuleCookies, Name: "Missing Secure", Severity: models.SeverityMedium, Description: "cookie sin Secure", Recommendation: "set Secure"}},
	}
	if err := HTMLReport(report, "test.html"); err != nil {
		t.Fatalf("html: %v", err)
	}
	if err := SARIFReport(report, "test.sarif.json"); err != nil {
		t.Fatalf("sarif: %v", err)
	}
	if err := MarkdownReport(report, "test.md"); err != nil {
		t.Fatalf("md: %v", err)
	}
}
