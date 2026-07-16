package reporter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// JSONReport generates a JSON report file
func JSONReport(report *models.ScanReport, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	if outputPath == "" {
		outputPath = fmt.Sprintf("report_%s_%s.json", report.Target, report.ID)
	}

	return os.WriteFile(outputPath, data, 0644)
}

// JSONString returns the report as a JSON string
func JSONString(report *models.ScanReport) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("json marshal: %w", err)
	}
	return string(data), nil
}
