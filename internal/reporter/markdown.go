package reporter

import (
	"fmt"
	"os"
	"strings"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// MarkdownReport generates a Markdown report.
func MarkdownReport(report *models.ScanReport, outputPath string) error {
	var sb strings.Builder
	sb.WriteString("# VulnScanner Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s  \n", report.Target))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", report.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", report.Duration.Round(1e9)))

	sb.WriteString("## Summary\n\n")
	sb.WriteString("| Severity | Count |\n|----------|-------|\n")
	counts := map[models.Severity]int{}
	for _, r := range report.Results {
		counts[r.Severity]++
	}
	for _, sev := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
		if counts[sev] > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", sev, counts[sev]))
		}
	}
	sb.WriteString("\n## Findings\n\n")
	for i, r := range report.Results {
		sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n", i+1, r.Severity, r.Name))
		sb.WriteString(fmt.Sprintf("- **Module:** %s\n", r.Module))
		sb.WriteString(fmt.Sprintf("- **Description:** %s\n", r.Description))
		sb.WriteString(fmt.Sprintf("- **Recommendation:** %s\n", r.Recommendation))
		if r.Evidence != "" {
			sb.WriteString(fmt.Sprintf("- **Evidence:**\n```\n%s\n```\n", r.Evidence))
		}
		sb.WriteString("\n")
	}
	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}
