package reporter

import (
	"fmt"
	"strings"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"

	"github.com/go-pdf/fpdf"
)

// PDFReport generates a professional PDF report
func PDFReport(report *models.ScanReport, outputPath string) error {
	if outputPath == "" {
		outputPath = fmt.Sprintf("report_%s_%s.pdf", report.Target, report.ID)
	}

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.AliasNbPages("")

	// --- Header/Footer ---
	pdf.SetHeaderFunc(func() {
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(0, 8, "VulnScanner - Security Audit Report", "", 0, "R", false, 0, "")
		pdf.Ln(12)
	})

	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 10, fmt.Sprintf("Page %d/{nb}", pdf.PageNo()),
			"", 0, "C", false, 0, "")
	})

	// --- Page 1: Title ---
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 24)
	pdf.SetTextColor(30, 60, 180)
	pdf.CellFormat(0, 15, "Vulnerability Scan Report", "", 0, "L", false, 0, "")
	pdf.Ln(20)

	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(50, 50, 50)
	rows := [][2]string{
		{"Target", report.Target},
		{"Scan ID", report.ID},
		{"Date", report.Timestamp.Format(time.RFC1123)},
		{"Duration", report.Duration.Round(time.Second).String()},
		{"Modules", strings.Join(moduleNames(report.ModulesRun), ", ")},
		{"Status", report.Status},
	}
	for _, r := range rows {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(40, 8, r[0]+":", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(0, 8, r[1], "", 1, "L", false, 0, "")
	}
	pdf.Ln(10)

	// --- Summary Table ---
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(30, 60, 180)
	pdf.CellFormat(0, 10, "Executive Summary", "", 1, "L", false, 0, "")
	pdf.Ln(4)

	summary := report.Summary
	summaryData := []struct {
		Label string
		Count int
		Color []int
	}{
		{"Total Checks", summary.TotalChecks, []int{50, 50, 50}},
		{"Vulnerabilities", summary.Vulnerabilities, []int{200, 50, 50}},
		{"High", summary.High, []int{220, 60, 60}},
		{"Medium", summary.Medium, []int{220, 180, 60}},
		{"Low", summary.Low, []int{60, 60, 220}},
		{"Info", summary.Info, []int{128, 128, 128}},
	}

	for _, s := range summaryData {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(s.Color[0], s.Color[1], s.Color[2])
		pdf.CellFormat(60, 8, s.Label, "1", 0, "L", true, 0, "")
		pdf.CellFormat(20, 8, fmt.Sprintf("%d", s.Count), "1", 1, "C", true, 0, "")
	}
	pdf.Ln(10)

	// --- Findings ---
	if len(report.Results) > 0 {
		pdf.SetFont("Helvetica", "B", 14)
		pdf.SetTextColor(30, 60, 180)
		pdf.CellFormat(0, 10, "Findings", "", 1, "L", false, 0, "")
		pdf.Ln(4)

		for i, r := range report.Results {
			if i > 0 && pdf.GetY() > 250 {
				pdf.AddPage()
			}

			// Severity color
			var sevColor []int
			switch r.Severity {
			case models.SeverityCritical, models.SeverityHigh:
				sevColor = []int{200, 50, 50}
			case models.SeverityMedium:
				sevColor = []int{200, 150, 30}
			case models.SeverityLow:
				sevColor = []int{60, 60, 200}
			default:
				sevColor = []int{100, 100, 100}
			}

			pdf.SetFont("Helvetica", "B", 10)
			pdf.SetTextColor(sevColor[0], sevColor[1], sevColor[2])
			pdf.CellFormat(20, 7, fmt.Sprintf("[%s]", strings.ToUpper(string(r.Severity))), "", 0, "L", false, 0, "")
			pdf.SetFont("Helvetica", "B", 10)
			pdf.SetTextColor(50, 50, 50)
			pdf.CellFormat(0, 7, r.Name, "", 1, "L", false, 0, "")

			pdf.SetFont("Helvetica", "", 9)
			pdf.SetTextColor(80, 80, 80)
			pdf.CellFormat(0, 6, r.Description, "", 1, "L", false, 0, "")

			if r.Evidence != "" {
				pdf.SetFont("Courier", "", 7)
				pdf.SetTextColor(60, 60, 60)
				// Truncate evidence to fit
				ev := r.Evidence
				if len(ev) > 200 {
					ev = ev[:200] + "..."
				}
				pdf.MultiCell(0, 4, ev, "", "L", false)
			}

			if r.Recommendation != "" {
				pdf.SetFont("Helvetica", "I", 8)
				pdf.SetTextColor(30, 120, 30)
				pdf.MultiCell(0, 5, "Fix: "+r.Recommendation, "", "L", false)
			}
			pdf.Ln(3)
		}
	}

	return pdf.OutputFileAndClose(outputPath)
}

func moduleNames(modules []models.Module) []string {
	names := make([]string, len(modules))
	for i, m := range modules {
		names[i] = string(m)
	}
	return names
}
