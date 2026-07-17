package reporter

import (
	"fmt"
	"html"
	"math"
	"os"
	"strings"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// HTMLReport generates an HTML report with a severity chart (inline SVG donut).
func HTMLReport(report *models.ScanReport, outputPath string) error {
	sevCounts := map[models.Severity]int{
		models.SeverityCritical: 0,
		models.SeverityHigh:     0,
		models.SeverityMedium:   0,
		models.SeverityLow:      0,
		models.SeverityInfo:     0,
	}
	for _, r := range report.Results {
		sevCounts[r.Severity]++
	}

	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\">")
	sb.WriteString("<title>VulnScanner Report — " + html.EscapeString(report.Target) + "</title>")
	sb.WriteString("<style>body{font-family:system-ui,sans-serif;margin:2rem;background:#0d1117;color:#c9d1d9}")
	sb.WriteString(".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;margin:0.5rem 0}")
	sb.WriteString(".crit{color:#f85149}.high{color:#ff7b72}.med{color:#d29922}.low{color:#58a6ff}.info{color:#8b949e}")
	sb.WriteString("table{width:100%;border-collapse:collapse}td,th{border:1px solid #30363d;padding:6px;text-align:left}")
	sb.WriteString("</style></head><body>")
	sb.WriteString("<h1>VulnScanner — " + html.EscapeString(report.Target) + "</h1>")
	sb.WriteString(fmt.Sprintf("<p>Generado: %s | Duración: %s</p>", report.Timestamp.Format("2006-01-02 15:04"), report.Duration.Round(1e9)))

	// Donut chart
	sb.WriteString(severityDonut(sevCounts))
	sb.WriteString("<h2>Findings</h2><table><tr><th>Sev</th><th>Modulo</th><th>Nombre</th><th>Desc</th></tr>")
	for _, r := range report.Results {
		cls := strings.ToLower(string(r.Severity))
		sb.WriteString(fmt.Sprintf("<tr><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			cls, r.Severity, r.Module, html.EscapeString(r.Name), html.EscapeString(r.Description)))
	}
	sb.WriteString("</table></body></html>")

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

func severityDonut(c map[models.Severity]int) string {
	total := 0
	for _, v := range c {
		total += v
	}
	if total == 0 {
		return "<p>Sin findings</p>"
	}
	colors := map[models.Severity]string{
		models.SeverityCritical: "#f85149",
		models.SeverityHigh:     "#ff7b72",
		models.SeverityMedium:   "#d29922",
		models.SeverityLow:      "#58a6ff",
		models.SeverityInfo:     "#8b949e",
	}
	var sb strings.Builder
	sb.WriteString("<svg width=\"200\" height=\"200\" viewBox=\"0 0 200 200\">")
	cx, cy, r := 100, 100, 80
	offset := 0.0
	for _, sev := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
		n := c[sev]
		if n == 0 {
			continue
		}
		frac := float64(n) / float64(total)
		angle := frac * 360
		sb.WriteString(donutArc(cx, cy, r, offset, offset+angle, colors[sev]))
		offset += angle
	}
	sb.WriteString(fmt.Sprintf("<text x=\"100\" y=\"105\" text-anchor=\"middle\" fill=\"#fff\">%d</text></svg>", total))
	sb.WriteString("<ul>")
	for _, sev := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
		if c[sev] > 0 {
			sb.WriteString(fmt.Sprintf("<li class=\"%s\">%s: %d</li>", strings.ToLower(string(sev)), sev, c[sev]))
		}
	}
	sb.WriteString("</ul>")
	return sb.String()
}

func donutArc(cx, cy, r int, start, end float64, color string) string {
	const rad = 3.141592653589793 / 180
	x1 := float64(cx) + float64(r)*cosDeg(start)
	y1 := float64(cy) + float64(r)*sinDeg(start)
	x2 := float64(cx) + float64(r)*cosDeg(end)
	y2 := float64(cy) + float64(r)*sinDeg(end)
	large := 0.0
	if end-start > 180 {
		large = 1
	}
	return fmt.Sprintf("<path d=\"M %f %f A %d %d 0 %d 1 %f %f L %d %d Z\" fill=\"%s\"/>",
		x1, y1, r, r, int(large), x2, y2, cx, cy, color)
}

func cosDeg(d float64) float64 { return math.Cos(d * 3.141592653589793 / 180) }
func sinDeg(d float64) float64 { return math.Sin(d * 3.141592653589793 / 180) }
