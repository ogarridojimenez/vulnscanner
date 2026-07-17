package reporter

import (
	"encoding/json"
	"os"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// SARIFReport generates a SARIF 2.1.0 file for GitHub Security integration.
func SARIFReport(report *models.ScanReport, outputPath string) error {
	s := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "VulnScanner",
					InformationURI: "https://github.com/ogarridojimenez/vulnscanner",
					Version:        "1.0.0",
					Rules:          buildSARIFRules(report),
				},
			},
			Results: buildSARIFResults(report),
		}},
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID          string      `json:"id"`
	ShortDesc   sarifText   `json:"shortDescription"`
	FullDesc    sarifText   `json:"fullDescription"`
	DefaultConf sarifConfig `json:"defaultConfiguration"`
}
type sarifConfig struct {
	Level string `json:"level"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifLocation struct {
	Physical sarifPhys `json:"physicalLocation"`
}
type sarifPhys struct {
	Artifact sarifArtifact `json:"artifactLocation"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}

func sevToSARIFLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func buildSARIFRules(report *models.ScanReport) []sarifRule {
	seen := map[string]bool{}
	var rules []sarifRule
	for _, r := range report.Results {
		id := string(r.Module) + "-" + r.Name
		if seen[id] {
			continue
		}
		seen[id] = true
		rules = append(rules, sarifRule{
			ID:          id,
			ShortDesc:   sarifText{Text: r.Name},
			FullDesc:    sarifText{Text: r.Description},
			DefaultConf: sarifConfig{Level: sevToSARIFLevel(r.Severity)},
		})
	}
	return rules
}

func buildSARIFResults(report *models.ScanReport) []sarifResult {
	var out []sarifResult
	for _, r := range report.Results {
		id := string(r.Module) + "-" + r.Name
		out = append(out, sarifResult{
			RuleID:  id,
			Level:   sevToSARIFLevel(r.Severity),
			Message: sarifText{Text: r.Description + " | Recommendation: " + r.Recommendation},
			Locations: []sarifLocation{{
				Physical: sarifPhys{Artifact: sarifArtifact{URI: report.Target}},
			}},
		})
	}
	return out
}
