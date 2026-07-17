package main

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/ogarridojimenez/vulnscanner/internal/auth"
	"github.com/ogarridojimenez/vulnscanner/internal/config"
	"github.com/ogarridojimenez/vulnscanner/internal/models"
	"github.com/ogarridojimenez/vulnscanner/internal/reporter"
	"github.com/ogarridojimenez/vulnscanner/internal/scanner"
	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Run a vulnerability scan against a target",
	Long: `Run vulnerability scan against a domain or IP address.

Examples:
  vulnscan scan example.com
  vulnscan scan example.com --full
  vulnscan scan example.com --ports 80,443,8080 --workers 20
  vulnscan scan example.com --full --output report.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		cfg.Target = target

		// Load config file if provided (Feature 004)
		configFile, _ := cmd.Flags().GetString("config")
		if configFile != "" {
			fc, err := config.LoadFromFile(configFile)
			if err != nil {
				return fmt.Errorf("config load failed: %w", err)
			}
			cfg.ApplyFromFile(fc)
			color.Yellow("Loaded config: %s", configFile)
		}

		// Parse ports if provided
		portsStr, _ := cmd.Flags().GetString("ports")
		if portsStr != "" {
			parts := strings.Split(portsStr, ",")
			for _, p := range parts {
				var port int
				if _, err := fmt.Sscanf(p, "%d", &port); err == nil {
					cfg.Ports = append(cfg.Ports, port)
				}
			}
		}

		// Determine modules
		full, _ := cmd.Flags().GetBool("full")
		modulesStr, _ := cmd.Flags().GetString("modules")
		if full {
			cfg.Modules = []string{"port", "headers", "tls", "directory", "sqli", "xss", "ssrf", "lfi", "redirect", "cookies", "tech", "subdomain"}
		} else if modulesStr != "" {
			cfg.Modules = strings.Split(modulesStr, ",")
		} else {
			cfg.Modules = []string{"port", "headers", "tls", "directory", "sqli", "xss"}
		}

		// Log level
		slog.SetLogLoggerLevel(slog.LevelInfo)
		if verbose {
			slog.SetLogLoggerLevel(slog.LevelDebug)
		}

		// Auth session (Feature 003)
		authLoginURL, _ := cmd.Flags().GetString("auth-login-url")
		if authLoginURL != "" {
			authUser, _ := cmd.Flags().GetString("auth-user")
			authPass, _ := cmd.Flags().GetString("auth-pass")
			authTokenField, _ := cmd.Flags().GetString("auth-token-field")
			if authUser == "" || authPass == "" {
				return fmt.Errorf("auth requires --auth-user and --auth-pass")
			}
			cfg.AuthLoginURL = authLoginURL
			cfg.AuthUser = authUser
			cfg.AuthPass = authPass
			cfg.AuthTokenField = authTokenField
			color.Yellow("Authenticating with %s...", authLoginURL)
			sess, err := auth.NewSession(auth.Config{
				LoginURL:   authLoginURL,
				Username:   authUser,
				Password:   authPass,
				TokenField: authTokenField,
				Timeout:    cfg.Timeout,
			})
			if err != nil {
				return fmt.Errorf("auth failed: %w", err)
			}
			cfg.SetAuthSession(sess)
			color.Green("Authenticated successfully")
		}

		// Print banner
		color.Cyan("VulnScanner — Security Audit Tool")
		fmt.Println()

		// Run scan
		start := time.Now()
		scan := scanner.New(cfg)
		results, modulesRun, err := scan.Run(target)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}
		duration := time.Since(start)

		// Build report
		summary := models.BuildSummary(results)
		reportID := fmt.Sprintf("scan_%s_%s",
			sanitizeFilename(target),
			start.Format("20060102_150405"))

		report := &models.ScanReport{
			ID:         reportID,
			Target:     target,
			Timestamp:  start,
			Duration:   duration,
			ModulesRun: modulesRun,
			Results:    results,
			Summary:    summary,
			Status:     "completed",
		}

		// Print results table
		printResultsTable(target, report)

		// Save to database
		dbPath := cfg.DBPath
		store := storage.NewSQLiteStore(dbPath)
		if err := store.Init(); err != nil {
			slog.Warn("could not init storage", "error", err)
		} else {
			if err := store.SaveScan(report); err != nil {
				slog.Warn("could not save scan", "error", err)
			}
			count, _ := store.Count()
			color.Magenta("\nDatabase: %s (%d previous scans)", dbPath, count-1)
		}

		// Generate report file
		outputFile, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")

		if outputFile == "" {
			ext := ".json"
			switch format {
			case "pdf":
				ext = ".pdf"
			case "html":
				ext = ".html"
			case "sarif":
				ext = ".sarif.json"
			case "md":
				ext = ".md"
			}
			outputFile = fmt.Sprintf("report_%s_%s%s",
				sanitizeFilename(target),
				start.Format("20060102_150405"),
				ext)
		}

		switch format {
		case "pdf":
			if err := reporter.PDFReport(report, outputFile); err != nil {
				slog.Warn("could not generate PDF report", "error", err)
			} else {
				color.Green("Report saved: %s", outputFile)
			}
		case "html":
			if err := reporter.HTMLReport(report, outputFile); err != nil {
				slog.Warn("could not generate HTML report", "error", err)
			} else {
				color.Green("Report saved: %s", outputFile)
			}
		case "sarif":
			if err := reporter.SARIFReport(report, outputFile); err != nil {
				slog.Warn("could not generate SARIF report", "error", err)
			} else {
				color.Green("Report saved: %s", outputFile)
			}
		case "md":
			if err := reporter.MarkdownReport(report, outputFile); err != nil {
				slog.Warn("could not generate Markdown report", "error", err)
			} else {
				color.Green("Report saved: %s", outputFile)
			}
		default:
			if err := reporter.JSONReport(report, outputFile); err != nil {
				slog.Warn("could not generate JSON report", "error", err)
			} else {
				color.Green("Report saved: %s", outputFile)
			}
		}

		fmt.Println()
		return nil
	},
}

var severityColors = map[models.Severity]func(format string, a ...interface{}) string{
	models.SeverityCritical: color.New(color.FgHiRed, color.Bold).SprintfFunc(),
	models.SeverityHigh:     color.New(color.FgRed).SprintfFunc(),
	models.SeverityMedium:   color.New(color.FgYellow).SprintfFunc(),
	models.SeverityLow:      color.New(color.FgBlue).SprintfFunc(),
	models.SeverityInfo:     color.New(color.FgWhite).SprintfFunc(),
}

func printResultsTable(target string, report *models.ScanReport) {
	cyan := color.New(color.FgCyan).SprintfFunc()
	green := color.New(color.FgGreen).SprintfFunc()

	fmt.Println()
	fmt.Printf("Target: %s\n", cyan(target))
	fmt.Println("┌──────────────────────────────────────┬──────────────┬──────────┐")

	moduleNames := map[models.Module]string{
		models.ModulePort:      "Port Scan",
		models.ModuleHeaders:   "Security Headers",
		models.ModuleTLS:       "TLS Check",
		models.ModuleDirectory: "Directory Fuzzing",
		models.ModuleSQLi:      "SQLi Detection",
		models.ModuleXSS:       "XSS Detection",
	}

	for _, mod := range report.ModulesRun {
		modResults := models.ResultList(report.Results).ByModule(mod)
		name := moduleNames[mod]
		if name == "" {
			name = string(mod)
		}

		var findings string
		var sev string

		if len(modResults) > 0 {
			vulns := 0
			for _, r := range modResults {
				if r.Severity == models.SeverityHigh || r.Severity == models.SeverityCritical || r.Severity == models.SeverityMedium {
					vulns++
				}
			}
			findings = fmt.Sprintf("%d encontrados", len(modResults))
			if vulns > 0 {
				sev = fmt.Sprintf("%d vuln", vulns)
			} else {
				sev = "INFO"
			}
		} else {
			findings = "0"
			sev = "-"
		}

		sevColor := severityColors[models.SeverityInfo]
		if sev == "INFO" {
			sevColor = color.New(color.FgWhite).SprintfFunc()
		} else if sev != "-" {
			sevColor = color.New(color.FgYellow).SprintfFunc()
		}

		fmt.Printf("│ %-36s │ %-12s │ %-8s │\n", name, findings, sevColor(sev))
	}

	fmt.Println("└──────────────────────────────────────┴──────────────┴──────────┘")
	fmt.Println()
	green("Scan completed in %s", report.Duration.Round(time.Second))
}

func init() {
	scanCmd.Flags().Bool("full", false, "run all scan modules")
	scanCmd.Flags().String("modules", "", "comma-separated module list (e.g. ssrf,lfi,redirect,cookies,tech,subdomain)")
	scanCmd.Flags().String("ports", "", "comma-separated ports to scan (e.g. 80,443,8080)")
	scanCmd.Flags().String("format", "json", "report format: json, pdf, html, sarif, md")
	scanCmd.Flags().StringP("output", "o", "", "output file path")
	// Auth (Feature 003)
	scanCmd.Flags().String("auth-login-url", "", "login URL for authenticated scans")
	scanCmd.Flags().String("auth-user", "", "username for authenticated scans")
	scanCmd.Flags().String("auth-pass", "", "password for authenticated scans")
	scanCmd.Flags().String("auth-token-field", "", "JSON field name for auth token in login response")
	// Config file (Feature 004)
	scanCmd.Flags().String("config", "", "path to YAML/TOML config file")
}

// sanitizeFilename replaces characters unsafe for filenames
func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, "://", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "?", "_")
	s = strings.ReplaceAll(s, "&", "_")
	return s
}
