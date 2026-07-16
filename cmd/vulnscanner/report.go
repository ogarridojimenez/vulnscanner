package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ogarridojimenez/vulnscanner/internal/reporter"
	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

var reportCmd = &cobra.Command{
	Use:   "report [scan-id]",
	Short: "Export a scan report",
	Long: `Export a previously completed scan as JSON or PDF.

Examples:
  vulnscan report scan_example-com_20260716_123456
  vulnscan report scan_example-com_20260716_123456 --format pdf -o report.pdf`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID := args[0]
		format, _ := cmd.Flags().GetString("format")
		outputFile, _ := cmd.Flags().GetString("output")

		store := storage.NewSQLiteStore(cfg.DBPath)
		if err := store.Init(); err != nil {
			return fmt.Errorf("init db: %w", err)
		}

		report, err := store.GetScan(scanID)
		if err != nil {
			return fmt.Errorf("get scan %s: %w", scanID, err)
		}

		if outputFile == "" {
			ext := ".json"
			if format == "pdf" {
				ext = ".pdf"
			}
			outputFile = fmt.Sprintf("report_%s_%s%s", report.Target, scanID, ext)
		}

		if format == "pdf" {
			if err := reporter.PDFReport(report, outputFile); err != nil {
				return fmt.Errorf("pdf report: %w", err)
			}
		} else {
			if err := reporter.JSONReport(report, outputFile); err != nil {
				return fmt.Errorf("json report: %w", err)
			}
		}

		fmt.Printf("Report saved: %s\n", outputFile)
		return nil
	},
}

func init() {
	reportCmd.Flags().String("format", "json", "report format: json or pdf")
	reportCmd.Flags().StringP("output", "o", "", "output file path")
}
