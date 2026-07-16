package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show vulnerability summary across all scans",
	Long:  `Aggregate vulnerability statistics from all stored scan results.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		store := storage.NewSQLiteStore(cfg.DBPath)
		if err := store.Init(); err != nil {
			return fmt.Errorf("init db: %w", err)
		}

		stats, err := store.Summary()
		if err != nil {
			return fmt.Errorf("summary: %w", err)
		}

		if len(stats) == 0 {
			color.Yellow("No vulnerabilities found in database.")
			return nil
		}

		fmt.Println()
		color.Cyan("Vulnerability Summary")
		fmt.Println("┌────────────┬───────┬──────────────────────┐")
		fmt.Printf("│ %-10s │ %-5s │ %-20s │\n", "Severity", "Count", "Last Seen")
		fmt.Println("├────────────┼───────┼──────────────────────┤")

		sevColors := map[string]func(string, ...interface{}) string{
			"critical": color.New(color.FgHiRed, color.Bold).SprintfFunc(),
			"high":     color.New(color.FgRed).SprintfFunc(),
			"medium":   color.New(color.FgYellow).SprintfFunc(),
			"low":      color.New(color.FgBlue).SprintfFunc(),
			"info":     color.New(color.FgWhite).SprintfFunc(),
		}

		total := 0
		for _, s := range stats {
			cf := sevColors[s.Severity]
			if cf == nil {
				cf = fmt.Sprintf
			}
			fmt.Printf("│ %-10s │ %5d │ %-20s │\n",
				cf("%-10s", s.Severity), s.Count, s.LastSeen.Format("2006-01-02 15:04"))
			total += s.Count
		}

		fmt.Println("└────────────┴───────┴──────────────────────┘")
		color.Cyan("Total: %d vulnerabilities across all scans", total)
		fmt.Println()

		return nil
	},
}
