package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show scan history",
	Long:  `List recent vulnerability scans from the local database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		limit, _ := cmd.Flags().GetInt("limit")

		store := storage.NewSQLiteStore(cfg.DBPath)
		if err := store.Init(); err != nil {
			return fmt.Errorf("init db: %w", err)
		}

		scans, err := store.ListScans(limit)
		if err != nil {
			return fmt.Errorf("list scans: %w", err)
		}

		if len(scans) == 0 {
			color.Yellow("No scans found in database.")
			return nil
		}

		fmt.Println()
		color.Cyan("Recent Scans")
		fmt.Println("┌─────────────────────────────────────┬─────────────────────┬───────────┬──────────┐")
		fmt.Printf("│ %-35s │ %-19s │ %-9s │ %-8s │\n", "ID", "Date", "Target", "Findings")
		fmt.Println("├─────────────────────────────────────┼─────────────────────┼───────────┼──────────┤")

		for _, s := range scans {
			shortID := s.ID
			if len(shortID) > 35 {
				shortID = shortID[:32] + "..."
			}
			date := s.Timestamp.Format("2006-01-02 15:04")
			target := s.Target
			if len(target) > 9 {
				target = target[:9]
			}
			fmt.Printf("│ %-35s │ %-19s │ %-9s │ %-8s │\n",
				shortID, date, target, s.Status)
		}
		fmt.Println("└─────────────────────────────────────┴─────────────────────┴───────────┴──────────┘")
		fmt.Println()

		return nil
	},
}

func init() {
	historyCmd.Flags().Int("limit", 10, "number of scans to show")
}
