package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ogarridojimenez/vulnscanner/internal/config"
)

var (
	cfg     = config.DefaultConfig()
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "vulnscan",
	Short: "Web vulnerability scanner from the terminal",
	Long: `VulnScanner is a web vulnerability scanner built in Go.
It scans targets for open ports, missing security headers, TLS issues,
hidden directories, and basic SQLi/XSS vulnerabilities.

Complete documentation is available at https://github.com/ogarridojimenez/vulnscanner`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Apply verbose flag globally
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Global persistent flags
	rootCmd.PersistentFlags().IntVarP(&cfg.Workers, "workers", "w", 10, "number of concurrent workers")
	rootCmd.PersistentFlags().DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "timeout per request (e.g. 5s, 30s)")
	rootCmd.PersistentFlags().StringVar(&cfg.Cookie, "cookie", "", "session cookie for authenticated scans")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVar(&cfg.DBPath, "db", cfg.DBPath, "path to history database")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(summaryCmd)
	rootCmd.AddCommand(dbCmd)
}
