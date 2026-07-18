package main

import (
	"fmt"

	"github.com/ogarridojimenez/vulnscanner/internal/server"
	"github.com/ogarridojimenez/vulnscanner/internal/storage"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the VulnScanner API server (Producer-ready, Feature 005)",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")
		dbPath, _ := cmd.Flags().GetString("db")
		uiPass, _ := cmd.Flags().GetString("ui-password")
		apiToken, _ := cmd.Flags().GetString("api-token")
		store := storage.NewSQLiteStore(dbPath)
		if err := store.Init(); err != nil {
			return fmt.Errorf("storage init: %w", err)
		}
		defer store.Close()
		srv := server.New(store, uiPass, apiToken)
		if uiPass != "" {
			fmt.Println("UI auth enabled (password protected)")
		}
		if apiToken != "" {
			fmt.Println("API auth enabled (Bearer token required)")
		}
		fmt.Printf("VulnScanner API listening on %s\n", addr)
		return srv.Run(addr)
	},
}

func init() {
	serveCmd.Flags().String("addr", ":8080", "listen address for API server")
	serveCmd.Flags().String("db", "vulnscanner.db", "SQLite database path")
	serveCmd.Flags().String("ui-password", "", "password to protect the web UI (empty = open)")
	serveCmd.Flags().String("api-token", "", "Bearer token for API auth (empty = open)")
	rootCmd.AddCommand(serveCmd)
}
