package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Database management commands",
	Long:  `Initialize and check the local scan database.`,
}

var dbInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the database",
	RunE: func(cmd *cobra.Command, args []string) error {
		store := storage.NewSQLiteStore(cfg.DBPath)
		if err := store.Init(); err != nil {
			return fmt.Errorf("db init: %w", err)
		}
		color.Green("Database initialized: %s", cfg.DBPath)
		return nil
	},
}

var dbCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check database health",
	RunE: func(cmd *cobra.Command, args []string) error {
		store := storage.NewSQLiteStore(cfg.DBPath)
		if err := store.Init(); err != nil {
			return fmt.Errorf("db init: %w", err)
		}
		if err := store.Health(); err != nil {
			return fmt.Errorf("db health: %w", err)
		}
		count, _ := store.Count()
		color.Green("Database OK — %d scans stored", count)
		return nil
	},
}

func init() {
	dbCmd.AddCommand(dbInitCmd)
	dbCmd.AddCommand(dbCheckCmd)
	dbCmd.AddCommand(dbExportCmd)
	dbCmd.AddCommand(dbImportCmd)
}

var dbExportCmd = &cobra.Command{
	Use:   "export [file.json]",
	Short: "Export all scans to JSON file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store := storage.NewSQLiteStore(cfg.DBPath)
		if err := store.Init(); err != nil {
			return fmt.Errorf("db init: %w", err)
		}
		defer store.Close()

		scans, err := store.ListScans(10000)
		if err != nil {
			return fmt.Errorf("list scans: %w", err)
		}

		export := map[string]interface{}{
			"version":     "1.0",
			"exported_at": time.Now(),
			"count":       len(scans),
			"scans":       scans,
		}

		data, _ := json.MarshalIndent(export, "", "  ")
		if err := os.WriteFile(args[0], data, 0644); err != nil {
			return fmt.Errorf("write file: %w", err)
		}
		color.Green("Exported %d scans to %s", len(scans), args[0])
		return nil
	},
}

var dbImportCmd = &cobra.Command{
	Use:   "import [file.json]",
	Short: "Import scans from JSON file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store := storage.NewSQLiteStore(cfg.DBPath)
		if err := store.Init(); err != nil {
			return fmt.Errorf("db init: %w", err)
		}
		defer store.Close()

		data, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}

		var payload struct {
			Scans []models.ScanReport `json:"scans"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return fmt.Errorf("parse json: %w", err)
		}

		imported := 0
		for _, scan := range payload.Scans {
			if err := store.SaveScan(&scan); err != nil {
				continue
			}
			imported++
		}
		color.Green("Imported %d/%d scans", imported, len(payload.Scans))
		return nil
	},
}
