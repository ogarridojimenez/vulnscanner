package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

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
}
