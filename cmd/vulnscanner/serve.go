package main

import (
	"fmt"

	"github.com/ogarridojimenez/vulnscanner/internal/ldapauth"
	"github.com/ogarridojimenez/vulnscanner/internal/logger"
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
		logLevel, _ := cmd.Flags().GetString("log-level")
		rateLimit, _ := cmd.Flags().GetInt("rate-limit")
		jwtSecret, _ := cmd.Flags().GetString("jwt-secret")

		// LDAP flags
		ldapURL, _ := cmd.Flags().GetString("ldap-url")
		ldapBaseDN, _ := cmd.Flags().GetString("ldap-base-dn")
		ldapBindDN, _ := cmd.Flags().GetString("ldap-bind-dn")
		ldapBindPass, _ := cmd.Flags().GetString("ldap-bind-pass")
		ldapUserFilter, _ := cmd.Flags().GetString("ldap-user-filter")
		ldapAdminGroup, _ := cmd.Flags().GetString("ldap-admin-group")

		logger.Setup(logLevel)
		store := storage.NewSQLiteStore(dbPath)
		if err := store.Init(); err != nil {
			return fmt.Errorf("storage init: %w", err)
		}
		defer store.Close()

		// LDAP client
		var ldapClient *ldapauth.Client
		if ldapURL != "" {
			ldapClient = ldapauth.New(ldapauth.Config{
				URL:        ldapURL,
				BaseDN:     ldapBaseDN,
				BindDN:     ldapBindDN,
				BindPass:   ldapBindPass,
				UserFilter: ldapUserFilter,
				AdminGroup: ldapAdminGroup,
				StartTLS:   false,
			})
			fmt.Printf("LDAP auth enabled: %s\n", ldapURL)
		}

		srv := server.New(store, uiPass, apiToken, rateLimit, jwtSecret, ldapClient)
		if uiPass != "" {
			fmt.Println("UI auth enabled (password protected)")
		}
		if apiToken != "" {
			fmt.Println("API auth enabled (Bearer token required)")
		}
		if rateLimit > 0 {
			fmt.Printf("Rate limiting enabled: %d req/min\n", rateLimit)
		}
		if jwtSecret != "" {
			fmt.Println("JWT auth enabled")
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
	serveCmd.Flags().String("log-level", "info", "log level: debug, info, warn, error")
	serveCmd.Flags().Int("rate-limit", 0, "max requests per minute per IP (0 = disabled)")
	serveCmd.Flags().String("jwt-secret", "", "JWT signing secret (empty = disabled, uses static token instead)")

	// LDAP flags
	serveCmd.Flags().String("ldap-url", "", "LDAP server URL (e.g. ldap://ldap.example.com:389)")
	serveCmd.Flags().String("ldap-base-dn", "", "LDAP base DN for user search")
	serveCmd.Flags().String("ldap-bind-dn", "", "LDAP service account DN (empty = anonymous bind)")
	serveCmd.Flags().String("ldap-bind-pass", "", "LDAP service account password")
	serveCmd.Flags().String("ldap-user-filter", "(uid=%s)", "LDAP user search filter (%%s = username placeholder)")
	serveCmd.Flags().String("ldap-admin-group", "", "LDAP group DN for admin role assignment")

	rootCmd.AddCommand(serveCmd)
}
