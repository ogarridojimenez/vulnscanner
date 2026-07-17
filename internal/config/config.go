package config

import (
	"time"
)

// Config holds all scan configuration
type Config struct {
	Target       string
	TargetsFile  string
	Full         bool
	Workers      int
	Ports        []int
	Timeout      time.Duration
	Cookie       string
	OutputFormat string
	OutputFile   string
	DBPath       string
	Modules      []string

	// Extended config (from file)
	RateLimit    float64     // requests per second per host (0 = unlimited)
	Proxy        string      // e.g. http://127.0.0.1:8080
	ModuleConfig *FileConfig // raw file config for module access

	// Auth (Feature 003)
	AuthLoginURL   string
	AuthUser       string
	AuthPass       string
	AuthTokenField string
	AuthUserField  string
	AuthPassField  string
	authSession    interface{} // *auth.Session when authenticated
}

// SetAuthSession stores an authenticated session (Feature 003)
func (c *Config) SetAuthSession(s interface{}) {
	c.authSession = s
}

// GetAuthSession returns the authenticated session if any
func (c *Config) GetAuthSession() interface{} {
	return c.authSession
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Workers:      10,
		Timeout:      5 * time.Second,
		OutputFormat: "json",
		DBPath:       defaultDBPath(),
		Modules:      []string{},
	}
}

func defaultDBPath() string {
	return "~/.vulnscanner/history.db"
}

// CommonHTTPPorts are the default TCP ports to scan
var CommonHTTPPorts = []int{80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 9090, 9443}

// SecurityHeaders list of security-related HTTP headers to check
var SecurityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"X-XSS-Protection",
	"Referrer-Policy",
	"Permissions-Policy",
	"Access-Control-Allow-Origin",
	"Cross-Origin-Resource-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Embedder-Policy",
	"Cache-Control",
}

// CommonPaths for directory fuzzing
var CommonPaths = []string{
	"/admin", "/login", "/wp-admin", "/administrator",
	"/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
	"/backup", "/config", "/api", "/swagger", "/docs",
	"/.htaccess", "/.gitignore", "/phpinfo.php", "/info.php",
	"/test", "/dev", "/vendor", "/node_modules",
	"/.well-known/security.txt", "/crossdomain.xml",
	"/clientaccesspolicy.xml", "/wsdl", "/graphql",
	"/v1", "/v2", "/health", "/metrics", "/status",
}
