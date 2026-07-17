package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// FileConfig represents the YAML/TOML configuration file structure
type FileConfig struct {
	Workers      int           `yaml:"workers" toml:"workers"`
	Timeout      time.Duration `yaml:"timeout" toml:"timeout"`
	Modules      []string      `yaml:"modules" toml:"modules"`
	RateLimit    float64       `yaml:"rate_limit" toml:"rate_limit"` // requests per second per host
	Proxy        string        `yaml:"proxy" toml:"proxy"`
	Cookie       string        `yaml:"cookie" toml:"cookie"`
	OutputFormat string        `yaml:"output_format" toml:"output_format"`
	DBPath       string        `yaml:"db_path" toml:"db_path"`

	// Module-specific overrides
	PortScan  PortScanConfig  `yaml:"port_scan" toml:"port_scan"`
	Headers   HeadersConfig   `yaml:"headers" toml:"headers"`
	Directory DirectoryConfig `yaml:"directory" toml:"directory"`
	SQLi      PayloadConfig   `yaml:"sqli" toml:"sqli"`
	XSS       PayloadConfig   `yaml:"xss" toml:"xss"`
	SSRF      PayloadConfig   `yaml:"ssrf" toml:"ssrf"`
	LFI       PayloadConfig   `yaml:"lfi" toml:"lfi"`
	Redirect  PayloadConfig   `yaml:"redirect" toml:"redirect"`
	Subdomain SubdomainConfig `yaml:"subdomain" toml:"subdomain"`
	Tech      TechConfig      `yaml:"tech" toml:"tech"`
	Cookies   CookiesConfig   `yaml:"cookies" toml:"cookies"`
	Auth      AuthConfig      `yaml:"auth" toml:"auth"`
}

type PortScanConfig struct {
	Enabled bool  `yaml:"enabled" toml:"enabled"`
	Ports   []int `yaml:"ports" toml:"ports"`
}

type HeadersConfig struct {
	Enabled bool     `yaml:"enabled" toml:"enabled"`
	Checks  []string `yaml:"checks" toml:"checks"`
}

type DirectoryConfig struct {
	Enabled bool     `yaml:"enabled" toml:"enabled"`
	Paths   []string `yaml:"paths" toml:"paths"`
}

type PayloadConfig struct {
	Enabled  bool     `yaml:"enabled" toml:"enabled"`
	Payloads []string `yaml:"payloads" toml:"payloads"`
}

type SubdomainConfig struct {
	Enabled    bool     `yaml:"enabled" toml:"enabled"`
	Wordlist   []string `yaml:"wordlist" toml:"wordlist"`
	MaxWorkers int      `yaml:"max_workers" toml:"max_workers"`
}

type TechConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
}

type CookiesConfig struct {
	Enabled bool `yaml:"enabled" toml:"enabled"`
}

type AuthConfig struct {
	Type     string `yaml:"type" toml:"type"` // form, basic, jwt, cookie
	LoginURL string `yaml:"login_url" toml:"login_url"`
	Username string `yaml:"username" toml:"username"`
	Password string `yaml:"password" toml:"password"`
	Token    string `yaml:"token" toml:"token"`
	Cookie   string `yaml:"cookie" toml:"cookie"`
	RenewMax int    `yaml:"renew_max" toml:"renew_max"`
}

// LoadFromFile loads configuration from a YAML or TOML file
func LoadFromFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	fc := &FileConfig{}
	switch {
	case strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml"):
		if err := yaml.Unmarshal(data, fc); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	case strings.HasSuffix(path, ".toml"):
		if err := toml.Unmarshal(data, fc); err != nil {
			return nil, fmt.Errorf("failed to parse TOML: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s (use .yaml, .yml or .toml)", path)
	}
	return fc, nil
}

// ApplyToFileConfig merges file config into the runtime Config
func (c *Config) ApplyFromFile(fc *FileConfig) {
	if fc.Workers > 0 {
		c.Workers = fc.Workers
	}
	if fc.Timeout > 0 {
		c.Timeout = fc.Timeout
	}
	if len(fc.Modules) > 0 {
		c.Modules = fc.Modules
	}
	if fc.Cookie != "" {
		c.Cookie = fc.Cookie
	}
	if fc.OutputFormat != "" {
		c.OutputFormat = fc.OutputFormat
	}
	if fc.DBPath != "" {
		c.DBPath = fc.DBPath
	}
	if fc.RateLimit > 0 {
		c.RateLimit = fc.RateLimit
	}
	if fc.Proxy != "" {
		c.Proxy = fc.Proxy
	}
	c.ModuleConfig = fc
}

// ExampleConfig returns a sample configuration for documentation
func ExampleConfig() string {
	return `# VulnScanner configuration example
workers: 15
timeout: 10s
rate_limit: 10.0
proxy: ""
output_format: json
cookie: ""

modules:
  - port
  - headers
  - tls
  - directory
  - sqli
  - xss
  - ssrf
  - lfi
  - redirect
  - cookies
  - tech
  - subdomain

port_scan:
  enabled: true
  ports: [80, 443, 8080, 8443]

directory:
  enabled: true
  paths:
    - /admin
    - /login

sqli:
  enabled: true
  payloads:
    - "' OR '1'='1"

auth:
  type: form
  login_url: https://example.com/login
  username: admin
  password: secret
  renew_max: 3
`
}
