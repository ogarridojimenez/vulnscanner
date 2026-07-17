package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFileYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	yaml := `
workers: 20
timeout: 15s
rate_limit: 5.0
proxy: "http://127.0.0.1:8080"
modules:
  - ssrf
  - lfi
output_format: html
`
	if err := os.WriteFile(p, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadFromFile(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if fc.Workers != 20 {
		t.Errorf("workers=20, got %d", fc.Workers)
	}
	if fc.RateLimit != 5.0 {
		t.Errorf("rate=5.0, got %f", fc.RateLimit)
	}
	if fc.Proxy != "http://127.0.0.1:8080" {
		t.Errorf("proxy mismatch: %q", fc.Proxy)
	}
	if len(fc.Modules) != 2 {
		t.Errorf("modules=2, got %d", len(fc.Modules))
	}
}

func TestLoadFromFileTOML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.toml")
	toml := `
workers = 8
timeout = "10s"
rate_limit = 2.5

[auth]
type = "form"
login_url = "https://x.com/login"
username = "admin"
`
	if err := os.WriteFile(p, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadFromFile(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if fc.Workers != 8 {
		t.Errorf("workers=8, got %d", fc.Workers)
	}
	if fc.Auth.Username != "admin" {
		t.Errorf("auth user mismatch: %q", fc.Auth.Username)
	}
}

func TestApplyFromFile(t *testing.T) {
	cfg := DefaultConfig()
	fc := &FileConfig{Workers: 30, RateLimit: 3.0, Proxy: "http://p:8080"}
	cfg.ApplyFromFile(fc)
	if cfg.Workers != 30 {
		t.Errorf("apply workers failed")
	}
	if cfg.RateLimit != 3.0 {
		t.Errorf("apply ratelimit failed")
	}
	if cfg.Proxy != "http://p:8080" {
		t.Errorf("apply proxy failed")
	}
}
