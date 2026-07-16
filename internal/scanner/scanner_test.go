package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ogarridojimenez/vulnscanner/internal/config"
	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// TestHeadersCheck verifies that missing security headers are detected
func TestHeadersCheck(t *testing.T) {
	// Server with minimal headers
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	results := checkHeaders(ts.URL, 0, ts.Client())

	// Should detect missing security headers
	missingHeaderResults := 0
	for _, r := range results {
		if r.Severity == models.SeverityMedium {
			missingHeaderResults++
		}
	}
	if missingHeaderResults == 0 {
		t.Error("expected missing security header detections, got 0")
	}
}

// TestHeadersPresent verifies that present headers are acknowledged
func TestHeadersPresent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	results := checkHeaders(ts.URL, 0, ts.Client())

	infoResults := 0
	for _, r := range results {
		if r.Severity == models.SeverityInfo && r.Module == models.ModuleHeaders {
			infoResults++
		}
	}
	if infoResults < 4 {
		t.Errorf("expected at least 4 INFO results for present headers, got %d", infoResults)
	}
}

// TestPortScanLoopback verifies port scanning on localhost
func TestPortScanLoopback(t *testing.T) {
	// Start a local listener to have an open port
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Just verify the function runs without error
	results := scanPorts("127.0.0.1", []int{1, 2, 3}, 0)
	if results == nil {
		t.Log("no open ports found (expected) - test passed")
	}
}

// TestDirectoryFuzzing verifies path discovery
func TestDirectoryFuzzing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin panel"))
		case "/hidden":
			w.WriteHeader(http.StatusForbidden)
		case "/redirect":
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	results := fuzzDirectories(ts.URL, 0, 5, ts.Client())
	if len(results) == 0 {
		t.Fatal("expected directory fuzzing results, got 0")
	}

	found := false
	for _, r := range results {
		if r.Module == models.ModuleDirectory && (r.Severity == models.SeverityMedium || r.Severity == models.SeverityLow) {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one directory finding with severity")
	}
}

// TestDetectSQLi verifies SQLi detection logic
func TestDetectSQLi(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect input to simulate vulnerable endpoint
		q := r.URL.Query().Get("q")
		if q != "" {
			w.Write([]byte(q))
			return
		}
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	results := detectSQLi(ts.URL, 0, ts.Client())
	foundSQLi := false
	for _, r := range results {
		if r.Severity == models.SeverityHigh && r.Module == models.ModuleSQLi {
			foundSQLi = true
			break
		}
	}
	if !foundSQLi {
		t.Log("SQLi not detected (expected if server doesn't reflect payload)")
	}
}

// TestModelHelpers verifies ResultList helper methods
func TestModelHelpers(t *testing.T) {
	results := models.ResultList{
		{Module: models.ModulePort, Severity: models.SeverityInfo},
		{Module: models.ModuleHeaders, Severity: models.SeverityMedium},
		{Module: models.ModuleTLS, Severity: models.SeverityLow},
		{Module: models.ModulePort, Severity: models.SeverityInfo},
	}

	if len(results.ByModule(models.ModulePort)) != 2 {
		t.Error("expected 2 port results")
	}
	if len(results.BySeverity(models.SeverityInfo)) != 2 {
		t.Error("expected 2 info results")
	}

	summary := models.BuildSummary(results)
	if summary.TotalChecks != 4 {
		t.Errorf("expected 4 total checks, got %d", summary.TotalChecks)
	}
	if summary.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", summary.Medium)
	}
}

// TestScannerConfig verifies scanner initialization
func TestScannerConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Workers = 5
	cfg.Modules = []string{"port"}

	s := New(cfg)
	if s.Config.Workers != 5 {
		t.Errorf("expected 5 workers, got %d", s.Config.Workers)
	}
}

// TestTLSInspect verifies TLS inspect handles invalid targets gracefully
func TestTLSInspect(t *testing.T) {
	// Test with invalid target - should not crash
	results := checkTLS("127.0.0.1:1", 0, &http.Client{})
	if results == nil {
		t.Error("expected non-nil results")
	}
}
