package scanner

import (
	"testing"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/config"
	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

func BenchmarkScanConcurrency(b *testing.B) {
	cfg := config.DefaultConfig()
	cfg.Workers = 20
	cfg.Timeout = 5 * time.Second
	cfg.Modules = []string{"port", "headers"}
	sc := New(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = sc.Run("http://testphp.vulnweb.com")
	}
}

func BenchmarkLoadPayloads(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = loadPayloads("ssrf")
	}
}

func TestModuleResultShape(t *testing.T) {
	r := models.Result{
		Module:   models.ModuleSSRF,
		Severity: models.SeverityCritical,
		Name:     "SSRF test",
	}
	if r.Module != models.ModuleSSRF {
		t.Error("module mismatch")
	}
	if r.Severity != models.SeverityCritical {
		t.Error("severity mismatch")
	}
}
