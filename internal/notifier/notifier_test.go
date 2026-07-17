package notifier

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

func TestNotifyWebhook(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.WriteHeader(200)
	}))
	defer srv.Close()

	report := &models.ScanReport{
		Target:  "http://x.com",
		Results: []models.Result{{Severity: models.SeverityCritical, Module: models.ModuleSSRF}},
		Status:  "completed",
	}
	cfg := Config{SlackWebhook: srv.URL}
	if err := Notify(cfg, report); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if gotBody == "" {
		t.Error("no body received by webhook")
	}
}

func TestFormatMessage(t *testing.T) {
	report := &models.ScanReport{
		Target: "http://y.com",
		Results: []models.Result{
			{Severity: models.SeverityCritical},
			{Severity: models.SeverityHigh},
			{Severity: models.SeverityHigh},
		},
	}
	msg := formatMessage(report)
	if msg == "" {
		t.Error("empty message")
	}
}
