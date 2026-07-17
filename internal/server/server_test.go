package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

func TestHealthEndpoint(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()

	srv := New(store)
	r := srv.engine
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("health status: %d", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status field: %q", resp["status"])
	}
}

func TestScanEnqueue(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()

	srv := New(store)
	r := srv.engine
	body := `{"target":"http://testphp.vulnweb.com","modules":["headers"]}`
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/scan", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("scan enqueue status: %d body=%s", w.Code, w.Body.String())
	}
}
