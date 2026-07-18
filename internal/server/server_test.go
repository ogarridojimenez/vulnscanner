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

	srv := New(store, "", "", 0)
	r := srv.engine
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("health status: %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status field: %q", resp["status"])
	}
	if resp["uptime"] == nil || resp["uptime"] == "" {
		t.Error("missing uptime")
	}
	if resp["db_status"] != "ok" {
		t.Errorf("db_status: %q", resp["db_status"])
	}
}

func TestScanEnqueue(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()
	srv := New(store, "", "", 0)
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

func TestAPIAuthRequired(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()
	srv := New(store, "", "my-secret-token", 0)
	r := srv.engine

	// No token → 401
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no token should be 401, got %d", w.Code)
	}

	// Wrong token → 401
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/scans", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token should be 401, got %d", w.Code)
	}

	// Correct token → 200
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/scans", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("correct token should be 200, got %d", w.Code)
	}
}

func TestAPIAuthDisabled(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()
	srv := New(store, "", "", 0) // no apiToken
	r := srv.engine

	// No token → 200 (auth disabled)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("no auth should be 200, got %d", w.Code)
	}
}
