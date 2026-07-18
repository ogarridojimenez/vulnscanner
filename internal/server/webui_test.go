package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

func TestWebUIRoutes(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()

	srv := New(store, "", "", 0, "")
	r := srv.engine

	routes := []struct {
		path string
		code int
	}{
		{"/", http.StatusOK},
		{"/dashboard", http.StatusOK},
		{"/scan/new", http.StatusOK},
		{"/scan/abc123", http.StatusOK},
	}

	for _, rt := range routes {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", rt.path, nil)
		r.ServeHTTP(w, req)
		if w.Code != rt.code {
			t.Errorf("route %s: expected %d, got %d", rt.path, rt.code, w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if ct[:9] != "text/html" {
			t.Errorf("route %s: expected text/html, got %q", rt.path, ct)
		}
	}
}
