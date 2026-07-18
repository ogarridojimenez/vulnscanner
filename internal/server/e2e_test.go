package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

func TestE2EScanComplete(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()
	srv := New(store, "", "", 0, "", nil)
	r := srv.engine

	// Start a local target server
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(200)
		fmt.Fprint(w, "<html><body>test</body></html>")
	}))
	defer target.Close()

	// 1. POST /api/scan
	body := fmt.Sprintf(`{"target":"%s","modules":["headers","tech"]}`, target.URL)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/scan", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("scan enqueue: %d %s", w.Code, w.Body.String())
	}
	var scanResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &scanResp)
	scanID := scanResp["scan_id"]
	if scanID == "" {
		t.Fatal("no scan_id returned")
	}

	// 2. Poll GET /api/scans/:id until completed (max 10s)
	var report map[string]interface{}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/api/scans/"+scanID, nil)
		r.ServeHTTP(w, req)
		if w.Code == http.StatusOK {
			json.Unmarshal(w.Body.Bytes(), &report)
			if report["status"] == "completed" {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	if report["status"] != "completed" {
		t.Fatalf("scan not completed: status=%v", report["status"])
	}

	// 3. Verify results
	results, ok := report["results"].([]interface{})
	if !ok || len(results) == 0 {
		t.Fatal("no results in report")
	}

	// 4. Verify summary populated
	summary, ok := report["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("summary missing")
	}
	if summary["total_checks"].(float64) == 0 {
		t.Error("summary total_checks is 0")
	}

	// 5. Verify DB persistence
	n, err := store.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n < 1 {
		t.Error("scan not persisted in DB")
	}

	t.Logf("E2E OK: scan_id=%s, findings=%d, summary=%+v", scanID, len(results), summary)
}
