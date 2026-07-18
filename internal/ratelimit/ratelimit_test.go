package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAllow(t *testing.T) {
	l := New(3, time.Minute)

	if !l.Allow("test") {
		t.Fatal("first request should be allowed")
	}
	if !l.Allow("test") {
		t.Fatal("second request should be allowed")
	}
	if !l.Allow("test") {
		t.Fatal("third request should be allowed")
	}
	if l.Allow("test") {
		t.Fatal("fourth request should be blocked")
	}
}

func TestDifferentKeys(t *testing.T) {
	l := New(1, time.Minute)

	if !l.Allow("a") {
		t.Fatal("key a should be allowed")
	}
	if l.Allow("a") {
		t.Fatal("key a second should be blocked")
	}
	if !l.Allow("b") {
		t.Fatal("key b should be allowed")
	}
}

func TestReset(t *testing.T) {
	l := New(1, 50*time.Millisecond)

	if !l.Allow("test") {
		t.Fatal("first should be allowed")
	}
	if l.Allow("test") {
		t.Fatal("second should be blocked")
	}

	time.Sleep(60 * time.Millisecond)

	if !l.Allow("test") {
		t.Fatal("after reset should be allowed")
	}
}

func TestMiddleware(t *testing.T) {
	l := New(2, time.Minute)

	handler := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		handler.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	retryAfter := w.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("Retry-After header missing")
	}
}
