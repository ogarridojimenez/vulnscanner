package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

func TestUIAuthEnabled(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()

	srv := New(store, "secret", "")
	r := srv.engine

	// Dashboard without cookie -> redirect to /login
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/dashboard", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "/login") {
		t.Errorf("expected redirect to /login, got %d -> %s", w.Code, w.Header().Get("Location"))
	}

	// Login with wrong password -> no cookie
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("POST", "/login", strings.NewReader("password=wrong"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w2, req2)
	if w2.Result().Cookies() != nil && len(w2.Result().Cookies()) > 0 {
		t.Errorf("wrong password should not set cookie")
	}

	// Login with correct password -> sets cookie
	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest("POST", "/login", strings.NewReader("password=secret"))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w3, req3)
	cookies := w3.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie after correct login")
	}
	tok := cookies[0].Value

	// Dashboard with valid cookie -> 200
	w4 := httptest.NewRecorder()
	req4, _ := http.NewRequest("GET", "/dashboard", nil)
	req4.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Errorf("dashboard with valid cookie: expected 200, got %d", w4.Code)
	}

	// Logout invalidates token
	w5 := httptest.NewRecorder()
	req5, _ := http.NewRequest("GET", "/logout", nil)
	req5.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	r.ServeHTTP(w5, req5)

	w6 := httptest.NewRecorder()
	req6, _ := http.NewRequest("GET", "/dashboard", nil)
	req6.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	r.ServeHTTP(w6, req6)
	if w6.Code != http.StatusFound {
		t.Errorf("after logout, dashboard should redirect, got %d", w6.Code)
	}
}

func TestUIAuthDisabled(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()

	srv := New(store, "", "")
	r := srv.engine

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/dashboard", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("auth disabled: dashboard should be 200, got %d", w.Code)
	}
}
