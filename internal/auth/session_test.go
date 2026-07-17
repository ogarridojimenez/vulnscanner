package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewSessionFormLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			w.WriteHeader(404)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}
		if r.Form.Get("username") == "admin" && r.Form.Get("password") == "secret" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
			w.WriteHeader(200)
			w.Write([]byte("ok"))
		} else {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()

	sess, err := NewSession(Config{
		LoginURL: srv.URL + "/login",
		Username: "admin",
		Password: "secret",
		Timeout:  5e9,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sess.Cookies) == 0 {
		t.Error("expected cookies from login")
	}
	if sess.Expired() {
		t.Error("session should not be expired immediately")
	}
}

func TestNewSessionJSONToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token":"jwt-xyz","user":"admin"}`))
	}))
	defer srv.Close()

	sess, err := NewSession(Config{
		LoginURL:   srv.URL,
		Username:   "admin",
		Password:   "x",
		TokenField: "token",
		Timeout:    5e9,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.Token != "jwt-xyz" {
		t.Errorf("expected token 'jwt-xyz', got %q", sess.Token)
	}
	if !strings.Contains(sess.Headers["Authorization"], "Bearer") {
		t.Error("expected Authorization header with Bearer token")
	}
}

func TestSessionApply(t *testing.T) {
	sess := &Session{
		Cookies: []*http.Cookie{{Name: "sid", Value: "999"}},
		Headers: map[string]string{"X-Custom": "yes"},
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	sess.Apply(req)
	if req.Header.Get("X-Custom") != "yes" {
		t.Error("header not applied")
	}
	if c, err := req.Cookie("sid"); err != nil || c.Value != "999" {
		t.Error("cookie not applied")
	}
}
