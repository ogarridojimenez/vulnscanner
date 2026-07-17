package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetectSSRF(t *testing.T) {
	// Mock server that reflects SSRF attempt
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("url")
		if q == "http://169.254.169.254/" {
			w.Write([]byte("ami-id: fake-instance"))
		} else {
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	payloads, err := loadPayloads("../rules/ssrf.txt")
	if err != nil || len(payloads) == 0 {
		t.Fatal("no SSRF payloads loaded:", err)
	}
	results := detectSSRF(srv.URL, &http.Client{}, defaultTimeout, payloads)
	if len(results) == 0 {
		t.Error("expected at least one SSRF result")
	}
}

func TestDetectLFI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		if strings.Contains(f, "etc/passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
		} else {
			w.Write([]byte("not found"))
		}
	}))
	defer srv.Close()

	payloads, err := loadPayloads("../rules/lfi.txt")
	if err != nil || len(payloads) == 0 {
		t.Fatal("no LFI payloads loaded:", err)
	}
	results := detectLFI(srv.URL, &http.Client{}, defaultTimeout, payloads)
	if len(results) == 0 {
		t.Error("expected at least one LFI result")
	}
}

func TestDetectRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		red := r.URL.Query().Get("redirect")
		if red == "//evil.com" {
			http.Redirect(w, r, "https://evil.com", http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	payloads, err := loadPayloads("../rules/redirect.txt")
	if err != nil || len(payloads) == 0 {
		t.Fatal("no redirect payloads loaded:", err)
	}
	results := detectRedirect(srv.URL, &http.Client{}, defaultTimeout, payloads)
	if len(results) == 0 {
		t.Error("expected at least one open redirect result")
	}
}

func TestCheckCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Secure: false, HttpOnly: false})
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	results := checkCookies(srv.URL, &http.Client{}, defaultTimeout)
	if len(results) == 0 {
		t.Error("expected cookie findings")
	}
}

func TestDetectTech(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.Write([]byte(`<html><head><meta name="generator" content="WordPress"></head><body></body></html>`))
	}))
	defer srv.Close()

	results := detectTech(srv.URL, &http.Client{}, defaultTimeout)
	if len(results) == 0 {
		t.Error("expected tech detection results")
	}
}

func TestEnumSubdomains(t *testing.T) {
	// We don't do live DNS; just verify the function doesn't panic on empty
	results := enumSubdomains("example.com", []string{"nonexistent123456"})
	// May be empty or have result; just ensure no panic
	_ = results
}
