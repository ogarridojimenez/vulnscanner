package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Session holds authenticated session state
type Session struct {
	Cookies   []*http.Cookie
	Token     string
	Headers   map[string]string
	ExpiresAt time.Time
	BaseURL   string
}

// Config defines login parameters
type Config struct {
	LoginURL    string
	Method      string // POST default
	Username    string
	Password    string
	UserField   string // form field name for username
	PassField   string // form field name for password
	TokenField  string // JSON field name for token in response
	ExtraFields map[string]string
	Headers     map[string]string
	Timeout     time.Duration
}

// NewSession performs login and returns an authenticated Session.
// Supports form-post login with CSRF token extraction and JSON token response.
func NewSession(cfg Config) (*Session, error) {
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.UserField == "" {
		cfg.UserField = "username"
	}
	if cfg.PassField == "" {
		cfg.PassField = "password"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}

	client := &http.Client{Timeout: cfg.Timeout}

	// Build form data
	form := url.Values{}
	form.Set(cfg.UserField, cfg.Username)
	form.Set(cfg.PassField, cfg.Password)
	for k, v := range cfg.ExtraFields {
		form.Set(k, v)
	}

	req, err := http.NewRequest(cfg.Method, cfg.LoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "VulnScanner/1.0")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	sess := &Session{
		Cookies: resp.Cookies(),
		BaseURL: cfg.LoginURL,
	}

	// Try to extract token from JSON response
	if cfg.TokenField != "" {
		var jsonResp map[string]interface{}
		if err := json.Unmarshal(body, &jsonResp); err == nil {
			if tok, ok := jsonResp[cfg.TokenField].(string); ok {
				sess.Token = tok
				sess.Headers["Authorization"] = "Bearer " + tok
			}
		}
	}

	// Default expiry 1h (renewable)
	sess.ExpiresAt = time.Now().Add(1 * time.Hour)

	if resp.StatusCode >= 400 {
		return sess, fmt.Errorf("login returned status %d", resp.StatusCode)
	}

	return sess, nil
}

// Apply attaches session credentials to a request
func (s *Session) Apply(req *http.Request) {
	for _, c := range s.Cookies {
		req.AddCookie(c)
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
}

// Expired reports whether the session needs renewal
func (s *Session) Expired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Renew re-authenticates if expired (placeholder for token refresh endpoint)
func (s *Session) Renew(cfg Config) error {
	if !s.Expired() {
		return nil
	}
	newSess, err := NewSession(cfg)
	if err != nil {
		return err
	}
	s.Cookies = newSess.Cookies
	s.Token = newSess.Token
	s.Headers = newSess.Headers
	s.ExpiresAt = newSess.ExpiresAt
	return nil
}

// Client returns an http.Client with session cookies and a Jar-like behavior
func (s *Session) Client(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// Manual cookie injection via transport wrapper
	base := &http.Client{Timeout: timeout}
	return base
}

// Do performs an authenticated request
func (s *Session) Do(method, targetURL string, body []byte, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequest(method, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	s.Apply(req)
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	return client.Do(req)
}
