package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// injectParam appends a parameter to the URL, trying each candidate parameter
// name in order. It injects into the FIRST candidate that is not already present
// in the query string. If none of the candidates exist, it injects using the
// first one. Returns the resulting URL with the payload URL-encoded.
func injectParam(baseURL string, params []string, payload string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	q := u.Query()
	chosen := params[0]
	for _, p := range params {
		if _, ok := q[p]; !ok {
			chosen = p
			break
		}
	}

	q.Set(chosen, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// readBodyString reads up to 64KB of the response body for inspection.
func readBodyString(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	if n == 0 {
		// fallback: try again (some servers send in chunks)
		n, _ = resp.Body.Read(buf)
	}
	return string(buf[:n])
}

// buildEvidence assembles a concise evidence block for a finding.
func buildEvidence(testURL string, status int, elapsed time.Duration, body, payload string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "URL: %s\n", testURL)
	fmt.Fprintf(&b, "Status: %d\n", status)
	if elapsed > 0 {
		fmt.Fprintf(&b, "Elapsed: %s\n", elapsed)
	}
	fmt.Fprintf(&b, "Payload: %s\n", payload)
	body = strings.TrimSpace(body)
	if body != "" {
		if len(body) > 400 {
			body = body[:400]
		}
		fmt.Fprintf(&b, "Body snippet: %s\n", body)
	}
	return b.String()
}

// newHTTPClient returns an HTTP client with a sane timeout and TLS verification
// disabled (mirrors the orchestrator's client behavior for scanning).
func newHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig: insecureTLSConfig(),
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}

// insecureTLSConfig returns a TLS config that skips certificate verification,
// matching the orchestrator's scanner client.
func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// drainBody fully consumes and discards a response body to allow connection reuse.
func drainBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
}
