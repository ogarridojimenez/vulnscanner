package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// ssrfMarkers are fingerprints of cloud metadata / local file disclosure
// that indicate a successful SSRF.
var ssrfMarkers = []string{
	"ami-id",
	"instance-id",
	"instanceType",
	"latest/meta-data",
	"computeMetadata",
	"metadata.google.internal",
	"iqn.", // iSCSI initiator (openstack/cloud)
}

// detectSSRF probes the target for Server-Side Request Forgery by injecting
// internal/cloud URLs into GET parameters and inspecting the response.
//
// Detection logic:
//   - CRITICAL: response body contains cloud metadata markers
//     (e.g. "ami-id", "instance-id") -> metadata service reached
//   - HIGH: a file:// payload was reflected / local file content read
//   - MEDIUM: response time exceeded 5s -> possible blind SSRF (time-based)
func detectSSRF(baseURL string, client *http.Client, timeout time.Duration, payloads []string) []models.Result {
	var results []models.Result

	if len(payloads) == 0 {
		if p, err := loadPayloads("ssrf.txt"); err == nil {
			payloads = p
		}
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	params := []string{"url", "redirect", "path", "next", "file", "doc", "uri", "target"}

	for _, payload := range payloads {
		pURL := ensureScheme(baseURL)
		pURL = injectParam(pURL, params, payload)

		req, err := http.NewRequest(http.MethodGet, pURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "VulnScanner/1.0")

		if client == nil {
			client = &http.Client{Timeout: timeout}
		}

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)
		if err != nil {
			continue
		}

		body := readBodyString(resp)
		resp.Body.Close()

		severity, reason, isPositive := classifySSRF(body, elapsed, payload)
		if !isPositive {
			continue
		}

		evidence := buildEvidence(pURL, resp.StatusCode, elapsed, body, payload)
		results = append(results, models.Result{
			Module:         models.ModuleSSRF,
			Name:           "Server-Side Request Forgery (SSRF)",
			Severity:       severity,
			Description:    fmt.Sprintf("SSRF vector detected. %s", reason),
			Recommendation: "Validate and allowlist outbound URLs. Block access to link-local (169.254.169.254) and internal address ranges. Avoid passing user input directly to URL fetchers.",
			Evidence:       evidence,
			Details: map[string]string{
				"payload":          payload,
				"response_time_ms": fmt.Sprintf("%d", elapsed.Milliseconds()),
			},
		})
	}

	return results
}

// classifySSRF inspects the response body and timing to assign a severity.
func classifySSRF(body string, elapsed time.Duration, payload string) (models.Severity, string, bool) {
	lower := strings.ToLower(body)

	// CRITICAL: cloud metadata reached.
	for _, m := range ssrfMarkers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return models.SeverityCritical,
				fmt.Sprintf("Cloud metadata fingerprint '%s' found in response body.", m), true
		}
	}

	// HIGH: local file read via file:// payload.
	if strings.HasPrefix(payload, "file://") {
		if strings.Contains(body, "root:x:") || strings.Contains(body, "[fonts]") ||
			strings.Contains(body, "bin/bash") || strings.Contains(body, "for 16-bit app support") {
			return models.SeverityHigh,
				"Local file content was disclosed in the response (file:// payload).", true
		}
	}

	// MEDIUM: possible blind SSRF via timing (only when request took long).
	if elapsed > 5*time.Second {
		return models.SeverityMedium,
			fmt.Sprintf("Response took %s (>5s) suggesting a possible blind/time-based SSRF.", elapsed), true
	}

	return "", "", false
}
