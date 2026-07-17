package scanner

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// lfiParams are the GET parameter names commonly abused for LFI/RFI.
var lfiParams = []string{"file", "page", "path", "include", "doc", "view"}

// base64SourceRegex matches a plausible base64-encoded source file block
// (long run of base64 alphabet), used to detect source disclosure via
// php://filter base64 encoding.
var base64SourceRegex = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

// detectLFI probes the target for Local/Remote File Inclusion by injecting
// traversal and wrapper payloads into common parameters.
//
// Detection logic:
//   - HIGH: response body contains "/etc/passwd" content ("root:"),
//     Windows "win.ini" content ("[fonts]"), or base64 source code.
//   - MEDIUM: an external http(s):// payload appears echoed/referenced in the
//     response body, suggesting Remote File Inclusion (RFI).
func detectLFI(baseURL string, client *http.Client, timeout time.Duration, payloads []string) []models.Result {
	var results []models.Result

	if len(payloads) == 0 {
		if p, err := loadPayloads("lfi.txt"); err == nil {
			payloads = p
		}
	}

	for _, payload := range payloads {
		pURL := ensureScheme(baseURL)
		pURL = injectParam(pURL, lfiParams, payload)

		req, err := http.NewRequest(http.MethodGet, pURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "VulnScanner/1.0")

		if client == nil {
			client = newHTTPClient(timeout)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body := readBodyString(resp)
		resp.Body.Close()

		severity, reason, isPositive := classifyLFI(body, payload)
		if !isPositive {
			continue
		}

		evidence := buildEvidence(pURL, resp.StatusCode, 0, body, payload)
		results = append(results, models.Result{
			Module:         models.ModuleLFI,
			Name:           "Local/Remote File Inclusion (LFI/RFI)",
			Severity:       severity,
			Description:    fmt.Sprintf("File inclusion vector detected. %s", reason),
			Recommendation: "Validate and allowlist file/path inputs. Never pass user input to include/require or file readers. Disable dangerous wrappers (php://, expect://).",
			Evidence:       evidence,
			Details: map[string]string{
				"payload": payload,
			},
		})
	}

	return results
}

// classifyLFI inspects the response body for LFI/RFI fingerprints.
func classifyLFI(body string, payload string) (models.Severity, string, bool) {
	lower := strings.ToLower(body)

	// HIGH: confirmed local file disclosure.
	if strings.Contains(body, "root:x:") {
		return models.SeverityHigh, "Contents of /etc/passwd ('root:' entry) leaked via LFI.", true
	}
	if strings.Contains(body, "[fonts]") {
		return models.SeverityHigh, "Contents of Windows win.ini ('[fonts]' section) leaked via LFI.", true
	}
	if m := base64SourceRegex.FindString(body); m != "" {
		// Only flag if it looks like encoded PHP/source (contains php tags after decode is
		// expensive; instead require a long base64 run combined with a wrapper payload).
		if strings.Contains(payload, "base64") || strings.Contains(payload, "php://") {
			return models.SeverityHigh, "Base64-encoded source code disclosed (php://filter wrapper).", true
		}
		_ = m
	}

	// MEDIUM: possible RFI — external http(s) host from payload reflected in body.
	if strings.HasPrefix(payload, "http://") || strings.HasPrefix(payload, "https://") {
		if strings.Contains(lower, strings.ToLower(payload)) ||
			strings.Contains(strings.ToLower(payload), extractHost(lower)) {
			return models.SeverityMedium, "External URL payload referenced in response — possible Remote File Inclusion.", true
		}
	}

	return "", "", false
}

// extractHost is a small helper that returns the host portion of a URL-ish
// string (used only for a loose RFI reflection match).
func extractHost(s string) string {
	idx := strings.Index(s, "://")
	if idx == -1 {
		return s
	}
	return s[idx+3:]
}
