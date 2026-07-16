package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/config"
	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// checkHeaders performs a GET request and inspects security-related response headers.
func checkHeaders(targetURL string, timeout time.Duration, client *http.Client) []models.Result {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	url := ensureScheme(targetURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return []models.Result{{
			Module:      models.ModuleHeaders,
			Name:        "Invalid URL",
			Severity:    models.SeverityLow,
			Description: fmt.Sprintf("Could not create request for %s: %v", url, err),
		}}
	}
	req.Header.Set("User-Agent", "VulnScanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return []models.Result{{
			Module:      models.ModuleHeaders,
			Name:        "Request Failed",
			Severity:    models.SeverityLow,
			Description: fmt.Sprintf("GET %s failed: %v", url, err),
		}}
	}
	defer resp.Body.Close()

	results := make([]models.Result, 0)

	// Check each recommended security header.
	for _, hdr := range config.SecurityHeaders {
		val := resp.Header.Get(hdr)
		if val == "" {
			results = append(results, models.Result{
				Module:         models.ModuleHeaders,
				Name:           fmt.Sprintf("Missing Security Header: %s", hdr),
				Severity:       models.SeverityMedium,
				Description:    fmt.Sprintf("Security header %s is missing from the response.", hdr),
				Recommendation: fmt.Sprintf("Add the %s header to improve security posture.", hdr),
				Details: map[string]string{
					"header": hdr,
				},
			})
		} else {
			results = append(results, models.Result{
				Module:      models.ModuleHeaders,
				Name:        fmt.Sprintf("Security Header Present: %s", hdr),
				Severity:    models.SeverityInfo,
				Description: fmt.Sprintf("Security header %s is present: %s", hdr, val),
				Evidence:    val,
				Details: map[string]string{
					"header": hdr,
					"value":  val,
				},
			})
		}
	}

	// Check for information disclosure via Server header.
	if serverVal := resp.Header.Get("Server"); serverVal != "" {
		results = append(results, models.Result{
			Module:         models.ModuleHeaders,
			Name:           "Server Header Disclosure",
			Severity:       models.SeverityMedium,
			Description:    fmt.Sprintf("Server header discloses server software: %s", serverVal),
			Recommendation: "Remove or obfuscate the Server header to reduce information leakage.",
			Evidence:       serverVal,
			Details: map[string]string{
				"header": "Server",
				"value":  serverVal,
			},
		})
	}

	// Check for information disclosure via X-Powered-By header.
	if xpbVal := resp.Header.Get("X-Powered-By"); xpbVal != "" {
		results = append(results, models.Result{
			Module:         models.ModuleHeaders,
			Name:           "X-Powered-By Header Disclosure",
			Severity:       models.SeverityMedium,
			Description:    fmt.Sprintf("X-Powered-By header discloses technology: %s", xpbVal),
			Recommendation: "Remove the X-Powered-By header to reduce information leakage.",
			Evidence:       xpbVal,
			Details: map[string]string{
				"header": "X-Powered-By",
				"value":  xpbVal,
			},
		})
	}

	return results
}

// ensureScheme prepends https:// if no scheme is present.
func ensureScheme(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "https://" + target
}
