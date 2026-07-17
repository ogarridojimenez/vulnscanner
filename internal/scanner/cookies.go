package scanner

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// checkCookies performs a GET request and inspects the Set-Cookie flags
// (Secure, HttpOnly, SameSite) for each cookie returned by the target.
func checkCookies(baseURL string, client *http.Client, timeout time.Duration) []models.Result {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	url := ensureScheme(baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return []models.Result{{
			Module:      models.Module("cookies"),
			Name:        "Invalid URL",
			Severity:    models.SeverityLow,
			Description: fmt.Sprintf("Could not create request for %s: %v", url, err),
		}}
	}
	req.Header.Set("User-Agent", "VulnScanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return []models.Result{{
			Module:      models.Module("cookies"),
			Name:        "Request Failed",
			Severity:    models.SeverityLow,
			Description: fmt.Sprintf("GET %s failed: %v", url, err),
		}}
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()

	// No cookies set -> INFO result.
	if len(cookies) == 0 {
		return []models.Result{{
			Module:      models.Module("cookies"),
			Name:        "No Cookies Set",
			Severity:    models.SeverityInfo,
			Description: "The target did not set any cookies in the response.",
			Evidence:    fmt.Sprintf("GET %s -> %d", url, resp.StatusCode),
		}}
	}

	results := make([]models.Result, 0)
	info := true

	for _, c := range cookies {
		// Secure flag
		if !c.Secure {
			info = false
			results = append(results, models.Result{
				Module:         models.Module("cookies"),
				Name:           fmt.Sprintf("Insecure Cookie (no Secure): %s", c.Name),
				Severity:       models.SeverityMedium,
				Description:    fmt.Sprintf("Cookie '%s' is set without the Secure flag and may be transmitted over plain HTTP and intercepted.", c.Name),
				Recommendation: "Set the Secure flag on all sensitive cookies so they are only sent over HTTPS.",
				Evidence:       fmt.Sprintf("Cookie: %s; Secure=false", c.Name),
				Details: map[string]string{
					"cookie": c.Name,
					"flag":   "Secure",
				},
			})
		}

		// HttpOnly flag
		if !c.HttpOnly {
			info = false
			results = append(results, models.Result{
				Module:         models.Module("cookies"),
				Name:           fmt.Sprintf("Cookie without HttpOnly: %s", c.Name),
				Severity:       models.SeverityMedium,
				Description:    fmt.Sprintf("Cookie '%s' is set without the HttpOnly flag and is accessible to JavaScript (vulnerable to XSS cookie theft).", c.Name),
				Recommendation: "Set the HttpOnly flag on session/credential cookies to prevent client-side script access.",
				Evidence:       fmt.Sprintf("Cookie: %s; HttpOnly=false", c.Name),
				Details: map[string]string{
					"cookie": c.Name,
					"flag":   "HttpOnly",
				},
			})
		}

		// SameSite flag
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == http.SameSiteDefaultMode {
			info = false
			results = append(results, models.Result{
				Module:         models.Module("cookies"),
				Name:           fmt.Sprintf("Weak SameSite Cookie: %s", c.Name),
				Severity:       models.SeverityLow,
				Description:    fmt.Sprintf("Cookie '%s' has SameSite=None or is unset, increasing CSRF risk.", c.Name),
				Recommendation: "Set SameSite=Lax or SameSite=Strict on cookies unless cross-site usage is required.",
				Evidence:       fmt.Sprintf("Cookie: %s; SameSite=%s", c.Name, sameSiteString(c.SameSite)),
				Details: map[string]string{
					"cookie": c.Name,
					"flag":   "SameSite",
				},
			})
		}
	}

	if info && len(results) == 0 {
		results = append(results, models.Result{
			Module:      models.Module("cookies"),
			Name:        "Cookies Properly Hardened",
			Severity:    models.SeverityInfo,
			Description: "All cookies examined have Secure, HttpOnly and an explicit SameSite attribute set.",
			Evidence:    fmt.Sprintf("%d cookie(s) inspected", len(cookies)),
		})
	}

	return results
}

// sameSiteString returns a human-readable name for an http.SameSite value.
func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteDefaultMode:
		return "Default/Unset"
	case http.SameSiteNoneMode:
		return "None"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	default:
		return "Unknown"
	}
}
