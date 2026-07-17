package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// redirectParams are the GET parameter names commonly abused for open redirects.
var redirectParams = []string{"redirect", "url", "next", "return", "to", "target"}

// detectRedirect probes the target for Open Redirect vulnerabilities by injecting
// external/controlled URLs into redirect parameters and inspecting the Location
// header of the redirect response.
//
// A redirect is reported (MEDIUM) when the server answers with a 3xx status and
// the Location header points to a host that is NOT the original target host or
// one of its subdomains.
func detectRedirect(baseURL string, client *http.Client, timeout time.Duration, payloads []string) []models.Result {
	var results []models.Result

	if len(payloads) == 0 {
		if p, err := loadPayloads("redirect.txt"); err == nil {
			payloads = p
		}
	}

	// Determine the canonical target host for external-domain comparison.
	targetHost := ""
	if u, err := url.Parse(ensureScheme(baseURL)); err == nil {
		targetHost = u.Hostname()
	}

	for _, payload := range payloads {
		pURL := ensureScheme(baseURL)
		pURL = injectParam(pURL, redirectParams, payload)

		// Build a client that does NOT follow redirects so we can capture the
		// Location header directly. Reuse the caller's client transport/timeout
		// if provided.
		probeClient := client
		if probeClient == nil {
			probeClient = newHTTPClient(timeout)
		} else {
			probeClient = &http.Client{
				Timeout:   probeClient.Timeout,
				Transport: probeClient.Transport,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse // capture redirect, don't follow
				},
			}
		}

		req, err := http.NewRequest(http.MethodGet, pURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "VulnScanner/1.0")

		resp, err := probeClient.Do(req)
		if err != nil {
			// A redirect error (ErrNoLocation / "redirect") still yields a resp
			// in many cases; ignore hard network failures.
			continue
		}

		status := resp.StatusCode
		location := resp.Header.Get("Location")
		resp.Body.Close()

		if !isRedirectStatus(status) || location == "" {
			continue
		}

		if isExternalRedirect(location, targetHost) {
			evidence := buildEvidence(pURL, status, 0, "Location: "+location, payload)
			results = append(results, models.Result{
				Module:         models.ModuleRedirect,
				Name:           "Open Redirect",
				Severity:       models.SeverityMedium,
				Description:    fmt.Sprintf("Redirect parameter accepted an off-domain target (%s).", location),
				Recommendation: "Validate redirect targets against an allowlist of internal hosts. Never redirect to user-supplied URLs without validation.",
				Evidence:       evidence,
				Details: map[string]string{
					"payload":  payload,
					"location": location,
					"status":   fmt.Sprintf("%d", status),
				},
			})
		}
	}

	return results
}

// isRedirectStatus reports whether the status code is a redirect (3xx).
func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, // 301
		http.StatusFound,             // 302
		http.StatusSeeOther,          // 303
		http.StatusTemporaryRedirect, // 307
		http.StatusPermanentRedirect: // 308
		return true
	}
	return false
}

// isExternalRedirect determines whether the Location points to a host that is
// not the target host nor a subdomain of it.
func isExternalRedirect(location, targetHost string) bool {
	loc, err := url.Parse(location)
	if err != nil {
		// Relative location without scheme/host cannot be an external redirect.
		return false
	}

	// Absolute URL with a host?
	if loc.Host != "" {
		return !isSameOrSubdomain(loc.Hostname(), targetHost)
	}

	// Scheme-relative (//evil.com) URLs.
	if strings.HasPrefix(location, "//") {
		host := strings.SplitN(strings.TrimPrefix(location, "//"), "/", 2)[0]
		return !isSameOrSubdomain(host, targetHost)
	}

	// Otherwise it is a path/relative redirect — internal.
	return false
}

// isSameOrSubdomain reports whether candidate is the same host as base or a
// subdomain of it. An empty base disables the check (treats all as external).
func isSameOrSubdomain(candidate, base string) bool {
	if base == "" {
		return false
	}
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	base = strings.ToLower(strings.TrimSpace(base))

	if candidate == base {
		return true
	}
	return strings.HasSuffix(candidate, "."+base)
}
