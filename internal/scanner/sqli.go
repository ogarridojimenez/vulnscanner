package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// SQLi payloads for basic injection detection
var sqliPayloads = []string{
	"' OR '1'='1",
	"' OR '1'='1' --",
	"' OR '1'='1' #",
	"1' AND '1'='1",
	"' UNION SELECT 1--",
	"1; DROP TABLE users--",
	"\" OR \"1\"=\"1",
	"' OR 1=1--",
	"1' ORDER BY 1--",
	"admin' --",
}

// XSS payloads for basic cross-site scripting detection
var xssPayloads = []string{
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"<svg onload=alert(1)>",
	"\"><script>alert(1)</script>",
	"<body onload=alert(1)>",
	"<iframe src=javascript:alert(1)>",
	"<input onfocus=alert(1) autofocus>",
	"<details open ontoggle=alert(1)>",
	"javascript:alert(1)",
	"'><img src=x onerror=alert(1)>",
}

// detectSQLi checks for basic SQL injection vulnerabilities
func detectSQLi(target string, timeout time.Duration, client *http.Client) []models.Result {
	var results []models.Result

	// Build test URL — append to query param if exists, otherwise add ?q=
	testURL := target
	if !strings.Contains(target, "?") {
		testURL = target + "?q="
	} else {
		testURL = target + "&q="
	}

	for _, payload := range sqliPayloads {
		fullURL := testURL + urlEncode(payload)

		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "VulnScanner/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Read a small portion of the body for reflection check
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		body := string(buf[:n])

		// Check if payload is reflected (basic detection)
		// Also check for SQL error messages in response
		if strings.Contains(body, payload) || hasSQLError(body) {
			evidence := fmt.Sprintf("Payload: %s\nStatus: %d\nURL: %s", payload, resp.StatusCode, fullURL)
			if len(evidence) > 500 {
				evidence = evidence[:500]
			}
			results = append(results, models.Result{
				Module:         models.ModuleSQLi,
				Name:           "Potential SQL Injection",
				Severity:       models.SeverityHigh,
				Description:    fmt.Sprintf("SQL injection vector detected with payload: %s", payload),
				Recommendation: "Use parameterized queries / prepared statements. Validate and sanitize all user input.",
				Evidence:       evidence,
			})
			break // One finding is enough
		}
	}

	if len(results) == 0 {
		results = append(results, models.Result{
			Module:      models.ModuleSQLi,
			Name:        "SQL Injection Check",
			Severity:    models.SeverityInfo,
			Description: "No basic SQL injection vulnerabilities detected.",
		})
	}

	return results
}

// detectXSS checks for basic cross-site scripting vulnerabilities
func detectXSS(target string, timeout time.Duration, client *http.Client) []models.Result {
	var results []models.Result

	// Build test URL
	testURL := target
	if !strings.Contains(target, "?") {
		testURL = target + "?q="
	} else {
		testURL = target + "&q="
	}

	for _, payload := range xssPayloads {
		fullURL := testURL + urlEncode(payload)

		req, err := http.NewRequest("GET", fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "VulnScanner/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		body := string(buf[:n])

		// Check if payload or parts of it are reflected
		reflected := false
		for _, frag := range []string{"<script>", "<img src=", "<svg", "onerror=", "onload="} {
			if strings.Contains(body, frag) && strings.Contains(body, "alert") {
				reflected = true
				break
			}
		}

		if reflected {
			evidence := fmt.Sprintf("Payload: %s\nStatus: %d\nURL: %s", payload, resp.StatusCode, fullURL)
			if len(evidence) > 500 {
				evidence = evidence[:500]
			}
			results = append(results, models.Result{
				Module:         models.ModuleXSS,
				Name:           "Potential XSS Vulnerability",
				Severity:       models.SeverityHigh,
				Description:    fmt.Sprintf("Cross-site scripting vector detected with payload: %s", payload),
				Recommendation: "Encode output properly. Use Content-Security-Policy headers. Validate input.",
				Evidence:       evidence,
			})
			break
		}
	}

	if len(results) == 0 {
		results = append(results, models.Result{
			Module:      models.ModuleXSS,
			Name:        "XSS Check",
			Severity:    models.SeverityInfo,
			Description: "No basic XSS vulnerabilities detected.",
		})
	}

	return results
}

// hasSQLError checks response body for common SQL error messages
func hasSQLError(body string) bool {
	sqlErrors := []string{
		"SQL syntax",
		"mysql_fetch",
		"ORA-",
		"PostgreSQL",
		"SQLite",
		"unclosed quotation mark",
		"Microsoft OLE DB",
		"ODBC Driver",
		"error in your SQL syntax",
		"Warning: mysql",
		"Division by zero in",
		"unexpected T_STRING",
	}
	bodyLower := strings.ToLower(body)
	for _, err := range sqlErrors {
		if strings.Contains(bodyLower, strings.ToLower(err)) {
			return true
		}
	}
	return false
}

// urlEncode performs basic URL encoding for payloads
func urlEncode(s string) string {
	s = strings.ReplaceAll(s, "<", "%3C")
	s = strings.ReplaceAll(s, ">", "%3E")
	s = strings.ReplaceAll(s, "\"", "%22")
	s = strings.ReplaceAll(s, "'", "%27")
	s = strings.ReplaceAll(s, " ", "+")
	return s
}
