package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// detectTech performs a GET request and attempts to identify the technologies
// and frameworks used by the target by inspecting HTML, script sources and
// response headers.
func detectTech(baseURL string, client *http.Client, timeout time.Duration) []models.Result {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	url := ensureScheme(baseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return []models.Result{{
			Module:      models.Module("tech"),
			Name:        "Invalid URL",
			Severity:    models.SeverityLow,
			Description: fmt.Sprintf("Could not create request for %s: %v", url, err),
		}}
	}
	req.Header.Set("User-Agent", "VulnScanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return []models.Result{{
			Module:      models.Module("tech"),
			Name:        "Request Failed",
			Severity:    models.SeverityLow,
			Description: fmt.Sprintf("GET %s failed: %v", url, err),
		}}
	}
	defer resp.Body.Close()

	detected := make(map[string]string) // name -> evidence

	// Parse HTML with goquery.
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err == nil {
		// <meta name="generator" content="..."> -> WordPress, Drupal, etc.
		doc.Find("meta").Each(func(_ int, s *goquery.Selection) {
			if name, _ := s.Attr("name"); strings.EqualFold(name, "generator") {
				if content, ok := s.Attr("content"); ok && content != "" {
					detected[normalizeTech(content)] = fmt.Sprintf("meta generator: %s", content)
				}
			}
		})

		// <script src="..."> based detection.
		doc.Find("script").Each(func(_ int, s *goquery.Selection) {
			if src, ok := s.Attr("src"); ok && src != "" {
				lower := strings.ToLower(src)
				switch {
				case strings.Contains(lower, "/wp-includes/") || strings.Contains(lower, "/wp-content/"):
					detected["WordPress"] = fmt.Sprintf("script src: %s", src)
				case strings.Contains(lower, "/jquery/"):
					detected["jQuery"] = fmt.Sprintf("script src: %s", src)
				case strings.Contains(lower, "/react/") || strings.Contains(lower, "react"):
					detected["React"] = fmt.Sprintf("script src: %s", src)
				case strings.Contains(lower, "/angular/") || strings.Contains(lower, "angular"):
					detected["Angular"] = fmt.Sprintf("script src: %s", src)
				case strings.Contains(lower, "/vue/") || strings.Contains(lower, "vue"):
					detected["Vue"] = fmt.Sprintf("script src: %s", src)
				case strings.Contains(lower, "/bootstrap/"):
					detected["Bootstrap"] = fmt.Sprintf("script src: %s", src)
				}
			}
		})

		// Inline/class hints for Tailwind.
		if doc.Find(".tailwind, .tw-").Length() > 0 || strings.Contains(doc.Text(), "tailwind") {
			detected["Tailwind"] = "class/utility hints"
		}
	}

	// Header-based detection.
	headerTech := map[string]string{
		"X-Powered-By": "",
		"Server":       "",
	}
	for h := range headerTech {
		if v := resp.Header.Get(h); v != "" {
			detected[normalizeTech(v)] = fmt.Sprintf("header %s: %s", h, v)
		}
	}
	if v := resp.Header.Get("X-AspNet-Version"); v != "" {
		detected["ASP.NET"] = fmt.Sprintf("header X-AspNet-Version: %s", v)
	}
	if v := resp.Header.Get("X-Drupal-Cache"); v != "" {
		detected["Drupal"] = fmt.Sprintf("header X-Drupal-Cache: %s", v)
	}

	// Framework keyword search in server/headers for common stacks.
	allHeaders := strings.ToLower(fmt.Sprintf("%v", resp.Header))
	frameworkHints := map[string][]string{
		"Joomla":    {"joomla"},
		"Django":    {"django", "csrftoken"},
		"Rails":     {"rails", "ruby"},
		"Express":   {"express"},
		"Laravel":   {"laravel"},
		"Spring":    {"spring"},
		"WordPress": {"wordpress", "wp-"},
		"Drupal":    {"drupal"},
		"Vue":       {"vue"},
		"React":     {"react"},
		"Angular":   {"angular"},
		"jQuery":    {"jquery"},
		"Bootstrap": {"bootstrap"},
		"Tailwind":  {"tailwind"},
	}
	for fw, kws := range frameworkHints {
		for _, kw := range kws {
			if strings.Contains(allHeaders, kw) {
				if _, ok := detected[fw]; !ok {
					detected[fw] = fmt.Sprintf("header keyword: %s", kw)
				}
			}
		}
	}

	results := make([]models.Result, 0)
	for name, evidence := range detected {
		results = append(results, models.Result{
			Module:      models.Module("tech"),
			Name:        fmt.Sprintf("Technology Detected: %s", name),
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Detected technology/framework: %s", name),
			Evidence:    evidence,
			Details: map[string]string{
				"technology": name,
			},
		})
	}

	if len(results) == 0 {
		results = append(results, models.Result{
			Module:      models.Module("tech"),
			Name:        "No Technologies Identified",
			Severity:    models.SeverityInfo,
			Description: "No technologies or frameworks could be identified from the response.",
		})
	}

	return results
}

// normalizeTech maps a raw generator/header string to a canonical framework name.
func normalizeTech(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "wordpress"):
		return "WordPress"
	case strings.Contains(lower, "drupal"):
		return "Drupal"
	case strings.Contains(lower, "joomla"):
		return "Joomla"
	case strings.Contains(lower, "django"):
		return "Django"
	case strings.Contains(lower, "rails") || strings.Contains(lower, "ruby"):
		return "Rails"
	case strings.Contains(lower, "express") || strings.Contains(lower, "node"):
		return "Express"
	case strings.Contains(lower, "laravel"):
		return "Laravel"
	case strings.Contains(lower, "spring"):
		return "Spring"
	case strings.Contains(lower, "jquery"):
		return "jQuery"
	case strings.Contains(lower, "react"):
		return "React"
	case strings.Contains(lower, "angular"):
		return "Angular"
	case strings.Contains(lower, "vue"):
		return "Vue"
	case strings.Contains(lower, "bootstrap"):
		return "Bootstrap"
	case strings.Contains(lower, "tailwind"):
		return "Tailwind"
	default:
		return strings.TrimSpace(raw)
	}
}
