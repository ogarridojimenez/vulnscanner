package scanner

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/config"
	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// fuzzDirectories performs directory/file enumeration by requesting common paths.
func fuzzDirectories(baseURL string, timeout time.Duration, concurrency int, client *http.Client) []models.Result {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if concurrency <= 0 {
		concurrency = 10
	}

	url := ensureScheme(baseURL)
	paths := config.CommonPaths

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []models.Result
		sem     = make(chan struct{}, concurrency)
	)

	for _, p := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			targetURL := url + path
			req, err := http.NewRequest(http.MethodGet, targetURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "VulnScanner/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			r := classifyPath(path, targetURL, resp.StatusCode)
			if r != nil {
				mu.Lock()
				results = append(results, *r)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()
	return results
}

// classifyPath creates a Result based on the HTTP status code for a discovered path.
func classifyPath(path, fullURL string, statusCode int) *models.Result {
	switch {
	case statusCode == 200:
		return &models.Result{
			Module:      models.ModuleDirectory,
			Name:        fmt.Sprintf("Directory Found: %s", path),
			Severity:    models.SeverityMedium,
			Description: fmt.Sprintf("Path %s returned HTTP %d — resource exists.", path, statusCode),
			Evidence:    fmt.Sprintf("GET %s -> %d", fullURL, statusCode),
			Details: map[string]string{
				"path":        path,
				"url":         fullURL,
				"status_code": fmt.Sprintf("%d", statusCode),
			},
		}

	case statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308:
		return &models.Result{
			Module:      models.ModuleDirectory,
			Name:        fmt.Sprintf("Redirect: %s", path),
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Path %s returned HTTP %d (redirect).", path, statusCode),
			Evidence:    fmt.Sprintf("GET %s -> %d", fullURL, statusCode),
			Details: map[string]string{
				"path":        path,
				"url":         fullURL,
				"status_code": fmt.Sprintf("%d", statusCode),
			},
		}

	case statusCode == 401 || statusCode == 403:
		return &models.Result{
			Module:      models.ModuleDirectory,
			Name:        fmt.Sprintf("Forbidden/Protected: %s", path),
			Severity:    models.SeverityLow,
			Description: fmt.Sprintf("Path %s returned HTTP %d — exists but access is restricted.", path, statusCode),
			Evidence:    fmt.Sprintf("GET %s -> %d", fullURL, statusCode),
			Details: map[string]string{
				"path":        path,
				"url":         fullURL,
				"status_code": fmt.Sprintf("%d", statusCode),
			},
		}

	case statusCode >= 200 && statusCode < 300:
		return &models.Result{
			Module:      models.ModuleDirectory,
			Name:        fmt.Sprintf("Found: %s", path),
			Severity:    models.SeverityMedium,
			Description: fmt.Sprintf("Path %s returned HTTP %d (2xx success).", path, statusCode),
			Evidence:    fmt.Sprintf("GET %s -> %d", fullURL, statusCode),
			Details: map[string]string{
				"path":        path,
				"url":         fullURL,
				"status_code": fmt.Sprintf("%d", statusCode),
			},
		}

	default:
		return nil
	}
}
