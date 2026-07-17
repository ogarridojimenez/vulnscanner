package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// enumSubdomains resolves a list of subdomains (read from rules/subdomains.txt
// via loadPayloads) against the given parent domain using a concurrent worker
// pool, returning INFO results for each subdomain that resolves.
func enumSubdomains(domain string, payloads []string) []models.Result {
	// Prefer the supplied payloads; if empty, fall back to the wordlist file.
	subs := payloads
	if len(subs) == 0 {
		if loaded, err := loadPayloads("subdomains.txt"); err == nil {
			subs = loaded
		}
	}
	if len(subs) == 0 {
		return []models.Result{{
			Module:      models.Module("subdomain"),
			Name:        "No Subdomains To Enumerate",
			Severity:    models.SeverityInfo,
			Description: "No subdomain wordlist available to enumerate.",
		}}
	}

	const maxWorkers = 20
	sem := make(chan struct{}, maxWorkers)
	resultsCh := make(chan models.Result, len(subs))
	var wg sync.WaitGroup

	resolver := net.DefaultResolver
	resolveTimeout := 3 * time.Second

	for _, sub := range subs {
		fqdn := fmt.Sprintf("%s.%s", sub, domain)
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
			defer cancel()

			addrs, err := resolver.LookupHost(ctx, name)
			if err != nil {
				return
			}
			if len(addrs) == 0 {
				return
			}
			resultsCh <- models.Result{
				Module:      models.Module("subdomain"),
				Name:        fmt.Sprintf("Subdomain Resolved: %s", name),
				Severity:    models.SeverityInfo,
				Description: fmt.Sprintf("Subdomain %s resolves to %v", name, addrs),
				Evidence:    fmt.Sprintf("%s -> %s", name, strings.Join(addrs, ", ")),
				Details: map[string]string{
					"subdomain": name,
					"addresses": strings.Join(addrs, ", "),
				},
			}
		}(fqdn)
	}

	wg.Wait()
	close(resultsCh)

	results := make([]models.Result, 0)
	for r := range resultsCh {
		results = append(results, r)
	}

	if len(results) == 0 {
		results = append(results, models.Result{
			Module:      models.Module("subdomain"),
			Name:        "No Subdomains Resolved",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("None of the %d enumerated subdomains resolved for %s.", len(subs), domain),
		})
	}

	return results
}
