package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// serviceForPort maps common TCP ports to their well-known service names.
var serviceForPort = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	143:   "imap",
	443:   "https",
	465:   "smtps",
	587:   "smtp",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle-db",
	2049:  "nfs",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgres",
	5900:  "vnc",
	5984:  "couchdb",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	9000:  "sonarqube",
	9090:  "http-admin",
	9200:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",
}

// scanPorts performs concurrent TCP port scanning against the given host.
// It returns a Result for every open port with its detected service name.
func scanPorts(host string, ports []int, timeout time.Duration) []models.Result {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []models.Result
	)

	// Limit concurrency to avoid exhausting local ephemeral ports.
	sem := make(chan struct{}, 50)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return // port closed or filtered
			}
			conn.Close()

			service := serviceForPort[p]
			if service == "" {
				service = "unknown"
			}

			r := models.Result{
				Module:      models.ModulePort,
				Name:        fmt.Sprintf("Open Port %d", p),
				Severity:    models.SeverityInfo,
				Description: fmt.Sprintf("Port %d (%s) is open on %s", p, service, host),
				Evidence:    fmt.Sprintf("tcp/%d", p),
				Details: map[string]string{
					"port":    fmt.Sprintf("%d", p),
					"service": service,
				},
			}
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}
