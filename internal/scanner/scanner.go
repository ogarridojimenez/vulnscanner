package scanner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/auth"
	"github.com/ogarridojimenez/vulnscanner/internal/config"
	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// Scanner orchestrates all scan modules using a worker pool.
type Scanner struct {
	Config  *config.Config
	client  *http.Client
	workers chan struct{}
}

// New creates a new Scanner from the given configuration.
func New(cfg *config.Config) *Scanner {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
	// Apply proxy if configured
	if cfg.Proxy != "" {
		if p, err := url.Parse(cfg.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}
	// Apply authenticated session if present (Feature 003)
	if sess := cfg.GetAuthSession(); sess != nil {
		if authSess, ok := sess.(*auth.Session); ok {
			client.Transport = &authTransport{Base: tr, session: authSess}
		}
	}
	return &Scanner{
		Config:  cfg,
		client:  client,
		workers: make(chan struct{}, cfg.Workers),
	}
}

// modulesToRun returns the list of module names to execute based on config.
func (s *Scanner) modulesToRun() []models.Module {
	if s.Config.Full {
		return []models.Module{
			models.ModulePort, models.ModuleHeaders, models.ModuleTLS,
			models.ModuleDirectory, models.ModuleSQLi, models.ModuleXSS,
			models.ModuleSSRF, models.ModuleLFI, models.ModuleRedirect,
			models.ModuleCookies, models.ModuleTech, models.ModuleSubdomain,
		}
	}
	if len(s.Config.Modules) > 0 {
		mods := make([]models.Module, len(s.Config.Modules))
		for i, m := range s.Config.Modules {
			mods[i] = models.Module(m)
		}
		return mods
	}
	return []models.Module{models.ModuleHeaders, models.ModuleTLS}
}

// Run executes all activated scanner modules and returns the combined results.
func (s *Scanner) Run(target string) (models.ResultList, []models.Module, error) {
	results := make(models.ResultList, 0)
	resultsCh := make(chan models.Result, 100)
	var wg sync.WaitGroup

	modules := s.modulesToRun()

	// Launch each module in its own goroutine.
	for _, mod := range modules {
		wg.Add(1)
		go func(moduleName models.Module) {
			defer wg.Done()
			s.runModule(moduleName, target, resultsCh)
		}(mod)
	}

	// Close results channel when all modules finish.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results.
	for r := range resultsCh {
		results = append(results, r)
	}

	if len(results) == 0 {
		return results, modules, fmt.Errorf("no modules executed or all returned empty")
	}

	return results, modules, nil
}

// runModule dispatches work to the correct scanner function.
func (s *Scanner) runModule(moduleName models.Module, target string, out chan<- models.Result) {
	// Acquire worker slot for this module
	s.acquireWorker()
	defer s.releaseWorker()

	switch moduleName {
	case models.ModulePort:
		ports := s.Config.Ports
		if len(ports) == 0 {
			ports = config.CommonHTTPPorts
		}
		for _, r := range scanPorts(target, ports, s.Config.Timeout) {
			out <- r
		}
	case models.ModuleHeaders:
		for _, r := range checkHeaders(target, s.Config.Timeout, s.client) {
			out <- r
		}
	case models.ModuleTLS:
		for _, r := range checkTLS(target, s.Config.Timeout, s.client) {
			out <- r
		}
	case models.ModuleDirectory:
		for _, r := range fuzzDirectories(target, s.Config.Timeout, s.Config.Workers, s.client) {
			out <- r
		}
	case models.ModuleSQLi:
		for _, r := range detectSQLi(target, s.Config.Timeout, s.client) {
			out <- r
		}
	case models.ModuleXSS:
		for _, r := range detectXSS(target, s.Config.Timeout, s.client) {
			out <- r
		}
	case models.ModuleSSRF:
		for _, r := range detectSSRF(target, s.client, s.Config.Timeout, nil) {
			out <- r
		}
	case models.ModuleLFI:
		for _, r := range detectLFI(target, s.client, s.Config.Timeout, nil) {
			out <- r
		}
	case models.ModuleRedirect:
		for _, r := range detectRedirect(target, s.client, s.Config.Timeout, nil) {
			out <- r
		}
	case models.ModuleCookies:
		for _, r := range checkCookies(target, s.client, s.Config.Timeout) {
			out <- r
		}
	case models.ModuleTech:
		for _, r := range detectTech(target, s.client, s.Config.Timeout) {
			out <- r
		}
	case models.ModuleSubdomain:
		domain := target
		for _, r := range enumSubdomains(domain, nil) {
			out <- r
		}
	}
}

// acquireWorker blocks until a worker slot is available.
func (s *Scanner) acquireWorker() {
	s.workers <- struct{}{}
}

// releaseWorker frees a worker slot.
func (s *Scanner) releaseWorker() {
	<-s.workers
}
