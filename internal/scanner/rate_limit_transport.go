package scanner

import (
	"net/http"

	"github.com/ogarridojimenez/vulnscanner/internal/config"
)

// rateLimitTransport wraps an http.RoundTripper and applies per-host rate limiting.
type rateLimitTransport struct {
	Base    http.RoundTripper
	limiter *config.RateLimiter
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	t.limiter.Wait(host)
	return t.Base.RoundTrip(req)
}

// wrapWithRateLimit returns a client transport that rate-limits requests per host.
func wrapWithRateLimit(base http.RoundTripper, rps float64) http.RoundTripper {
	if rps <= 0 {
		return base
	}
	return &rateLimitTransport{Base: base, limiter: config.NewRateLimiter(rps)}
}
