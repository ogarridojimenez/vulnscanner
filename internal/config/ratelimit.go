package config

import (
	"net/http"
	"net/url"
	"sync"
	"time"
)

// RateLimiter implements a token-bucket rate limiter per host
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*tokenBucket
	rate     float64 // requests per second
}

type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	rate     float64
	lastTick time.Time
}

// NewRateLimiter creates a rate limiter with the given requests-per-second limit
func NewRateLimiter(rps float64) *RateLimiter {
	if rps <= 0 {
		rps = 1000 // effectively unlimited
	}
	return &RateLimiter{
		limiters: make(map[string]*tokenBucket),
		rate:     rps,
	}
}

// getBucket returns (creating if needed) the bucket for a host
func (rl *RateLimiter) getBucket(host string) *tokenBucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if b, ok := rl.limiters[host]; ok {
		return b
	}
	b := &tokenBucket{
		tokens:   rl.rate,
		max:      rl.rate,
		rate:     rl.rate,
		lastTick: time.Now(),
	}
	rl.limiters[host] = b
	return b
}

// Wait blocks until a token is available for the given host
func (rl *RateLimiter) Wait(host string) {
	b := rl.getBucket(host)
	b.mu.Lock()
	defer b.mu.Unlock()

	for b.tokens < 1 {
		now := time.Now()
		elapsed := now.Sub(b.lastTick).Seconds()
		b.tokens += elapsed * b.rate
		if b.tokens > b.max {
			b.tokens = b.max
		}
		b.lastTick = now
		if b.tokens < 1 {
			time.Sleep(time.Duration((1-b.tokens)/b.rate*1000) * time.Millisecond)
		}
	}
	b.tokens--
}

// ApplyProxy configures the HTTP client transport to use a proxy if set
func ApplyProxy(client *http.Client, proxyURL string) error {
	if proxyURL == "" {
		return nil
	}
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	// We need a configurable transport; create one based on default
	baseTransport, ok := transport.(*http.Transport)
	if !ok {
		baseTransport = &http.Transport{}
	}
	baseTransport.Proxy = http.ProxyURL(pu)
	client.Transport = baseTransport
	return nil
}
