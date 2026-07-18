package ratelimit

import (
	"net/http"
	"sync"
	"time"
)

type visitor struct {
	count    int
	reset    time.Time
	lastSeen time.Time
}

type Limiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	limit    int
	window   time.Duration
}

func New(limit int, window time.Duration) *Limiter {
	l := &Limiter{
		visitors: make(map[string]*visitor),
		limit:    limit,
		window:   window,
	}
	go l.cleanup()
	return l
}

func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	v, exists := l.visitors[key]
	if !exists || now.After(v.reset) {
		l.visitors[key] = &visitor{
			count:    1,
			reset:    now.Add(l.window),
			lastSeen: now,
		}
		return true
	}

	v.lastSeen = now
	if v.count >= l.limit {
		return false
	}
	v.count++
	return true
}

func (l *Limiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, exists := l.visitors[key]
	if !exists {
		return 0
	}
	remaining := v.reset.Sub(time.Now())
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		for k, v := range l.visitors {
			if time.Since(v.lastSeen) > l.window*2 {
				delete(l.visitors, k)
			}
		}
		l.mu.Unlock()
	}
}

func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := extractKey(r)
		if !l.Allow(key) {
			retryAfter := l.RetryAfter(key)
			w.Header().Set("Retry-After", formatDuration(retryAfter))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded","retry_after":"` + formatDuration(retryAfter) + `"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func extractKey(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return "ip:" + xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return "ip:" + xri
	}
	return "ip:" + r.RemoteAddr
}

func TokenKey(r *http.Request, token string) string {
	return "token:" + token
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	seconds := int(d.Seconds()) + 1
	return string(rune('0'+seconds/60)) + "m" + string(rune('0'+seconds%60)) + "s"
}
