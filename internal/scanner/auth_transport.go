package scanner

import (
	"net/http"

	"github.com/ogarridojimenez/vulnscanner/internal/auth"
)

// authTransport wraps an http.RoundTripper and injects the authenticated
// session's cookies and headers into every outgoing request.
type authTransport struct {
	Base    http.RoundTripper
	session *auth.Session
}

// RoundTrip implements http.RoundTripper
func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone request to avoid mutating the original
	r := req.Clone(req.Context())
	t.session.Apply(r)
	return t.Base.RoundTrip(r)
}
