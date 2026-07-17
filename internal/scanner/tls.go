package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// TLS-related constants
var weakCipherSuites = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:             "TLS_RSA_WITH_RC4_128_SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:         "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:         "TLS_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:     "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:       "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:  "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
}

// tlsVersionName maps TLS version constants to human-readable names.
var tlsVersionName = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// checkTLS performs TLS/SSL checks on the target's HTTPS ports.
func checkTLS(target string, timeout time.Duration, client *http.Client) []models.Result {
	results := make([]models.Result, 0)

	// Determine host and ports to check.
	host := target
	specifiedPort := 0

	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return results
		}
		host = u.Hostname()
		if u.Port() != "" {
			specifiedPort, _ = fmt.Sscanf(u.Port(), "%d", &specifiedPort)
		}
	} else if h, p, err := net.SplitHostPort(target); err == nil {
		host = h
		fmt.Sscanf(p, "%d", &specifiedPort)
	}

	// Gather ports to check — default to 443 if none specified.
	ports := []int{}
	if specifiedPort > 0 {
		ports = append(ports, specifiedPort)
	} else {
		// If the target is a URL, check common HTTPS ports.
		ports = append(ports, 443, 8443, 9443)
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	for _, port := range ports {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		r := inspectTLS(addr, port, timeout)
		if r != nil {
			results = append(results, r...)
		}
	}

	return results
}

// inspectTLS dials a TLS connection and inspects the certificate and cipher details.
func inspectTLS(addr string, port int, timeout time.Duration) []models.Result {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // nolint: gosec — we inspect manually
	})
	if err != nil {
		return []models.Result{{
			Module:      models.ModuleTLS,
			Name:        fmt.Sprintf("TLS Connection Failed (port %d)", port),
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Could not establish TLS connection to %s: %v", addr, err),
			Details: map[string]string{
				"addr": addr,
				"port": fmt.Sprintf("%d", port),
			},
		}}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	results := make([]models.Result, 0)

	// --- TLS version check ---
	if name, ok := tlsVersionName[state.Version]; ok {
		sev := models.SeverityInfo
		if state.Version <= tls.VersionTLS11 {
			sev = models.SeverityHigh
		} else if state.Version == tls.VersionTLS12 {
			sev = models.SeverityInfo
		}
		results = append(results, models.Result{
			Module:      models.ModuleTLS,
			Name:        fmt.Sprintf("TLS Version: %s", name),
			Severity:    sev,
			Description: fmt.Sprintf("Connection uses %s on port %d", name, port),
			Evidence:    name,
			Details: map[string]string{
				"version": name,
				"port":    fmt.Sprintf("%d", port),
			},
		})
	}

	// --- Cipher suite check ---
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	_, isWeak := weakCipherSuites[state.CipherSuite]
	if isWeak {
		results = append(results, models.Result{
			Module:         models.ModuleTLS,
			Name:           "Weak Cipher Suite",
			Severity:       models.SeverityHigh,
			Description:    fmt.Sprintf("Weak cipher suite in use: %s", cipherName),
			Recommendation: "Disable weak cipher suites and prefer AEAD ciphers like TLS_AES_128_GCM_SHA256.",
			Evidence:       cipherName,
			Details: map[string]string{
				"cipher_suite": cipherName,
				"port":         fmt.Sprintf("%d", port),
			},
		})
	} else {
		results = append(results, models.Result{
			Module:      models.ModuleTLS,
			Name:        "Cipher Suite",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Cipher suite in use: %s", cipherName),
			Evidence:    cipherName,
			Details: map[string]string{
				"cipher_suite": cipherName,
				"port":         fmt.Sprintf("%d", port),
			},
		})
	}

	// --- Certificate checks ---
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		// Expiry
		daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
		expirySev := models.SeverityLow
		expiryDesc := fmt.Sprintf("Certificate expires in %d days (%s)", daysRemaining, cert.NotAfter.Format(time.RFC3339))
		if daysRemaining < 0 {
			expirySev = models.SeverityHigh
			expiryDesc = fmt.Sprintf("Certificate EXPIRED on %s (%d days ago)", cert.NotAfter.Format(time.RFC3339), -daysRemaining)
		} else if daysRemaining < 30 {
			expirySev = models.SeverityMedium
		} else if daysRemaining < 90 {
			expirySev = models.SeverityLow
		} else {
			expirySev = models.SeverityInfo
		}

		results = append(results, models.Result{
			Module:      models.ModuleTLS,
			Name:        "Certificate Expiry",
			Severity:    expirySev,
			Description: expiryDesc,
			Evidence:    fmt.Sprintf("NotAfter: %s", cert.NotAfter.Format(time.RFC3339)),
			Details: map[string]string{
				"not_after":      cert.NotAfter.Format(time.RFC3339),
				"days_remaining": fmt.Sprintf("%d", daysRemaining),
				"issuer":         cert.Issuer.CommonName,
				"subject":        cert.Subject.CommonName,
			},
		})

		// Signature algorithm
		sigAlgo := cert.SignatureAlgorithm.String()
		results = append(results, models.Result{
			Module:      models.ModuleTLS,
			Name:        "Signature Algorithm",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Certificate signature algorithm: %s", sigAlgo),
			Evidence:    sigAlgo,
			Details: map[string]string{
				"signature_algorithm": sigAlgo,
			},
		})

		// Self-signed check
		if len(cert.Issuer.Organization) > 0 && len(cert.Subject.Organization) > 0 {
			if cert.Issuer.Organization[0] == cert.Subject.Organization[0] {
				results = append(results, models.Result{
					Module:         models.ModuleTLS,
					Name:           "Self-Signed Certificate",
					Severity:       models.SeverityMedium,
					Description:    "The server presents a self-signed certificate which may indicate a lack of proper PKI.",
					Recommendation: "Replace the self-signed certificate with one issued by a trusted Certificate Authority.",
					Evidence:       fmt.Sprintf("Issuer: %s, Subject: %s", cert.Issuer.CommonName, cert.Subject.CommonName),
					Details: map[string]string{
						"issuer":  cert.Issuer.CommonName,
						"subject": cert.Subject.CommonName,
					},
				})
			}
		}

		// Certificate chain verification
		if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			results = append(results, models.Result{
				Module:         models.ModuleTLS,
				Name:           "Certificate Chain Not Verified",
				Severity:       models.SeverityMedium,
				Description:    "The certificate chain could not be verified against known CA roots.",
				Recommendation: "Ensure the certificate is issued by a trusted CA and the full chain is presented.",
				Details: map[string]string{
					"addr": addr,
				},
			})
		}
	}

	return results
}
