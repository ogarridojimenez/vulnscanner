package scanner

import (
	"strings"
	"testing"
)

// FuzzLoadPayloads ensures loadPayloads never panics on arbitrary module names.
func FuzzLoadPayloads(f *testing.F) {
	seeds := []string{"ssrf", "lfi", "redirect", "subdomain", "", "xss", "sqli", "../../etc/passwd"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, module string) {
		// Must not panic; may return error for missing file
		payloads, err := loadPayloads(module)
		if err != nil {
			// expected for nonexistent modules
			return
		}
		// If loaded, no payload should be a comment or empty
		for _, p := range payloads {
			if strings.TrimSpace(p) == "" {
				t.Errorf("empty payload for module %q", module)
			}
			if strings.HasPrefix(p, "#") {
				t.Errorf("comment leaked into payloads: %q", p)
			}
		}
	})
}
