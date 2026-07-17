package scanner

import (
	"os"
	"strings"
	"time"
)

// loadPayloads reads a newline-delimited payload file from the rules
// directory. Lines beginning with '#' and blank lines are ignored.
// It returns the trimmed, non-empty entries and any read error.
// loadPayloads reads a payload file (one per line, # comments ignored).
// It searches multiple locations: the given path, then "rules/<path>",
// then "../rules/<path>" to support both CLI (root) and test (package dir) execution.
func loadPayloads(path string) ([]string, error) {
	locations := []string{
		path,
		"rules/" + path,
		"../rules/" + path,
		"../../rules/" + path,
	}
	var lastErr error
	for _, loc := range locations {
		data, err := os.ReadFile(loc)
		if err == nil {
			var out []string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				out = append(out, line)
			}
			return out, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// defaultTimeout is used when no timeout is provided
const defaultTimeout = 10 * time.Second
