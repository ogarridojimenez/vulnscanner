package scanner

import (
	"bufio"
	"os"
	"strings"
)

// LoadTargetsFromFile reads a list of targets (one per line, # comments ignored).
func LoadTargetsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, sc.Err()
}
