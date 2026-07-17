package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// Config holds notification targets.
type Config struct {
	SlackWebhook   string
	DiscordWebhook string
	EmailSMTP      string // not implemented in this build; reserved
	EmailTo        string
}

// Notify sends a summary of a completed scan to all configured targets.
func Notify(cfg Config, report *models.ScanReport) error {
	msg := formatMessage(report)
	var firstErr error
	if cfg.SlackWebhook != "" {
		if err := postWebhook(cfg.SlackWebhook, slackPayload(msg)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("slack: %w", err)
		}
	}
	if cfg.DiscordWebhook != "" {
		if err := postWebhook(cfg.DiscordWebhook, discordPayload(msg)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("discord: %w", err)
		}
	}
	return firstErr
}

func formatMessage(r *models.ScanReport) string {
	crit, high := 0, 0
	for _, res := range r.Results {
		if res.Severity == models.SeverityCritical {
			crit++
		}
		if res.Severity == models.SeverityHigh {
			high++
		}
	}
	return fmt.Sprintf("VulnScanner: %s completado. Findings: %d (CRITICAL: %d, HIGH: %d)",
		r.Target, len(r.Results), crit, high)
}

func slackPayload(text string) map[string]string {
	return map[string]string{"text": text}
}

func discordPayload(text string) map[string]string {
	return map[string]string{"content": text}
}

func postWebhook(url string, body interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
