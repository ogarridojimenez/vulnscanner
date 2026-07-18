package logger

import (
	"log/slog"
	"testing"
)

func TestSetup(t *testing.T) {
	// Should not panic
	Setup("info")
	slog.Info("test message", "key", "value")

	Setup("debug")
	slog.Debug("debug message")

	Setup("warn")
	slog.Warn("warn message")

	Setup("error")
	slog.Error("error message")

	Setup("") // default
	slog.Info("default level")
}
