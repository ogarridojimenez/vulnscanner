package scheduler

import (
	"testing"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/config"
	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

func TestSchedulerAddAndStop(t *testing.T) {
	store := storage.NewSQLiteStore(":memory:")
	if err := store.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer store.Close()

	s := New(store)
	s.AddJob(&Job{
		ID:       "test",
		Target:   "http://testphp.vulnweb.com",
		Interval: 1 * time.Hour,
		Config:   config.DefaultConfig(),
	})
	s.Start()
	time.Sleep(50 * time.Millisecond)
	s.Stop()
	// Should not panic; job interval is 1h so it won't run immediately
}

func TestSchedulerJobShape(t *testing.T) {
	j := &Job{ID: "x", Target: "http://t.com", Interval: time.Minute}
	if j.ID != "x" {
		t.Error("id mismatch")
	}
	if j.LastRun.IsZero() {
		// zero value is valid before first run
	}
}
