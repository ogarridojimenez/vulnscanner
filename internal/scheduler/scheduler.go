package scheduler

import (
	"fmt"
	"sync"
	"time"

	"github.com/ogarridojimenez/vulnscanner/internal/config"
	"github.com/ogarridojimenez/vulnscanner/internal/models"
	"github.com/ogarridojimenez/vulnscanner/internal/notifier"
	"github.com/ogarridojimenez/vulnscanner/internal/reporter"
	"github.com/ogarridojimenez/vulnscanner/internal/scanner"
	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

// Job defines a scheduled scan.
type Job struct {
	ID       string
	Target   string
	Interval time.Duration
	Config   *config.Config
	Notif    notifier.Config
	LastRun  time.Time
	mu       sync.Mutex
}

// Scheduler runs scan jobs on intervals.
type Scheduler struct {
	jobs   map[string]*Job
	mu     sync.Mutex
	store  *storage.SQLiteStore
	stopCh chan struct{}
}

// New creates a scheduler with storage backend.
func New(store *storage.SQLiteStore) *Scheduler {
	return &Scheduler{
		jobs:   make(map[string]*Job),
		store:  store,
		stopCh: make(chan struct{}),
	}
}

// AddJob registers a job.
func (s *Scheduler) AddJob(j *Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[j.ID] = j
}

// Start begins the scheduling loop.
func (s *Scheduler) Start() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.checkAndRun()
			}
		}
	}()
}

// Stop halts the scheduler.
func (s *Scheduler) Stop() {
	close(s.stopCh)
}

func (s *Scheduler) checkAndRun() {
	s.mu.Lock()
	jobs := make([]*Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		jobs = append(jobs, j)
	}
	s.mu.Unlock()

	for _, j := range jobs {
		j.mu.Lock()
		due := time.Since(j.LastRun) >= j.Interval
		j.mu.Unlock()
		if due {
			go s.runJob(j)
		}
	}
}

func (s *Scheduler) runJob(j *Job) {
	j.mu.Lock()
	j.LastRun = time.Now()
	j.mu.Unlock()

	cfg := j.Config
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	cfg.Target = j.Target
	sc := scanner.New(cfg)
	results, modulesRun, err := sc.Run(j.Target)
	if err != nil {
		fmt.Printf("[scheduler] job %s error: %v\n", j.ID, err)
		return
	}
	report := &models.ScanReport{
		ID:         fmt.Sprintf("sched_%s_%d", j.ID, time.Now().Unix()),
		Target:     j.Target,
		Timestamp:  time.Now(),
		Duration:   0,
		ModulesRun: modulesRun,
		Results:    results,
		Status:     "completed",
	}
	if s.store != nil {
		_ = s.store.SaveScan(report)
	}
	_ = reporter.JSONReport(report, fmt.Sprintf("scheduled_%s.json", j.ID))
	_ = notifier.Notify(j.Notif, report)
}
