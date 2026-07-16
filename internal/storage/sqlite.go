package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"

	"github.com/ogarridojimenez/vulnscanner/internal/models"
)

// SQLiteStore implements Store using github.com/ncruces/go-sqlite3 (CGO-free)
type SQLiteStore struct {
	db     *sql.DB
	dbPath string
}

// NewSQLiteStore creates a new SQLite store
func NewSQLiteStore(dbPath string) *SQLiteStore {
	if dbPath == "" {
		dbPath = "~/.vulnscanner/history.db"
	}
	return &SQLiteStore{dbPath: dbPath}
}

func (s *SQLiteStore) dbFile() string {
	p := s.dbPath
	if len(p) > 0 && p[0] == '~' {
		home, _ := os.UserHomeDir()
		p = filepath.Join(home, p[1:])
	}
	return p
}

// Init creates the database and tables
func (s *SQLiteStore) Init() error {
	dbPath := s.dbFile()

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create db dir %s: %w", dir, err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	s.db = db

	// Enable WAL mode and foreign keys
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("pragma %s: %w", p, err)
		}
	}

	if err := s.createTables(); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	return nil
}

func (s *SQLiteStore) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		target TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		duration_seconds REAL,
		modules TEXT,
		summary TEXT,
		raw_output TEXT,
		status TEXT DEFAULT 'completed'
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT REFERENCES scans(id),
		module TEXT NOT NULL,
		name TEXT NOT NULL,
		severity TEXT CHECK(severity IN ('critical','high','medium','low','info')),
		description TEXT,
		recommendation TEXT,
		evidence TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
	`
	_, err := s.db.Exec(schema)
	return err
}

// SaveScan persists a scan report and its findings
func (s *SQLiteStore) SaveScan(report *models.ScanReport) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	modJSON, _ := json.Marshal(report.ModulesRun)
	sumJSON, _ := json.Marshal(report.Summary)
	rawJSON, _ := json.Marshal(report)

	_, err = tx.Exec(`
		INSERT INTO scans (id, target, timestamp, duration_seconds, modules, summary, raw_output, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, report.ID, report.Target, report.Timestamp, report.Duration.Seconds(),
		string(modJSON), string(sumJSON), string(rawJSON), report.Status)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	for _, r := range report.Results {
		_, err = tx.Exec(`
			INSERT INTO vulnerabilities (scan_id, module, name, severity, description, recommendation, evidence)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, report.ID, string(r.Module), r.Name, string(r.Severity),
			r.Description, r.Recommendation, r.Evidence)
		if err != nil {
			return fmt.Errorf("insert vuln: %w", err)
		}
	}

	return tx.Commit()
}

// ListScans returns recent scan records
func (s *SQLiteStore) ListScans(limit int) ([]models.ScanRecord, error) {
	if limit <= 0 {
		limit = 10
	}

	rows, err := s.db.Query(`
		SELECT id, target, timestamp, duration_seconds, modules, summary, raw_output, status
		FROM scans ORDER BY timestamp DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	var records []models.ScanRecord
	for rows.Next() {
		var rec models.ScanRecord
		var ts string
		if err := rows.Scan(&rec.ID, &rec.Target, &ts, &rec.DurationSeconds,
			&rec.Modules, &rec.SummaryJSON, &rec.RawOutputJSON, &rec.Status); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		rec.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		records = append(records, rec)
	}
	return records, nil
}

// GetScan retrieves a scan by ID
func (s *SQLiteStore) GetScan(id string) (*models.ScanReport, error) {
	rec, err := s.GetScanRecord(id)
	if err != nil {
		return nil, err
	}
	var report models.ScanReport
	if err := json.Unmarshal([]byte(rec.RawOutputJSON), &report); err != nil {
		return nil, fmt.Errorf("unmarshal report: %w", err)
	}
	return &report, nil
}

// GetScanRecord retrieves the raw DB record
func (s *SQLiteStore) GetScanRecord(id string) (*models.ScanRecord, error) {
	var rec models.ScanRecord
	var ts string
	err := s.db.QueryRow(`
		SELECT id, target, timestamp, duration_seconds, modules, summary, raw_output, status
		FROM scans WHERE id = ?
	`, id).Scan(&rec.ID, &rec.Target, &ts, &rec.DurationSeconds,
		&rec.Modules, &rec.SummaryJSON, &rec.RawOutputJSON, &rec.Status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("scan not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("get scan %s: %w", id, err)
	}
	rec.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
	return &rec, nil
}

// Summary returns vulnerability stats
func (s *SQLiteStore) Summary() ([]VulnStats, error) {
	rows, err := s.db.Query(`
		SELECT v.severity, COUNT(*) as count, MAX(v.timestamp) as last_seen
		FROM vulnerabilities v
		GROUP BY v.severity
		ORDER BY CASE v.severity
			WHEN 'critical' THEN 1
			WHEN 'high' THEN 2
			WHEN 'medium' THEN 3
			WHEN 'low' THEN 4
			WHEN 'info' THEN 5
		END
	`)
	if err != nil {
		return nil, fmt.Errorf("summary: %w", err)
	}
	defer rows.Close()

	var stats []VulnStats
	for rows.Next() {
		var s VulnStats
		var ts string
		if err := rows.Scan(&s.Severity, &s.Count, &ts); err != nil {
			return nil, fmt.Errorf("summary row: %w", err)
		}
		s.LastSeen, _ = time.Parse("2006-01-02 15:04:05", ts)
		stats = append(stats, s)
	}
	return stats, nil
}

// Count returns number of stored scans
func (s *SQLiteStore) Count() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM scans").Scan(&count)
	return count, err
}

// Health checks database connectivity
func (s *SQLiteStore) Health() error {
	if s.db == nil {
		return fmt.Errorf("database not initialized")
	}
	return s.db.Ping()
}

// Close closes the database connection
func (s *SQLiteStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
