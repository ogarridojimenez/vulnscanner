package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ogarridojimenez/vulnscanner/internal/config"
	"github.com/ogarridojimenez/vulnscanner/internal/models"
	"github.com/ogarridojimenez/vulnscanner/internal/reporter"
	"github.com/ogarridojimenez/vulnscanner/internal/scanner"
	"github.com/ogarridojimenez/vulnscanner/internal/storage"
)

// ScanRequest is the API payload to enqueue a scan.
type ScanRequest struct {
	Target   string   `json:"target" binding:"required"`
	Modules  []string `json:"modules"`
	Workers  int      `json:"workers"`
	Timeout  string   `json:"timeout"`
	Format   string   `json:"format"`
	AuthUser string   `json:"auth_user"`
	AuthPass string   `json:"auth_pass"`
}

// Server wraps the Gin engine and a scan store.
type Server struct {
	engine  *gin.Engine
	store   *storage.SQLiteStore
	auth    *uiAuth
	apiToken string
	mu      sync.Mutex
	scans   map[string]*models.ScanReport
}

// New creates the API server. If uiPassword is non-empty, the web UI is protected.
// If apiToken is non-empty, API endpoints require Bearer token auth.
func New(store *storage.SQLiteStore, uiPassword string, apiToken string) *Server {
	gin.SetMode(gin.ReleaseMode)
	s := &Server{
		engine:   gin.New(),
		store:    store,
		auth:     newUIAuth(uiPassword),
		apiToken: apiToken,
		scans:    make(map[string]*models.ScanReport),
	}
	s.engine.Use(gin.Recovery())
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().Format(time.RFC3339)})
	})

	// Auth (Feature 009)
	s.engine.GET("/login", s.auth.loginPage)
	s.engine.POST("/login", s.auth.handleLogin)
	s.engine.GET("/logout", s.auth.handleLogout)

	// Web UI (Feature 008) — protected by requireAuth
	ui := s.engine.Group("/")
	ui.Use(s.auth.requireAuth)
	{
		ui.GET("/", s.serveLanding)
		ui.GET("/dashboard", s.serveApp)
		ui.GET("/scan/new", s.serveApp)
		ui.GET("/scan/:id", s.serveApp)
	}

	// API (Feature 010) — protected by requireAPIAuth if token set
	api := s.engine.Group("/api")
	if s.apiToken != "" {
		api.Use(s.requireAPIAuth)
	}
	{
		api.POST("/scan", s.handleScan)
		api.GET("/scans", s.handleList)
		api.GET("/scans/:id", s.handleGet)
	}
}

// requireAPIAuth validates Bearer token from Authorization header.
func (s *Server) requireAPIAuth(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	if auth == "" || auth != "Bearer "+s.apiToken {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.Next()
}

func (s *Server) serveLanding(c *gin.Context) {
	data, err := assets.ReadFile("static/landing.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "asset not found")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

func (s *Server) serveApp(c *gin.Context) {
	data, err := assets.ReadFile("static/app.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "asset not found")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

func (s *Server) handleScan(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg := config.DefaultConfig()
	cfg.Target = req.Target
	if len(req.Modules) > 0 {
		cfg.Modules = req.Modules
	}
	if req.Workers > 0 {
		cfg.Workers = req.Workers
	}
	if req.Timeout != "" {
		if d, err := time.ParseDuration(req.Timeout); err == nil {
			cfg.Timeout = d
		}
	}

	// Run async, store result when done
	reportID := fmt.Sprintf("api_%d", time.Now().UnixNano())
	go func() {
		sc := scanner.New(cfg)
		results, modulesRun, err := sc.Run(req.Target)
		if err != nil {
			fmt.Printf("[api] scan error: %v\n", err)
			return
		}
		rep := &models.ScanReport{
			ID:         reportID,
			Target:     req.Target,
			Timestamp:  time.Now(),
			Duration:   0,
			ModulesRun: modulesRun,
			Results:    results,
			Summary:    models.BuildSummary(results),
			Status:     "completed",
		}
		s.mu.Lock()
		s.scans[reportID] = rep
		s.mu.Unlock()
		if s.store != nil {
			_ = s.store.SaveScan(rep)
		}
		fmtVal := req.Format
		if fmtVal == "" {
			fmtVal = "json"
		}
		_ = reporter.JSONReport(rep, fmt.Sprintf("api_%s.json", reportID))
	}()

	c.JSON(http.StatusAccepted, gin.H{"scan_id": reportID, "status": "queued"})
}

func (s *Server) handleList(c *gin.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]gin.H, 0, len(s.scans))
	for id, r := range s.scans {
		list = append(list, gin.H{"id": id, "target": r.Target, "findings": len(r.Results), "status": r.Status})
	}
	c.JSON(http.StatusOK, gin.H{"scans": list})
}

func (s *Server) handleGet(c *gin.Context) {
	id := c.Param("id")
	s.mu.Lock()
	rep, ok := s.scans[id]
	s.mu.Unlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	c.JSON(http.StatusOK, rep)
}

// Run starts the HTTP server with graceful shutdown.
func (s *Server) Run(addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s.engine,
	}

	// Start server in goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("[server] listen error: %v\n", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("\n[server] shutting down...")

	// Graceful shutdown with 5s timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		fmt.Printf("[server] forced shutdown: %v\n", err)
		return err
	}
	fmt.Println("[server] stopped gracefully")
	return nil
}
