# Roadmap — VulnScanner (Expanded)

## Fase 1: Módulos de detección avanzada ✅
- [x] SSRF detection
- [x] LFI/RFI detection
- [x] Open redirect detection
- [x] Cookie mismanagement
- [x] Tech detection
- [x] Subdomain enumeration

## Fase 2: Escaneo autenticado ✅
- [x] Login automático (form + JSON token)
- [x] Sesión con renovación
- [x] authTransport inyecta cookies/headers

## Fase 3: Reportes adicionales ✅
- [x] HTML (donut SVG)
- [x] SARIF 2.1.0
- [x] Markdown

## Fase 4: Configuración avanzada ✅
- [x] config.yaml / config.toml loader
- [x] --config flag
- [x] Rate limiting (token bucket)
- [x] Proxy support

## Fase 5: Producer-ready ✅
- [x] Gin REST API (serve)
- [x] Scheduler de escaneos periódicos
- [x] Notificaciones (Slack/Discord/Email)
- [x] Multi-target (--targets-file)

## Fase 6: Calidad ✅
- [x] Integration tests (storage, reporter)
- [x] Benchmarks (concurrency)
- [x] Fuzzing (payloads)
- [x] CI: vet + fmt + coverage + fuzz

## Fase 7: Web UI ✅
- [x] Landing page explicativa (`/`)
- [x] Dashboard de escaneos (`/dashboard`)
- [x] Formulario nuevo escaneo (`/scan/new`)
- [x] Detalle de escaneo (`/scan/:id`)
- [x] Assets embebidos (embed.FS, sin CGO)

## Fase 8: UI Authentication ✅
- [x] Flag `--ui-password` para proteger panel
- [x] Login page + cookie de sesión HttpOnly
- [x] Middleware `requireAuth` (redirige a /login)
- [x] Logout invalida sesión
- [x] Sin password = modo abierto (retrocompatible)

## Fase 9: Fix bugs críticos ✅
- [x] Graceful shutdown en server (signal handling + http.Server.Shutdown)
- [x] .gitignore completo (binarios, DB, WAL/SHM, IDE, OS)
- [x] Build/vet/tests OK

## Fase 10: API Auth ✅
- [x] Token bearer para endpoints `/api/*`
- [x] Flag `--api-token` en serve
- [x] Middleware auth en routes API
- [x] Tests: TestAPIAuthRequired, TestAPIAuthDisabled

## Fase 11: Logging estructurado ✅
- [x] Reemplazar fmt.Printf por slog (niveles: info/warn/error)
- [x] Request logging middleware en server
- [x] Log de findings por scan
- [x] Flag --log-level en serve

## Fase 12: Health checks + métricas ✅
- [x] GET /health detallado (DB status, uptime, memory)
- [x] Contadores: scans completados, findings totales
- [x] Prometheus metrics endpoint (opcional)

## Fase 13: Tests E2E ✅
- [x] Test completo: scan → storage → report
- [x] Test multi-target end-to-end
- [x] Test API con curl assertions

## Fase 14: Export/import DB ✅
- [x] `vulnscan db export` → JSON
- [x] `vulnscan db import` ← JSON
- [x] Backup automático al iniciar

## Fase 15: Web UI mejoras ✅
- [x] Filtros por severidad/módulo en dashboard
- [x] Paginación (>10 scans)
- [x] Búsqueda por target

## Fase 16: Comparación de escaneos ✅
- [x] Selección de 2 escaneos
- [x] Diff de findings (nuevos/resueltos)
- [x] Reporte comparativo

## Estado
**Fases 1-16 completas.** Features 017-023 en backlog (specs listos).

## Backlog 🔜

| # | Feature | Estado | Complejidad |
|---|---------|--------|-------------|
| 017 | Rate Limiting API | spec ✅ | Baja |
| 018 | WebSocket Real-time | spec ✅ | Media |
| 019 | Docker/Dockerfile | spec ✅ | Baja |
| 020 | CI/CD GitHub Actions | spec ✅ | Baja |
| 021 | JWT Authentication | spec ✅ | Media |
| 022 | Dashboard Stats Charts | spec ✅ | Media |
| 023 | OAuth/LDAP Login | spec ✅ | Alta |
