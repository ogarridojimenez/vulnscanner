# Roadmap — VulnScanner

## Hecho ✅
_(nada aún)_

## Siguiente 🔜

### Fase 1 — Base del proyecto
- [ ] Init Go module + estructura de directorios
- [ ] Cobra CLI con subcomandos (scan, history, report, summary, db)
- [ ] Models compartidos (Target, Result, Report, Severity)
- [ ] Config loading
- [ ] Worker pool base para ejecución paralela de módulos

### Fase 2 — Módulos de escaneo
- [ ] Port Scan (concurrente, TCP común)
- [ ] Security Headers check
- [ ] TLS/SSL check

### Fase 3 — Módulos avanzados
- [ ] Directory Fuzzing
- [ ] SQLi Detection
- [ ] XSS Detection

### Fase 4 — Persistencia y reportes
- [ ] SQLite storage (scans + vulnerabilities)
- [ ] JSON output estructurado
- [ ] PDF generation con tabla de hallazgos
- [ ] Output coloreado en terminal

### Fase 5 — CI/CD y distribución
- [ ] GitHub Actions (lint → test → build)
- [ ] Docker multi-stage
- [ ] README con ejemplos y badges
- [ ] Tests con servidor mock httptest

## Backlog 💡
- Escaneo desde archivo de targets (`--file`)
- Autenticación por cookie
- Resolución DNS + subdomain discovery
- Rate limiting de peticiones por target
- Escaneo de puertos UDP
