# Roadmap — VulnScanner

## Hecho ✅
- [x] Init Go module + estructura de directorios
- [x] Cobra CLI con subcomandos (scan, history, report, summary, db)
- [x] Models + Config
- [x] Scanner: port, headers, tls, directory, sqli/xss (6 módulos)
- [x] Reporter: JSON + PDF
- [x] Storage: SQLite (CGO-free, ncruces/go-sqlite3)
- [x] Tests (8 tests con httptest)
- [x] Docker multi-stage
- [x] GitHub Actions CI/CD (pasando)
- [x] Repo público en GitHub
- [x] README + documentación Obsidian

## Siguiente 🔜 (futuro)
- [ ] Más módulos (SSRF, LFI, open redirect)
- [ ] Escaneo autenticado con cookies/sesión
- [ ] Reporte HTML
- [ ] Configuración vía YAML/TOML
- [ ] Rate limiting configurable
- [ ] Web UI (opcional)
