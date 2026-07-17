# Roadmap — VulnScanner (Expanded)

## Fase 1: Módulos de detección avanzada ✅
- [x] SSRF detection
- [x] LFI/RFI detection
- [x] Open redirect detection
- [x] Cookie mismanagement
- [x] Tech detection (Wappalyzer-like)
- [x] Subdomain enumeration

## Fase 2: Escaneo autenticado ✅
- [x] Login automático (form-based, basic auth, JWT)
- [x] Session/cookie renewal
- [x] Auth context en todos los módulos

## Fase 3: Reportes adicionales ✅
- [x] HTML con gráficos (donut SVG)
- [x] SARIF 2.1.0
- [x] Markdown

## Fase 4: Configuración avanzada ⏳
- [x] YAML/TOML loader (internal/config/loader.go)
- [x] Rate limiting por host (internal/config/ratelimit.go)
- [ ] Proxy support wiring en CLI (transport listo)
- [ ] CLI flag --config

## Fase 5: Producer-ready ⏳
- [ ] Web UI + API server (Gin)
- [ ] Scheduler de escaneos (cron)
- [ ] Notificaciones (Slack/Discord/Email)
- [ ] Multi-target scan desde archivo

## Fase 6: Calidad ⏳
- [x] Integration tests (reporter)
- [ ] Fuzzing de payloads ampliado
- [ ] Benchmarks de concurrencia
- [ ] CI/CD actualizado (coverage)
