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

## Estado final
**TODAS LAS FASES COMPLETAS** — VulnScanner es production-ready.
