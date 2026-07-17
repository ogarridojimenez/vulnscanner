# Plan Maestro — VulnScanner Expansion

## Fases y dependencias

```
Fase 1: Detection Modules (002)  ← independiente
Fase 2: Auth Scan (003)          ← depende de Fase 1 (auth context en módulos)
Fase 3: Reports (004)            ← independiente
Fase 4: Config (005)             ← independiente
Fase 5: Producer (006)           ← depende de 002,003,004,005
Fase 6: Quality (007)            ← depende de todas
```

## Fase 1: Módulos de detección (002)
- [ ] SSRF scanner (`internal/scanner/ssrf.go`)
- [ ] LFI/RFI scanner (`internal/scanner/lfi.go`)
- [ ] Open Redirect scanner (`internal/scanner/redirect.go`)
- [ ] Cookie scanner (`internal/scanner/cookies.go`)
- [ ] Tech Detection (`internal/scanner/tech.go` + goquery)
- [ ] Subdomain Enum (`internal/scanner/subdomain.go` + DNS)
- [ ] Rules: ssrf.txt, lfi.txt, redirect.txt, subdomains.txt
- [ ] Integrar en orchestrator (scanner.go)
- [ ] Tests para cada módulo

## Fase 2: Auth Scan (003)
- [ ] Auth context struct (`internal/auth/`)
- [ ] Login form parser
- [ ] Cookie renewal logic
- [ ] Basic Auth / JWT support
- [ ] Propagar en todos los módulos
- [ ] Tests con httptest auth server

## Fase 3: Reports (004)
- [ ] HTML reporter (`internal/reporter/html.go`)
- [ ] SARIF reporter (`internal/reporter/sarif.go`)
- [ ] Markdown reporter (`internal/reporter/md.go`)
- [ ] Chart SVG inline para HTML
- [ ] Tests de generación

## Fase 4: Config (005)
- [ ] Config loader YAML (`internal/config/yaml.go`)
- [ ] Config loader TOML (`internal/config/toml.go`)
- [ ] Rate limiter (`internal/ratelimit/`)
- [ ] Proxy transport (`internal/config/proxy.go`)
- [ ] CLI flags `--config`, `--rate-limit`, `--proxy`
- [ ] Tests de carga

## Fase 5: Producer (006)
- [ ] API server Gin (`cmd/vulnscanner/serve.go` + `internal/api/`)
- [ ] Web UI templates (`internal/api/webui/`)
- [ ] Scheduler cron (`internal/scheduler/`)
- [ ] Notifications (`internal/notify/`)
- [ ] Multi-target (`cmd/vulnscanner/scan.go --targets`)
- [ ] Tests de API con httptest

## Fase 6: Quality (007)
- [ ] Integration tests storage
- [ ] Integration tests reporter
- [ ] Fuzz targets
- [ ] Benchmarks
- [ ] CI/CD update (fuzz + bench jobs)

## Orden de implementación
1. Fase 1 (base de detección)
2. Fase 4 (config, necesaria para productización)
3. Fase 3 (reportes, paralelo a auth)
4. Fase 2 (auth, depende de módulos)
5. Fase 5 (producer, depende de todo)
6. Fase 6 (quality, al final)

## Estimación
- Fase 1: ~600 LOC
- Fase 2: ~300 LOC
- Fase 3: ~400 LOC
- Fase 4: ~250 LOC
- Fase 5: ~800 LOC
- Fase 6: ~200 LOC tests
Total: ~2550 LOC nuevas
