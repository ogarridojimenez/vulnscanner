# Roadmap — VulnScanner (Expanded)

## Fase 1: Módulos de detección avanzada
- [ ] SSRF detection
- [ ] LFI/RFI detection
- [ ] Open redirect detection
- [ ] Cookie mismanagement
- [ ] Tech detection (Wappalyzer-like)
- [ ] Subdomain enumeration

## Fase 2: Escaneo autenticado
- [ ] Login automático (form-based, basic auth, JWT)
- [ ] Session/cookie renewal
- [ ] Auth context en todos los módulos

## Fase 3: Reportes adicionales
- [ ] HTML con gráficos
- [ ] SARIF 2.1.0
- [ ] Markdown

## Fase 4: Configuración avanzada
- [ ] YAML/TOML loader
- [ ] Rate limiting por host
- [ ] Proxy support (Burp/Zap)

## Fase 5: Producer-ready
- [ ] Web UI + API server (Gin)
- [ ] Scheduler de escaneos (cron)
- [ ] Notificaciones (Slack/Discord/Email)
- [ ] Multi-target scan desde archivo

## Fase 6: Calidad
- [ ] Integration tests (storage, reporter)
- [ ] Fuzzing de payloads ampliado
- [ ] Benchmarks de concurrencia
- [ ] CI/CD actualizado
