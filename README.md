# VulnScanner 🔍

Escáner de vulnerabilidades web con CLI, API REST y dashboard visual.

## Features

- **10 módulos de detección**: Headers, TLS, puertos, XSS, SQLi, SSRF, LFI/RFI, open redirect, tech detection, subdomain enum
- **Escaneo autónomo y autenticado** (form-based, JSON token)
- **Web UI** con dashboard, filtros, paginación, charts, comparación de escaneos
- **API REST** con auth (Bearer token / JWT / LDAP)
- **Reportes**: JSON, HTML (donut SVG), SARIF 2.1.0, Markdown, PDF
- **Scheduler** de escaneos periódicos
- **Notificaciones**: Slack, Discord, Email
- **WebSocket** para updates en tiempo real
- **Docker** multi-stage (alpine, ~15MB)
- **CI/CD** GitHub Actions

## Instalación

### Go
```bash
go install github.com/ogarridojimenez/vulnscanner/cmd/vulnscanner@latest
```

### Docker
```bash
docker compose up -d
# Web UI: http://localhost:8080
```

### Build local
```bash
go build -o vulnscan ./cmd/vulnscanner
```

## Uso rápido

### CLI
```bash
# Escaneo básico
vulnscan scan --target https://ejemplo.com

# Full scan con reporte
vulnscan scan --target https://ejemplo.com --full --report results.json

# Multi-target
vulnscan scan --targets-file targets.txt --report scan.json

# Con auth
vulnscan scan --target https://ejemplo.com --auth-user admin --auth-pass secret
```

### API Server
```bash
# Iniciar servidor
vulnscan serve --addr :8080 --api-token mytoken

# Escanear via API
curl -X POST http://localhost:8080/api/scan \
  -H "Authorization: Bearer mytoken" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://ejemplo.com","modules":["headers","tls"]}'

# Ver escaneos
curl -H "Authorization: Bearer mytoken" http://localhost:8080/api/scans
```

### Web UI
```bash
# Con protección por password
vulnscan serve --ui-password secreto
# Abrir http://localhost:8080
```

## Flags principales

| Flag | Descripción |
|------|-------------|
| `--target` | URL o host a escanear |
| `--targets-file` | Archivo con un target por línea |
| `--full` | Ejecuta todos los módulos |
| `--report` | Ruta del reporte JSON |
| `--addr` | Dirección del servidor (default `:8080`) |
| `--api-token` | Token Bearer para API |
| `--jwt-secret` | Secret JWT (habilita auth JWT) |
| `--ldap-url` | URL del servidor LDAP |
| `--ui-password` | Password para Web UI |
| `--rate-limit` | Max req/min por IP |
| `--log-level` | debug, info, warn, error |

## Arquitectura

```
cmd/vulnscanner/     → CLI (cobra)
internal/
  scanner/           → Motor de escaneo + módulos
  server/            → Gin API + Web UI embebida
  storage/           → SQLite (ncruces/go-sqlite3)
  reporter/          → JSON, HTML, SARIF, Markdown, PDF
  ratelimit/         → Token bucket rate limiter
  jwtauth/           → JWT access+refresh tokens
  ldapauth/          → LDAP authentication
  ws/                → WebSocket hub
  scheduler/         → Cron-based scan scheduling
  notifier/          → Slack/Discord/Email
  config/            → YAML/TOML config loader
```

## Auth

| Método | Flags | Uso |
|--------|-------|-----|
| Bearer token | `--api-token` | `Authorization: Bearer <token>` |
| JWT | `--jwt-secret` | Login → access+refresh tokens |
| LDAP | `--ldap-url`, `--ldap-base-dn`, etc. | Login LDAP → JWT tokens |
| UI password | `--ui-password` | Cookie HttpOnly |

## Configuración

```yaml
# config.yaml
target: https://ejemplo.com
modules:
  - headers
  - tls
  - xss
workers: 10
timeout: 30s
```

```bash
vulnscan scan --config config.yaml
```

## Módulos de detección

| Módulo | Qué detecta |
|--------|-------------|
| `headers` | Headers de seguridad (CSP, HSTS, X-Frame, etc.) |
| `tls` | Certificados, versiones TLS, cipher suites |
| `ports` | Puertos abiertos (TCP common) |
| `xss` | Cross-Site Scripting básico |
| `sqli` | SQL Injection básico |
| `ssrf` | Server-Side Request Forgery |
| `lfi` | Local/Remote File Inclusion |
| `open_redirect` | Redirecciones abiertas |
| `tech` | Detección de tecnologías (Wappalyzer-like) |
| `subdomains` | Enumeración de subdominios |

## Docker

```bash
docker compose up -d
```

El volumen `vulnscan-data` persiste la base de datos SQLite.

## CI/CD

- **Test**: Go 1.21/1.22, vet, gofmt, tests
- **Build**: Cross-compile (linux/amd64, linux/arm64, darwin/arm64, windows/amd64)
- **Release**: Tag `v*` → GitHub Release con binarios

## License

MIT
