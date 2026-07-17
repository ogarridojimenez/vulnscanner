# VulnScanner 🔍

> Escáner de vulnerabilidades web desde terminal, construido en Go.

`vulnscan` es una herramienta CLI que audita targets web en busca de vulnerabilidades comunes: puertos abiertos, cabeceras de seguridad faltantes, problemas TLS/SSL, directorios ocultos y detección básica de SQLi/XSS.

Inspirado en `nmap` + `nuclei`, pero con un solo binario CGO-free, cero dependencias externas en runtime.

---

## Instalación

```bash
# Desde release
curl -LO https://github.com/ogarridojimenez/vulnscanner/releases/latest/download/vulnscan_linux_amd64
chmod +x vulnscan_linux_amd64 && sudo mv vulnscan_linux_amd64 /usr/local/bin/vulnscan

# O compilar desde fuente
git clone https://github.com/ogarridojimenez/vulnscanner.git
cd vulnscanner && go build -o vulnscan ./cmd/vulnscanner/
```

## Uso

```bash
# Escaneo básico
vulnscan scan example.com

# Escaneo completo (todos los módulos)
vulnscan scan example.com --full

# Escaneo con workers y puertos específicos
vulnscan scan example.com --ports 80,443,8080,8443 --workers 20

# Escaneo con módulos específicos
vulnscan scan example.com --modules ssrf,lfi,redirect,cookies,tech,subdomain --workers 10

# Escaneo autenticado
vulnscan scan example.com --auth-login-url https://app.com/login --auth-user admin --auth-pass secret

# Reportes: json, pdf, html, sarif, md
vulnscan scan example.com --full --format html -o report.html
vulnscan scan example.com --full --format sarif -o report.sarif.json
vulnscan scan example.com --full --format md -o report.md

# Configuración avanzada desde archivo
vulnscan scan example.com --config config.yaml

# Gestión de base de datos
vulnscan db init
vulnscan db check
```

## Módulos

| Módulo | Descripción | Severidad típica |
|--------|-------------|-----------------|
| **Port Scan** | Escaneo TCP concurrente con detección de servicios (25+ puertos comunes) | INFO |
| **Security Headers** | Verifica 12 cabeceras OWASP (HSTS, CSP, XFO, etc.) | MEDIUM si faltan |
| **TLS Check** | Versión TLS, cifrado, caducidad, cadena de certificados | HIGH si expirado |
| **SQLi Detection** | 13 payloads, detección por reflexión | HIGH si reflejado |
| **XSS Detection** | 11 payloads, detección por reflexión | HIGH si reflejado |
| **SSRF Detection** | 8 payloads, metadata cloud + blind | CRITICAL si metadata |
| **LFI/RFI** | 8 payloads, etc/passwd + RFI | HIGH si LFI |
| **Open Redirect** | 6 payloads, Location externo | MEDIUM |
| **Cookie Audit** | Flags Secure/HttpOnly/SameSite | MEDIUM si falta |
| **Tech Detection** | goquery + headers (Wappalyzer-like) | INFO |
| **Subdomain Enum** | Resolución DNS concurrente (20 workers) | INFO |

## Flags globales

| Flag | Default | Descripción |
|------|---------|-------------|
| `--workers` / `-w` | 10 | Workers concurrentes |
| `--timeout` | 5s | Timeout por petición |
| `--cookie` | — | Cookie para escaneos autenticados |
| `--modules` | — | Lista de módulos (ssrf,lfi,redirect,cookies,tech,subdomain) |
| `--auth-login-url` | — | URL de login para escaneo autenticado |
| `--auth-user` / `--auth-pass` | — | Credenciales de login |
| `--auth-token-field` | — | Campo JSON del token en respuesta de login |
| `--format` | json | json, pdf, html, sarif, md |
| `--config` | — | Archivo YAML/TOML de configuración |
| `--db` | `~/.vulnscanner/history.db` | Ruta a base de datos |
| `-v` / `--verbose` | false | Salida detallada |

## Arquitectura

```
cmd/vulnscanner/       → CLI (Cobra)
internal/config/       → Configuración y defaults
internal/models/       → Dominio (Target, Result, ScanReport)
internal/scanner/      → 12 módulos de escaneo con worker pool
internal/reporter/     → JSON, PDF, HTML, SARIF, Markdown
internal/auth/         → Login automático + sesión (Feature 003)
internal/config/       → Configuración YAML/TOML + rate-limit + proxy
rules/                 → Payloads SQLi/XSS/SSRF/LFI/redirect/subdomains
```

**Principios:**
- ✅ Sin CGO — binario 100% portable
- ✅ Concurrencia real con goroutines + worker pool fan-out
- ✅ Arquitectura limpia con interfaces separadas
- ✅ Almacenamiento local SQLite para historial
- ✅ Reportes en JSON y PDF
- ✅ Tests con servidores mock httptest
- ✅ Docker multi-stage
- ✅ CI/CD con GitHub Actions

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`):
- **Lint**: `go vet` + `gofmt` check
- **Test**: matrix Go 1.23/1.24 con `-race`
- **Build Release**: cross-compile en tags `v*` (linux/darwin/windows × amd64/arm64)
- **Docker**: build de imagen en tags `v*`

## Stack

| Componente | Librería |
|------------|----------|
| CLI Framework | `spf13/cobra` |
| Output coloreado | `fatih/color` |
| PDF Reports | `go-pdf/fpdf` |
| Base de datos | `ncruces/go-sqlite3` (CGO-free) |

## Licencia

MIT
