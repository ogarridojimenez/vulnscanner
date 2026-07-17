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

# Salida a JSON
vulnscan scan example.com --full --output report.json

# Salida a PDF
vulnscan scan example.com --full --format pdf -o report.pdf

# Historial y estadísticas
vulnscan history
vulnscan summary
vulnscan report <scan-id> --format pdf

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
| **Directory Fuzzing** | 30 rutas comunes, detecta 200/403/301 | MEDIUM si encontrado |
| **SQLi Detection** | 13 payloads, detección por reflexión | HIGH si reflejado |
| **XSS Detection** | 11 payloads, detección por reflexión | HIGH si reflejado |

## Flags globales

| Flag | Default | Descripción |
|------|---------|-------------|
| `--workers` / `-w` | 10 | Workers concurrentes |
| `--timeout` | 5s | Timeout por petición |
| `--cookie` | — | Cookie para escaneos autenticados |
| `--db` | `~/.vulnscanner/history.db` | Ruta a base de datos |
| `-v` / `--verbose` | false | Salida detallada |

## Arquitectura

```
cmd/vulnscanner/       → CLI (Cobra)
internal/config/       → Configuración y defaults
internal/models/       → Dominio (Target, Result, ScanReport)
internal/scanner/      → 6 módulos de escaneo con worker pool
internal/reporter/     → JSON y PDF
internal/storage/      → SQLite CGO-free
rules/                 → Payloads SQLi/XSS
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
