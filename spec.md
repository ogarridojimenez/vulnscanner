# VulnScanner — Especificación del Proyecto

## 🎯 Propósito
Scanner de vulnerabilidades web desde CLI. Complemento ofensivo a GoShield (defensivo). Demostrar concurrencia, tooling de seguridad, CI/CD y generación de reportes.

## 🏗️ Arquitectura (Hexagonal / Clean)

```
vulnscanner/
├── cmd/vulnscanner/main.go        # Entry point con Cobra CLI
├── internal/
│   ├── scanner/                    # Core: lógica de escaneo
│   │   ├── scanner.go              # Orquestador con worker pool
│   │   ├── port.go                 # Escaneo de puertos
│   │   ├── headers.go              # Análisis headers de seguridad
│   │   ├── tls.go                  # Check SSL/TLS
│   │   ├── directory.go            # Fuzzing de directorios
│   │   └── sqli.go                 # Detección básica SQLi/XSS
│   ├── reporter/                   # Generación de reportes
│   │   ├── json.go                 # Reporte JSON
│   │   └── pdf.go                  # Reporte PDF
│   ├── storage/                    # Persistencia
│   │   ├── store.go                # Interfaz Store
│   │   └── sqlite.go               # Implementación SQLite
│   ├── models/                     # Structs compartidas
│   │   ├── target.go
│   │   ├── result.go
│   │   └── report.go
│   └── config/                     # Configuración
│       └── config.go
├── pkg/
│   └── cve/                        # (opcional) Lookup CVEs
├── rules/                          # Payloads para detección
│   ├── sqli.txt
│   └── xss.txt
├── Dockerfile                      # Multi-stage
├── docker-compose.yml              # App + SQLite volume
└── .github/workflows/
    └── ci.yml                      # Tests + lint + build
```

## ⚙️ Funcionalidades

### CLI (Cobra)

```bash
# Escaneo rápido
vulnscan scan example.com

# Escaneo completo (todos los módulos)
vulnscan scan example.com --full --workers 20

# Escaneo de puertos específicos
vulnscan scan example.com --ports 80,443,8080,8443

# Escaneo con autenticación
vulnscan scan example.com --cookie "session=abc123"

# Escaneo desde archivo de targets
vulnscan scan --file targets.txt

# Ver historial de escaneos
vulnscan history

# Ver detalles de un escaneo
vulnscan report <scan-id>

# Exportar reporte PDF
vulnscan report <scan-id> --format pdf -o report.pdf

# Ver resumen de vulnerabilidades encontradas
vulnscan summary

# Health check de la DB
vulnscan db check

# Inicializar base de datos
vulnscan db init
```

### Flags principales
| Flag | Default | Descripción |
|------|---------|-------------|
| `--target` / `-t` | — | URL o IP objetivo |
| `--file` / `-f` | — | Archivo con lista de targets |
| `--full` | false | Ejecutar todos los módulos |
| `--workers` | 10 | Número de workers concurrentes |
| `--ports` | comunes | Puertos a escanear |
| `--timeout` | 5s | Timeout por petición |
| `--cookie` | — | Cookie de sesión |
| `--format` | json | Formato de reporte (json/pdf) |
| `--output` / `-o` | — | Archivo de salida |

### Módulos de escaneo

| Módulo | Descripción | Input | Output |
|--------|-------------|-------|--------|
| **Port Scan** | Escanea puertos TCP comunes | target, ports, workers | Lista de puertos abiertos |
| **Headers** | Analiza headers de seguridad HTTP | URL | Security Headers Score |
| **TLS** | Verifica certificado SSL (expiración, versión, ciphers) | URL | Estado TLS, días para expirar |
| **Directory** | Fuzzing de directorios/archivos comunes | URL, wordlist | Archivos/dirs encontrados |
| **SQLi Detection** | Prueba payloads básicos SQLi | URL + parámetros | Posibles vulnerabilidades |
| **XSS Detection** | Prueba payloads básicos XSS | URL + parámetros | Posibles vulnerabilidades |

### Ejemplo de output (JSON)
```json
{
  "id": "scan_20260713_abc123",
  "target": "example.com",
  "timestamp": "2026-07-13T10:30:00Z",
  "duration": "45.2s",
  "modules_run": ["port", "headers", "tls", "directory"],
  "summary": {
    "total_checks": 145,
    "vulnerabilities": 3,
    "high": 1,
    "medium": 1,
    "low": 1,
    "info": 2
  },
  "results": [
    {
      "module": "port",
      "port": 443,
      "status": "open",
      "service": "https"
    },
    {
      "module": "headers",
      "header": "Strict-Transport-Security",
      "status": "missing",
      "severity": "medium",
      "recommendation": "Add HSTS header with min-age 31536000"
    }
  ]
}
```

## 🛠️ Stack Tecnológico

| Componente | Tecnología | Propósito |
|------------|-----------|-----------|
| **Lenguaje** | Go 1.23+ | Rendimiento, concurrencia nativa |
| **CLI Framework** | Cobra | Comandos, flags, autocompletado |
| **Concurrencia** | Goroutines + worker pool (fan-out) | Escaneo paralelo por módulo |
| **HTTP Client** | net/http + custom transport | Peticiones configurables (timeout, proxy, cookies) |
| **SQLite** | modernc.org/sqlite (puro Go, sin CGO) | Persistencia de resultados |
| **PDF** | go-pdf/fpdf o maroto | Reportes profesionales |
| **Logging** | slog (stdlib) | Log estructurado |
| **Testing** | testing + httptest + testify | Tests unitarios e integración |
| **CI/CD** | GitHub Actions | Build + lint + test automáticos |
| **Docker** | Multi-stage build | Distribución |
| **Seguridad** | net/http TLS config | Timeouts, cipher suites seguras |

### Dependencias clave (Go modules)
```go
require (
    github.com/spf13/cobra v1.9.x
    modernc.org/sqlite v1.34.x
    github.com/jung-kurt/gofpdf/v2 v2.17.x
    github.com/stretchr/testify v1.10.x
    github.com/fatih/color v1.18.x       // Output coloreado en terminal
)
```

## 📊 Sistema de Severidad

| Severidad | Color | Descripción |
|-----------|-------|-------------|
| **CRITICAL** | 🔴 Rojo | Riesgo inmediato, exploitable públicamente |
| **HIGH** | 🟠 Naranja | Vulnerabilidad confirmada |
| **MEDIUM** | 🟡 Amarillo | Mala configuración, header faltante |
| **LOW** | 🔵 Azul | Info leakage, banner grabbing |
| **INFO** | ⚪ Gris | Puerto abierto, servicio detectado |

## 🗄️ Esquema SQLite

```sql
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    duration_seconds REAL,
    modules TEXT,
    summary TEXT JSON,
    raw_output TEXT JSON,
    status TEXT DEFAULT 'completed'
);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT REFERENCES scans(id),
    module TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('critical','high','medium','low','info')),
    description TEXT,
    recommendation TEXT,
    evidence TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
```

## 📋 Plan de Implementación (3-4 semanas)

| Fase | Tareas | Semana |
|------|--------|--------|
| **1. Base** | Proyecto Go, Cobra CLI, flags, config, models | Semana 1 |
| **2. Módulos** | Port scan (workers pool) + Headers check + TLS check | Semana 1-2 |
| **3. Avanzado** | Directory fuzzing + SQLi/XSS detection + SQLite storage | Semana 2-3 |
| **4. Reportes** | JSON output + PDF generation + colores terminal | Semana 3 |
| **5. CI/CD** | GitHub Actions, Docker multi-stage, README | Semana 4 |
| **6. Tests** | Test suite completa (unit + integration + owasp mock) | Semana 4 |

## 🔍 Lo que aporta al CV

1. **Concurrencia real:** Worker pool con goroutines para escaneo paralelo (diferente a un simple CRUD)
2. **Arquitectura Hexagonal:** Separación clara scanner/reporter/storage
3. **Security Tooling:** Port scan, TLS audit, header analysis, fuzzing (complementa GoShield)
4. **CI/CD profesional:** GitHub Actions multi-stage (lint → test → build → release)
5. **Reportes PDF:** Generación de documentos profesionales desde CLI
6. **Persistencia:** SQLite embebido + consultas SQL
7. **Diseño de APIs internas:** Interfaces bien definidas entre módulos

## 📂 Mock API endpoints para tests

```go
// Test server que expone endpoints vulnerables (httptest)
GET  /api/users?id=1' OR '1'='1   → refleja parámetro (SQLi test)
GET  /search?q=<script>alert(1)</script>  → refleja parámetro (XSS test)
GET  /admin                       → 200 sin autenticación (header check)
GET  /.env                        → 200 si existe (directory fuzzing)
```

## ✅ Criterios de éxito

- [ ] `vulnscan scan example.com` corre y produce output
- [ ] Worker pool procesa N targets concurrentemente
- [ ] Todos los módulos reportan resultados
- [ ] Reportes JSON y PDF generados correctamente
- [ ] Historial de escaneos persistido en SQLite
- [ ] GitHub Actions: `go vet`, `go test`, `go build` pasan
- [ ] Docker build multi-stage funciona
- [ ] 65%+ cobertura de tests
- [ ] README con ejemplos de uso y badges
