# Tech Stack — VulnScanner (Expanded)

## Core (existene)
- Go 1.23+ (CGO-free)
- `spf13/cobra` — CLI framework
- `fatih/color` — Output coloreado en terminal
- `go-pdf/fpdf` — Reportes PDF
- `ncruces/go-sqlite3` — Storage SQLite

## Nuevas dependencias (fase de expansión)

| Categoría | Librería | Uso |
|-----------|----------|-----|
| Config | `gopkg.in/yaml.v3` | Configuración YAML personalizada |
| Config | `github.com/BurntSushi/toml` | Configuración TOML alternativa |
| HTML parsing | `github.com/PuerkitoBio/goquery` | Detección de tecnologías (Wappalyzer-like) |
| Web server | `github.com/gin-gonic/gin` | API server + Web UI |
| HTTP client | `net/http` (stdlib) | Proxy support, auth sessions |
| Scheduler | `github.com/robfig/cron/v3` | Escaneos recurrentes |
| Notifications | `github.com/slack-go/slack` | Slack/Discord webhooks |
| Templates | `html/template` (stdlib) | Reportes HTML |
| SARIF | `github.com/owenrumney/go-sarif` | SARIF 2.1.0 output |

## Principios no negociables (actualizados)
1. **CGO-free** — Todas las dependencias deben ser puras Go
2. **Sin dependencias de servicios externos** en runtime (salvo notificaciones opcionales)
3. **Concurrencia real** — worker pools para todos los módulos
4. **Configurable** — YAML/TOML para módulos, payloads, timeouts
5. **Extensible** — Nuevos módulos implementan la interfaz `Scanner`
6. **Testeable** — httptest para todos los módulos de red

## Restricciones
- Binario único portable
- Sin acceso a internet obligatorio (subdomain enum usa DNS local primero)
- Proxy opcional (Burp/Zap) vía `HTTP_PROXY`
