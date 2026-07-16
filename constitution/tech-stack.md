# Stack Tecnológico — VulnScanner

## Tecnologías
| Componente | Tecnología | Propósito |
|------------|-----------|-----------|
| Lenguaje | Go 1.23+ | Rendimiento, concurrencia nativa |
| CLI Framework | Cobra + pflag | Comandos, flags, subcomandos |
| Concurrencia | Goroutines + worker pool (fan-out) | Escaneo paralelo |
| HTTP Client | net/http + custom transport | Timeout, proxy, cookies configurables |
| SQLite | modernc.org/sqlite (CGO-free) | Persistencia de resultados |
| PDF | go-pdf/fpdf | Reportes profesionales |
| Colores | fatih/color | Output coloreado en terminal |
| Logging | slog (stdlib) | Log estructurado |
| Testing | testing + httptest + testify | Tests unitarios e integración |

## Comandos
```bash
go build -o vulnscan.exe ./cmd/vulnscanner/
go test ./...
go vet ./...
go run ./cmd/vulnscanner/ scan example.com
```

## Convenciones
- **Idioma:** Código y comentarios en inglés. Output de CLI en inglés.
- **Naming:** camelCase en Go estándar. Paquetes: `internal/scanner`, `internal/reporter`, `internal/storage`, `internal/models`, `internal/config`.
- **Manejo de errores:** Errores envueltos con `fmt.Errorf("context: %w", err)`. Nunca `panic` fuera de main.
- **Interfaces:** Definir interfaces pequeñas (1-2 métodos) en el package que las consume.

## Prohibiciones explícitas
- ❌ NO usar CGO ni librerías que requieran CGO
- ❌ NO ejecutar comandos externos (nmap, curl, nuclei)
- ❌ NO escanear sin consentimiento explícito del target
- ❌ NO almacenar credenciales ni datos sensibles en logs
