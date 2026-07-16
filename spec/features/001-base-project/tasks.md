# 001 · Base del proyecto — Tareas

| # | Tarea | Depende de | Criterio de aceptación |
|---|-------|-----------|------------------------|
| 1 | go mod init + crear directorios | — | `go build ./...` compila |
| 2 | Models (target, result, report, severity, module) | 1 | Structs exportadas, compila |
| 3 | Config (flags, struct, constructor) | 1 | `Config{}` se crea con defaults |
| 4 | CLI root + subcomandos (scan, history, report, summary, db) | 2,3 | `go run ./cmd/vulnscanner/ --help` muestra subcomandos |
| 5 | Worker pool base | 2,3 | Pool ejecuta N workers y retorna resultados |
| 6 | main.go — integración | 4,5 | `vulnscan scan example.com` corre sin error |
| 7 | Build + verify | 6 | `go build -o vulnscan.exe ./cmd/vulnscanner/` exit 0 |
