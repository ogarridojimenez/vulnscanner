# Validación — Feature 005: Configuración avanzada

## Requisitos → Evidencia

| Requisito | Evidencia | Estado |
|-----------|-----------|--------|
| CUANDO se pase --config YAML/TOML, EL SISTEMA DEBE cargar la config | `config.LoadFromFile` + `scan.go` flag | ✅ |
| CUANDO rate_limit > 0, EL SISTEMA DEBE limitar requests por host | `rateLimitTransport` + scanner chain | ✅ |
| CUANDO proxy configurado, EL SISTEMA DEBE enrutar por proxy | `scanner.go` tr.Proxy | ✅ |
| CUANDO modules en archivo, EL SISTEMA DEBE usarlos | `ApplyFromFile` → cfg.Modules | ✅ |

## Tests
- `loader_test.go`: YAML, TOML, ApplyFromFile ✅
- Smoke test CLI con config.example.yaml ✅

## Veredicto
✅ APROBADO — Fase 4 completa.
