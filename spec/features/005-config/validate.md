# Validación — Feature 004: Configuración avanzada

## Requisitos → Evidencia

| Requisito | Evidencia | Estado |
|-----------|-----------|--------|
| CUANDO se pase --config YAML/TOML, EL SISTEMA DEBE cargar config | loader_test.go (TestLoadFromFileYAML/TOML) | ✅ |
| CUANDO RateLimit>0, EL SISTEMA DEBE limitar peticiones | rateLimitTransport + scanner.New | ✅ |
| CUANDO Proxy configurado, EL SISTEMA DEBE enrutar | proxy en tr.Proxy | ✅ |
| CUANDO --config presente, EL SISTEMA DEBE aplicar valores | smoke test con config.example.yaml | ✅ |

## Veredicto: APROBADO
