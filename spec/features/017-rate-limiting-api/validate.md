# Validación — Feature 017: Rate Limiting API

| Requisito | Evidencia | Estado |
|-----------|-----------|--------|
| Token bucket por IP | `internal/ratelimit/ratelimit.go` — `Allow(key)` | ✅ |
| Token-aware (rate-limita por token si apiToken configurado) | `rateLimitMiddleware()` usa key = token o IP | ✅ |
| Flag --rate-limit | `serve.go` — `--rate-limit` int flag | ✅ |
| 429 Too Many Requests | `rateLimitMiddleware()` → `c.AbortWithStatusJSON(429, ...)` | ✅ |
| Retry-After header | `Retry-After: <seconds>` en respuesta 429 | ✅ |
| Tests | `TestAllow`, `TestDifferentKeys`, `TestReset`, `TestMiddleware` | ✅ |
| Build/vet | `go build ./...` y `go vet ./...` pass | ✅ |

**Veredicto**: ✅ Aprobado
