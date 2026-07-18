# Validación — Feature 021: JWT Auth

| Requisito | Evidencia | Estado |
|-----------|-----------|--------|
| Generate access token | `internal/jwtauth/jwt.go` — `GenerateAccess(username, role)` | ✅ |
| Generate refresh token | `GenerateRefresh(username)` | ✅ |
| Validate token | `ValidateAccess(token)` → claims | ✅ |
| Middleware | `requireJWTAuth()` — Bearer header, sets context | ✅ |
| Login endpoint | `POST /api/auth/login` → access + refresh tokens | ✅ |
| Refresh endpoint | `POST /api/auth/refresh` → new access token | ✅ |
| Flag --jwt-secret | `serve.go` — habilita JWT, backward compatible | ✅ |
| HS256 | `jwt.SigningMethodHS256` | ✅ |
| Tests | 7/7 PASS (Generate, Validate, Expired, Invalid, Claims) | ✅ |

**Veredicto**: ✅ Aprobado
