# 017 · Rate Limiting API

**Estado:** propuesta

## Qué hace
Limita requests por IP/token para abusar la API del escáner.

## Requisitos (EARS)
- CUANDO un cliente exceda N requests/min, EL SISTEMA DEBE retornar 429 Too Many Requests
- CUANDO el header X-Forwarded-For existe, EL SISTEMA DEBE rate-limitar por IP real
- DONDE se use `--api-token`, EL SISTEMA DEBE rate-limitar por token en vez de IP
- CUANDO se supere el límite, EL SISTEMA DEBE incluir header Retry-After

## No funcionales
- Límite default: 60 req/min por IP, 120 req/min por token
- Store in-memory (map + mutex), sin persistencia entre restarts

## Criterios de aceptación
- [ ] 61 requests en <1min → 429 en la 61
- [ ] Header Retry-After presente en 429
- [ ] Token auth rate-limita por token, no por IP

## Fuera de alcance
- Persistencia de contadores en DB
- Rate limit por endpoint (solo global)
