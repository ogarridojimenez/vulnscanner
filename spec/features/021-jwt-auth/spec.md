# 021 · JWT Authentication

**Estado:** propuesta

## Qué hace
Reemplaza Bearer token estático por JWT con tokens expirables y refresh.

## Requisitos (EARS)
- CUANDO el usuario haga login, EL SISTEMA DEBE retornar access token (15min) + refresh token (7d)
- CUANDO el access token expire, EL SISTEMA DEBE rechazar con 401
- CUANDO se use refresh token válido, EL SISTEMA DEBE emitir nuevo access token
- SI el refresh token es inválido, EL SISTEMA DEBE rechazar con 401

## No funcionales
- Lib: golang-jwt/jwt/v5
- Algoritmo: HS256 (secret configurable)
- Refresh tokens almacenados en DB (revocables)

## Criterios de aceptación
- [ ] Login → access + refresh tokens
- [ ] Access token expirado → 401
- [ ] Refresh → nuevo access token
- [ ] Refresh revocado → 401

## Fuera de alcance
- OAuth2 flow (ver 023)
- Multi-tenant
