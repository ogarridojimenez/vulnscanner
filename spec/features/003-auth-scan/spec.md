# Spec — Feature 003: Escaneo autenticado

## Objetivo
Permitir escaneos autenticados con login automático y renovación de sesión.

## Actores
- Usuario con credenciales del target

## Historias de usuario
- Como auditor, quiero loguearme con usuario/clave para escanear áreas protegidas
- Como auditor, quiero que la sesión se renueve si expira durante el escaneo
- Como auditor, quiero pasar cookies manuales (JWT, session) sin login

## Requisitos funcionales (EARS)
- CUANDO el usuario pasa `--auth-form URL --auth-user X --auth-pass Y`, EL SISTEMA DEBE POST los credenciales y capturar cookies de sesión.
- CUANDO el usuario pasa `--cookie "session=..."`, EL SISTEMA DEBE usar esa cookie en todas las requests.
- CUANDO una request devuelve 401/403 tras login exitoso, EL SISTEMA DEBE reintentar login y renovar cookie (máx 3 veces).
- CUANDO el login es Basic Auth, EL SISTEMA DEBE enviar header `Authorization: Basic`.
- CUANDO el login es JWT, EL SISTEMA DEBE parsear el token y renovarlo si expira.

## Requisitos no funcionales
- Auth context se propaga a todos los módulos scanner
- Credenciales nunca se loggean en plaintext
- Timeout de sesión configurable

## Non-goals
- No soportar OAuth2 flow completo (solo bearer token manual)
- No soportar 2FA

## Criterios de aceptación
- `vulnscan scan example.com --auth-form https://example.com/login --auth-user admin --auth-pass secret` escanea autenticado
- `vulnscan scan example.com --cookie "auth=abc123"` usa cookie manual
- Tests con httptest server que requiere auth
