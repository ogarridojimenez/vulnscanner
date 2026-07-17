# Especificación — Feature 009: UI Authentication

## Objetivo
Proteger el panel web de VulnScanner con autenticación, evitando acceso
anónimo al dashboard y formularios de escaneo.

## Actores
- Administrador que levanta `vulnscan serve`
- Usuario de seguridad autorizado

## Historias de usuario
- Como admin, quiero proteger la UI con usuario/contraseña.
- Como usuario, quiero hacer login y mantener sesión.
- Como admin, quiero que sin credenciales la UI redirija a login.

## Requisitos funcionales (EARS)
- CUANDO se inicie serve con `--ui-password`, EL SISTEMA DEBE requerir login para rutas web.
- CUANDO el usuario envíe credenciales válidas, EL SISTEMA DEBE crear cookie de sesión.
- CUANDO una petición web carezca de sesión válida, EL SISTEMA DEBE redirigir a `/login`.
- CUANDO el usuario cierre sesión, EL SISTEMA DEBE invalidar la cookie.
- CUANDO NO se configure `--ui-password`, EL SISTEMA NO DEBE requerir auth (modo abierto).

## Requisitos no funcionales
- Sesión por cookie HttpOnly, sin almacenamiento externo.
- Contraseña no se expone en la API.

## Non-goals
- No multi-usuario/roles en esta fase.
- No OAuth externo.

## Criterios de aceptación
- `serve --ui-password secret` → `/dashboard` redirige a `/login` sin cookie.
- POST `/login` con password correcta → cookie set, redirect a `/`.
- GET `/logout` → limpia cookie.
- Sin `--ui-password` → comportamiento actual (abierto).
