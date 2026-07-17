# Especificación — Feature 008: Web UI

## Objetivo
Añadir una interfaz web embebida en el binario (sin dependencias externas) que
permita usar VulnScanner sin línea de comandos: landing explicativa, dashboard
de escaneos y formulario de nuevo escaneo.

## Actores
- Usuario de seguridad (pentester, devsecops)
- Administrador de CI/CD

## Historias de usuario
- Como usuario, quiero una landing que explique qué es VulnScanner y sus módulos.
- Como usuario, quiero lanzar un escaneo desde el navegador con un formulario.
- Como usuario, quiero ver el listado de escaneos y su estado.
- Como usuario, quiero ver el detalle de un escaneo con sus findings.

## Requisitos funcionales (EARS)
- CUANDO el usuario acceda a `/`, EL SISTEMA DEBE servir la landing page (HTML).
- CUANDO el usuario acceda a `/dashboard`, EL SISTEMA DEBE listar los escaneos.
- CUANDO el usuario envíe el formulario de `/scan`, EL SISTEMA DEBE hacer POST /api/scan.
- CUANDO el usuario acceda a `/scan/:id`, EL SISTEMA DEBE mostrar el detalle del reporte.
- CUANDO se sirva la UI, EL SISTEMA DEBE usar assets embebidos (embed.FS).

## Requisitos no funcionales
- Sin CGO, sin assets externos en runtime.
- UI responsive básica (CSS inline).
- Reutiliza endpoints API existentes.

## Non-goals
- No auth de la UI en esta fase (se agrega en fase posterior).
- No WebSocket (polling simple del lado cliente).

## Criterios de aceptación
- `vulnscan serve` sirve `/`, `/dashboard`, `/scan/new`, `/scan/:id`.
- Landing explica módulos y flags.
- Formulario lanza escaneo y redirige a dashboard.
