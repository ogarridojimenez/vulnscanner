# Spec — Feature 002: Módulos de detección avanzada

## Objetivo
Ampliar la cobertura de detección con 6 nuevos módulos: SSRF, LFI/RFI, Open Redirect, Cookie Mismanagement, Tech Detection y Subdomain Enumeration.

## Actores
- Usuario de VulnScanner (pentester/auditor)

## Historias de usuario
- Como auditor, quiero detectar SSRF para reportar acceso a metadata cloud
- Como auditor, quiero detectar LFI/RFI para reportar RCE via include
- Como auditor, quiero detectar open redirect para reportar phishing
- Como auditor, quiero detectar cookies sin flags de seguridad
- Como auditor, quiero saber qué tecnologías usa el target (Wappalyzer-like)
- Como auditor, quiero enumerar subdominios para ampliar superficie

## Requisitos funcionales (EARS)

### SSRF
- CUANDO se escanea un parámetro con payloads SSRF (`http://169.254.169.254/`, `http://localhost/`, `file:///etc/passwd`), EL SISTEMA DEBE reportar si el servidor hace request a la URL inyectada (detección por diferencial de tiempo/respuesta).
- CUANDO se detecta acceso a metadata cloud (169.254.169.254, 192.168.0.1), EL SISTEMA DEBE marcar como CRITICAL.

### LFI/RFI
- CUANDO se inyecta `../../../../etc/passwd` en parámetros, EL SISTEMA DEBE reportar si el body contiene contenido de archivo del sistema.
- CUANDO se inyecta URL externa (RFI) y el server la incluye, EL SISTEMA DEBE marcar como HIGH.

### Open Redirect
- CUANDO se inyecta `//evil.com` o `https://evil.com` en parámetros de redirect, EL SISTEMA DEBE seguir la redirección y reportar si termina en dominio externo (MEDIUM).

### Cookie Mismanagement
- CUANDO el target setea cookies, EL SISTEMA DEBE verificar `Secure`, `HttpOnly`, `SameSite` y reportar ausencias (LOW/MEDIUM).

### Tech Detection
- CUANDO se analiza la respuesta HTTP, EL SISTEMA DEBE extraer tecnologías via goquery (meta tags, scripts, headers) y generar lista de frameworks/CMS/servidores (INFO).

### Subdomain Enumeration
- CUANDO se especifica un dominio, EL SISTEMA DEBE resolver subdominios comunes via DNS (wordlist) y reportar los que resuelven (INFO).

## Requisitos no funcionales
- Todos los módulos implementan interfaz `Scanner`
- Concurrencia con worker pool existente
- Payloads en `rules/` (ssrf.txt, lfi.txt, redirect.txt, subdomains.txt)

## Non-goals
- No hacer brute-force de directorios profundo (ya existe directory fuzzing)
- No hacer exploitation real (solo detección)

## Criterios de aceptación
- `vulnscan scan example.com --module ssrf,lfi,redirect,cookies,tech,subdomain` ejecuta los 6 módulos
- Tests con httptest mock para cada módulo
- Sin falsos positivos críticos en targets dummy
