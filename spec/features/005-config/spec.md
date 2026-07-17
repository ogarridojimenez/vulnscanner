# Spec — Feature 005: Configuración avanzada

## Objetivo
Permitir personalización via YAML/TOML, rate limiting y proxy support.

## Actores
- Usuario avanzado que quiere tunear el escáner

## Historias de usuario
- Como usuario, quiero cargar un archivo YAML con módulos, payloads y timeouts personalizados
- Como usuario, quiero limitar requests por host para no saturar el target
- Como usuario, quiero rutear todo por Burp/Zap para interceptar

## Requisitos funcionales (EARS)
- CUANDO el usuario pasa `--config vulnscan.yaml`, EL SISTEMA DEBE cargar módulos habilitados, payloads custom, timeouts y workers desde el archivo.
- CUANDO se configura `rate_limit: 10/s`, EL SISTEMA DEBE limitar requests al host a 10 por segundo (token bucket).
- CUANDO se configura `proxy: http://127.0.0.1:8080`, EL SISTEMA DEBE rutear todas las requests por ese proxy.
- CUANDO el archivo tiene formato TOML (`.toml`), EL SISTEMA DEBE parsearlo con `BurntSushi/toml`.

## Requisitos no funcionales
- Config struct con valores por defecto (fallback si falta)
- Rate limiter se aplica por host (map de limiters)
- Proxy se aplica a nivel HTTP client (Transport.Proxy)

## Non-goals
- No soportar configuración via env vars (solo archivo)

## Criterios de aceptación
- `vulnscan scan example.com --config custom.yaml` usa config personalizada
- Rate limiting observable (requests no exceden límite)
- Proxy verificable con `httpbin.org` o Burp local
