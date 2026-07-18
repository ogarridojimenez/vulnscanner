# Misión — VulnScanner

## Propósito
Escáner de vulnerabilidades web con API REST, dashboard visual y CLI. Audita targets: puertos, headers HTTP, TLS, fuzzing de directorios, detección SQLi/XSS, y más. Incluye Web UI para gestión de escaneos en tiempo real.

## Principios rectores
1. **CLI + API + Web UI** — Triple interfaz: terminal, API REST, dashboard visual.
2. **Concurrencia real** — Worker pool con goroutines. Cada módulo se ejecuta en paralelo.
3. **Portabilidad** — Binario único, SQLite embebido (sin CGO), Docker multi-stage.
4. **Reportes profesionales** — JSON, HTML, SARIF 2.1.0, Markdown, PDF.
5. **Zero dependencies externas** — No requiere nmap, nuclei, curl ni nada fuera del binario.
6. **Production-ready** — Auth (JWT/LDAP), rate limiting, WebSocket, health checks, CI/CD.

## Usuarios
- **Primario:** Desarrolladores/DevOps que auditan sus propios dominios
- **Secundario:** Equipos de seguridad ofensiva en pentesting ligero

## Non-goals
- NO es un reemplazo de nmap (solo TCP común, no OS fingerprinting)
- NO es un WAF (para eso está GoShield)
- NO escanea vulnerabilidades complejas (solo detección básica por payloads)
