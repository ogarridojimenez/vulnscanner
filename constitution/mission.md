# Misión — VulnScanner

## Propósito
Escáner de vulnerabilidades web desde terminal que audita targets remotos: puertos, headers HTTP, TLS, fuzzing de directorios y detección básica de SQLi/XSS. Complemento ofensivo a GoShield (defensivo).

## Principios rectores
1. **CLI-first** — Sin servidor, sin dashboard. Todo funciona desde terminal con output coloreado.
2. **Concurrencia real** — Worker pool con goroutines. Cada módulo se ejecuta en paralelo.
3. **Portabilidad** — Binario único, SQLite embebido (sin CGO), Docker multi-stage.
4. **Reportes profesionales** — Output JSON estructurado + PDF para compartir.
5. **Zero dependencies externas** — No requiere nmap, nuclei, curl ni nada fuera del binario.

## Usuarios
- **Primario:** Desarrolladores/DevOps que auditan sus propios dominios
- **Secundario:** Equipos de seguridad ofensiva en pentesting ligero

## Non-goals
- NO es un reemplazo de nmap (solo TCP común, no OS fingerprinting)
- NO es un WAF (para eso está GoShield)
- NO tiene UI web ni dashboard
- NO escanea vulnerabilidades complejas (solo detección básica por payloads)
