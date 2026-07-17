# Manual de Usuario — VulnScanner 🔍

> Escáner de vulnerabilidades web desde terminal (CLI en Go).
> Versión: todas las fases (1-6) — production-ready.

---

## 1. Instalación

### Desde release
```bash
# Linux/macOS
curl -LO https://github.com/ogarridojimenez/vulnscanner/releases/latest/download/vulnscan_linux_amd64
chmod +x vulnscan_linux_amd64 && sudo mv vulnscan_linux_amd64 /usr/local/bin/vulnscan

# Windows: descarga vulnscan_windows_amd64.exe desde Releases y añade al PATH
```

### Compilar desde fuente
```bash
git clone https://github.com/ogarridojimenez/vulnscanner.git
cd vulnscanner
go build -o vulnscan ./cmd/vulnscanner/
```

### Verificar
```bash
vulnscan --help
vulnscan --version
```

---

## 2. Conceptos básicos

`vulnscan` audita un **target** (URL o host) ejecutando **módulos** de detección.
Cada módulo produce **findings** (hallazgos) con una **severidad**:

| Severidad | Significado |
|-----------|-------------|
| 🔴 CRITICAL | Explotable inmediatamente (ej. SSRF a metadata cloud) |
| 🟠 HIGH | Vulnerabilidad seria (SQLi, XSS, LFI) |
| 🟡 MEDIUM | Configuración débil (cabeceras, cookies) |
| 🔵 LOW | Mejora menor |
| ⚪ INFO | Información (puertos, tecnologías) |

Los resultados se guardan en SQLite (`~/.vulnscanner/history.db`) y se exportan
en el formato elegido (`--format`).

---

## 3. Comando `scan` (escaneo principal)

### Sintaxis
```bash
vulnscan scan <TARGET> [flags]
```
`<TARGET>` puede ser `example.com`, `http://...` o `https://...`.

### Ejemplos rápidos
```bash
# Escaneo básico (módulos por defecto: puertos, cabeceras, TLS, directorios)
vulnscan scan example.com

# Escaneo completo (todos los módulos)
vulnscan scan example.com --full

# Módulos específicos
vulnscan scan example.com --modules ssrf,lfi,redirect,cookies,tech,subdomain

# Puertos y workers personalizados
vulnscan scan example.com --ports 80,443,8080,8443 --workers 20

# Reporte en distintos formatos
vulnscan scan example.com --full --format html -o report.html
vulnscan scan example.com --full --format sarif -o report.sarif.json
vulnscan scan example.com --full --format md -o report.md
vulnscan scan example.com --full --format pdf -o report.pdf
```

### Flags de `scan`

| Flag | Default | Descripción |
|------|---------|-------------|
| `--full` | false | Ejecuta todos los módulos |
| `--modules` | — | Lista separada por comas (ssrf,lfi,redirect,cookies,tech,subdomain,port,headers,tls,directory,sqli,xss) |
| `--ports` | — | Puertos TCP a escanear (ej. `80,443,8080`) |
| `--workers` / `-w` | 10 | Workers concurrentes |
| `--timeout` | 5s | Timeout por petición |
| `--cookie` | — | Cookie para escaneos autenticados |
| `--format` | json | json, pdf, html, sarif, md |
| `-o` / `--output` | — | Ruta del archivo de reporte |
| `--config` | — | Archivo YAML/TOML de configuración |
| `--targets-file` | — | Archivo con múltiples targets (uno por línea) |
| `--auth-login-url` | — | URL de login para escaneo autenticado |
| `--auth-user` | — | Usuario de login |
| `--auth-pass` | — | Contraseña de login |
| `--auth-token-field` | — | Campo JSON del token en respuesta de login |
| `--db` | `~/.vulnscanner/history.db` | Ruta de la base de datos |
| `-v` / `--verbose` | false | Salida detallada |

---

## 4. Módulos disponibles

| Módulo | Flag | Detecta |
|--------|------|---------|
| Port Scan | `port` | Puertos abiertos + servicios |
| Security Headers | `headers` | 12 cabeceras OWASP (HSTS, CSP, XFO…) |
| TLS Check | `tls` | Versión TLS, caducidad, cadena |
| Directory Fuzzing | `directory` | Directorios/archivos ocultos |
| SQLi Detection | `sqli` | Inyección SQL por reflexión |
| XSS Detection | `xss` | Cross-site scripting por reflexión |
| **SSRF Detection** | `ssrf` | Server-Side Request Forgery (metadata cloud) |
| **LFI/RFI** | `lfi` | Local/Remote File Inclusion (etc/passwd) |
| **Open Redirect** | `redirect` | Redirecciones externas no controladas |
| **Cookie Audit** | `cookies` | Flags Secure/HttpOnly/SameSite |
| **Tech Detection** | `tech` | Tecnologías (Wappalyzer-like) |
| **Subdomain Enum** | `subdomain` | Subdominios por resolución DNS |

**Ejemplo dirigido:**
```bash
vulnscan scan https://mi-app.com --modules ssrf,lfi,redirect,cookies
```

---

## 5. Configuración avanzada (`--config`)

Evita repetir flags creando un archivo `config.yaml` o `config.toml`:

```yaml
# config.yaml
workers: 20
timeout: 15s
rate_limit: 2.0        # peticiones/seg por host
output_format: json
proxy: ""              # ej. http://127.0.0.1:8080
modules:
  - ssrf
  - cookies
  - tech
auth:
  login_url: https://app.com/login
  username: admin
  password: secret
  token_field: token
```

```toml
# config.toml
workers = 20
timeout = "15s"
rate_limit = 2.0
output_format = "json"
modules = ["ssrf", "cookies", "tech"]
```

Usar:
```bash
vulnscan scan https://mi-app.com --config config.yaml
```

Archivo de ejemplo incluido: `config.example.yaml`.

---

## 6. Escaneo autenticado

Muchas apps solo muestran vulnerabilidades tras login. VulnScanner puede
iniciar sesión automáticamente:

```bash
# Login por formulario
vulnscan scan https://mi-app.com \
  --auth-login-url https://mi-app.com/login \
  --auth-user admin \
  --auth-pass secret

# Login con token en respuesta JSON
vulnscan scan https://mi-app.com \
  --auth-login-url https://api.com/login \
  --auth-user admin \
  --auth-pass secret \
  --auth-token-field token
```

La sesión (cookies + token Bearer) se inyecta en todas las peticiones del escaneo.

---

## 7. Escaneo multi-target

Para auditar varios sitios a la vez, crea un archivo (uno por línea):

```text
# targets.txt
http://testphp.vulnweb.com
https://httpbin.org
https://otro-sitio.com
```

```bash
vulnscan scan dummy --targets-file targets.txt --modules headers,ssrf --workers 5
```
> Nota: `dummy` es requerido por la sintaxis pero se ignora; los targets
> reales vienen del archivo. Los comentarios (`#`) se ignoran.

---

## 8. Servidor API (Producer-ready)

Levanta una API REST para integrar VulnScanner en pipelines CI/CD o dashboards:

```bash
vulnscan serve --addr :8080 --db scans.db
```

### Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/health` | Healthcheck (`{"status":"ok"}`) |
| POST | `/api/scan` | Encola un escaneo async |
| GET | `/api/scans` | Lista de escaneos completados |
| GET | `/api/scans/:id` | Detalle de un escaneo |

### Ejemplo con curl
```bash
# Healthcheck
curl http://localhost:8080/health

# Encolar escaneo
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://testphp.vulnweb.com","modules":["headers","cookies"],"workers":10,"format":"json"}'

# Listar resultados
curl http://localhost:8080/api/scans
```

Respuesta de encola: `{"scan_id":"api_...","status":"queued"}`.
El escaneo corre en segundo plano; consulta `/api/scans` para ver el estado.

---

## 9. Scheduler y notificaciones

El paquete `scheduler` permite programar escaneos periódicos (integrable en
tu propio código o un servicio). Las notificaciones se envían vía webhook:

```go
import "github.com/ogarridojimenez/vulnscanner/internal/notifier"

cfg := notifier.Config{
    SlackWebhook: "https://hooks.slack.com/services/XXX",
    // o DiscordWebhook / EmailSMTP
}
notifier.Notify(cfg, report)
```

Soporta: **Slack**, **Discord**, **Email (SMTP)**.

---

## 10. Gestión de base de datos

```bash
vulnscan db init    # Inicializa SQLite
vulnscan db check   # Verifica integridad
```

Los escaneos se acumulan en `~/.vulnscanner/history.db` (o el `--db` indicado)
para histórico y comparativas.

---

## 11. Formatos de reporte

| Formato | Uso recomendado |
|---------|-----------------|
| `json` | Pipelines, parseo automático |
| `pdf` | Entrega a clientes |
| `html` | Visualización en navegador (gráfico donut) |
| `sarif` | Integración con GitHub Security / IDEs |
| `md` | Documentación en Markdown |

**SARIF** se importa en GitHub: *Security → Code scanning → Upload SARIF*.

---

## 12. Ejemplos de flujo completo

### Auditoría rápida de un sitio
```bash
vulnscan scan https://mi-tienda.com --full --format html -o tienda.html
```

### Pentest autenticado + reporte SARIF para GitHub
```bash
vulnscan scan https://mi-tienda.com \
  --auth-login-url https://mi-tienda.com/login \
  --auth-user pentester --auth-pass P@ss \
  --full --format sarif -o scan.sarif.json
```

### Campaña sobre múltiples activos
```bash
vulnscan scan dummy --targets-file activos.txt --modules ssrf,lfi,redirect --workers 15
```

### Integración CI/CD vía API
```bash
vulnscan serve --addr :8080 &
curl -X POST localhost:8080/api/scan -d '{"target":"https://staging.app","modules":["sqli","xss"]}'
```

---

## 13. Solución de problemas

| Síntoma | Causa probable | Solución |
|---------|----------------|----------|
| `scan failed: context deadline` | Timeout muy bajo | Sube `--timeout 15s` |
| Sin hallazgos en módulos avanzados | Target no vulnerable o requiere auth | Usa `--auth-*` o `--cookie` |
| `load targets: no such file` | Ruta de `--targets-file` incorrecta | Verifica ruta absoluta |
| API no responde | Puerto ocupado | Cambia `--addr :9090` |
| Proxy bloquea | Mal configurado | Revisa `proxy:` en config |

---

## 14. Buenas prácticas

1. **Siempre con autorización**: solo escanea sistemas propios o con permiso.
2. Usa `--workers` moderado (10-20) para no saturar el target.
3. Para escaneos largos, usa `--config` para reproducibilidad.
4. Exporta SARIF si usas GitHub Security.
5. Habilita notificaciones en CI para alertas automáticas.

---

*VulnScanner — desarrollado con metodología Spec-Driven Development (SDD).*
