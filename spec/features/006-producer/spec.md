# Spec — Feature 006: Producer-ready

## Objetivo
Transformar VulnScanner de CLI tool a herramienta lista para producción: Web UI/API, scheduler, notificaciones y multi-target.

## Actores
- Equipos de secops que necesitan escaneos programados y centralizados

## Historias de usuario
- Como secops, quiero una API REST para lanzar escaneos desde CI/CD
- Como secops, quiero una Web UI para ver resultados sin CLI
- Como secops, quiero programar escaneos semanales automáticos
- Como secops, quiero recibir alertas en Slack cuando hay CRITICAL
- Como auditor, quiero escanear 100 dominios desde un archivo

## Requisitos funcionales (EARS)
- CUANDO el usuario ejecuta `vulnscan serve --port 8080`, EL SISTEMA DEBE iniciar API REST (Gin) con endpoints: `POST /api/v1/scan`, `GET /api/v1/scan/:id`, `GET /api/v1/scans`, `GET /api/v1/report/:id`.
- CUANDO el usuario accede a `http://localhost:8080/`, EL SISTEMA DEBE servir Web UI (HTML+JS) con formulario de scan y tabla de resultados.
- CUANDO el usuario configura `scheduler.cron: "0 0 * * 0"`, EL SISTEMA DEBE ejecutar escaneo semanal automático (robfig/cron).
- CUANDO un escaneo produce finding CRITICAL/HIGH, EL SISTEMA DEBE enviar notificación via webhook (Slack/Discord) o SMTP si está configurado.
- CUANDO el usuario pasa `--targets targets.txt`, EL SISTEMA DEBE escanear cada línea como target independiente con su propio reporte.

## Requisitos no funcionales
- API server corre en goroutine separada del CLI
- Web UI usa template HTML embebido (no assets externos obligatorios)
- Scheduler persiste en SQLite (tabla `schedules`)
- Notificaciones son best-effort (no fallan el scan)

## Non-goals
- No hacer multi-tenancy / auth en la API (asumimos red confiable)
- No hacer clustering/distribuido

## Criterios de aceptación
- `vulnscan serve` expone API documentada
- Web UI funcional contra API local
- Scheduler dispara scan en horario configurado
- Webhook llega a Slack test channel
- `vulnscan scan --targets list.txt` escanea múltiples targets
