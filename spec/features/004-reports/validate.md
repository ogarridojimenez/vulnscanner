# Validación — Feature 004: Reportes HTML/SARIF/Markdown

## Requisitos de spec.md → Evidencia

| Requisito | Evidencia | Estado |
|-----------|-----------|--------|
| CUANDO el usuario solicite reporte HTML, EL SISTEMA DEBE generar HTML con resumen por severidad | `reporter/html.go` + test `reporter_test.go` | ✅ |
| CUANDO el usuario solicite SARIF, EL SISTEMA DEBE generar SARIF 2.1.0 válido | `reporter/sarif.go` (schema sarif-2.1.0.json) | ✅ |
| CUANDO el usuario solicite Markdown, EL SISTEMA DEBE generar MD | `reporter/markdown.go` | ✅ |
| CUANDO se use `--format`, EL SISTEMA DEBE soportar json/pdf/html/sarif/md | `scan.go` switch format | ✅ |

## Desviaciones
- Ninguna. Todo implementado según spec.

## Veredicto
✅ APROBADO — Fase 3 completa y verificada (build + tests).
