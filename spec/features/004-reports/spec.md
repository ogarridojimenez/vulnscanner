# Spec — Feature 004: Reportes adicionales

## Objetivo
Agregar formatos de reporte HTML (con gráficos), SARIF y Markdown.

## Actores
- Usuario que necesita reportes para diferentes audiencias

## Historias de usuario
- Como auditor, quiero un reporte HTML visual con gráficos para el cliente
- Como devsecops, quiero SARIF para integrar con GitHub Security tab
- Como técnico, quiero Markdown para docs en repo

## Requisitos funcionales (EARS)
- CUANDO el usuario pasa `--format html`, EL SISTEMA DEBE generar reporte HTML con tabla de hallazgos y gráfico de severidad (chart inline SVG o JS CDN opcional).
- CUANDO el usuario pasa `--format sarif`, EL SISTEMA DEBE generar SARIF 2.1.0 válido con cada finding como `result` con `ruleId`, `level`, `message`, `location`.
- CUANDO el usuario pasa `--format md`, EL SISTEMA DEBE generar Markdown con tablas y badges de severidad.
- CUANDO se generan reportes, EL SISTEMA DEBE soportar `--output archivo` y `--output -` (stdout).

## Requisitos no funcionales
- Reporter interface se extiende con `GenerateHTML`, `GenerateSARIF`, `GenerateMarkdown`
- HTML usa `html/template` (no dependencias externas)
- SARIF usa `github.com/owenrumney/go-sarif`

## Non-goals
- No generar PDF interactivo (ya existe PDF básico)

## Criterios de aceptación
- `vulnscan scan example.com --full --format html -o report.html` genera HTML válido
- SARIF validado contra schema oficial
- Markdown renderiza en GitHub
