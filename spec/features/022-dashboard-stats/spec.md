# 022 · Dashboard Stats con Charts

**Estado:** propuesta

## Qué hace
Gráficas en el dashboard: evolución de findings, top vulnerabilidades, timeline.

## Requisitos (EARS)
- EL SISTEMA DEBE mostrar gráfica de findings por severidad (donut/pie)
- EL SISTEMA DEBE mostrar evolución de scans en el tiempo (line chart)
- EL SISTEMA DEBE mostrar top 10 vulnerabilidades más frecuentes
- CUANDO no haya datos, EL SISTEMA DEBE mostrar mensaje vacío

## No funcionales
- Lib: Chart.js v4 (CDN, sin build tools)
- Responsive: mobile-friendly
- Datos via API existente /api/scans

## Criterios de aceptación
- [ ] Dashboard muestra 3 gráficas
- [ ] Gráficas se actualizan al cargar scans
- [ ] Mobile: gráficas redimensionan correctamente

## Fuera de alcance
- Export de gráficas a imagen/PDF
- Filtros de fecha en gráficas
