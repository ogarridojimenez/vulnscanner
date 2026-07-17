# Validación — Feature 008: Web UI

## Requisitos → Evidencia

| Requisito | Evidencia | Estado |
|-----------|-----------|--------|
| CUANDO GET /, EL SISTEMA DEBE servir landing | webui_test.go + live curl 200 | ✅ |
| CUANDO GET /dashboard, EL SISTEMA DEBE listar | webui_test.go + live 200 | ✅ |
| CUANDO POST form /scan/new, EL SISTEMA DEBE llamar API | app.html fetch /api/scan | ✅ |
| CUANDO GET /scan/:id, EL SISTEMA DEBE mostrar detalle | webui_test.go + live 200 | ✅ |
| CUANDO sirva UI, EL SISTEMA DEBE usar embed.FS | embed.go + assets | ✅ |

## Veredicto: APROBADO
