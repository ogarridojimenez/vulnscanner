# Validación — Feature 009: UI Authentication

## Requisitos → Evidencia

| Requisito | Evidencia | Estado |
|-----------|-----------|--------|
| CUANDO serve --ui-password, EL SISTEMA DEBE requerir login | auth_test.go + live 302→/login | ✅ |
| CUANDO credenciales válidas, EL SISTEMA DEBE crear cookie | live login ok → cookie set | ✅ |
| CUANDO sin sesión válida, EL SISTEMA DEBE redirigir /login | live 302→/login | ✅ |
| CUANDO logout, EL SISTEMA DEBE invalidar cookie | live logout → 302, dashboard bloquea | ✅ |
| CUANDO sin --ui-password, EL SISTEMA NO DEBE requerir auth | auth_test.go TestUIAuthDisabled 200 | ✅ |

## Veredicto: APROBADO
