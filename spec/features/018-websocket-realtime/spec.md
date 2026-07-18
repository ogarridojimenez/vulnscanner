# 018 · WebSocket Real-time Updates

**Estado:** propuesta

## Qué hace
Actualizaciones en vivo del estado de un scan sin recargar la página.

## Requisitos (EARS)
- CUANDO un scan cambie de estado, EL SISTEMA DEBE notificar a todos los WebSocket conectados
- CUANDO un cliente se conecte via WS, EL SISTEMA DEBE enviar el estado actual del scan
- SI el scan no existe, EL SISTEMA DEBE cerrar la conexión con error
- MIENTRAS el scan esté corriendo, EL SISTEMA DEBE enviar progreso cada 2s

## No funcionales
- lib: gorilla/websocket o nhooyr/websocket
- Max conexiones concurrentes: 100
- Ping/pong cada 30s para detectar desconexiones

## Criterios de aceptación
- [ ] WS connect → recibir estado inicial
- [ ] Scan en progreso → updates cada 2s
- [ ] Scan completado → notificación final + cierre
- [ ] >100 conexiones → rechazar

## Fuera de alcance
- Autenticación del canal WS
- Historial de mensajes
