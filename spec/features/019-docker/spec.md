# 019 · Docker/Dockerfile

**Estado:** propuesta

## Qué hace
Containerizar VulnScanner para deploy reproducible.

## Requisitos (EARS)
- EL SISTEMA DEBE proporcionar Dockerfile multi-stage (build + runtime)
- EL SISTEMA DEBE funcionar con `docker run` sin configuración adicional
- DONDE se use Docker, EL SISTEMA DEBE exponer puerto 8080
- EL SISTEMA DEBE almacenar DB en volumen montado

## No funcionales
- Imagen base: golang:1.22-alpine (build) + alpine:3.19 (runtime)
- Tamaño imagen final: <30MB
- docker-compose.yml para desarrollo con volume

## Criterios de aceptación
- [ ] `docker build -t vulnscanner .` completa sin error
- [ ] `docker run -p 8080:8080 vulnscanner` arranca
- [ ] DB persiste al reiniciar container (volumen)
- [ ] Imagen <30MB

## Fuera de alcance
- Kubernetes manifests
- Helm charts
