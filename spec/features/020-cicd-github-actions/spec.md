# 020 · CI/CD GitHub Actions

**Estado:** propuesta

## Qué hace
Pipeline automático: lint + test + build + release en cada push/PR.

## Requisitos (EARS)
- EN CADA push/PR, EL SISTEMA DEBE ejecutar go vet + go test
- EN CADA tag v*, EL SISTEMA DEBE crear release con binarios cross-compilados
- SI los tests fallan, EL SISTEMA DEBE bloquear el merge
- EL SISTEMA DEBE cachear módulos Go para builds rápidos

## No funcionales
- Go versions: 1.21 + 1.22 (matrix)
- OS targets: linux/amd64, linux/arm64, darwin/arm64, windows/amd64
- Cache: actions/cache para $GOPATH/pkg/mod

## Criterios de aceptación
- [ ] PR con código rojo → job rojo
- [ ] Push tag v1.0.0 → release con 4 binarios
- [ ] Build <2min con cache

## Fuera de alcance
- Deploy automático (Heroku, Vercel, etc.)
- Coverage reporting a servicio externo
