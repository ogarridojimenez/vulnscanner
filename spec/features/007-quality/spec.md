# Spec — Feature 007: Calidad y pruebas

## Objetivo
Elevar la cobertura de tests, agregar fuzzing y benchmarks, y actualizar CI/CD.

## Actores
- Maintainers del proyecto

## Historias de usuario
- Como maintainer, quiero tests de integración de storage y reporter
- Como maintainer, quiero fuzzing de payloads para detectar panic en parsers
- Como maintainer, quiero benchmarks de concurrencia para medir escalabilidad

## Requisitos funcionales (EARS)
- CUANDO se ejecuta `go test ./internal/storage/...`, EL SISTEMA DEBE probar Save/Load/List con DB temporal.
- CUANDO se ejecuta `go test ./internal/reporter/...`, EL SISTEMA DEBE probar JSON/PDF/HTML/SARIF/MD generation con fixtures.
- CUANDO se ejecuta `go test -fuzz FuzzParseResponse`, EL SISTEMA DEBE correr fuzzing por 30s sin panic.
- CUANDO se ejecuta `go test -bench .`, EL SISTEMA DEBE reportar throughput de scanner con N workers.
- CUANDO se hace push a main, EL SISTEMA DEBE ejecutar CI con nuevos tests + fuzz + bench en matrix.

## Requisitos no funcionales
- Coverage objetivo: >70% en storage y reporter
- Fuzz corpus en `testdata/`
- Benchmarks en `*_bench_test.go`

## Non-goals
- No hacer E2E contra targets reales en CI (solo mocks)

## Criterios de aceptación
- `go test ./...` pasa con nuevos integration tests
- `go test -fuzz` no crashea
- CI verde con matrix ampliado
