# 001 · Base del proyecto — Plan

## Enfoque
Construir el esqueleto completo del proyecto: módulo Go, estructura de carpetas, modelos de datos, configuración, CLI con Cobra. Todo preparado para que los módulos de escaneo se conecten después.

## Arquitectura
```
cmd/vulnscanner/main.go → rootCmd
  ├── scanCmd       → scanner.Run(target, config)
  ├── historyCmd    → storage.ListScans()
  ├── reportCmd     → reporter.Generate(scanID, format)
  ├── summaryCmd    → storage.Summary()
  └── dbCmd         → storage.Init/Check()

internal/
  scanner/   → orquestador + módulos
  reporter/  → JSON + PDF output
  storage/   → SQLite persistence
  models/    → structs compartidas
  config/    → flags + configuración
```

## Implementación
1. go mod init + directorios
2. Models: Target, Result, ScanReport, Severity, Module
3. Config: Config struct + Load desde flags/env
4. CLI root + subcomandos Cobra
5. Worker pool base (para ejecución paralela de módulos)
6. Integration: main.go glue todo
7. Build y verificar
