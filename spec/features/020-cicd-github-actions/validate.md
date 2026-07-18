# Validación — Feature 020: CI/CD GitHub Actions

| Requisito | Evidencia | Estado |
|-----------|-----------|--------|
| Test job (push/PR) | `ci.yml` — trigger push/PR main | ✅ |
| Go matrix (1.21/1.22) | Matrix strategy en test job | ✅ |
| go vet + gofmt | Lint step en test job | ✅ |
| CGO_ENABLED=0 | Env en test y build jobs | ✅ |
| Cross-compile | linux/amd64, linux/arm64, darwin/arm64, windows/amd64 | ✅ |
| GitHub Release | `softprops/action-gh-release@v2` en tag v* | ✅ |
| Caching | `actions/cache@v4` para go modules | ✅ |

**Veredicto**: ✅ Aprobado
