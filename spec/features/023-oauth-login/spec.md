# 023 · OAuth/LDAP Login

**Estado:** propuesta

## Qué hace
Login corporativo vía OAuth2 (Google, GitHub, Azure AD) o LDAP.

## Requisitos (EARS)
- CUANDO se configure OAuth, EL SISTEMA DEBE redirigir al provider para autenticar
- CUANDO el provider valide, EL SISTEMA DEBE crear sesión local
- DONDE se use LDAP, EL SISTEMA DEBE autenticar contra servidor LDAP/AD
- SI la autenticación externa falla, EL SISTEMA DEBE mostrar error claro

## No funcionales
- Libs: golang.org/x/oauth2, go-ldap/ldap
- Providers soportados: Google, GitHub, Azure AD (OIDC)
- Config: flags --oauth-provider, --oauth-client-id, --oauth-client-secret
- LDAP: --ldap-url, --ldap-bind-dn, --ldap-base-dn

## Criterios de aceptación
- [ ] OAuth flow completo: redirect → callback → sesión
- [ ] LDAP bind → sesión
- [ ] Fallback a password local si no hay OAuth/LDAP configurado

## Fuera de alcance
- SAML
- Multi-factor auth (MFA)
- SCIM provisioning
