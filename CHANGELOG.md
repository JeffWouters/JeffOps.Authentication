# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/) from 1.0 on.

## [Unreleased]

First public preview (`0.1.0-alpha`).

### Added

- **Token server** on OpenIddict: authorization code + PKCE, refresh with live revalidation, client credentials, personal
  access tokens, userinfo, end-session, back-channel logout, pushed authorization requests, device authorization grant,
  `private_key_jwt`, DPoP (with server nonces and `dpop_jkt`), workload identity federation; signing keys in the database or Azure Key Vault.
- **Sign-in**: OpenID Connect providers, Microsoft Entra, SAML 2.0 (signed requests, IdP-initiated logout), local accounts (passwords, TOTP, recovery codes,
  passkeys, lockout, verification, reset) and a hosted login UI.
- **Enterprise**: DNS-verified tenant domains, per-tenant SSO and SSO-only, SCIM 2.0 provisioning of users and groups.
- **Delegation**: impersonation with target approval and break-glass, lockbox tenant access, tenant switch.
- **Authorization**: permissions, scopes, roles, attribute policies, ceilings, and management with four-eyes approval,
  break-glass, recertification and group role assignments.
- **Clients**: JWT validation (with DPoP) for resource services, service tokens, a backend-for-frontend with YARP.
- **Entitlements**: `RequireEntitlement` endpoint convention answering 402.
- **Testing**: an in-memory test token issuer and fakes for consumers' tests.

### Security

Fixed before the first release, from an independent review of DPoP, SAML, delegation and SCIM (see the commit history for
details): DPoP-bound tokens are enforced on the token server's own APIs and as actor tokens; SAML responses are bound to the
signed assertion (rewrapped assertions were accepted); SCIM can only provision addresses in the tenant's verified domains;
partner impersonation honours lockbox approval and the relationship's ceiling; creating SCIM tokens needs the
`auth.enterprise.scim_tokens` policy. `AccessLevel.Delegated` now ranks below
`Organization`. Fuzz tests cover the DPoP proof validator and the SCIM parsers.

### Dependencies

- Only permissively licensed packages, without exceptions: `Microsoft.Data.SqlClient` 7.x (Entra authentication to SQL
  Server is now its optional `Microsoft.Data.SqlClient.Extensions.Azure` package), and SqlClient's proprietary native
  networking is excluded in favour of its managed networking. Consumers who want the same: see docs/DESIGN.md §6.5.
