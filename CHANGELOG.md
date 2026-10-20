# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/) from 1.0 on.

## [Unreleased]

## [0.1.0-alpha] - 2026-10-20

First public preview.

### Added

- **Token server** on OpenIddict: authorization code + PKCE, refresh with live revalidation, client credentials, personal
  access tokens, userinfo, end-session, back-channel logout, pushed authorization requests, device authorization grant,
  `private_key_jwt`, DPoP (with server nonces and `dpop_jkt`), workload identity federation; signing keys in the database or Azure Key Vault.
- **Sign-in**: OpenID Connect providers, Microsoft Entra, SAML 2.0 (signed requests, IdP-initiated logout), local accounts (passwords, TOTP, recovery codes,
  passkeys, lockout, verification, reset) and a hosted login UI.
- **Enterprise**: DNS-verified tenant domains, per-tenant SSO and SSO-only, SCIM 2.0 provisioning of users and groups.
- **Tenancy**: tenants shared across products, with memberships from linked Entra directories, invitations, tenant SSO, SCIM
  and product signup; tenant administrators and platform operators, and the policies the token server and Enterprise use.
- **Delegation**: impersonation with target approval and break-glass, lockbox tenant access, tenant switch.
- **Authorization**: permissions, scopes, roles, attribute policies, ceilings, and management with four-eyes approval,
  break-glass, recertification and group role assignments.
- **Clients**: JWT validation (with DPoP) for resource services, service tokens, a backend-for-frontend with YARP.
- **Entitlements**: `RequireEntitlement` endpoint convention answering 402.
- **Testing**: an in-memory test token issuer and fakes for consumers' tests.
- **Providers per client** (`Clients[].Providers`): each product signs in through its own app registration at the provider
  (its own consent screen); the login page names the client and offers only its providers. Entra `Scopes` is configurable.

### Security

- **Hardening from a full security review (2026-10):** the token server's own APIs accept only tokens issued for them
  (`account` scope, audience `jeffops-account`; the BFF fetches one for `/bff/account/*`); tokens from personal access tokens
  never act as the user's own session; platform administrators get no personal access tokens; a tenant's provider claims
  only accounts its provisioning created, other existing accounts are linked after their owner confirms; verified domains are
  re-checked daily and operators can revoke them.
- Delegated administration is held to a ceiling; tenant headers scope only service tokens and the BFF strips them; ABAC
  treats missing attributes as unknown (Deny fails closed); role-change requests expire and can't be decided twice;
  device-flow confirmation names the real client; local sign-in counts parallel guesses and caps emailed codes.
  `prompt=login` and `max_age` reach upstream providers, and their older authentication is refused. The email-domain
  allow-list needs verified emails. SAML metadata downloads are bounded, and cached metadata is bound to its source.
  Providers without certificates are refused. Suspended tenants' SCIM, providers and domains stop working.
- Rate limits are on by default (`JeffOps:RateLimiting`). Clients removed from configuration are deleted. Token keys stay
  consistent across instances, and outside Development the Data Protection key ring must be persisted and encrypted
  (`JeffOps:DataProtection:KeyDirectory` is new). BFF and PAT cache entries are bound to their keys: BFF users sign in once
  more after upgrading. DPoP proofs may be dated at most a minute ahead, with a per-key quota at resource services. CI pins
  actions to commits, restores from lock files and nuget.org only, releases only tags on `main`, and attests provenance.
- PKCE is S256 only; client assertions are single-use; end-session signs out without asking only for a request that names
  the session (`id_token_hint`), otherwise the user confirms. Impersonation tokens never carry `step_up` and get no ID
  token; step-up expires with `Mfa:StepUpMaxAge`. Local registration follows the email-domain policy, recovery codes are
  80-bit (earlier 40-bit codes are refused; users generate new ones), and a reset that verifies an email removes earlier
  second factors. SCIM tokens can expire and SCIM writes are audited; SAML assertions must be encrypted with RSA-OAEP
  and AES-GCM. Resource services accept only `at+jwt` access tokens. Outside Development, `AllowedHosts: *`, unlisted
  proxy hops, short decision-cache keys and placeholder client secrets fail startup.

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

[Unreleased]: https://github.com/JeffWouters/JeffOps.Authentication/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/JeffWouters/JeffOps.Authentication/releases/tag/v0.1.0-alpha
