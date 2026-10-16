# JeffOps.Authentication

Reusable authentication and authorization libraries for multi-tenant .NET 10 applications. It has three parts:

- an OpenID Connect token server built on OpenIddict
- permission-based authorization evaluated locally in each service
- client libraries for SPAs (through a BFF), web apps, native apps, CLIs and services

> Status: **pre-release**. All roadmap phases are implemented and tested, but nothing is published to NuGet yet and the
> public API may still change.

## What's in it

- **Token server:** authorization code + PKCE, refresh with live revalidation, client credentials, personal access tokens,
  userinfo, end-session, back-channel logout, PAR, device flow, `private_key_jwt`, DPoP, workload identity federation;
  signing keys in the database or Azure Key Vault.
- **Sign-in:** any OpenID Connect provider, Microsoft Entra, SAML 2.0, and local accounts (passwords, TOTP, recovery codes,
  passkeys, lockout, verification, reset), with a hosted login UI.
- **Enterprise:** DNS-verified tenant domains, per-tenant SSO and SSO-only, SCIM 2.0 provisioning of users and groups.
- **Delegation:** impersonation with the target's approval (and break-glass), lockbox tenant access, tenant switch.
- **Authorization:** permissions with wildcards, scopes, roles, attribute policies, ceilings (PAT, delegation, step-up,
  impersonation), and management with four-eyes approval, break-glass, recertification, group role assignments.
- **Clients:** JWT validation for resource services (with DPoP), service tokens, and a backend-for-frontend with YARP,
  including acting sessions for impersonation and tenant switch.

## Getting started

[docs/getting-started.md](docs/getting-started.md) walks through a token server, an API with permissions, a SPA behind the
BFF and service-to-service calls, with the configuration for each.

## Design

Everything is in [docs/DESIGN.md](docs/DESIGN.md): the goals, architecture, package map, security baseline, decisions and roadmap.

Key rules:

- **Clean Architecture + vertical slices + minimal APIs.** Code is organised by use case. Endpoints call handlers directly, with no mediator library.
- **Free, permissive dependencies only** (MIT, Apache-2.0, BSD). `BannedPackages.txt` lists banned packages, and the build fails if a project references one.
- **Architecture tests** enforce the dependency rules, slice isolation, handler registration and the package policy.

## Build and test

Requires the .NET 10 SDK. `global.json` pins the SDK version and selects Microsoft.Testing.Platform as the test runner.

```bash
dotnet build JeffOps.Authentication.slnx -c Release
dotnet test --solution JeffOps.Authentication.slnx -c Release
```

Release builds are strict: warnings are errors, analyzers and code style are enforced, and transitive NuGet audit is on. Debug builds skip analyzers so local builds are faster.

## Layout

```
src/
  Shared/           SharedKernel, Abstractions
  Authentication/   Domain, Application, Infrastructure, Persistence.SqlServer, Endpoints, UI
    Plugins/        KeyVault, Federation.Entra, Federation.Oidc, Federation.Saml
    Modules/        LocalAccounts, Delegation, Enterprise (each with a .SqlServer package)
  Authorization/    Domain, Application, Infrastructure, Persistence.SqlServer, Endpoints, AspNetCore
  Clients/          Client, Bff, Bff.Yarp
  Common/           Security.AspNetCore, Entitlements, Testing
tests/              one test project per src project, plus Architecture.Tests
```

## Licence

[Apache-2.0](LICENSE).
