# JeffOps.Authentication

Reusable authentication and authorization libraries for multi-tenant .NET 10 applications. It has three parts:

- an OpenID Connect token server built on OpenIddict
- permission-based authorization evaluated locally in each service
- client libraries for SPAs (through a BFF), web apps, native apps, CLIs and services

> Status: **phase 0, scaffold**. Packages are empty apart from the shared kernel. Do not use yet.

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
    Plugins/        KeyVault, Federation.Entra, Federation.Oidc
    Modules/        LocalAccounts, Delegation
  Authorization/    Domain, Application, Infrastructure, Persistence.SqlServer, Endpoints, AspNetCore
  Clients/          Client, Bff, Bff.Yarp
  Common/           Security.AspNetCore, Entitlements, Testing
tests/              one test project per src project, plus Architecture.Tests
```

## Licence

[Apache-2.0](LICENSE).
