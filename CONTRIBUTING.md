# Contributing

Thanks for helping. This project is a set of security libraries, so changes are reviewed with that in mind: small,
focused pull requests with tests are the easiest to accept.

## Before you start

- Read [docs/DESIGN.md](docs/DESIGN.md), especially §6 (architecture and dependency rules), §16 (security baseline) and
  the decisions (§18). Proposals that change a decision start as an issue.
- Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Building and testing

Requires the .NET SDK pinned in `global.json`.

```bash
dotnet build JeffOps.Authentication.slnx -c Release
dotnet test --solution JeffOps.Authentication.slnx -c Release
dotnet pack JeffOps.Authentication.slnx -c Release -o artifacts
```

Release builds are strict (analyzers, code style, warnings as errors, transitive NuGet audit); CI builds Release. The
architecture tests enforce the layering, slice isolation, handler registration, solution membership and the licence policy.

## How code is organised

- **Clean Architecture + vertical slices + minimal APIs.** One folder per use case under `Features/`; endpoints call
  handler interfaces directly. No mediator library, no MVC controllers.
- **Hand-written public surface.** Endpoints and public types are written and reviewed by hand; no API or code generators.
- **Time and randomness** come from `TimeProvider` and `RandomNumberGenerator` (the build bans `DateTime.UtcNow` and
  `System.Random`).
- **Errors** are `Result`/`Error` values with stable codes, answered as RFC 9457 problem details.

## Dependencies

Only free, permissively licensed packages (MIT, Apache-2.0, BSD and similar). `BannedPackages.txt` lists packages that
must never be used (for example FluentAssertions, MediatR, AutoMapper, Moq), and a test checks the licence of every
resolved package, transitive ones included. Add a dependency only when the platform can't reasonably do the job.

## Tests

- xUnit v3 with Shouldly and NSubstitute; integration tests run real hosts on `TestServer` with SQLite.
- Every behaviour change comes with a test; every security fix with a test that fails without it.
- Use `FakeTimeProvider` for anything time-dependent instead of sleeping.

## Pull requests

- Keep the change focused and describe the why.
- Update `docs/DESIGN.md` when behaviour or a decision changes, and `CHANGELOG.md` under *Unreleased*.
- Make sure the Release build and all tests pass.

By contributing you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
