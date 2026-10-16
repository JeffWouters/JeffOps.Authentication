# Security policy

JeffOps.Authentication is security software. We treat every report seriously and are grateful for responsible
disclosure.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" on the repository's **Security** tab, or directly at
<https://github.com/JeffWouters/JeffOps.Authentication/security/advisories/new>).

Please include:

- the affected package(s) and version(s);
- a description of the issue and its impact;
- steps or a minimal proof of concept to reproduce it;
- any suggested fix or mitigation.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment and severity (CVSS) | within 10 working days |
| Fix for critical or high severity | as fast as possible, normally within 30 days |
| Public advisory and credit (if you want it) | when a fixed version is available |

We coordinate the disclosure date with you and publish a GitHub security advisory (with a CVE where applicable) together
with the fixed packages.

## Supported versions

Until 1.0, only the latest preview receives fixes. From 1.0 on, the latest minor version of the current major version is
supported, and critical fixes are back-ported to the previous major version for six months after a new major release.

## Scope

In scope: everything published from this repository (`JeffOps.Authentication.*`, `JeffOps.Authorization.*`,
`JeffOps.Security.AspNetCore`, `JeffOps.Entitlements`). Out of scope: vulnerabilities in dependencies (report them
upstream; we update promptly), and findings that require a misconfiguration the documentation warns against.

## Hardening notes for deployers

- Run the token server over HTTPS only, behind a proxy that forwards the original scheme and host.
- Keep signing keys out of the database where possible (Azure Key Vault / Managed HSM plug-in), and share the Data
  Protection key ring between replicas through a protected store.
- Leave local accounts off in production unless you need them, and plug in a real `IAccountEmailSender` and `INotifier`.
- Use DPoP or `private_key_jwt` for high-value clients, and workload identity federation instead of stored secrets for CI.
- Keep `Mfa:RequireForSensitiveActions` on.
