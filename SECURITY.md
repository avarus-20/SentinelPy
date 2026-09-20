# Security Policy

## Scope

SentinelPy is a **local CLI** for authorized, read-only review of HTTP response headers on a **single URL**. It is not a hosted scanner.

## Supported versions

Current stable release: **[v1.3.0](https://github.com/avarus-20/SentinelPy/releases/tag/v1.3.0)**. Report security issues against the latest **1.3.x** tag when possible.

| Version | Supported |
| --- | --- |
| 1.3.x | yes |
| 1.2.x | yes (maintenance; upgrade to 1.3.x recommended) |
| 1.1.x | best effort |
| 1.0.x | best effort |
| < 1.0 | no |

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories for this repository, or contact the maintainer through GitHub.

Do **not** open public issues for exploitable vulnerabilities.

Include:

- Description and impact
- Steps to reproduce with **synthetic** targets only
- Suggested fix if available

## Out of scope

- Findings about missing headers on third-party sites you do not own
- Requests to add bypass, exploitation, or credential testing features
