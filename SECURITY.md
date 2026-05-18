# Security Policy

## Reporting a Vulnerability

If you find a security issue in sec-audit itself (e.g. privilege escalation, credential leak in output, unsafe shell injection), **do not open a public issue**.

Report privately via GitHub: [Security → Report a vulnerability](../../security/advisories/new)

Please include:
- A description of the issue and its impact
- Steps to reproduce
- Affected version (git commit or tag)

I aim to respond within 72 hours and to release a fix within 14 days of confirmation.

## Scope

In scope: the sec-audit binary itself — code execution, output handling, file parsing, privilege misuse.

Out of scope: findings that sec-audit *reports about your system* (those are intentional, that's the point).
