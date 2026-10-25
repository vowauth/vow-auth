# Security

vow-auth decides who gets in, so a weakness here is a weakness of every application that uses it.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue.

Please include what you found, how to reproduce it and what an attacker gains. We confirm receipt within three working days and keep you informed until a fix is released. We credit reporters who want it.

## Supported versions

Nothing is released yet. Until the first release, fixes go to the development branch.

## How the code is checked

- Every change runs the tests, Biome, the type checker and knip.
- CodeQL (`security-extended`) and Semgrep with the project's own rules (`semgrep/`) look for vulnerable code; each rule has tests.
- `pnpm audit` and Dependabot watch the dependencies.
- The guarantees about who can issue access, and the tests that hold them, are in `docs/issuance.md`.
