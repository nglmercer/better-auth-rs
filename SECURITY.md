# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Report it privately through
GitHub's security advisory form for this repository (Security tab, "Report a
vulnerability"). If that form is unavailable, contact the maintainers through the
address listed on the repository profile.

Include the affected version or commit, the configuration, and steps to reproduce.
Do not include live credentials or real user data.

## Response targets

These are targets for a project in early development, not commitments:

- Acknowledge a report within 3 business days.
- Confirm or reject it within 10 business days.
- Ship a fix or a documented mitigation for confirmed issues before disclosure.

## Supported versions

No release is supported yet. The `main` branch is the only line receiving fixes.
The support table will appear here with the first release candidate.

## Known accepted risks

Dependency advisories accepted for now are listed in
[docs/supply-chain.md](docs/supply-chain.md). Each one names the parent crate and
the change that would remove it.
