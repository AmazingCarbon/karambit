# Security policy

## Reporting a vulnerability

Report vulnerabilities privately. Do not open a public issue, pull request or discussion about one.

1. Open the repository's **Security** tab and choose **Report a vulnerability**.
   You can also go straight to <https://github.com/AmazingCarbon/karambit/security/advisories/new>.
2. Describe the problem and include the details listed below.

The report stays private until the maintainer publishes an advisory.

### What to include

- The Karambit version or commit, and your macOS version.
- Steps to reproduce, or a proof of concept.
- What you expected to happen, and what happened.
- The guarantee you think is broken, and the impact.

Use synthetic secret values in every report, for example `synthetic-test-secret`. Never send a real
secret.

### What to expect

Karambit is maintained by one person, so responses are best effort. The maintainer aims to
acknowledge a report within 7 days. After that, the maintainer will confirm whether the report is in
scope and agree on a fix and a disclosure date with you.

## Supported versions

Karambit is alpha software. Only the latest release receives security fixes.

## Scope

In scope:

- the `karambit` CLI and daemon (`crates/`)
- the Secure Enclave helper (`se-helper/`)
- the desktop app (`app/`)

Out of scope:

- The same-user limits listed in [docs/threat-model.md](docs/threat-model.md). They are known and
  documented, so they are not vulnerabilities. A way to break a guarantee that the threat model says
  Karambit does make is in scope.

Read the full [threat model](docs/threat-model.md) to see which guarantees Karambit makes and which
it does not.
