# Contributing

Thanks for your interest in Karambit. It is alpha software, so please open an issue before you start
a large change.

## Prerequisites

- Rust, stable toolchain (install with [rustup](https://rustup.rs))
- Xcode command line tools, for Swift (`xcode-select --install`)
- Node.js, for the desktop app

## Build and test

```sh
cargo test --workspace --exclude karambit-gui
(cd se-helper && swift build)
(cd app && npm test)
```

Tests run the same in a plain terminal, in CI and inside an AI agent session: `.cargo/config.toml` gives every test process a synthetic agent marker, and tests that need a human caller clear the agent lists in their own config.

## Ground rules

- Never put real secrets in tests, fixtures, issues, logs or pull requests. Use synthetic values only,
  such as `synthetic-test-secret`.
- Keep pull requests small and focused on one change.
- A security-sensitive change must update [docs/threat-model.md](docs/threat-model.md) in the same pull
  request. Do not weaken a stated guarantee, and do not add a claim the threat model does not support.

## Reporting security problems

Do not report vulnerabilities in a public issue or pull request. Follow [SECURITY.md](SECURITY.md).

## License

Karambit is licensed under the Apache License 2.0. By submitting a contribution, you agree that it is
licensed under the same terms, as Section 5 of the license describes. You do not need to sign a
Developer Certificate of Origin or a CLA.
