# Changelog

All notable changes to Karambit are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `karambit mv OLD NEW` renames a secret, and `karambit mv OLD/ NEW/` moves a folder. Value, access
  level and backup copy are kept; it is human-only, asks for Touch ID and ends temporary access.
- App: an Edit button for secrets (name, value and access) and "Rename or move…" in the folder menu.

## [0.1.0] - 2026-10-29

Alpha. Not independently audited. macOS only for now. See the [threat model](docs/threat-model.md)
for what Karambit does and does not protect.

### Added

- Encrypted local vault. Each secret has its own key, and Secure Enclave keys that cannot be exported
  wrap those keys.
- Four access levels per secret: public, agents, agents with Touch ID, and only me with Touch ID.
- Touch ID for secrets that need it, enforced by the Secure Enclave for unwraps through the helper.
- `karambit run`: starts a program with the secrets it asks for, and redacts exact copies of non-public
  values from its stdout and stderr.
- Leases: temporary agent access, limited by time, folder, command and number of uses. `block` refuses
  agent requests until you unblock.
- AWS profiles, and AWS IAM Identity Center (SSO) sign-in. The AWS CLI and SDKs get credentials through a
  local endpoint.
- Paper backup key, with `karambit recover` and `backup verify`.
- `karambit secure`: moves `.env` files into the vault and writes a `.env.schema` with no values.
  `secure rebuild` puts the original files back.
- `karambit doctor --agent-env`: checks what the current environment can reach, for that run only.
- `karambit call`: one fixed CI build-status request (Jenkins-compatible API). Not a general broker.
- `run --jail`: experimental macOS sandbox. Not a security boundary.
- Desktop app. Copying a value to the clipboard clears it after a set time.
- Hash-chained audit log. Writes are best effort, and the log is not tamper-proof.

[0.1.0]: https://github.com/AmazingCarbon/karambit/releases/tag/v0.1.0
