# Changelog

All notable changes to Karambit are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Folder YOLO: one Touch ID grants up to 7 days of temporary access to a folder's non-public keys,
  including Only me keys and keys added, moved in or given a new value through Karambit.
  Keys keep their access level and encryption at rest. Public keys and output redaction stay unchanged.
- `karambit yolo start FOLDER --to GRANTEE --hours N`, `yolo end FOLDER [--to GRANTEE]` and `yolo ls [--json]`.
  YOLO has one RAM-only record per folder and grantee, separate from a key's 8 temporary accesses.
  It ends on expiry, End, agent blocking or daemon restart, and continues through screen lock.
- App YOLO dialog, folder and key tags, per-agent banners and Status rows with separate End buttons.
  The dialog defaults to 6 hours. A dedicated helper approval names Only me keys and keys added later;
  the upgrade requires the normal helper and daemon re-pin.
- `karambit mv OLD NEW` renames a secret, and `karambit mv OLD/ NEW/` moves a folder. Value, access
  level and backup copy are kept; it is human-only, asks for Touch ID and ends temporary access.
- A secret can hold up to 8 leases, one for each agent or session. A new grant replaces only that
  agent's lease. A use is served by one lease and scopes are never combined. `karambit lease revoke NAME --to AGENT`
  ends one; without `--to` it ends all. The app lists each temporary access with its own End button.
- App: an Edit button for secrets (name, value and access) and "Rename or move" in the folder menu.

### Fixed

- App End all temporary access now ends per-key access and YOLO records together in the daemon.
  Its warning includes ancestor YOLOs even when the selected key is not covered. Exact key names
  no longer select same-named folders. Background refresh keeps access dialog drafts unchanged.
  Failed YOLO queries report an error or unknown state instead of hiding active access.
- Key inspectors and secret details show covering YOLO records with scoped End buttons and active
  override explanations, while keeping the stored access level visible.

### Changed

- Granting a lease to one agent no longer replaces another agent's lease on the same secret.
  `karambit ls --json` and `brief` list every lease (`leases`); `lease` stays as the one that ends first.

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
