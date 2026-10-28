# SYNTHETIC legacy (v1-format) migration fixtures

- Source: the crypto/store code of release 0.1.0.
- Generated: 2026-10-04 (UTC).
- Generator: `crates/core/tests/core.rs`, `legacy_fixtures::generate_legacy_fixtures`.
- Production crypto/store source is unchanged from that release; `crypto::CURRENT_V = 2`.
- No live vault, Secure Enclave, installed binary, AWS or Vault service was used.

## Regeneration

From a checkout of the source revision with this test harness and these synthetic key files applied (optionally with `CARGO_TARGET_DIR` set to a scratch directory):

```sh
cargo test -q -p karambit-core -- --ignored generate_legacy_fixtures
cargo test -q -p karambit-core
```

Do not regenerate with later crypto/store code: these are frozen compatibility inputs, not round-trip outputs from the future reader. Review any regeneration diff. Ephemeral keys, DEKs, nonces and age encryption randomness intentionally change ciphertext on regeneration. The P-256 scalars and existing age identity remain fixed. If the age identity file is missing, the generator creates a new **synthetic** one and updates the associated backup and config recipient.

The generator uses `make_p`, `crypto::wrap_dek`, `seal`, `backup_wrap` and `store::save_secret`/`save_config`. The private `crypto::aad` is not accessed: v1 uses the baseline's public `crypto::wrap_with_aad` with the historical literal `karambit/v1/dek/{tier}/{agent_allowed as u8}/{name}`. Only default optional JSON fields are removed after serialization; encrypted bytes remain intact. A v1 envelope is not merely a v2 version-field edit.

## Inventory

All six JSON envelopes contain `eph`, `wrap_nonce`, `wrapped_dek`, `nonce`, `ct`, policy fields and timestamps. Exact plaintext for each is `SYNTHETIC pre-M1 <name> plaintext` (this exact string is frozen inside the ciphertext; do not change it) (UTF-8, no trailing newline).

| File under this directory | Version | Tier | Effective key | Optional fields |
|---|---|---|---|---|
| `secrets/v1/open.json` | 1 | open | open (implicit) | key/public/backup absent |
| `secrets/v1/bio.json` | 1 | bio | bio (implicit) | key/public/backup absent |
| `secrets/v1/agent.json` | 1 | open | agent (explicit) | public/backup absent; agent_allowed=true |
| `secrets/v2/open.json` | 2 | open | open (implicit) | key/public/backup absent |
| `secrets/v2/bio.json` | 2 | bio | bio (explicit) | public absent; age backup present |
| `secrets/v2/agent.json` | 2 | open | agent (explicit) | public=true; backup absent; agent_allowed=true |

The v1/agent combination exercises the pre-change reader's supported explicit key selection, not a claim that a particular historical release originally emitted that combination. Agent is a key ID, not a tier.

- `config.json`: baseline Config, synthetic age recipient, synthetic `.invalid` SSO portals with `limit_minutes=45` and absent `limit_minutes`.
- `minimal/config.json`: baseline Config with `backup_recipient`, `human_lease_hours`, and `sso_portals` absent, exercising load defaults.
- `SYNTHETIC-p256-keys.json`: fixed software P-256 private scalars (32 bytes of 1=open, 2=bio, 3=agent). These deliberately different keys also exercise effective key selection. **Public test material, never real keys.**
- `SYNTHETIC-age-identity.txt`: synthetic age private identity for the backup. **Public test material, never use for real secrets.**

Each envelope has its own non-ignored direct `store::load_secret` + config-load + unwrap/decrypt test. Backup recovery separately decrypts the known plaintext in the bio-v2 test. Config variants each have a direct-load test; missing config files fail rather than accidentally passing via defaults. A negative test flips one decoded ciphertext byte in memory and requires decryption failure. No test uses `list_secrets` or resolves ambient vault paths.
