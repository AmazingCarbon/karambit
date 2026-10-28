# Karambit threat model and operating modes

Status: describes the code of release 0.1.0, plus later amendments. Written to say
no more than the code does. Anything not in the code is marked **planned** and
must not be read as a current guarantee. Sources: the operating-mode definitions below, the
numbered limits in section 4 (`#2`…`#13`), and the code locations cited
inline as `file:fn`.

## Platform capabilities

Guarantees are defined by capabilities **(1)–(8)** below, not by an OS brand or
API. macOS is the current implementation; Linux/Windows entries are **candidates,
not implemented or validated equivalents**. The earlier baseline and incremental
history below retain implementation detail; their API names describe mechanisms,
not additional portable guarantees. In particular, “Touch ID” means capability
(1)'s user-presence gate, kernel identity/anchors require (2)+(3), helper/shim
binding requires (2)+(3)+(4), clipboard disclosure depends on (5), daemon-held
state on (7), and lock-ended cache reuse on (8). Encryption, policy, redaction and
audit are platform-neutral software properties, not extra OS isolation promises.
Mode A uses (1)–(4)+(7), with (8) for human cache reuse; Mode B additionally needs
(6); Mode C custody requires daemon authority (1)–(4)+(7) and request policy,
not merely a sandbox. Clipboard disclosure is separate from A/B/C.

### Capability matrix

Paths are relative to the repository. Degraded tiers below are **required port /
future doctor behavior**, not claims that today's doctor implements eight new
checks. A missing capability must never silently become a software substitute.

| Capability | Guarantee it provides | macOS implementation today (mechanism + source) | Linux candidate | Windows candidate | Degraded tier / required doctor report |
|---|---|---|---|---|---|
| **(1) Hardware-bound non-exportable key + user-presence unwrap** | Hardware keeps the private key non-exportable; protected unwrap needs user presence. Cached DEKs and no-prompt keys do not require fresh presence. | CryptoKit `SecureEnclave.P256.KeyAgreement.PrivateKey`, `.privateKeyUsage` + `.biometryCurrentSet` for bio; `WhenUnlockedThisDeviceOnly` for bio/open, `AfterFirstUnlockThisDeviceOnly` for agent (`se-helper/Sources/se-helper/main.swift:accessControl`). DEK ECDH/HKDF wrapping: `crates/core/src/crypto.rs`. No-prompt blobs remain usable by same-user programs. | TPM2 sealed/key-agreement key plus independently trusted presence authorization; TPM alone is insufficient. | TPM-backed CNG key plus verified Windows Hello/presence policy; Hello alone is not equivalent unwrap enforcement. | **No hardware/presence guarantee** if either half is absent; refuse operations requiring that half. Doctor must name the missing half (`unsupported`) or verified weakness (`fail`), never certify software keys as equivalent. |
| **(2) Kernel-attested caller identity with unforgeable process generation** | Binds authority to a process incarnation, not a caller-supplied PID. Does not prove the caller is human. | Unix socket `LOCAL_PEERTOKEN` PID + `pidversion`, live `TASK_AUDIT_TOKEN` rechecks (`crates/core/src/daemon.rs`). Helper socketpair uses `LOCAL_PEERPID` + kernel start sec/usec instead (same-microsecond residual; protocol below). | `SO_PEERCRED` plus pidfd / `SO_PEERPIDFD` where available; prove race-free peer-to-generation binding. | Named-pipe client identity, access token and retained process handle/creation identity; validate reuse/race semantics. | **No process-bound authority** without verified generation; refuse scoped redemption/cache authority relying on it. Doctor must report missing (`unsupported`) or weaker/reuse-prone identity (`fail`), not accept UID/PID alone. |
| **(3) Peer process introspection (exe, ancestry, start time, env)** | Supplies independently observed executable and ancestry for policy; agent labels remain heuristics. | `proc_pidpath`, `proc_pidinfo` (BSD start/parent and vnode cwd), `sysctl(KERN_PROCARGS2)` (`crates/core/src/agent.rs`); unreadable env disables human-anchor reuse. | `/proc/<pid>/{exe,stat,environ,cwd}` with pidfd/rechecks; ptrace/hidepid restrictions may prevent reads. | Process image query, process times and parent snapshot; environment access may require process-memory rights. | **Unverified ancestry/executable**, not “human.” Refuse dependent binding or cache reuse. Doctor must list unreadable fields (`inconclusive` if probe uncertain, `unsupported` if unavailable). |
| **(4) Pinned-binary launch channel** | Delivers only to an authenticated helper/shim and binds target/hash/argv/cwd; not immutable execution or same-user isolation. | SHA-256 paired pins, inherited fd-3 Unix socketpair and one-use helper challenge (`crates/core/src/helper.rs`, `launch.rs`, Swift `main.swift`); bound shim/target rechecks and descriptor hygiene (`daemon.rs`, `shim.rs`, all under `crates/core/src/`). Writable pins, hash-to-exec races and cooperative-exec bypass remain (below). | Pinned executable fd / `execveat`, private socketpair, pidfd-bound child and descriptor hygiene. | Pinned executable identity, restricted inherited handles/private pipe and verified child process handle. | **Unbound launch**: refuse command-scoped credential delivery; never fall back to legacy release. Doctor must report missing channel (`unsupported`) or failed pin/child binding (`fail`), including writable trust-root limits. |
| **(5) Clipboard with history/sync exclusion + auto-clear** | Reduces clipboard retention only where exclusions are honored; does not stop readers or recall copies. | `NSPasteboard` `org.nspasteboard.ConcealedType` / `TransientType`; helper sleeps then clears only if `changeCount` unchanged (`se-helper/Sources/se-helper/main.swift:cmdClip`). **No `.currentHostOnly` yet: Universal Clipboard exclusion is not guaranteed.** Markers are advisory; helper death can prevent clearing. | Wayland compositor-specific sensitive-content/history policy and timed ownership clearing; X11 generally weaker. | Clipboard history/cloud exclusion formats plus sequence-checked timed clear; verify consumer compliance. | **Clipboard retention/sync exposure** (already partial on macOS). Doctor must report known exclusion weakness (`fail`), unsupported exclusions (`unsupported`), or unverified manager behavior (`inconclusive`); timer alone is not a pass. |
| **(6) Child sandbox** | Constrains a launched process tree's filesystem/IPC/network authority; the child still holds its credential. | **Opt-in spike**: Seatbelt SPI installed by the trusted shim (`core/src/sandbox`, `shim.rs`, under `crates/`). Loopback TCP port allowlist only; remote egress needs a loopback proxy. Deprecated mechanism; not portable confinement certification. | Namespaces + seccomp + Landlock with separately enforced network policy; coverage must be tested. | AppContainer/restricted token with filesystem/IPC/network policy; Job Objects alone are not a security sandbox. | **Mode A only**, no Mode B isolation. Doctor must report `unsupported` when absent, `fail` for an enforced-policy escape, and refuse to label an unconfined run sandboxed. |
| **(7) Per-user service lifecycle** | Owns in-memory leases/sessions and stops local reuse on expiry/restart; cannot revoke already-issued upstream credentials. | Auto-spawn with `setsid`, private 0700 run directory / 0600 Unix socket, same-UID peer check, reaper and 20-minute idle exit (`crates/core/src/daemon.rs:spawn_real`, `serve`). RAM state is lost on restart; not a protected service account. | systemd user service + private authenticated socket; equivalent in-memory lifecycle. | Per-user service/agent with ACL-protected named pipe and lifecycle supervision. | **No managed session lifetime**: refuse daemon-dependent operations rather than persist secrets as fallback. Doctor must report service unavailable (`inconclusive` if temporary) or unsupported lifecycle (`unsupported`); socket reachability is not lifecycle proof. |
| **(8) Screen-lock signal** | Ends human cached authorization on lock, subject to observation latency; does not recall delivered plaintext. | Fail-closed ECDH probe of `WhenUnlocked` open key (`crates/core/src/helper.rs:screen_locked`); daemon checks cached use and five-second reaper (`daemon.rs`). Any probe error counts as locked; not a native lock notification. | logind session lock state/signals, with compositor/session-specific validation. | WTS session lock notifications plus verified current session state. | **No lock-ended cache guarantee**: disable human cache reuse and require fresh presence. Doctor must report absent signal (`unsupported`), known unreliable signal (`fail`) or uncertain observation (`inconclusive`). |

Doctor must identify the capability number, observed mechanism, lost guarantee and
refused/degraded operation. `inconclusive` and `unsupported` are never passes;
a positive result covers only the tested environment. Today's seven environment
probes (section 6) are not this capability certification. Ports and the platform
seam are pending: new OS-specific code belongs behind a small platform trait/module
with a separate macOS implementation and refusing non-macOS stub, not in core logic.

## 1. What Karambit is (and is not) protecting

Karambit keeps secret values encrypted at rest (per-secret DEK, ChaCha20-Poly1305, wrapped
using capability (1), currently Secure Enclave keys; `crates/core/src/crypto.rs`, `store.rs`) and decides who may unlock
them (`crates/core/src/lib.rs:unlock`, `daemon.rs`).

**Threat it addresses:** an AI agent, or a careless tool, that would otherwise find
plaintext in dotfiles, shell history, config, or a chat transcript; and an agent that is
not allowed a secret trying to get it through Karambit's own commands.

**Threat it does not address:** code running as your OS user that chooses to go around
Karambit (section 4). Any tool you hand a secret to.

**Secrecy is not safety.** Keeping a value out of an agent's context is not the same as
limiting what the agent can do with the access it was given. In Mode A the tool using the
credential can do anything the credential allows. Even in Mode C (planned), an agent can
still cause damage through the broker; only policy limits that. Do not read
"the agent never saw the password" as "the agent could not misuse the account."

## 2. Operating modes

Modes A, B and C classify how a **credential is used by a tool**. They do not
cover human disclosure (`get`, GUI copy): those are a separate category, described after the
table and in section 3. Each mode has its own guarantee.

| Mode | Who holds plaintext | Guarantee | Non-guarantee | Status |
|---|---|---|---|---|
| **A: Trusted-tool injection** | The tool Karambit launches (env var, or an ECS-style loopback credential endpoint) | Karambit does not write the value to disk or config. Non-public literal values Karambit resolved itself (at least 4 bytes), and SSO role credentials minted for a bound launch (added to the redaction set before the target receives them), are redacted from the child's stdout/stderr. Access is audited on a best-effort basis. A lease scopes the access served through it (any non-public secret); an agent-allowed bio secret can also be unlocked without a lease by a fresh Touch ID, and open-tier and public secrets need no lease. | A malicious or compromised tool can read, store and exfiltrate the value. Redaction is a filter on two streams, not a boundary (section 4). Ending a lease does not recall a static credential the tool already copied. | **Current**: `run`, `aws <PROFILE>`, `run --aws` |
| **B: Sandboxed execution** | The tool, inside a capability (6) sandbox | Mode A, plus capability (6): the jailed process tree cannot read other secrets (key blobs, `~/.aws`, `~/.vault-token`, the daemon socket) and egress is limited to allowed hosts. It still holds its own credential. | Sandbox escapes; platform policy coverage must be verified. The macOS candidate `sandbox-exec` is deprecated. | **Spike**: `run --jail`; limited to loopback TCP exceptions, not arbitrary host filtering. See limits below. |
| **C: Broker custody** | The Karambit daemon only | The tool never sees credential bytes. Karambit authorizes each request (fixed tool, later host/method/path) and scrubs responses within stated limits. | An agent can still do damage through the broker; only policy limits that. Scrubbing has size/encoding limits. | **Partly implemented (fixed tools only); the broader broker is planned**. Nothing in the code today. |

Mode-specific exports (`SOPS_AGE_KEY_CMD`, `--file` pipe) are Mode A
by these definitions and remain planned. This build has no credential-export command.

**Human disclosure operations** are not a credential-use mode and are not Mode A, B or C:
`get` (clipboard or `--stdout`) and GUI copy hand the plaintext to a human, or to whatever
reads the clipboard or stdout, with no tool launched and no redaction. Their gates are
listed per operation in section 3. Other operations that touch plaintext (GUI "add") are
also outside A/B/C. The claim here is only that A/B/C cover credential use by tools; this
document does not claim every plaintext path fits one of them.

## 3. Existing commands mapped to modes

Verified against `crates/cli/src/main.rs`, `crates/core/src/*.rs`,
`app/src-tauri/src/main.rs` in release 0.1.0.

| Command | Mode | What happens (code) | Holds plaintext |
|---|---|---|---|
| `karambit run -e VAR=ref -- cmd` | **A** | `cmd_run` calls the bound owner API; a pinned child shim redeems a single-use bound launch, then execs the canonical target with an explicit **environment**. Owner stdout/stderr pumps apply `Redactor`. | child process (and its env, readable by same-user processes while it runs, #8) |
| `karambit run -- cmd` with `.karambit.env` | **A** | same, refs from `./.karambit.env` (`main.rs:env_specs`) | child |
| `karambit run --aws P -- cmd`, `karambit aws P -- cmd`, `whoami` | **A** | Bound redemption creates a per-run daemon loopback endpoint; the shim receives only endpoint URI/token and region, never AWS keys. Child gets empty AWS config files. Endpoint lifetime follows the target, including failed exec cleanup. Static key parts and the endpoint token are redacted. | the AWS SDK/CLI in the child, after fetching from the endpoint |
| `karambit run --no-redact` | **A**, without redaction | human-only (`fence::Verb::NoRedact`, CLI lookup in `launch_bound` and daemon lookup for `RunUnredacted`); child inherits the terminal. | child |
| `karambit get NAME` | Human disclosure (not A/B/C) | `main.rs:Cmd::Get`: refused for agent callers unless the entry is public (`fence::Verb::Get` CLI lookup in `Cmd::Get`); then `unlock("get", …, gate_open=true)`. Fresh auth depends on the entry: **open-tier** secrets get a Touch ID from the reveal gate (`lib.rs:448-449`); **bio** secrets get it only by unwrapping through the helper, which is **skipped** if a human self-lease ("Only me + Touch ID": bio, agents off, not public) is active, because `unlock` serves it from the daemon with no new prompt until the screen locks or the lease is revoked (`lib.rs:405-426`, `452-459`, `daemon.rs:Req::Use` non-agent branch, `daemon.rs:508-530`). Public entries never prompt. The caller counts as human whenever agent detection did not fire (section 4). Value goes to the clipboard via the helper (`helper.rs:clip`, auto-clears after `clip_seconds`, default 30). | the human; the clipboard until cleared |
| `karambit get NAME --stdout` | Human disclosure (not A/B/C) | same gates as `get`; writes the value to stdout. No redaction, so if anything captures that stdout the value is captured. | whoever reads stdout |
| GUI "copy" | Human disclosure (not A/B/C) | `app/src-tauri/src/main.rs:copy_secret` (`:65-69`): `unlock("copy", …, gate_open=true)` then `helper::clip`; the same gates as `get` apply, including the human self-lease exception (a leased bio secret is copied with no fresh Touch ID). The GUI process is the caller (`Caller::gui()`, treated as human). The Rust side returns only the seconds-to-clear number, not the value, to the webview. The helper sets the pasteboard with `org.nspasteboard.ConcealedType`/`TransientType` markers and clears after N seconds if unchanged (`se-helper/.../main.swift`). | the human; the clipboard until cleared (any same-user process can read the pasteboard meanwhile) |
| GUI "add" (new secret) | not an injection; outside A/B/C | Creating a new name needs **no** Touch ID (`lib.rs:285-287,316-317`); only overwrite authenticates. `app/src-tauri/src/main.rs:add` takes the value from the webview as a string: the webview process does hold plaintext at entry time. (A native secure input path is not implemented.) | GUI webview, briefly |
| GUI/CLI "delete" | no plaintext | Agent callers are refused outright, with no prompt: `fence::Verb::Rm` is checked in the CLI (`lib.rs:remove`, `:890-891`) and in the daemon (`fence::request_verb` maps `Req::Delete` to `Rm`). For a human (including the GUI, `app/src-tauri/src/main.rs:60-62`), `lib.rs:remove_internal` (`:901-902`) asks for Touch ID only if any target is bio tier; deleting open-tier secrets is not prompted. | n/a |
| `list`, `status`, `policy`, `lease *`, `audit` | no plaintext | metadata only | n/a |

Notes on what Mode A redaction actually covers (`shim.rs`, `redact.rs`):
- It covers surviving non-public assignments, static AWS key parts and the endpoint
  bearer token. Public values are deliberately not redacted. Intent-before-effect
  run-child and launch audit records remain mandatory.
- AWS-profile paths keep keys out of env/argv. Plain env injection can explicitly
  inject AWS-named variables; the shared ambient scrub removes listed inherited
  credentials. Reserved AWS names are removed on profile launches.
- SSO role credentials are minted by the daemon after launch. For a bound launch the owner keeps
  its redaction connection open; before the daemon answers a credential fetch it sends the new
  access key id, secret key and session token to the owner and waits (2 s) for the owner to add
  them to its filter, else it answers 503 and serves nothing. They stay out of env/argv and are
  scrubbed from output like static keys. Endpoints without an owner (`--no-redact`, legacy
  `AwsOpen`) have no filter to inform. `--no-redact` is recorded when it is approved: `RunUnredacted`
  stores a short-lived (120 s) approval for that owner and command, `LaunchPrepare{no_redact}` spends it
  (a bare flag without it is refused), and the resulting endpoint carries `unredacted` for its whole
  life, so credential refresh keeps working after the prepare deadline. Any other SSO endpoint still
  fails closed ("redaction feed ended") once its owner's feed is gone.
- Values shorter than 4 bytes are not redacted (`redact.rs:MIN_REDACT_LEN`). Values of
  32+ bytes are also matched as 16-byte fragments so truncated copies are caught.
- Only the child's stdout and stderr are filtered. Files it writes, the network, `/dev/tty`
  and anything else the child does are not.
- A value a child fetches on its own (for example `aws secretsmanager get-secret-value`
  from inside a `run`) is not Karambit-resolved and is **not** redacted (limit **#13**,
  open until Mode C, or read-only roles without
  `GetSecretValue`).

## 4. Same-user limits

All of the following are true in release 0.1.0. They are stated so neither the README nor the docs
imply otherwise. The only hard boundary against a determined
same-user process is capability (1)'s fresh user-presence unwrap (`bio`, currently Touch ID); everything else below is enforced in software
that the same user can edit, replace, or bypass.

Numbers refer to the numbered limits in this section; "fix" column is the planned mitigation, if
any. Nothing in that column is implemented yet.

| # | Limit | Evidence | Planned |
|---|---|---|---|
| #6 | **No-prompt keys are usable by any process running as you.** `open.key` and `agent.key` are files; the Secure Enclave binds them to this Mac, not to Karambit. A 20-line foreign program using CryptoKit decrypted no-prompt secrets without Karambit (verified in testing). So Public and Agents-level secrets are readable by any code you run outside a jail. | limit #6; README Limits | Keychain ACL spike, code-signature check: not implemented. Separate macOS user: not implemented. Mode B jail hides blobs only for jailed trees. |
| #8 | **Injected env is readable by same-user processes** while the child runs (for example `ps -E`). AWS-profile delivery (`aws <PROFILE>`/`run --aws`) uses the loopback endpoint instead; ordinary `run -e`, including AWS-named variables, uses the env (`cmd_run`). | `shim.rs` explicit target envp; limit #8 | `--file`/pipe delivery is not implemented; the doctor can check sibling env |
| #9 | **Redaction is defeated by re-encoding.** It matches literal bytes (plus 16-byte fragments for long values). base64, hex, URL-encoding, splitting with inserted bytes, or short values are not caught. Redaction firing does not prove a leak; redaction not firing does not prove safety. | `redact.rs`; limit #9 | encoding-aware redaction + short-value warnings: not implemented |
| #12 | **AWS SSO access levels are daemon-enforced, not Secure Enclave-enforced.** One SSO session can mint any role the user has in that portal. The daemon enforces levels from what you approved at login, not from vault files. It holds against agents that go through Karambit or the daemon socket; a process able to read daemon memory could take SSO tokens (needs debugger rights with SIP on; untested). Role credentials already handed out stay valid at AWS until their own expiry after a sign-out or limit. | limit #12; README §AWS SSO | by design; no step |
| #13 | Secrets Manager values a child fetches itself are not redacted (section 3). Open. | limit #13 | Mode C or read-only roles |

Other limits, same source, all open in release 0.1.0:

- **Agent detection is a speed bump** (`agent.rs`, module doc): parent process names plus
  env markers. A process that double-forks and scrubs its env looks like a human (verified in testing). Agents that are not in the list are logged as a human
  (#10; the list is `store.rs` `agent_process_names`, and it includes Hermes).
- **package.json scripts are pinned with the schema, but only against agents.** `secure` wires
  `karambit run --` into npm scripts, so a changed script could send secrets to another command.
  Trusting a `.env.schema` also pins the SHA-256 of the sibling `package.json` `scripts`
  (`policy/profile.rs`, `trusted_scripts` in config); a change makes the profile
  `profile.untrusted` for agents. A human still only gets a warning and the Touch ID prompt's
  command line, and a same-user process can edit the config pin. Scripts of other
  package.json files (parent directories, workspaces) are not pinned.
- **`ssh localhost karambit ...` (Remote Login).** A same-user agent that appends its key to
  `~/.ssh/authorized_keys` gets a chain `sshd > shell > karambit` with no agent in it. `Caller.remote`
  is set when `sshd`/`sshd-session` is an ancestor or the process has `SSH_CONNECTION`/`SSH_TTY`
  (daemon: kernel ancestry and initial env of the socket peer; CLI: own env). `fence::require_human`
  now also refuses a remote caller for every fenced verb at both layers unless config
  `allow_ssh_human` is true (default off; enabling it is a relaxing change: human-only, Touch ID,
  refused from a remote caller). The audit row carries `remote`. Not closed: the env check can be
  cleared, and secrets an agent may use (open tier, agent leases) are reachable the same way; keep
  Remote Login off (`doctor` row `remote-login`). Beyond the fenced verbs, bound launches
  (`launch_authorizations`) and the legacy `Unlock`/`Use`/`HumanUnlock` paths treat a remote caller's
  `NeedsFreshAuth` and `HumanCached` decisions as `Deny` (`run_authorization`, `human_cache_eligible`), so
  no Touch ID prompt is raised and no human self-lease is spent for an SSH caller; with `allow_ssh_human`
  on, the ordinary prompt path returns.
- **Human privilege rests on "not detected as an agent".** Human-only actions look up
  `fence::AGENT_DENIED_VERBS`, which refuses only when the agent *was* detected
  (`fence::require_human`) or the caller is remote over SSH (above). A failed detection is treated as a human. The 3h "Only me + Touch ID"
  self-lease now additionally requires the same kernel-resolved terminal-app/Karambit GUI
  ancestor (PID + start time), bound by a daemon-observed Bio unwrap.
  Arbitrary app bundles, launchd, shells, SSH and multiplexers are not anchors. No anchor means
  fresh Touch ID and no cache creation/reuse. Same-app tabs share the cache; undetected code
  under that anchor and same-user GUI automation remain risks. Revoke, expiry and screen lock clear it.
- **Interpreters in a lease scope**: `node`, `python*`, `ruby`, `perl`, `php`, `deno`, `bun`,
  `java`, `osascript`, `lua`, `Rscript` and `pwsh` are refused as a bare `--cmd`, like shells. A
  `--script FILE` lease pins (interpreter path+hash, argv[1] path+hash) and refuses inline-code flags
  (`-e -c -m -p -r --eval --print --require --import`). Imported modules, config and environment
  (`NODE_OPTIONS`, `PYTHONSTARTUP`, ...) are not covered; the hash-to-exec race remains.
- **Lease grant prompt is never truncated**: the grant and human-unlock prompts list
  `N secrets: names`; a names list or scope that exceeds the helper's 120-character field is refused.
- **Lease `--cmd` scope trusts the program path the client reports** (#2, partial): a
  guardrail, not a guarantee (`main.rs:resolve_program`, `lib.rs:unlock` passes `run_cmd`).
  Kernel-reported path and argv/exe-hash binding: implemented (see bound redemption below).
- **Typed prompts are not caller authorization** (#5): typed prompts replace the historical
  caller-supplied `--reason` with fixed Swift templates and bounded quoted parameters.
  Direct callers can select a valid template but now fail the independent Swift
  caller gate. Semantic daemon routing and receiver enforcement are described below.
- **Audit is tamper-evident only against accident** (#7): the hash chain is unkeyed
  SHA-256 (`audit.rs:hash`); a full consistent rewrite by a same-user process passes
  `audit --verify`. Also `lib.rs:audit` discards write errors (`let _ = audit::log`), and
  `audited()` runs the operation and logs afterwards (`lib.rs:audited`), so a failed audit
  write does not stop a dispense. Intent-before-dispense ordering: implemented. Signed/anchored
  audit: not implemented. Rotation (16 MB segments) keeps the chain across files; removing the oldest
  segments is indistinguishable from a deliberate trim, so `--verify` reports it as
  "older part removed", not as tampering.
- **Config, pin file and binaries are user-writable**: `config.json`, the helper SHA-256
  pin (`keys/helper.sha256`), and `~/.local/bin` binaries can be edited by any same-user
  process. Root-owned binaries are not implemented.
- **`KARAMBIT_DEV=1` + `KARAMBIT_SE_HELPER` override exists only in debug builds**
  (`#[cfg(debug_assertions)]` in `helper.rs:locate`); release builds always go through the
  helper pin check (#11). Builds installed before this change still carry the override.
- **GUI is treated as the human caller** (`Caller::gui()`). There is no blanket Touch ID on
  GUI actions; gates are per operation: copy = `get` rules (human self-lease bypass, above);
  creating a new secret = no prompt; overwrite = Touch ID (`lib.rs:316-317`); delete = Touch
  ID only for bio targets (`lib.rs:901-902`), and agent callers are refused outright (`fence::Verb::Rm`); relaxing policy or config = Touch ID
  (`lib.rs:626-629,733`).
- **Lease and SSO state live in daemon RAM.** This is good for persistence (nothing on disk)
  but the daemon is a same-user process (`daemon.rs`, peer identity via `LOCAL_PEERTOKEN`).
- **Ad-hoc signed, not notarized.** There is no code-signature check on callers.

## 5. What a lease, a revoke or a logout does not do

- Revoking a lease (`Req::Revoke`) removes only the daemon's agent leases and human
  self-leases (`g.leases`, `g.human`; `daemon.rs:600-615`). It stops further dispensing
  **through that lease**. It does not touch open AWS endpoints (`g.aws` is not modified):
  `serve_aws` checks only the endpoint's own expiry and bearer token, not any Karambit lease
  (`daemon.rs:1092-1116`) plus the current block flags and policy `run` rule for the endpoint's
  caller (a new `deny` ends the endpoint on its next fetch; `approve` is not re-prompted), so a
  running `aws <PROFILE>`/`run --aws` child keeps getting credentials until the endpoint TTL (60 s to 12 h, `daemon.rs:633-637`) or `AwsClose`.
  For SSO endpoints the daemon can keep minting fresh role credentials from the session
  while it is valid (`daemon.rs:1117-1132`, `sso_fresh_creds`). Upstream credentials
  (static keys, already-issued role credentials) stay valid at AWS until their own expiry
  (README §AWS SSO). A static credential a Mode A tool copied cannot be recalled. A tool that
  holds a long-term key can also mint its own `sts get-session-token` credentials (up to 36 h);
  the opt-in per-profile `session_mint` makes the daemon do that exchange (1 h) and serve only the
  session, so the tool never holds the key (docs/aws.md). Sessions already handed out still can't be recalled.
  The daemon resolves the `aws` CLI only from `/opt/homebrew/bin`, `/usr/local/bin` and `/usr/bin`
  (canonicalized; regular executable, owner root or the daemon's user, not group/world-writable), never
  from its inherited `PATH`, and runs it with a cleared environment and an empty temporary `HOME`. A
  `session_mint` key and the lease DEK that opens it are refused to an agent on every legacy path
  (`Unlock` any action, `Copy`, `Use`); `aws-describe` returns masked metadata only.
  Linked-backend dynamic revocation now has a separate lifecycle implementation;
  see [the backend amendment](#linked-backends-interface) for its
  production availability and limits.
- Several distinct clocks already exist and are not one lease length: the Karambit lease,
  the AWS endpoint TTL (`daemon.rs:633-637`), SSO access-token expiry and refresh
  (`daemon.rs:950-959`), and upstream role-credential expiry with a cache freshness margin
  (`daemon.rs:1021-1025,1044`). They are not exposed as one model. The backend contract defines a
  unified five-clock backend contract (lease, backend login, upstream credential, cache,
  actual revocation). That backend lifecycle is now implemented separately; see
  [the backend amendment](#linked-backends-interface).

## 6. Doctor (`karambit doctor --agent-env`)

`karambit doctor --agent-env [--json]` runs seven rows from the environment it is launched in
(so run it from a plain shell and again from inside an agent to compare). Each row is
`pass`, `fail`, `inconclusive` or `unsupported` with a one-line reason; the footer is
`scope: this run only`. Exit code is 0 whatever the rows say; non-zero only if the doctor
itself cannot run.

| Row | What it does | fail / pass meaning |
|---|---|---|
| `sibling-env-ps` | Starts a synthetic sibling holding a random canary in its env, then runs `/bin/ps -E -p <pid>` from here. The sibling is killed and reaped on every path. | fail: the canary is visible, so a same-user process here can read sibling environments (#8). pass: `ps` ran and listed the sibling but not its env. inconclusive: `ps` failed or did not list it. |
| `vault-token` | `stat` + `access(R_OK)` on `~/.vault-token`; the file is never opened. | fail: exists and readable. pass: absent, or exists but unreadable. |
| `key-blob-use` | Compiles the embedded `crates/cli/src/key_use_probe.swift` with `/usr/bin/xcrun swiftc` (fallback `/usr/bin/swiftc`; 120 s limit) into the scratch dir and runs it (15 s limit; timeouts kill the process group and reap the direct child; environment cleared except `PATH`, `HOME`, `TMPDIR`, `DEVELOPER_DIR`). The probe is a standalone CryptoKit program, not the production helper, and never talks to Karambit (no daemon request). It creates a **synthetic** no-prompt Secure Enclave key (no user-presence or biometric flag, so no Touch ID), writes only its blob to a file in the scratch dir, drops the key, **reloads it from that file**, and checks ECDH against an ephemeral software peer. It prints only `match`, `mismatch` or `unavailable`; the doctor copies nothing else from it into the row. It reads nothing but the blob it wrote and removes it on every path. No live blob, Keychain item or vault file is involved. | fail: `match`, so a no-prompt Secure Enclave key blob was usable from this environment without Karambit (limit #6). inconclusive: `mismatch`, a non-zero exit or signal (code only), a timeout, or unrecognised output. unsupported: no Secure Enclave, no swift compiler or a compile error, or `KARAMBIT_DOCTOR_SKIP_KEY_PROBE=1` (`key-use probe skipped by KARAMBIT_DOCTOR_SKIP_KEY_PROBE`; the skip is shown in the output; the CLI tests set it so they never reach the Secure Enclave). **Never `pass`**: Karambit has no software-only way to stop a same-user process from using a no-prompt key blob; only the Touch ID tier holds. |
| `daemon-socket` | Connects to the vault's live socket path (with a timeout), then shuts down and closes **without writing a byte**. No request of any kind is sent (the daemon runs dispatch-time work, such as expiring launches and auditing, for every request including `Ping`, so even a "read-only" request is not side-effect free). The bare connection only refreshes the daemon idle timer. Never starts a daemon. | pass: the socket accepted a connection (`socket accepted a connection; no request sent`). inconclusive: no socket, stale or refused, or timeout. It shows reachability only, not that the daemon is healthy. |
| `audit-config-pin-writable` | `access(W_OK)` / metadata on `audit.jsonl`, `config.json`, `keys/*.sha256` (plus the canonical `helper.sha256`/`daemon.sha256`) and their directories. Nothing is opened for write. | fail: any discovered target is tamperable from here (file writable, or replaceable/creatable through a writable directory). inconclusive: nothing tamperable was found but something could not be judged (e.g. `keys/` cannot be listed, so extra pins are unknown; a metadata or access error other than a plain denial). pass: everything was judged and none is writable. |
| `redaction` | Pushes the canary's echo, base64 and 20-char truncation through the same `Redactor` a bound launch builds. | pass only if all three are redacted. Today the base64 form is **not** redacted, so the row reports `fail` (known limit #9, encoding-aware redaction planned); it lists which forms were redacted. |
| `remote-login` | Read-only. `systemsetup -getremotelogin` when it answers without admin rights; else `launchctl print system/com.openssh.sshd` (job loaded) and a 500 ms TCP connect to 127.0.0.1:22. Nothing is written or changed. | fail: Remote Login looks on (any signal). pass: `systemsetup` says off, or no signal found (the pass text says systemsetup was not usable). A custom sshd on another port is not seen. |
| `caller-agent` | Reports what `agent::detect` found for this process. | Always `pass`: it states the detection result (agent label, `no agent detected (human shell)`, or that the caller arrived over SSH); it is not a verdict. Detection is a heuristic (section 4). |

What the doctor never does: open any secret or key file of the live vault (it only reads
`config.json` through normal CLI startup and lists `keys/` names), open `~/.vault-token`, write to the audit log/config/pins, start the daemon, make
network calls, send any daemon request, or print the canary or any value. Its socket probe causes no
request dispatch, expiry or audit; the connection alone refreshes the daemon's idle timer. Its only
files are a 0700 `karambit-doctor-<pid>-<12 hex>` directory under `TMPDIR` (created 0700 atomically,
holding a `.karambit-doctor` marker written first), removed on exit including panic by deleting only
that marker and then `rmdir` (never a recursive delete: if another directory was swapped into the path,
only non-directory entries with one of four exact names may be unlinked: `.karambit-doctor`, `probe.swift`,
`probe` and `probe-key.blob`; the replacement remains whenever it holds anything else). Only the key-use row adds files to it
(those last three), each removed by exact name when that row ends, including on
timeout. The compiler and probe run with the scratch dir (made absolute) as cwd, in their own process group,
which is killed once they exit or time out, so no descendant that stays in that group survives the row.
A process that leaves the group (e.g. `setsid`) is beyond the doctor's reach and is not killed, but
stdout is read without blocking, a bounded number of reads per poll, on bounded clocks, so the doctor
still returns even if such a process keeps writing. Output over 256
bytes (compiler or probe), or stdout still held open after exit, is `inconclusive`, never interpreted. The probe reads its blob back
through the descriptor that created it (`O_EXCL|O_NOFOLLOW`), never by pathname, so a symlink swapped
into the scratch dir cannot redirect it to a live key file; after a hard crash they may remain in a crash leftover (the blob is a synthetic key, not a live one). Crash leftovers
are **identified, never deleted**: a directory matching that exact name grammar and holding a valid
marker (same uid, regular file, pid and nonce agreeing with the name) whose creating pid is gone is
listed as a crash leftover to delete by hand; any other `karambit-doctor-*` entry is listed as `not
doctor-owned, left in place`. (A check-then-delete by pathname cannot be bound to the checked
directory's identity if another process can rename entries in `TMPDIR`.) The canary is placed only
in the synthetic sibling's otherwise empty environment, for the `ps -E` check; there is no
canary-observation environment hook or output file in any build, and the exact-value no-leak proof
lives in unit tests.

What a doctor result does and does not prove:

- **A doctor result covers the tested run only**: that user, that process tree, that
  environment, that moment. It does not describe other agents, other shells, later
  configuration, or the rest of the host. A pass is "this probe did not succeed from here",
  not "the host is safe"; inconclusive and unsupported are not passes.
- `fail` rows are findings about the environment, not doctor errors.
- The `key-blob-use` row tests only a **synthetic** no-prompt key created and reloaded by the
  probe, not the live `open.key`/`agent.key`, and it never goes through Karambit's daemon. It is
  evidence for limit #6 (a blob file plus a same-user process is a usable key), and it can never
  `pass`: a non-`fail` result means the probe did not run or did not verify here, not that the
  live blobs are protected. Only the Touch ID tier holds against a same-user process.
- The canary is synthetic and never enters the live vault, so the redaction row proves the
  redactor's behaviour on the three forms only, not that any particular launch is leak-free.

## 7. Claims that are safe to make today

- Values are encrypted at rest and wrapped using capability (1), currently Secure Enclave keys; the Touch ID tier is
  enforced by the Secure Enclave for unwraps that go through the helper (README §Model).
  Not for a bio secret while a human self-lease is active.
- `run`/`aws <PROFILE>` deliver values to a tool you choose (Mode A), redact non-public
  Karambit-resolved literal values of at least 4 bytes (and SSO role credentials as they are minted)
  from that tool's stdout/stderr (not short values), and attempt to audit the use (audit is best effort).
  A lease scopes the access served through it; an agent-allowed bio secret can also be
  unlocked with a fresh Touch ID without a lease; open-tier access needs no lease.
- On the AWS-profile paths (`aws <PROFILE>`, `run --aws`), AWS keys are delivered through the
  loopback endpoint, and the known AWS env variables are removed from the child's env. Not
  for `run -e AWS_...=ref` or AWS variables elsewhere.

## 8. Claims not to make

- "Agents can't see secrets" / "agents never get values". In Mode A the tool gets the value,
  and no-prompt secrets are readable by any same-user process (#6).
- "Redaction protects against leaks". It protects against accidental plain-text echo only
  (#9, #13).
- "Sandboxed", "custody", "broker" for anything today. Modes B and C are planned.
- "Same-user safe" or "tamper-proof". Not true at this commit (section 4).
- A doctor result as a host-wide verdict (section 6).

## Helper, launch-channel and binding implementation history

The intermediate statuses below are historical; the launch channel section records
current receiver enforcement. Installation remains owner-gated.

### Typed prompts (partial)

Rust helper auth/ECDH callers now select a `helper::Prompt` operation variant and send
`--prompt '{"id":...,"params":[...]}'`, not rendered reason text. Parameters have control
characters and bidi/format controls removed and are capped at 120 Unicode scalars each.
Swift owns the fixed templates, quotes every parameter as JSON string data, and rejects
unknown IDs, extra fields, wrong arity/type, controls and overlong parameters before
command dispatch (including Open-key ECDH). Every current auth/ECDH call site uses this
protocol. Rust/Swift ID and arity consistency and the actual Foundation-only renderer
are tested without biometrics. This protocol requires a matching Rust/helper build;
old helpers do not implement template validation. Do not install this partial increment alone.

**Not implemented by typed prompts:** daemon-only launch, semantic client routing, the private
inherited challenge channel, or daemon executable pins. Existing callers still execute
helper operations directly; valid templates are not caller authorization. The launch channel work remains
incomplete until those enforcement and migration steps pass their negative tests.

Even after that enforcement, user-writable pins/binaries plus same-user process access
are **not an OS isolation boundary**. A replaced binary, or an independent CryptoKit
program using readable no-prompt key blobs, remains possible (#6). Neither typed prompts
nor the planned daemon channel make Karambit “same-user safe.”

### Required owner install ordering (not performed)

Retain the old trusted daemon/helper/protocol pair. Before replacing either executable,
use that old pair to authenticate the owner and stage the new pair's pins, inside an
audit intent. The old daemon must hash the staged candidates itself; agent requests and
failed authentication must publish nothing. Only then install and restart with the new
matching pair. If no trusted old pair remains, refuse and refer the owner to manual
offline bootstrap; no software bypass is approved. For migration of vaults that predate the launch channel (helper pin
present, daemon pin absent), only audited helper-pin approval through the still-pinned
old helper may establish the serving daemon's own executable pin, no-replace and subject
to retirement-history guards. Fresh uninitialized vault bootstrap may establish both
pins no-replace with the same guards. Preserve helper/daemon/protocol pin pairs together
in rollback artifacts. `install.sh` still needs the install-ordering update described here.

### Bootstrap increment (partial)

Init, status/selftest, public-key cache fallback and helper pin now use semantic
daemon requests with kernel-derived Caller attribution. Group B additionally routes
unlock/get/reveal/run credential delivery and unredacted-run approval. Copy/view/
aws-describe unlock halves use the same semantic route; clipboard itself, mutations,
recovery and other SSO paths remain pending C–F, as does helper parent/channel
enforcement. Do not install this increment as the completed launch channel. Peer initial-env markers
are now read from the kernel where available; unknown environment disables anchored
human cache reuse/insertion (see the caller-attribution notes above). Same-user limits above still apply.


RunUnredacted approval is a Mode-A supervisor trust: the daemon prompts for the
requested command, but the client controls redaction and the subsequent launch.
It is not credential authority and does not prove which child actually executes.
The shim/one-use launch binding (below) supersedes this trust. Run's optional SSO
endpoint is created internally from the daemon-derived unlock proof; no DEK is
returned by Unlock or sent by first-party clients. The legacy raw SsoOpen DEK field
remains pending group E. Neither change removes the same-user limits above.

### Mutation routing increment

Vault add/overwrite, policy rewrap, delete, config change and key upgrade now run
through semantic daemon requests, with kernel-peer attribution and existing
intent/proof/containment logic. Mutation responses carry no DEK or existing secret
plaintext. Add carries only the newly supplied value as input. Optional AWS STS
verification before add remains client-side; it is not daemon authority.

This is still partial routing, not a same-user OS boundary: recovery/backup,
remaining SSO and clipboard effects (D–F), Swift caller/channel enforcement and
paired installation remain pending. Raw legacy DEK-returning requests remain as
previously documented. Agent deletion was still gated by fresh Touch ID in this
increment; it is now refused outright by the capability fence (`Verb::Rm`, below).

### Recovery, retirement and backup rotation

Recover, RecoverFromPaper, RetireKeys, RetireKeysWithPaper and RotateBackup are
semantic daemon requests. CLI recovery and backup rotation use these library
wrappers; GUI/library callers inherit the same routing. Only counts, missing
names or the retired path return. The daemon uses the kernel Peer and persisted
config, never wire caller/proof claims. No State mutex spans helper or socket I/O;
the existing in-flight counter protects long requests from idle exit, and Revoke
can complete while recovery authentication waits.

The human-supplied age identity is operation input, not authority. It crosses one
same-user, kernel-peer-checked local Unix socket hop. Daemon request identity
fields and the received line use Zeroizing<String>; correlation parsing ignores
paper fields rather than cloning the whole JSON. Paper text is never audited or
logged. Decrypt/open verification precedes authentication, retirement and
keygen. BiometricsUnavailable is produced and consumed inside the daemon via its
typed error, not matched against wire/display strings. Clients need no unavailable
status to perform fallback. Cancellation and pin mismatch still refuse.

Outer daemon-recover, daemon-recover-from-paper, daemon-retire-keys and
daemon-backup-rotate intents surround execution and delivery. Existing nested
recover-operation/recovery-proof/named recover, retire-keys-operation and named
backup-rotate-operation history remains; rotation outcome follows config save.
Recovery refuses unless the paper key opens every secret (or the human names the exact
unrecoverable set), and an interrupted recovery resumes from `recovery.pending`. An
interrupted rotation leaves `backup_rotation` in config so `status` and `backup verify`
warn; `backup verify` trial-decrypts every backup copy rather than comparing with config.
Retirement marker/history, preserved pins, no-replace TOFU and trusted-copy
repinning are unchanged. Public-key fallback and rewrap are daemon-local.
Groups E–F retain their previous paths; helper capability/channel enforcement is
still part of the launch channel. Same-user writable binaries/pins are not an OS isolation boundary.

### Helper-spawn routing boundary

All supported helper-spawning operations now route through daemon semantic
handling, including portal setup, offline limit changes, stored SSO registration
and clipboard delivery. Spawn-capable Rust helper functions are crate-private.
Wire clients cannot submit SsoOpen DEKs or SsoRegister/SsoSet policy bindings;
these legacy variants are internal-only. Login's OIDC network step remains in
the client; the daemon derives registrations and the configured limit before its
existing approval. Stored-policy/revision checks and anchored human-cache rules
are unchanged.

Copy does not return plaintext to the CLI/GUI; only copied names and clear duration
are returned. The daemon's helper must have access to the user's GUI pasteboard.
In a launch context without that access, Copy fails clearly; there is no fallback
to sending plaintext or writing from the client. The Swift helper checks each
pasteboard-item write and the pasteboard write acknowledgement before reporting
success. This does not make a clipboard secret from other same-user applications,
prevent clipboard observers, or revoke copies already taken. Clear-after still
clears only if the pasteboard has not changed.

The launch channel now enforces the daemon spawn capability and the Swift parent/private-channel
check at both launch funnels (call_at and clip). Crate privacy and semantic routing
are not that enforcement and do not prevent another same-user executable using
CryptoKit or a replaced writable helper/pin. No installed pair migration, real GUI
session, hardware or pasteboard test is claimed by these synthetic routing tests.
Actual-child binding remains separate from today's declared Run command.

### Launch channel — enforced before Swift dispatch

The launch channel installs daemon-scoped, private-constructor `LaunchCap` authority at the
helper launch funnels. A scoped dispatch/reaper context supplies it; client
wrappers cannot construct it. Unit fixtures retain their explicit no-real-helper
launch guards. This is compile-time/process-structure hygiene, not an OS boundary.
The Swift receiver and paired daemon trust pins are implemented. Debug software
responders still ignore the channel; their fixture launch guards remain intact.

Protocol v1 (no argv/env/public-RPC challenge material):

* Each spawn has a private AF_UNIX/SOCK_STREAM socketpair. The daemon end and all
  original descriptors are CLOEXEC. `pre_exec` duplicates the child end to **fd 3**
  (clearing CLOEXEC only for that descriptor). The receiver's **FIRST startup
  action MUST set FD_CLOEXEC on fd 3**, before spawning any child. The Rust harness
  models this; Swift sets it before caller verification or dispatch. Without this
  receiver action a grandchild inherits fd 3.
* Before its first read, the daemon registers the `Command::spawn` child PID and
  `proc_pidinfo(PROC_PIDTBSDINFO)` start seconds **and microseconds**. Registration
  is private to that socket/responder, not a public lookup endpoint.
* Request is exactly **32 random nonce bytes**. Response is exactly **72 bytes**:
  nonce echo [0..32), child PID u32 [32..36), child start seconds u64 [36..44),
  child start microseconds u64 [44..52), daemon PID u32 [52..56), daemon start
  seconds u64 [56..64), daemon start microseconds u64 [64..72). Integers use
  unsigned **big endian**. No JSON, length prefix, secret or extra frame.
* After reading the nonce, daemon takes (burns) the registration before any
  response write. `LOCAL_PEERPID` must equal the spawned child PID. Both child
  and daemon start identities are re-read and must equal their registered values.
  Exactly one response is possible; the responder shuts down both directions
  after either response or refusal. A second challenge gets EOF, not a response.
* Read/write socket timeouts are **2 seconds each**. Closing the operation's
  channel guard shuts down a pending responder. For clip, the guard follows the
  child until the clear-timer process exits, including failed acknowledgement
  paths. Software helpers need not read/write fd 3 and do not wait for the timeout.
* Refusals send **no response bytes**. Internal errors are `launch channel:
  process identity unavailable`, `launch channel: peer identity unavailable`,
  `launch channel: registration already used`, or `launch channel: identity
  mismatch`; OS I/O errors propagate internally. The Swift receiver does
  turn EOF/short reply/timeout/mismatch into fixed `caller refused: ...` JSON
  before dispatch and any key read, LAContext, SE or pasteboard use.
* The receiver checks its fd-3 `LOCAL_PEERPID == getppid()`, parent's
  kernel start and canonical executable hash against the **anchored**
  `daemon.sha256` (trust root below), then sends a fresh nonce and compares **all**
  returned fields with the nonce, its own identity, and its parent's identity.
  Re-read parent identity/getppid after exchange; any change refuses. Fresh nonce
  plus one-use registration and kernel PID/start checks exclude stale answers and
  accidental channel reuse; they do **not** bind the answer to whichever process
  currently holds the other endpoint (see the purpose-built bypass below).
* **Trust root (MUST, release builds):** the receiver selects its pin root
  independently of argv and environment: `getpwuid(getuid())->pw_dir +
  "/.local/share/karambit/keys"` (not `$HOME`, not `KARAMBIT_DIR`). Before any
  file read, `--dir` must canonicalize to exactly that directory, else `caller
  refused: key directory not trusted`; `daemon.sha256` (and `helper.sha256`) are
  read only from the anchored root. A caller-selected `--dir` must never choose
  its own trust authority: otherwise any unpinned program could point `--dir` at
  a temp dir holding its own hash, answer the challenge itself, and pass every
  other check. A fixture root override may exist only under `#if DEBUG` and must
  be absent from release builds. Receiver negative: a software fake
  parent with a separate attacker-written pin directory is refused before any
  protected operation; an anchored positive control passes the caller check.
* **Consequence (owner approval required before the first release install):** release builds of the
  helper only serve the default vault location; a non-default `KARAMBIT_DIR`
  vault cannot use the helper. Anchoring the pin is essential; also restricting
  the key-data directory is the chosen compatibility policy.

`LOCAL_PEERTOKEN` returned EINVAL on a socketpair on the development macOS;
`LOCAL_PEERPID` plus kernel start seconds/microseconds is the binding used.
PID reuse in an identical microsecond start window is not formally excluded;
that negligible residual is accepted. No boot secret/HMAC is used: the receiver has no independent HMAC verification
key, and transmitting a daemon secret would add no proof beyond this live,
kernel-bound exchange. The genuine CLI in ordinary (non-daemon) mode has no
registered-child responder, so it cannot satisfy the challenge by accident.

This stops ordinary, accidental and agent-invoked direct helper calls (including a
redirected `--dir`). It does **not** stop purpose-built same-user bypass
programs. Named residual, alongside #6: **cooperative exec + inherited-endpoint
responder** — a same-user launcher creates the socketpair, forks a stopped helper
and a sibling responder holding the other endpoint, then execs the pinned CLI;
the helper then sees a pinned parent with unchanged PID/start, `LOCAL_PEERPID`
still names the socketpair creator, and the sibling echoes the non-secret answer.
No trusted file needs replacing. It gains nothing beyond #6 (such a program can
already drive CryptoKit directly on the user-readable key blobs). Optional partial
hardening (not implemented): require the parent's argv to be `<pinned exe>
daemon` via KERN_PROCARGS2 — narrows, does not close, this residual.

User-writable pins/binaries and same-user process access are not an OS isolation
boundary. A replaced binary or independent CryptoKit program using readable
no-prompt blobs remains possible (#6); this is not protection against a hostile
same-user takeover.

#### Paired pins and receiver status

The Rust daemon now establishes `keys/daemon.sha256` alongside `helper.sha256` on
fresh uninitialized vaults, using its own canonical kernel executable, never a
client-supplied daemon identity. No-replace bootstrap refuses retirement history;
missing helper pins on initialized vaults require owner offline bootstrap.
Vaults that predate the launch channel can establish a missing daemon pin only through audited HelperPin
and approval by a still-pinned old helper. Existing daemon pins are not TOFU targets.

`karambit helper pin --stage-daemon PATH --stage-helper PATH` requires both paths
and authenticates using the OLD trusted pair. The daemon hashes staged files.
Exact old bytes of both pins are read before approval and compared afterward;
change refuses with `pin changed during approval; retry`, with no publication.
Publication writes deduplicated old+new unions, helper first then daemon, with
same-directory temp/fsync/rename/directory fsync. Second-file failure restores the
first's exact bytes (and reports restoration failure). Normal `helper pin` on a
trusted pair prunes to current candidates. A retirement marker blocks all writes;
history alone blocks absent-pin TOFU but allows authenticated existing-pair repin.
Retirement preserves both pins. These are guarded writes, not an atomic two-file
transaction or protection from hostile same-user filesystem races.

**Owner approval required before the first release install — install-order amendment:** stage and pin
new helper/daemon binaries with the OLD trusted pair; install those exact staged
files; restart the daemon; then authenticate normal `karambit helper pin` on the
new pair to prune old hashes. If no trusted old pair exists, refuse online changes
and use owner-controlled offline bootstrap. No bypass command is provided here.
Installation remains owner-gated; this increment does not install or restart anything.

**Owner approval required before the first release install — non-default vault restriction:** the
release Swift receiver uses the passwd-home anchored trust root above, not HOME or
KARAMBIT_DIR. Non-default KARAMBIT_DIR vaults cannot use the release helper.

The Swift receiver obligations above are implemented in `main.swift`. Exact order:
(0) set fd 3 CLOEXEC if open; (1) independently select passwd-home trust root
(DEBUG-only `KARAMBIT_SE_TRUST_ROOT`), require one canonical matching `--dir`;
(2) parent PID > 1, kernel start identity, canonical kernel executable hash and
nonempty matching trimmed daemon pin line; (3) fd-3 kernel peer PID, two-second
send/receive timeouts, fresh 32-byte random challenge, exact 72-byte response,
nonce and every child/parent identity field; (4) recheck parent PID/start.
Only then are typed prompts validated and verbs dispatched. Socket errors use
fixed `caller refused:` JSON and exit 1; SIGPIPE is suppressed on the socket.
The whole exchange also has a two-second monotonic deadline. The DEBUG-only
`__probe_fd3` is reachable only after verification and reports the CLOEXEC bit;
it has no file, SE, LAContext or pasteboard effects and is absent from release.

Receiver tests build/copy only DEBUG Swift binaries, use temporary empty key
roots and synthetic test-process responders, and exercise pubkeys, valid-template
ECDH with empty stdin, and the post-gate fd probe. They test pins, redirected
roots, absent/short/closed/replayed channels, nonce/identity mismatch and paired
union/prune with two differently hashed test parents. Scratch-only mutation tests
are explicitly ignored by default because they rebuild each variant. Real auth,
keygen, selftest and clip are never exercised: full per-verb daemon routing is
covered by existing software-helper smokes, not real hardware/pasteboard claims.

User-writable pins/binaries and same-user process access are not an OS boundary;
independent CryptoKit access to readable no-prompt blobs remains possible (#6).

### Command grant pins (partial; actual-child binding pending)

`GrantLease.scope.cmds` accepts command names or absolute paths and the daemon
replaces every entry with `{path, sha256}` before approval and storage in RAM.
Names resolve against the daemon's PATH (absolute directories only); multiple
distinct canonical executable matches or missing matches are errors. Use an
absolute path to select a particular installation. Relative paths, shells and
named command wrappers are refused. Client-provided hash objects are rehashed,
not trusted. Restart still discards leases; no on-disk lease migration is added.

The existing `Use` scope check canonicalizes the CLI-reported target and reads its
entire file for a fresh SHA-256 on each check. Both canonical path and hash must
match. Name-only legacy scopes, including mixed name/pin lists, fail explicitly
with **re-grant required**; no entry is dropped or wildcard-migrated. Unscoped
get/reveal and human caches retain their separate authorization.

The legacy raw `Use` path is still advisory: a raw requester can report one target
and execute another. Production `karambit run` now uses bound Prepare/Bind/Redeem
instead; it no longer obtains launch credentials through legacy Unlock/Use or
AwsOpen/SsoOpen. **Raw-client legacy scoped release remains reachable until legacy
scoped rejection (below) rejects it.** The production switch alone is not the full launch-binding boundary.
Hash-to-exec races, mutable scripts/config and disclosure by the approved Mode A
child remain limits.

Use snapshots requested lease scopes and the revocation revision under a short
State lock, opens/fstats/hashes the target outside that lock, then rechecks live
lease expiry, grantee, cwd, scope equality and revision before dispensing or
incrementing uses. Changed scopes/revisions fail with a retry error; revocation
wins over an in-flight hash. Hash snapshots record the same fd's device/inode/size;
size/identity change while hashing refuses. This is not immutable execution and
does not exclude same-size concurrent rewrites or later filesystem replacement.

### Bound redemption (production env and AWS runs)

A crate-private, immutable `launch::LaunchBinding` can capture argv, canonical cwd,
canonical target SHA-256/dev/inode/size and an optional argv[1] regular-file snapshot.
Fresh read-only verification rejects changed argv/cwd, cwd symlink retargeting,
target/script replacement and script absent/non-regular ↔ regular transitions.
Relative argv[1] resolves against the captured cwd; FIFO/directory/device contents
are never hashed. Only argv[1] is considered, not interpreter flags, imports or
configuration; hashing still does not close the hash-to-exec race. The launch channel's unchanged
helper protocol now shares its full PID/start-seconds/microseconds reader with the
launch code. `LaunchPrepare { refs, env, target, argv, cwd, aws? }` and `LaunchCancel { id }`
now exist, but **release nothing**: Prepare returns only a random non-secret 128-bit
lookup ID and expiry. `LaunchBind { id }` now upgrades only its own socket into a session. It checks
LOCAL_PEERPID, full PID/start identity, checked parent identity before and after
fresh canonical executable hashing against the established CLI/daemon pin. A
mandatory owner/shim/target intent precedes atomic Pending-to-Bound installation.
Only that socket receives a 32-byte OS-random token; the owner receives none.
The token and immutable payload stay in a zeroizing-token session, never in the
global Bound containment metadata. The original owner and deadline are preserved.
Bind releases **no credentials**. `LaunchRedeem { token }` accepts exactly one next
frame on that same bound socket and returns `{ target, argv, cwd, env, aws? }` only there.
`target` carries the canonical executable path and SHA-256; env contains UTF-8 values
(NUL and invalid UTF-8 refuse). This path supports env and static/SSO AWS profiles, with explicit agent leases and non-prompting
Open/public or Open/agent-allowed policies, human-cache reuse, and fresh AUTH for
human-only Open refs and batched fresh Bio unwrap. Production `karambit run` now
uses this protocol and owner redaction. Legacy raw Use remains advisory until legacy scoped rejection (below).

Preparation authenticates the kernel peer executable against the owner-established
CLI/daemon hash pin and captures its PID/start seconds/microseconds. Env is a map
of validated variable names to references, never values; duplicate names are refused.
The refs list must exactly equal env references plus the optional AWS profile reference.
Each reference uses the shared legacy run decision: an agent's live explicit lease
(with matching grantee, cwd and pinned target), non-prompting Open/public, or
Open/agent-allowed policy. Both peer cwd and requested canonical cwd must satisfy
lease directory scope. Public refs ignore explicit leases, just like legacy run.
Unlike the earlier lease-only increment, human callers cannot use explicit Any,
Kind or Session leases: only legacy human policy paths qualify. HumanCached uses
exactly the legacy configuration gate and human-cache lookup: terminal/GUI anchor and
ancestry, expiry, screen-lock invalidation, and env_unknown disabling anchor reuse.
Prepare checks metadata only, without accessing the cached DEK or consuming a use;
Redeem repeats the screen probe and all live checks before atomically consuming one
cache use and cloning the DEK. A changed/expired cache refuses, never falls back to
a prompt. NeedsFreshAuth is accepted for human Open and Bio refs (including
Bio/public and Bio/agent-allowed); agents still cannot request fresh proof. An empty
cache permits fresh preparation; a failed screen probe still refuses. Prepare never prompts.
Snapshot capture/hash, kernel reads, randomness and audit run outside State; the final
lock rechecks revision, live lease scope/expiry/grantee and remaining uses. Prepare
**does not consume a lease use**; redemption must do that atomically with authorization.

The daemon registry holds only references and immutable launch metadata: an original
120-second TTL if any ref needs fresh proof, otherwise 30 seconds. Bind/Redeem never
extend it. There are 256 entries globally (including canceled/burned tombstones until expiry), at most
16 Pending entries per PID/start identity. Overflow refuses, never evicts. Cancel is
owner-only and idempotent while its tombstone exists; unknown/expired IDs return a
generic error. Take burns even on owner/expiry failure. Revoke-all (the GUI's lease
containment action), matching lease revocation and lease expiry burn pending entries.
Expiry sweeps run on each dispatched request and every five-second reaper tick.
Bound metadata shares the global registry bound and contains only identities,
creation/expiry and references, never a token, plaintext or DEK. Owner Cancel,
matching Revoke, lease expiry, deadline and shim-death sweeps invalidate it.
Session close, write failure, timeout, Drop, malformed/oversized input or any
request other than Redeem burns and closes with a generic refusal. A fixed 4 KiB
line buffer and per-read deadline limit bound session input. Reads are limited to the
remaining original deadline, and waiting sessions do not hold the in-flight
counter. Bound metadata supplies idle liveness only before its original deadline.
Containment audit is best-effort after burning. Redeem atomically consumes local
token/payload and still-Bound metadata (matching owner, shim and original timestamps)
before parsing/validation. Constant-time decoded-token comparison cannot confer
cross-connection authority. Fresh owner classification/identity, live shim/parent,
target/script binding, then lease revision/grantee/scope/pins/expiry/use budget are
rechecked; each distinct lease consumes exactly one use atomically. The daemon loads
fresh stored policy outside State and recomputes all decisions at finalization;
a changed kind (even a newly available lease) refuses. The Prepare kind is metadata,
not authority. Prepare and redeem intent records include a decision kind per ref. Filesystem,
kernel, hashing, audit, decryption and socket work occur outside State.

Authorization linearizes at lease consumption, like legacy Use: revocation before
consumption wins; revocation after consumption cannot recall an in-flight release.
Audit/decrypt/delivery failures still consume the use. Mandatory redeem intent names
target/hash/argv/cwd/script plus owner and shim identities before any ciphertext is
opened. Lease and HumanCached refs use the cached DEK and `crypto::open`; other refs reuse
legacy `unwrap_deks_local` with the same Open/Agent key selection, then `crypto::open`.
The typed Use context uses the shared legacy `run_context(argv)` text (first meaningful shell script line or joined argv; for `sh -c SCRIPT NAME ARG...` the positional arguments after the script are shown too, and a policy `approve` refuses when any of them is not shown in full). Fresh Open authorization
uses one existing typed `Prompt::Use` AUTH with all refs, caller and the shared legacy
run context, through existing prompt sanitization; canonical target and full argv are bound
by the approval hash. The audit log records argv with known secret values replaced and obvious
credentials masked (a secret flag's value is masked whole, spaces included), unmasked only
with the opt-in `audit_full_argv`; `argv_sha256` always covers the real argv. It runs only after fresh identity,
binding, policy and live authority checks and a mandatory `launch-auth` intent.
After fresh proof, config/policy/owner classification, binding, shim/parent and human-cache checks
are reloaded/repeated before finalize/use accounting. Cancel/Revoke/deadline/death
before finalize wins: zero opens, zero uses, no cache population. Denied/failed
proof burns the launch. The bounded worker inherits daemon dispatch LaunchCap,
never State or session authority. Bio DEKs travel only in Zeroizing wrappers over
the private channel. The caller stops waiting at the original deadline even if the
helper stays blocked. A late Bio result is explicitly wiped in the worker before
discard; disconnected-channel/error drops also zeroize keys. Late approval never
finalizes. Refused finalization drops all fresh DEKs without cache population.
The helper may remain blocked and its worker retains in-flight idle accounting
until it returns; no helper cancellation guarantee is claimed.

Multiple human-only Open refs need exactly one AUTH, including a mix with public
Open or already-cached Bio refs. Cached Bio is not fresh proof. Open AUTH never
populates the human cache. One or multiple uncached Bio refs use exactly one batched ECDH
Touch ID operation through the existing unwrap path, with the same typed Use
context. This fresh Bio proof covers accompanying human-only Open refs with no
extra AUTH; cached Bio never joins the unwrap batch. After successful finalization
and live authorization/use accounting, fresh eligible Bio DEKs populate the human cache with
the legacy human anchor, non-public/agents-off eligibility and configured duration
clamped to three hours. Non-anchored humans receive values but seed no cache.
The pre-prompt Bio files must equal their reloaded snapshots before these keys
can be used or cached; a replacement with the same policy still refuses.
All unwrap/helper/audit work is outside State. Bound dispatch enters the same
private LaunchCap scope as ordinary daemon dispatch; clients cannot construct it.
DEK clones, plaintext and exactly-sized serialized delivery buffers are zeroizing;
no serde Value owns env plaintext. Env-only sessions close after the bundle write;
AWS sessions instead remain open for endpoint lifetime as specified below.
Possession of a copied token never revives canceled authority.
Pending entries keep an otherwise idle daemon alive only until expiry plus a tick;
burned entries do not. The ordinary idle timeout and active-request counter still apply.

Prepare's mandatory additive audit intent records target canonical path/SHA-256,
argv, canonical cwd and optional script snapshot **before insertion**. Cancel/expiry/
revocation burn first and record best-effort containment outcomes outside State;
audit failure never delays containment. argv is operational metadata: callers should
not put credentials in it, and the audit record masks known secret values and obvious
credentials (heuristic, best effort) and adds `argv_sha256`; `audit-full-argv` (a
relaxing change) stores it as typed. Existing audit-chain format remains compatible,
and the log now rotates into `audit-<ts>.jsonl` segments that keep the chain.

**Env parity is complete:** lease, Open/public, Open/agent-allowed, HumanCached,
fresh human-only Open AUTH and fresh Bio ECDH are implemented. The shared pure
decision classifier is also used by legacy Unlock; legacy proof batching, human
cache checks and prompt behavior are unchanged. Fresh Bio supplies the mixed-set
proof and seeds eligible human-cache entries only after successful finalize.
AWS parity is complete through the bound session (static and SSO); shim
implementation, run switch and redaction are now integrated. A pending ID is not a token or proof of
child execution. Bind/Redeem retain live rechecks, burn-before-validation and
Redeeming/finalize containment. Authorization linearizes at finalization, including
non-lease sources; later containment cannot recall an authorized in-flight release.
Same-user writable pins, mutable input and hash-to-exec races remain the stated limits.


#### Bound AWS endpoints (static + SSO parity)

`aws` is the stored `aws/<profile>` entry reference, validated with the same
`aws::entry_name` grammar as legacy run. It joins the exact server-derived refs
set and uses the same shared run authorization as env secrets. The selected AWS
reference cannot also be mapped to env. Prepare releases only id/expiry, never
credentials or an endpoint token. Prepare never decrypts, prompts or uses network.
Registered SSO names are classified from the validated registration, independently
of shared run authorization over the stored entry. Agents require registration
`agent_allowed`, even with a valid stored-entry lease. Prepare captures the
registration/session revision binding and whether Open/non-agent-allowed SsoUse
is required. That flag counts as fresh for the original 120-second launch TTL.
Encrypted files still have no public type discriminator: unregistered SSO candidates
refuse at redeem after decrypt/parse and use accounting, before an endpoint/bundle.
A registration appearing, disappearing or changing after Prepare also refuses;
registration/session tombstones prevent remove/reinsert ABA.

After existing proof/finalization/use accounting and mandatory redeem intent, the
daemon opens and parses the static entry and creates the legacy `AwsEp` internally.
The shim alone receives `aws: {url, token, region?, endpoint_id}` alongside the
bound target/argv/cwd/env. No access key, secret key, session key or raw AWS entry
is serialized into this bundle or env. The token authorizes only this loopback
`/creds/<id>` endpoint; existing HTTP intent/token checks apply. Endpoint TTL is
four hours, matching legacy run's AwsOpen. Serialization retains the exactly-sized
zeroizing bundle buffer; the bundle's endpoint token is zeroizing too. Static AWS
redaction parts are **not** delivered yet; that is the supervisor-redaction increment.

Spent redemption retains containable Finalized metadata until endpoint attachment:
Cancel/Revoke/death/deadline during decrypt cannot resurrect authority. Endpoint
insertion and transition to Delivered metadata share one short State lock after
parsing, serialization, RNG and audit outside State. Delivered stores only endpoint
id, owner/shim identities, refs and creation/expiry, no credentials/token/DEK.
If bundle write or later validation fails, the socket guard removes the endpoint.
Delivered counts toward the same 256 global entries and a 16-per-owner Delivered
cap; Prepare and attachment both refuse at the per-owner cap. No eviction.

**AWS lifetime rule:** successful delivery keeps only the bound session socket open.
No next operation is accepted. EOF, any extra byte, socket error or session Drop
removes the endpoint and Delivered metadata, without grace. Blocking reads use
at most 250 ms (and never more than remaining endpoint TTL) so another connection's
Cancel/Revoke/AwsClose is observed without storing sockets or doing I/O under State.
Timeout ticks only inspect containment; they neither extend authority nor retry an
operation. Matching Revoke/lockdown, shim-death sweep and TTL also remove both sides;
removing the endpoint independently removes its Delivered metadata. The waiting
thread checks external removal each tick; scheduling and audit/filesystem latency
are not hard real-time guarantees. Endpoint/metadata containment precedes best-effort audit. The five-second reaper remains the sweep backstop.
Legacy endpoints survive lease expiry, so Delivered endpoints do too: lease expiry
burns only pre-delivery launches. Env-only close-after-write remains unchanged.
AWS endpoints keep the daemon alive through the existing `g.aws` idle predicate;
waiting sessions hold no in-flight counter. One blocked thread per Delivered
session is bounded by the global/per-owner caps.

This socket lifetime replaces legacy AwsClose-on-child-exit / RunSsoEndpoint Drop.
The shim keeps it open for the child's entire lifetime and closes it on exit or
failed exec; closing it on exec would immediately revoke AWS access. Pinned
`__launch`, private fd-3 instructions, target revalidation, owner redaction and the
production caller switch and legacy scoped rejection are integrated.

Bound SSO preserves the legacy prompt table: registration Open/non-agent-allowed
requires exactly one typed `Prompt::SsoUse {name, account, role}`. A human's
nonpublic Open stored entry additionally needs the shared `Prompt::Use`, in that
order; public Open needs SsoUse only. Bio uses the fresh Bio DEK proof without an
extra SsoUse when its registration is Bio. Agent-allowed SSO with an authorized
non-fresh stored entry needs no prompt. Both proof steps run in deadline-bounded
workers outside State, before reload/finalize/use accounting; the original deadline
never extends. Registration validity, policy, binding and caller are rechecked.

After opening the entry, the daemon requires parsed SSO and checks registered
`dek_sha256` against the DEK from this redemption, never a wire proof. It invokes
`sso_fresh_creds_bound` outside State, then checks binding, deadline and containment
before atomically inserting `AwsEp {sso, binding}` and attaching Delivered metadata.
Mint failures consume already-finalized uses like legacy Unlock/SsoOpen, but create
no endpoint. SSO endpoint TTL is twelve hours: `unlock_run` passes 12h to internal
SsoOpen, clamped to 60s–12h (static remains 4h). SSO bundle metadata adds `account`
and `role`, with `region` from the registration's `child_region()`; no credentials
or DEKs enter the bundle. The production run switch retains the explicit `--region`
override at environment construction. All endpoint/socket lifecycle rules above
apply unchanged to SSO. Fake-only tests exercise minting, exact prompt sequences,
DEK mismatch, registration/session ABA, blocked-proof containment and EOF cleanup.
These tests use fake AWS only; production CLI tests also use the same synthetic seams.

#### Production shim

`Karambit::launch_bound` and the hidden CLI `__launch` support bound env-only,
static AWS and registered SSO launches, Mode-A redaction, `--no-redact` and the
process-group signal policy. **`karambit run` uses this bound path.** The shim
added daemon support: a bounded, single-use
redaction release (`LaunchRedaction`, owner bound to the socket's audit-token
`pidversion` and re-verified with fresh kernel reads after audit intent),
Finalized-state retention for redaction, and a combined per-owner quota.

The bound path separates executable identity capture from command-scope policy:
any native executable, including `/bin/sh`, `/bin/bash`, `env` and `xargs`, can be
captured and rechecked. Shell/wrapper refusal applies only to a non-empty agent
lease command scope, not to human, public, Open agent-allowed or unscoped-lease
authority. An invalid scoped lease still permits independent stored-policy
fallback. Grant-time command pinning continues to reject shell/wrapper names,
including canonical symlink targets; a renamed copy does not match another
executable's canonical path/hash. The production caller switch and cargo-built CLI
end-to-end tests and raw legacy scoped rejection are integrated.

Client side, the CLI/GUI/shim verify the daemon before sending any request bytes: the
socket peer's audit token (pid, pidversion) must still be live, its kernel executable's
SHA-256 must be in `keys/daemon.sha256`, its initial environment (KERN_PROCARGS2) must
have no `DYLD_*` name and must be readable (karambit is not hardened-runtime signed, so
dyld would honour `DYLD_INSERT_LIBRARIES` under an unchanged hash), and the vault root
(resolved if it is a symlink), `run/` and `d.sock` must be owned by the current uid with
no group/other write. A verified (root, pid, pidversion) is cached per process; a
recycled pid or exec'd listener misses the cache. With no daemon pin on a vault that is
not yet initialized the check is skipped; on an initialized vault a missing pin is
refused. `karambit daemon` also refuses to start with a `DYLD_*` name in its own
environment. `Shutdown`/`HelperPin` are exempt so a stale pin stays recoverable. A same-user agent that can also rewrite the pin file is
still out of scope.

At Prepare the daemon records the owner's canonical executable path and its fd snapshot
(SHA-256, dev, inode, size). At Redeem, after the prompt and before release, it resolves
the owner's kernel executable again and refuses (`launch refused`) on any difference,
because `exec` keeps pid and start time.
Exec report: the owner also passes the shim a close-on-exec pipe on fd 4. The shim (or, for
AWS, its forked child) writes `P` just before `execve` and `E`+errno if it fails; a successful
exec closes the pipe. The owner turns "no `P`" or an `E` into a launch error (`karambit run`
exit 125, `--status-fd` `started:false`) instead of reporting the shim's exit code as the
program's. The size check at Prepare estimates the release from ciphertext lengths, argv and the
owner's ambient size and refuses over the 1 MB frame or `ARG_MAX` before any prompt or lease use;
linked-source (backend) values are only sized at release.

The owner receives only Prepare id/expiry, verifies its canonical current executable
against existing daemon hash pins, then spawns that executable with an empty
environment and a private inherited Unix socketpair on fd 3. The id, daemon socket
path, expiry, optional explicit region and scrubbed owner ambient environment travel
over that channel, never argv/env. Ambient names/values use Unix byte arrays,
preserving non-UTF8 values. The shared core scrub is identical to legacy: fixed
credential/proxy names, `AwsCreds::env_clear()` and actual `OP_SESSION_*` names.
Bound additionally excludes ambient `KARAMBIT_*` control variables, and, when the
caller is an agent, the code-loading list (`env::CODE_LOADING_ENV`: `DYLD_*`, `LD_PRELOAD`,
`PYTHONPATH`, `NODE_OPTIONS`, `RUBYOPT`, ...) unless the human listed the name in `allow_env`.
Dropped names (not values) are printed and audited as `launch-env-dropped`. Human callers keep
them, so a human's own `NODE_OPTIONS` still works; the list is by name, so an interpreter
variable it doesn't name still passes. Plain schema values with these names are refused for all
callers. The shim
retains its empty environment; it never inherits injected secrets. Ordinary
ambient environment is owner-controlled configuration, not new daemon authority.
Unknown ambient secret names are not discovered or classified by this scrub. Agent
detection gates the code-loading drop, so it is a speed bump, not a boundary (a process that
hides its agent ancestry keeps these variables).
Every other open descriptor above stderr is marked CLOEXEC by enumerating the real
descriptor table (`PROC_PIDLISTFDS`), not a soft-limit sweep. The shim repeats this
before every exec, covering descriptors above a lowered `RLIMIT_NOFILE`; a full
buffer fails closed. The daemon independently verifies shim kernel identity, pin
and parent relation. The shim alone binds/redeems on its own daemon connection.
JSON frames have fixed bounded zeroizing buffers; env values and the AWS bearer
token stay borrowed raw JSON literals and are unescaped directly into pre-sized
zeroizing buffers (no serde_json scratch copies). Both bundle and AWS object deny
unknown fields. The target gets explicit envp: scrubbed owner ambient, then approved injected
values (including explicitly injected scrub-list names), with injected values
winning. `KARAMBIT_INJECTED=1` is forced. On AWS launches reserved AWS names
are always removed/rebuilt from the bundle and explicit region override, never
ambient. This preserves direct `execve`, not shell fallback.

All targets receive `KARAMBIT_INJECTED=1`, matching legacy run. AWS targets receive
only endpoint URL/token, empty config/credentials file paths, SDK_LOAD_CONFIG=0,
and region variables; never static keys or SSO role credentials. The empty file is
created next to the private-channel daemon socket: production sockets are always
`<vault root>/run/d.sock`, so this yields exactly `<vault root>/run/aws-empty`
without consulting HOME/default vault state. File creation errors fail closed.
Explicit region wins over bundle region (static creds region or registered SSO
child region); neither means both AWS region variables are absent. Legacy AWS
credential/profile/web-identity variables are removed even if explicitly supplied
in the approved env map, before endpoint variables are installed.

The shim rechecks canonical target path and SHA-256 immediately before exec/fork,
and canonical cwd. Env-only sessions close after the owner GO gate and direct
execve preserves native status; there is no shell fallback. For AWS the shim forks
only after constructing argv/envp and allocating descriptor-sweep storage. The
child performs only mask restoration, chdir, syscall-only CLOEXEC sweep and execve;
failed exec uses `_exit(127)`. The child never inherits the control socket through
exec. The parent wipes/drops the redeemed bundle frame and all zeroizing env buffers
before waiting; it retains only lifecycle metadata and the control socket, not
credentials or bearer token. SIGINT/SIGTERM/SIGHUP/SIGQUIT are forwarded to the
child pid; waitpid retries EINTR. The parent closes the socket after child exit and
returns the same exit code, or resets the terminating signal to default and
re-raises it on itself. Exit is observed with `waitid(WEXITED|WNOWAIT)` so the child
stays an unreaped zombie while forwarding is blocked and the forwarding pid cleared;
only then is it reaped, so a forwarded signal can never reach a reused pid. No SIGTSTP/SIGCONT forwarding is added: correct job-control
stop/resume semantics require process-group policy beyond this API.

**Non-duplicating signal policy:** before daemon connection the
shim records its inherited owner process group and moves only itself to a new
process group. The AWS target rejoins the original group (both parent and child
call setpgid); env-only direct exec rejoins it too. No tty ownership change is
made. Terminal/group signals reach the target directly once, not the shim;
signals sent directly to the shim still forward once. Native counting tests send
killpg(owner group, SIGINT), then direct shim SIGINT and SIGTERM. SIGTSTP/SIGCONT
forwarding remains excluded. Like legacy, the owner CLI remains in the foreground
group and may terminate on SIGINT; its pipes then break, never become inherited
unredacted tty descriptors. The hidden shim arm suppresses error printing because
background tty writes with TOSTOP could suspend it.

**Mode-A redaction:** LaunchRedaction is a separate owner connection,
with exact kernel pid/start-seconds/start-microseconds authentication. The shim
cannot take it, nor can a sibling. After redemption Finalized/Delivered authority,
the daemon builds a sized zeroizing frame from the same redeemed values: static
AWS key parts first, then non-public values by reference name, never public values
or minted SSO role credentials (those arrive later on the same owner connection, below).
It additionally masks the endpoint bearer token
(already visible to the target and authorized Mode-A owner, not a new reference).
The owner borrows RawValue literals and decodes directly into zeroizing buffers;
no serde Value/String scratch owns secret values. Streaming Redactor behavior,
minimum lengths/fragments and static-AWS ExpiredToken hint match legacy.

The value-bearing State map is separate from reference-only PendingLaunches, with
one frame per capacity-counted registry entry. Its lifetime is at most the
original 30/120-second deadline, never the longer endpoint lifetime. Taking it
is single-use, with launch-redaction audit intent before removal/write. Cancel,
matching revoke, expiry, shim EOF/death and owner death remove the frame;
reconciliation drops/zeroizes it. It adds no daemon keep-alive. Env-only Finalized
metadata persists solely until owner take/exec socket EOF or original expiry.

The shim retains private fd 3 and waits for exactly one fixed GO byte, bounded by
the original launch deadline, before any target exec/fork. The owner sends GO only
after obtaining redaction material and starting both stdout/stderr pumps. Fetch
failure closes the channel and kills/reaps the shim: no target executed and no
unredacted target byte can reach the terminal. stdin remains inherited.
RunUnredacted performs the local `NoRedact` fence lookup and the existing daemon typed
Prompt::RunUnredacted proof **before Prepare**; only then are stdio inherited and
GO sent without redaction fetch. No generic proof RPC is introduced.

Launch prepare/bind/redeem intents retain canonical target/fresh SHA-256, argv,
canonical cwd and argv[1] regular-file canonical path/hash snapshot. Script
symlinks are followed and the canonical regular referent is hashed; FIFO, directory
and missing arguments are not hashed. Prepare now
explicitly records the kernel owner identity and null (not-yet-bound) shim;
bind/redeem record distinct owner and shim identities. Values never enter these
fields. argv is caller-supplied metadata: do not put secrets in argv. Mutable
scripts/config and hash-to-exec races remain limits, not OS isolation guarantees.

Production tests execute cargo-built `karambit run` and `karambit aws <PROFILE>` against
an in-process synthetic daemon. They cover env/default-file/argv/PATH, human shell
runs, typed no-redact proof, static/SSO endpoint lifetime, errors/status/signals,
renamed-shell refusal, replayed redemption from a sibling and target replacement.
No installed binary or spawned daemon is used. Legacy scoped rejection is covered
by separate synthetic daemon tests.

Daemon socket EOF/error does not kill the target: the endpoint is already gone,
while the child continues with dead credentials. SIGKILL of the shim similarly
closes its control fd and leaves an orphan target running with dead credentials.
Already-fetched credentials cannot be revoked. Tests explicitly release/reap or
observe completion of synthetic children. Owner cleanup sends Cancel on completion
and errors; spawn/write/wait errors kill/reap the shim. The owner API itself never
autostarts a daemon; cmd_run first uses the existing Ping/request availability path.

Synthetic real-process tests use a compiled C target and an in-process daemon,
loopback credential HTTP, fake SSO, full env-name checks, region precedence,
status/signal forwarding, target replacement, failed exec, socket disconnect,
shim death and high-fd hygiene. The cargo-built actual CLI `__launch` is also
exercised (never installed binaries). Production-CLI end-to-end tests now exercise
the switched owner API, whose current_exe implements __launch; lower-level tests
also retain cfg(test) dispatch. Legacy scoped rejection is integrated.
Writable pins, mutable scripts/config, child disclosure and the residual
hash-to-exec race remain explicit limits. The owner API defaults to redacted
stdio; inherited unredacted stdio requires the typed RunUnredacted proof.

#### Owner API parity

The owner accepts ordered `(name, reference)` assignments. Last assignment wins;
all overwritten references are dropped **before Prepare** and therefore cannot
be authorized, unlocked or added to redaction by that assignment. One stderr
note per repeated name is emitted, without references or values. This is an
explicitly narrower contract than legacy duplicate handling. Daemon exact-ref
set equality is unchanged. CLI parsing still processes explicit files before -e
and defaults to .karambit.env only without -e. cmd_run passes ordered assignments
to the owner API; it never falls back to legacy release on bound failure.

Bound Use prompt text and run audit `context` now share legacy `run_context` (audit's is
built from the masked argv; its script hash is of the real script). For shell scripts and
multi-line commands it shows line count, a short SHA-256 and collapsed leading `VAR=…`
lines. A policy `approve` run prompt shows the command in full or is refused
(`policy.approval_prompt_too_long`).
SsoUse remains exactly the legacy name/account/role prompt, without a context
field. Synthetic AUTH/transport-hook tests compare serialized Use prompts for
plain argv and multiline shell argv, and check unchanged SsoUse serialization.


#### Explicit owner target and production switch

The owner resolves a bare program name using its own PATH, or a slash-containing
name against its requested cwd, and sends a required absolute `target` separately
from verbatim argv. The daemon never resolves a launch target using its own PATH.
Missing target is a wire error. Target capture, command-scope shell restrictions,
pin comparison and fresh revalidation use that target, not the untrusted display
name in argv[0]. Canonical target/hash and original argv remain separate audit
fields. The shim already execs the canonical bundle target with original argv and
rechecks its hash before exec; no shell fallback or inherited shim environment is
introduced. Both bundle and private instruction schemas reject unknown fields.

Production cmd_run preserves its run-child audit envelope, profile validation,
exact application error texts and exit/signal mapping. It delegates release,
execution, scrub/redaction and endpoint cleanup to the owner API. No legacy
fallback is provided. Clap's missing-command usage error remains unchanged;
cmd_run retains its internal missing-command guard. Profile names containing
`aws/` remain invalid as before (only bare profile names are accepted).

#### Legacy scoped rejection

Raw agent `Use` never releases a command-scoped lease DEK, even for a correctly
claimed command. Each refused ref says ``scoped lease: use `karambit run` ``;
only bound LaunchRedeem spends this authority. Refused attempts do not consume
lease uses. Unscoped agent leases retain their existing behavior.

Legacy Unlock (including run, view and aws-describe) retains independent stored
policy authorization: public/Open agent-allowed unwraps and Bio fresh proof still
work, without spending a scoped lease. Private agent get/reveal/copy still cannot
spend any lease; an already-denied request with a matching scoped lease gains only
the same diagnostic. Human get/reveal/view/run and anchored human caches are unchanged.

Defense in depth refuses agent AwsOpen for a matching active command-scoped lease
without independent stored policy, and SsoOpen (including nested Unlock) without
independent registered policy. Independently authorized and human endpoints keep
their existing proof checks; these gates add no authority. AwsOpen continues to
host caller-supplied credentials, not prove their provenance. Refusals are audited:
Use records only ref names/reasons in `daemon-use-refused`, while failing Unlock,
AwsOpen and SsoOpen have their existing intent/outcome records. No DEKs, values,
credentials or endpoint tokens enter refusal records.

These are scoped-authority gates, not a blanket agent verb fence or OS isolation.
The verb fence is the separate capability fence table below.

### Capability fence (AGENT_DENIED_VERBS)

`crates/core/src/fence.rs` holds one table, `AGENT_DENIED_VERBS`, of the verbs an
agent caller may never perform: init, add (including `aws add` and `--sso`), rm,
relaxing policy, relaxing config, `get` of a non-public secret, lease grant, human
unlock, keys upgrade, helper pin, recover, key retirement, backup rotate/verify, the
paper ceremony, `--no-redact`, daemon stop, SSO login/logout, portal add/remove/limit
and SSO registration. Each row says whether the CLI, the daemon or both look it up,
and there is one refusal message (`fence::refusal`). Every earlier `deny_agent` call
and inline `is_agent()` refusal is now a lookup in this table.

- **Daemon is authoritative.** `handle_effect` maps the request to its verb
  (`fence::request_verb`, an exhaustive match so a new `Req` variant does not compile
  until classified) and refuses before any state, prompt, helper or key access. The
  caller is the kernel-derived `Peer`, never a wire claim. The refusal is audited by
  the existing `daemon-*` intent/outcome. `SsoPortalLimit` is checked at the top of
  dispatch because it is classified with delivery.
- **CLI refuses early.** `command_verb` (also exhaustive) runs before any prompt, stdin
  read or daemon request; the library client entry points repeat the lookup.
- **Conditional verbs.** `policy` and `config` stay reachable for agents because
  tightening reduces authority; only relaxation is the `PolicyRelax`/`ConfigRelax`
  lookup, in the operation. `get`/`copy`/`unlock` at the daemon remain governed by
  stored policy (`run_authorization`): an `agent_allowed` or public secret is still
  readable through `run`, and `karambit run` stays open to agents.
- **Not fenced** (they only reduce authority or are policy-governed): `run`, `aws <PROFILE>`,
  `whoami`, `aws show`, `ls`, `status`, `lease ls`, `lease revoke`, `audit`,
  `daemon status`, `sso status/ls`, `SsoForget` (local cache forget), and
  `doctor`.
- **Stricter than before.** Agents can no longer create secrets at all (`add`,
  `aws add`, `aws add --sso`), delete them (previously a Touch ID prompt), or run
  `init`. Daemon-side the fence now also covers `RetireKeys*`, `Recover*`,
  `RotateBackup`, `UpgradeKeys` and `RunUnredacted` as a dispatch lookup instead of
  a check inside the operation.
- **Limits.** The fence relies on agent detection (section 4): an undetected agent is a
  human. The CLI `rm` of a portal edits same-user-writable `config.json` with no daemon
  request, so only the CLI layer can fence it; a hostile same-user process can edit that
  file directly either way. `agent-process-names` removal (residual) is not a fence
  row.

## Linked backends interface

This amendment describes the generic source/backend code; it supersedes the earlier
statements that all backend lifecycle work is planned. It does not claim
the backend contract is fully implemented. This build registers no backends: the interface is
specified in [backend-contract.md](backend-contract.md). Sources: `cli/src/source.rs`,
`core/src/daemon.rs` (`backend_binding`, `resolve_values`, `source_mutation`), and
`core/src/backend/{registry,service}.rs` (paths relative to `crates/`).

### Authority and credential lifetime

- **Daemon-held credentials:** source tokens are encrypted at
  `sources/<name>/cred`. The daemon decrypts them for adapter calls; resolved values,
  grants and lifecycle state are RAM-only. Config contains binding metadata, not
  token bytes. This is still a same-user process, not OS isolation.
- **Session-bound grants:** backend cache access checks grant/session, ref/selector,
  source binding, expiry and authorization again at delivery. The current daemon
  creates human resolve grants for five minutes, anchored to the kernel-identified
  terminal/GUI ancestor; unanchored operations cannot reuse a session. Detected
  agents are refused even in bound `run`. Bound `run` is the intended agent delivery
  boundary, not permission to bypass this current refusal through raw Resolve.
- **Source administration:** add/rm/retarget are human-only with
  fresh daemon-mediated Touch ID; source ls is human-only metadata without Touch ID.
  Retarget/removal invalidates old grants/cache and blocks stale publication. Old
  dynamic cleanup retains the old endpoint/credential snapshot, never the replacement.
  An edited config is not approval of a new binding. Writable files and binaries
  still prevent a same-user tamper-proof claim.
- **Revoke-pending:** the lifecycle service disables reuse before upstream revoke.
  Failure retains cleanup in RAM, retrying after 1, 2, 4, 8, 16, 32, then 60 seconds
  (or a longer rate-limit delay), bounded by upstream expiry. Expiry without success
  is `expired-unconfirmed`, not revoked. An acknowledgement means the server accepted
  revoke, not proof every downstream service invalidated every copy. Static secrets
  cannot be recalled by ending local permission. Restart loses grants/cache and
  upstream tracking; issued credentials may remain valid until upstream expiry.
- **Availability:** no backend kinds are registered, so `source add` refuses every
  kind. The lifecycle service has **no automatic lease renewal**; subsequent
  authorized resolution re-issues after expiry rather than renewing. It cannot
  refresh credentials already injected into a child's env. Nonempty source policies
  are refused by the daemon resolver. `ref check` is offline but uses the empty
  registry, so it rejects backend kinds rather than validating their native refs.

### Boundary #13: separate agent and human AWS roles

Only Karambit-resolved values enter bound-run redaction. Literal/fragment matching,
the four-byte minimum and stdout/stderr-only coverage still apply. An agent running
`aws secretsmanager get-secret-value` (or an SDK/batch equivalent) fetches values
independently: Karambit does **not** see or redact those values. SSO role credentials
minted for a bound launch are added to the owner's redaction set before the target
receives them.

Give agents a role **without `secretsmanager:GetSecretValue`** or
`secretsmanager:BatchGetSecretValue`. A policy named “ReadOnly” is not sufficient:
reading a secret is a read operation. Use separate human secret-read authority,
not the same role in both profiles. This example identity policy is deliberately
small, not a complete role trust policy or a same-user boundary. Replace the sample
account, region and secret ARN with exact approved resources; do not apply it
unchanged.

Agent role: metadata for one secret, with an explicit denial of value reads even if
another identity policy allows them:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:DescribeSecret",
      "Resource": "arn:aws:secretsmanager:us-east-1:111111111111:secret:app/db-AbCdEf"
    },
    {
      "Effect": "Deny",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"],
      "Resource": "*"
    }
  ]
}
```

A customer-managed KMS key may additionally require `kms:Decrypt` for the human
role, which this example does not grant. Add only required non-secret agent actions;
do not give the agent role permission to assume a secret-reading role or modify
IAM/resource policies. Review all attached policies, trust policies and alternative
credentials: this deny constrains requests using this role, not an agent that
acquires another identity.

## Mode B Seatbelt spike

`run --jail [--allow-host localhost:PORT]... -- cmd` installs Seatbelt in the
trusted shim after authenticated redemption, GO and target/hash validation, before
untrusted exec (and before the AWS fork). Failure aborts launch; no unsandboxed
fallback. The private connected daemon channel is CLOEXEC and never reaches the
target. The daemon Prepare jail flag only permits an empty reference set; it is
not daemon-enforced policy or a claim that raw clients requested confinement.

The profile denies by default, permits ordinary file reads/writes and native
execution/fork, and denies reads/writes under the canonical vault (including key
blobs), HOME's default vault, `.vault-token`, `.aws`, `.ssh`, and `.kube`. Sibling
process inspection is not allowed (self inspection is); `open` and `osascript`
execution is denied. The mach-lookup allowlist is deliberately **empty**, so
LaunchServices/AppleEvents/keychain service access has no exception. Other IPC
and network operations remain denied. Only stdio survives target exec.

On this macOS release SBPL remote filters support `localhost` or wildcard, not
arbitrary host/IP selectors. **No wildcard fallback exists**: `--allow-host`
accepts only `localhost`, `127.0.0.1`, or `[::1]` with a nonzero port, granting TCP
to IPv4 **and** IPv6 loopback at that port. All other destinations are refused
before launch. Remote egress needs a loopback proxy; a loopback proxy design is not yet decided.
DNS and UDP are not permitted. The only implicit TCP allowance is a validated
loopback daemon-issued AWS credential endpoint; its bearer token still authorizes
requests. AWS empty config paths use `/dev/null`, not the protected vault.

Limits: this is an opt-in spike, not isolation of the calling agent or broker
custody. `sandbox-exec` and its Seatbelt SPI are deprecated/unsupported interfaces;
OS upgrades can break syntax, enforcement or compatibility. Doctor reports SPI
availability as **inconclusive**, not a proven security pass. Non-macOS Sandbox
is a refusing stub; the broader core portability refactor is still planned. Mach denial
breaks GUI/service-dependent CLIs. Credentials remain in the target; filesystem
writes, inherited stdio, allowed listeners/proxies, mutable paths/hardlinks and
same-user peers can disclose them. This is not a general filesystem allowlist,
anti-tamper guarantee, protection of previously copied key blobs, or protection
against sandbox/kernel escapes. Existing file descriptors and unjailed siblings
remain outside the boundary. Keep HOME/vault paths stable while running.

Synthetic paired probes are in `crates/core/tests/jail.rs` (file/key/dotfile reads,
sibling environment, denied loopback egress and explicit harmless local `open`
handler). Every negative requires the identical outside command to succeed first;
a missing prerequisite fails as inconclusive, never evidence of denial. The
production CLI/shim smoke is `crates/cli/tests/jail_cli.rs`; no live helper or keys.

## Subtractive policy

The optional config policy is portable evaluation, without OS calls or changes to
secret envelopes. Daemon unlock (after glob expansion), raw lease Use, bound
Prepare/redeem, fixed tool call plus credential, and backend resolve
apply it before accessing DEKs/credentials. Existing authorization remains
mandatory. Decisions with configured policy are fail-closed audited as
`policy-decision`, with `detail.reason_code` (`policy.rule_deny`,
`policy.prod_agent`, `policy.approval_required`, `policy.rule_allow`, `policy.base`),
subject/action/effect, never values. The `approve` effect fails closed (there is no approval flow yet). Tier tag
patterns apply to refs/tool ids; any matching prod tag wins over other tags.
Agent prod access requires explicit allow, but still requires base authority.
Session labels only select additional restrictions, never allow authority.

The trusted owner forwards explicit jail ports in Prepare; all loopback aliases
are checked, matching Seatbelt's dual-family allowance. Requested jail/egress
metadata is not evidence of installed confinement and never grants authority.
The daemon-issued credential endpoint remains the pre-existing implicit exception.
Raw clients can omit egress metadata: this policy does not constrain unjailed
network activity. Policy is not tamper-resistant against a same-user config writer;
older builds ignore it (this build preserves unknown config fields on save, and reports its build id
and loaded-policy SHA-256 so `policy test --live` can detect a daemon that is not enforcing the file). Existing agent-detection, credential copying and filesystem
limits remain. In-flight policy edits are not a transactional kill switch;
redeem re-evaluates current policy before credential access, without revoking
already-delivered values. Legacy internal lease Use also checks run restrictions.
