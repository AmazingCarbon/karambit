# Karambit reference

Detailed behaviour behind the [README](../README.md). The security analysis is in [threat-model.md](threat-model.md).

## Commands


Agents: see [docs/agents.md](agents.md) (copy into AGENTS.md) and `karambit help agent`.
A `run` that is refused or fails before the command starts exits 125 with a reason code,
`retry`, `actor` and a `next:` step; `--json` (or `KARAMBIT_FORMAT=json`) puts it on stderr
as `{"error":{...}}`. `run --status-fd N` writes one status line the command can't forge;
`"started":true` means the command was exec'd, so a launcher failure (exit 125, `launch_failed`) is `started:false`.
JSON output is compact unless stdout is a terminal or `--pretty` is given.
`mv` never replaces an existing secret, refuses `aws/*` and `sources/*`, and ends temporary access on the old names; scripts and profiles that use an old name must be updated.
`ls --brief` prints `name<TAB>access`. `call --list` shows the configured fixed tools.
The old `--touch`, `--agent`, `--human-only` and `--public` flags still work.

```sh
karambit add stripe/prod-key                     # value via hidden prompt or stdin, never argv
karambit add dev/db --access agents              # Agents · no prompt
karambit add bank/pin --access me-touch          # Only me · Touch ID: `karambit run` refuses agents
karambit ls                                      # ACCESS / NAME table, no values
karambit run -e STRIPE_KEY=stripe/prod-key -- ./deploy.sh
karambit run -- npm test                         # reads ./.karambit.env, else ./.env.schema (refs only, safe to commit)
karambit secure                                  # move ./.env* into the vault, leave .env.schema (alias: eat)
karambit secure rebuild                          # put the original .env files back
karambit get stripe/prod-key                     # human-only: clipboard, auto-clears
karambit policy 'dev/*' --access agents          # relaxing is human-only + Touch ID
karambit policy bank/pin --access me-touch       # tightening is always allowed
karambit add ci/email --access public       # not a secret: agents can read it, never redacted
karambit mv stripe/prod-key payments/stripe      # rename: keeps value and access; human + Touch ID
karambit mv stripe/ vendors/stripe/              # move a folder (both end in /); one Touch ID
karambit policy ci/url --access public      # promote an existing entry to public (human + Touch ID)
karambit config default-tier off
karambit audit ; karambit audit --verify          # reads across rotated audit-<time>.jsonl segments
karambit config audit-full-argv true            # record launch argv unmasked (human + Touch ID; default false)
karambit backup verify                          # retype paper key; opens every backup copy, reports "N of M"
karambit backup rotate                          # new paper key, re-encrypt all backup copies (re-run to finish if interrupted)
karambit recover [--accept-loss NAME[,NAME]]    # new SE keys, restore from typed paper key
karambit doctor --agent-env [--json]            # what can THIS environment reach? synthetic canary only
```


## Model

What Karambit does and does not guarantee depends on how a secret is used: **Mode A** (a trusted
tool receives the value; `run`, `aws <PROFILE>`, today), **Mode B** (sandboxed tool; planned) or **Mode C**
(broker custody; planned). Agents are not kept from values in Mode A: the tool you launch holds
them. See [docs/threat-model.md](threat-model.md) for the modes, the command-to-mode map and
the same-user limits.

## Platform capabilities

Guarantees depend on capabilities, not macOS APIs: **(1)** hardware-bound
non-exportable keys + user-presence unwrap; **(2)** kernel-attested caller identity
with an unforgeable process generation; **(3)** peer exe/ancestry/start/env
introspection; **(4)** pinned-binary launch channel; **(5)** clipboard history/sync
exclusion + auto-clear; **(6)** child sandbox; **(7)** per-user service lifecycle;
**(8)** screen-lock signal. See the [capability matrix](threat-model.md#capability-matrix)
for exact current mechanisms, Linux/Windows candidates and required degraded-tier
reporting. Ports and eight-capability doctor reporting are not implemented yet.

Here “Touch ID” names (1)'s current presence mechanism, caller/anchor checks need
(2)+(3), and helper/bound-run delivery needs (2)+(3)+(4). Daemon RAM lifetime needs
(7); lock-ended human cache reuse also needs (8). These are not protection against
hostile same-user code. Encryption, redaction and audit remain software properties.
**(6) is not implemented**: current runs are Mode A, not sandboxed. **(5) is partial**:
Concealed/Transient clipboard markers and unchanged-content auto-clear do not
ensure history exclusion; no `.currentHostOnly` is set, so Universal Clipboard
exclusion is not guaranteed. Copies already read cannot be recalled. Missing or
weaker capabilities must be reported, never silently presented as equivalent;
today's doctor environment probes are not a full capability certification.

Current macOS implementation of (1): three Secure Enclave P-256 keys, all bound to this Mac:

| key | used for | prompt | works while screen locked |
|---|---|---|---|
| `bio` (`.biometryCurrentSet`) | Touch ID secrets | Touch ID, **enforced by the Secure Enclave** | no |
| `agent` (AfterFirstUnlock) | no-prompt secrets agents may use, and public entries | none | **yes** (after one unlock since boot) |
| `open` (WhenUnlocked) | legacy no-prompt secrets not yet moved | none | no |

Access levels (GUI dropdown, most open first; the GUI labels them Public · not secret, Agents · no
prompt, Agents · Touch ID, Only me · Touch ID, and calls leases "temporary access"):

| level | tier | agents | key |
|---|---|---|---|
| Public | open | read it, never redacted | agent |
| Agents | open | yes, no prompt | agent |
| Agents + Touch ID | bio | yes, Touch ID each use or a lease | bio |
| Only me + Touch ID | bio | blocked | bio; after one Touch ID, reused for 3h or until the screen locks |

No-prompt "Only me" is **retired**: `add` and `policy` refuse open tier + agents blocked + not
public, because a same-user agent can read it anyway (see Limits). Old vaults: run
`karambit keys upgrade` once (human, one Touch ID) to create the agent key and move agent-enabled
no-prompt secrets onto it; until then they stop working when the screen locks.

Only a human with Touch ID can mark something public; `public` is bound into the DEK's AAD, so
editing `public: true` into a file makes it fail to decrypt rather than leak.

Per secret: random DEK encrypts the value (ChaCha20-Poly1305); DEK is wrapped to an SE key via
ECDH + HKDF. The wrap AAD binds name + tier + agent flag + public, so editing the JSON to relax
policy makes decryption fail. The file's `key` field says which SE key wraps it; a value that
contradicts the tier is refused. Toggling a tier rewraps the DEK only. A copy of each DEK is also
encrypted to an offline **age** recipient for recovery.

Policy rules:
- Tightening (touch on, agent deny) never needs a prompt.
- Relaxing (touch off, agent allow, relaxing config) is refused from agent callers and needs Touch ID.
- Code-loading environment (bound `run`/`aws`): when the caller is an agent, ambient variables that make a
  program load code (`DYLD_*`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`/`PYTHONSTARTUP`/`PYTHONHOME`/`PYTHONINSPECT`/`PYTHONUSERBASE`,
  `NODE_OPTIONS`/`NODE_PATH`/`NODE_REPL_EXTERNAL_MODULE`, `RUBYOPT`/`RUBYLIB`, `PERL5OPT`/`PERL5LIB`/`PERLLIB`,
  `JAVA_TOOL_OPTIONS`/`_JAVA_OPTIONS`/`JDK_JAVA_OPTIONS`, `BASH_ENV`, `ENV`, `ZDOTDIR`, `PROMPT_COMMAND`,
  `npm_config_node_options`) are dropped before the program starts. The run prints and audits
  (`launch-env-dropped`) the dropped names, never values. Human callers keep them. `karambit config allow-env A,B`
  lets named variables through for agents; adding a name is relaxing (human + Touch ID), removing one is not.
  A `.env.schema` or `.karambit.env` plain value with one of these names is refused for everyone, `env check`
  reports it, and `secure` leaves it out of the schema with a warning.
- Agents cannot create or delete secrets, grant leases, pin the helper, recover, rotate the backup or
  manage SSO portals and sign-in (a single table, `AGENT_DENIED_VERBS`, checked in both the CLI and the
  daemon). `get` and `--no-redact` are human-only too; `run`, `ls` and policy-permitted reads are not.
- `add` Touch ID is a policy gate (`add-requires-touch`), not crypto: encryption only needs the public key.
- `karambit run` (Mode A) gives one prompt for all requested bio secrets, and redacts non-public Karambit-resolved literal values (4+ bytes) in the child's stdout/stderr. The child still holds the plain value; see [docs/threat-model.md](threat-model.md).

## Leases (daemon)

```sh
karambit lease grant 'deploy/*' --hours 3 --to pi --cwd ~/code/myapp --cmd curl --max-uses 50
karambit lease grant 'deploy/*' --to pi --cmd /opt/homebrew/bin/node --script ./deploy.js   # interpreter + script
karambit lease ls ; karambit lease revoke 'deploy/*'
karambit daemon status ; karambit daemon stop      # stop = every lease ends
```

- Default lease length is 3h (max 168).
- **Human self-lease** ("Only me + Touch ID"): after one Touch ID, the daemon keeps the key for
  `human-lease-hours` (default/max 3, 0 disables). Reuse requires a non-agent caller descending
  from the same kernel-identified terminal application or Karambit GUI (PID + start time).
  Other terminal apps, restarted apps and unanchored/SSH/background callers require fresh Touch ID;
  unanchored callers never create a cache. Tabs in the same app share the anchor, shown in lease ls/audit.
  It ends on revoke, expiry or screen lock (checked every 5s and on each cached use).

- A small per-user daemon (`karambit daemon`, auto-started, exits after 20 idle min) holds leased
  keys in RAM only. Nothing on disk; restart = all leases gone.
- Caller identity uses capability (2) (`LOCAL_PEERTOKEN` audit token); cwd, ancestry and env inspection use (3). Agent classification still uses heuristic process/env markers.
- Granting is human-only + one Touch ID. Folder leases cover secrets that exist at grant time only.
- Blocking agents, turning Touch ID on, overwriting or deleting a secret ends its lease.
- Scope: `--cwd` (agent's working dir), `--cmd` (program path pinned with its SHA-256; shells and
  command wrappers refused), `--max-uses`.
- Interpreters (`node`, `python*`, `ruby`, `perl`, `php`, `deno`, `bun`, `java`, `osascript`, `lua`,
  `Rscript`, `pwsh`) are refused as a bare `--cmd`, since `node -e ...` runs anything. Use
  `--cmd INTERPRETER --script FILE[,FILE]` (repeatable): the lease then matches only that interpreter
  (path + hash) running exactly that script (path + hash) as argv[1], and never when argv has
  `-e`, `-c`, `-m`, `-p`, `-r`, `--eval`, `--print`, `--require` or `--import`. Modules the script
  imports are not hashed. Leases granted by older builds with a bare interpreter stay in the daemon's
  memory until they expire, but no longer match a launch; re-grant with `--script`.
- The grant prompt reads `N secrets: a, b, c` and shows the scope. If the names (or scope) do not fit
  the helper's 120-character field, the grant is refused ("too many secrets for one prompt; grant
  fewer or use a narrower pattern"), never cut off. Human unlock of Bio secrets is refused the same way.
- AWS profiles are served to `aws`/SDKs over a per-run loopback endpoint (ECS credentials format,
  random bearer token, closed on exit). No AWS keys in the child's environment.
- The SE helper binary is pinned by SHA-256; after a reinstall run `karambit helper pin` (install.sh does it).


## Limits (full list)

- **Bound `run`**: env, static AWS and registered SSO runs use a pinned child shim and
  single-use daemon redemption bound to that owner/shim, target hash, argv and cwd.
  The owner resolves PATH; the shim directly execs the canonical target, with no shell fallback.
  Raw legacy requests cannot spend command-scoped agent leases: use `karambit run`.
  Before any prompt, the daemon estimates the release size (local secret ciphertext lengths, argv and
  your environment) and refuses a launch over the 1 MB frame or `ARG_MAX` (`launch too large`), so no
  lease use is spent. Linked-source (backend) values can't be sized up front; they are checked at release only.
  Independent stored-policy disclosures, unscoped leases and human access retain
  their separate authorization; this is not a blanket agent verb fence.

Full threat model, operating modes and same-user limits: [docs/threat-model.md](threat-model.md).
Secrecy is not safety, and nothing here is a defence against code running as you outside Karambit.

- **`.biometryCurrentSet`**: adding or removing a fingerprint permanently invalidates the bio key.
  Recovery: `karambit recover BACKUP_FILE` (new SE keys, rewrap from the age copy). No backup = gone.
  Recovery first tests the paper key on every secret and refuses, changing nothing, if any has no
  backup copy or one the key cannot open. `--accept-loss NAME[,NAME]` must list exactly those
  secrets; they are then skipped and stay wrapped to the retired keys. A recovery interrupted
  part-way is finished by running `karambit recover` again.
  During an unfinished backup rotation, `recover` prints the rotation warning first: files this sheet
  cannot open may be readable with the other sheet.
- **Backup rotation** records `backup_rotation` in config before it rewrites the first file. If it
  stops part-way, `status` and `backup verify` warn, and some secrets need the new paper key while
  the rest still need the old one: keep both sheets and re-run `karambit backup rotate`.
  `backup verify` trial-decrypts every file's backup copy and fails unless the typed sheet opens all.
- **Agent detection** (parent process names + env markers) is a speed bump, not a boundary. A
  process that double-forks and scrubs its env looks like a human. The hard boundary is (1)'s fresh user-presence unwrap, not agent detection.
  In testing, an agent ran `env -i` from a detached subshell, read a no-prompt agents-blocked
  secret, and was logged as you.
- **SSH callers (`ssh localhost karambit ...`)**: with macOS Remote Login on, a same-user agent that
  appends its own key to `~/.ssh/authorized_keys` gets a process chain `sshd > shell > karambit` with no
  agent in it. Detection now marks a caller `remote` when `sshd`/`sshd-session` is an ancestor (daemon, from
  the kernel) or `SSH_CONNECTION`/`SSH_TTY` is set (the daemon reads the peer's initial environment; the CLI
  reads its own). `remote` is written to the audit log. Every human-only verb (the same table as agents, CLI
  and daemon layers) refuses a remote caller unless config `allow_ssh_human` is true
  (`karambit config allow-ssh-human on|off`; turning it on is a relaxing change, so human-only plus Touch
  ID, and refused from a remote caller). Default off. Remote callers still get no human anchor, so no
  self-lease reuse. Bound launches and the legacy unlock paths treat a remote caller's "needs a human"
  decisions (fresh Touch ID, cached human approval) as denied: `ssh localhost karambit run -e X=onlyme/secret -- cmd`
  is refused with "refused over SSH; set allow-ssh-human from a local terminal to allow", before any prompt.
  This is a name/env check, not a boundary: a process can clear `SSH_*` and re-parent;
  the sshd-ancestor check cannot be cleared that way. Secrets that agents may use (and public ones) stay reachable.
  `karambit doctor` has a `remote-login` row (read-only: `systemsetup` if it answers without admin, else a
  loaded sshd launchd job or an open loopback port 22) that fails when Remote Login looks on.
- **Static AWS keys and `session_mint`**: a program that holds an IAM-user key can run
  `sts get-session-token` (up to 36 h; `assume-role` too if allowed) and keep the new credentials after
  Karambit's endpoint is gone. With the per-profile opt-in `session_mint`
  (`karambit aws add NAME --session-mint`, or `karambit aws session-mint NAME on|off`) the daemon calls
  `sts:GetSessionToken` itself (1 hour, key by environment only, 30 s timeout) when the run
  starts and serves only the session; the endpoint lives 59 minutes. If the exchange fails the launch is
  refused (the key is never served instead), and a `session_mint` key is never released to an agent through any
  legacy path: `-e VAR=aws/NAME`, `get`/`reveal`/`run`/`copy`, or a lease's key (`Use`). An agent that asks to
  describe such a profile gets only its masked key id, region and flags. The `aws` CLI is taken only from
  `/opt/homebrew/bin/aws`, `/usr/local/bin/aws` or `/usr/bin/aws` (symlinks resolved; the target must be a regular
  executable owned by you or root and not group/world-writable), never from the daemon's inherited `PATH`
  (a planted `aws` there would receive the key), and runs with a cleared environment (`PATH=/usr/bin:/bin`,
  an empty temporary `HOME`, no `AWS_*` configuration). Both toggles are human-only and cost Touch ID because they
  rewrite the entry. AWS rules that apply (per AWS's GetSessionToken documentation; not re-tested against
  real AWS here): GetSessionToken credentials cannot call IAM APIs unless MFA was supplied, and cannot
  call any STS API except `AssumeRole` and `GetCallerIdentity`, so they cannot mint another session with
  `GetSessionToken`. A program holding the session can still call `sts:AssumeRole` if the user's policy
  allows it, which yields credentials Karambit cannot recall. Needs an IAM-user key allowed to call
  `sts:GetSessionToken`; temporary keys (ASIA…) and SSO profiles are refused. Not exercised against real AWS
  in tests (a fake `aws` binary stands in).
- **No-prompt keys are usable by any process running as you.** The Secure Enclave binds keys to the
  Mac, not to karambit: a 20-line program loaded `open.key`/`agent.key` and decrypted without
  karambit (verified in testing). Treat Public and Agents secrets as readable by any agent you run.
- **Human self-lease window**: because human-vs-agent is heuristic, an agent posing as human can
  reuse an "Only me + Touch ID" secret only under the same approved terminal-app/GUI ancestor
  (up to 3h, until screen lock/revoke). This is not per-tab isolation or protection from same-user
  GUI/terminal automation. Set `human-lease-hours 0` to require Touch ID every time.
- **`karambit doctor --agent-env`** probes the environment it runs in (sibling `ps -E`, `~/.vault-token`
  readability, daemon socket connect (no request sent), writability of audit/config/pins, redaction of a synthetic canary, agent
  detection) and prints pass / fail / inconclusive / unsupported per row. It never touches real secrets,
  never starts a daemon and never prints a value. It covers **this run only**; a pass is not a safety
  claim. Its `key-blob-use` row compiles and runs a small Swift probe (needs the Xcode command line
  tools) that creates a **synthetic** no-prompt Secure Enclave key, reloads it from a blob file and
  does an ECDH, without Karambit and without a prompt: `fail` means your environment can use such a
  key blob (limit above); the row is never `pass`. It touches no real key, and
  `KARAMBIT_DOCTOR_SKIP_KEY_PROBE=1` skips it (`unsupported`). Run it once from a plain shell
  and once from inside your agent, and compare. See the doctor section of
  [docs/threat-model.md](threat-model.md).
- **The CLI checks the daemon, within the pin.** Before a request leaves the CLI (an `add` carries the value),
  it takes the kernel's identity of the socket's listener and requires its executable hash to be in
  `keys/daemon.sha256`, and its initial environment (read from the kernel) must hold no `DYLD_*` name, or be
  unreadable (an unsigned-runtime binary would otherwise load an injected library under a matching hash).
  The vault (a symlinked root is resolved first), `run/` and `d.sock` must be owned by you and not group/other-writable.
  The daemon itself refuses to start when its own environment has a `DYLD_*` name; the CLI strips them when it
  spawns one. Before first init (no keys, `pub.json` or `config.json`) the check is skipped; afterwards a missing
  pin is refused. `daemon stop` and `helper pin` are exempt so a stale pin can be recovered. The pin file is itself same-user writable (next item), so this stops a fake
  daemon, not a same-user agent that also rewrites the pin.
- **Policy is enforced only by builds that know it.** Older builds ignore the `policy` section, and an
  older build saving config can drop it. A green `policy test` only evaluates the rules; run
  `karambit policy test FILE --live` to confirm the running daemon loaded the same policy.
- **Audit size**: `audit.jsonl` rotates at 16 MB to `audit-<unix time>.jsonl`; the next file's first line
  chains from the old file's last hash and `audit --verify` walks all segments. Deleting the oldest
  segments is reported as `chain ok (N events, older part removed before <time>)`; a gap or edit in what
  remains is still `BROKEN`. Nothing is deleted by Karambit.
- **Argv in the audit log**: launch records store argv with known secret values replaced by
  `[REDACTED:name]` and obvious credentials masked (`--password X`, `--token=X`, `-pX`,
  `Authorization: Bearer X`, `user:pass@` in URLs, `KEY=value` with a secret-looking name; an argv
  element that is a flag's value is masked whole, so `--password 'a b c'` leaks no word), plus
  `argv_sha256` (SHA-256 of each argument followed by a NUL byte). Masking is heuristic; set
  `audit-full-argv true` to store argv as typed. Turning it on is a relaxing change.
- **Touch ID prompt context for scripts**: `sh|bash|zsh -c` scripts and multi-line commands show
  `sh script, 7 lines, sha256 1a2b3c4d: VAR=… curl ... (+6 more lines)`. Leading `VAR=value` lines are
  shown by name only, not skipped. Arguments after the script (`sh -c 'eval "$1"' _ ARG`) follow as
  `-- args: ...`; a control character or a cut there makes the context incomplete. A policy `approve` prompt must show the whole command; if the
  script is multi-line or cut, the run is refused with `policy.approval_prompt_too_long`. Read the
  line count: more lines than you wrote means deny.
- **Not yet tamper-proof against a same-user agent**: config, the audit hash chain (unkeyed), the
  helper pin file and the installed binaries are all writable by you. The `KARAMBIT_DEV` helper
  override is debug-only (builds installed before that change still carry it).
- **Redaction** (Mode A) filters the child's stdout/stderr for Karambit-resolved values; it does not stop
  base64/re-encoded output, and it does not cover values a child fetches itself (e.g. `aws secretsmanager
  get-secret-value`; open). The child process has the plain value and can exfiltrate it; only inject into
  commands you trust. See [docs/threat-model.md](threat-model.md).
- **Boundary #13 (open): Secrets Manager values a child fetches itself are not redacted.** Only values
  Karambit resolved are filtered. Until a broker mode exists, give agent profiles a role without
  `secretsmanager:GetSecretValue`.
- **GUI** is treated as the human caller. Gates are per operation, not blanket: copy follows the `get`
  rules (a bio secret with an active "Only me" self-lease is copied with no new Touch ID), creating a
  new secret needs none, deleting open-tier secrets needs none. See [docs/threat-model.md](threat-model.md).
- Binaries are ad-hoc signed. Build locally; nothing is notarized.


## Tests

```sh
cargo test                 # crypto/redaction/policy with a software key, no SE needed
se-helper/.build/release/karambit-se-helper selftest
```


## Fixed tool calls (Mode C)

`karambit call ci-status JOB` makes one fixed CI build-status request (Jenkins-compatible API),
fetching only `GET https://HOST:PORT/job/JOB/lastBuild/api/json`. Configure an optional `tools`
map in `config.json` (no credentials in config), for example:

```json
"tools": {
  "ci-status": {
    "host": "ci.example.com", "port": 443,
    "method": "GET", "path_template": "/job/{job}/lastBuild/api/json",
    "credential_ref": "ci/status-api", "credential_host": "ci.example.com"
  }
}
```

Store `username:api-token` in that exact encrypted credential entry using the
existing human `add` flow. The tool inherits that entry's existing access level
(tier, public, agent-allowed); it does not grant new raw-secret authority or use
agent leases. Agents blocked by the entry's policy are refused. Host binding must
match, and the same credential cannot be configured for multiple host/port pairs.
Only simple job names (letters, digits, `_`, `-`) are accepted; nested jobs,
caller-selected URLs, methods and headers are intentionally unsupported.

The daemon keeps the credential, pins a checked public DNS address with curl
`--resolve`, refuses redirects and non-identity content encodings, buffers at most
1 MiB and scrubs literal, base64 and URL-encoded credential/components before
release. TLS verification remains on. It audits intent, decision and dispense;
audit failure before dispense prevents release. Errors never include server bodies
or curl stderr. Writable same-user config is not a tamper-proof host policy;
scrubbing is not a defense against arbitrary encodings or a malicious server.
Other existing Mode-A access to an agent-allowed credential remains possible.

Local tests generate a synthetic CA/certificate and use only localhost HTTPS.
Debug builds recognize the exact `KARAMBIT_TEST_FIXED_ENDPOINT=localhost:PORT`
and absolute `KARAMBIT_TEST_FIXED_CA` pair; no config field enables this exception.
Release builds ignore both and refuse loopback. These variables are for fixtures,
not deployment. Offline regression commands (no live vault/helper/network):

```sh
cargo test --offline -p karambit-core --test fixed_tool
cargo test --offline --release -p karambit-core --test fixed_tool fixed_tool_production_guard
```

## Experimental Mode B: `run --jail` (macOS)

```sh
karambit run --jail -- /bin/sh -c 'echo $((6*7))'
karambit run --jail --allow-host localhost:8080 -e TOKEN=dev/token -- my-tool
```

Opt-in Seatbelt confinement is applied in the authenticated shim before exec;
installation errors abort. Vault/key blobs and common credential dotfiles are
blocked, sibling inspection and LaunchServices are denied, and networking defaults
to deny. Only loopback TCP port exceptions are supported (`localhost`, `127.0.0.1`,
`[::1]` each allow both loopback address families); other hosts are explicitly
refused. Remote egress needs a loopback proxy (not yet designed). AWS runs additionally
allow their daemon-issued credential endpoint. `--allow-host` requires `--jail`.
No secrets are required for a jail-only computation.

This is a compatibility/security **spike**, not broker custody: the tool holds
its credentials, ordinary file writes/stdio remain possible, and same-user peers
are not jailed. Seatbelt/`sandbox-exec` is deprecated; non-macOS refuses. Doctor's
availability row is not enforcement proof. See [Mode B limits](threat-model.md#mode-b-seatbelt-spike).

## Subtractive policy

`karambit policy show` prints the optional `config.json` policy rules/tags (no
values). Existing `policy NAME --touch ...` access controls are unchanged.
For example, the optional config section is:

```json
"policy": {
  "rules": [
    {"subject":{"secret":"dev/*"},"action":"get","who":"agent","effect":"allow"},
    {"subject":{"tool":"deploy"},"action":"call","who":"agent","effect":"deny"}
  ],
  "tags": {"prod/*":"prod", "dev/*":"dev"}
}
```

Subjects are `secret` (local/backend reference glob), `tool` (exact id), or
`egress` (exact host:port). Actions: get/copy/view/run/call/export/egress; reveal
uses get, AWS describe uses view. (`export` is accepted in policy files but no command uses it.)
Who: `"any"`, `"agent"`, `{"kind":"pi"}`, or `{"session":"label"}`.
Session labels can only tighten; a session-scoped allow is ignored.
Deny beats approve beats allow; otherwise existing access applies. Tags are
pattern-to-`prod|preprod|dev`; any matching prod tag blocks agents unless an
explicit matching allow removes that default. Allow **never** bypasses secret
access, tool credential policy, fences or backend grants. Approve currently
requires a fresh, request-bound Touch ID approval (see below).
Jail Prepare checks every explicit allowed loopback port under all three spellings
(`localhost`, `127.0.0.1`, `[::1]`), because Seatbelt permits both address families.
This checks requested egress, not proof of confinement. No policy editor is added;
Test it on a copy of your config first. Older builds ignore this section
(and does not enforce it; saving with an older build can drop it). This build keeps
unknown top-level `config.json` fields when it saves, but it cannot change what an older
build does. `karambit status` and `karambit daemon status` show the running daemon's build id
and the SHA-256 of the policy it loaded; `karambit policy test cases.json --live` fails if that
hash differs from the file on disk, or if the daemon is an older build that reports none.

## Request approvals and agent containment

`approve` adds Touch ID; it never replaces per-secret access or an existing lease.
Approvals bind action, subjects, caller and request arguments with length-framed
SHA-256. They are single-use, daemon-memory-only and expire within 120 seconds
(including prompt time; ordinary bound leases retain their shorter launch deadline).
A bound `run` approves its complete local lease/ref set in one prompt, not once per
secret. Existing fresh-unlock and SSO prompts are combined for that run. Ref lists
that cannot fit the helper's 120-character names field are refused, not truncated.
Backend login/credential acquisition and `--no-redact` remain separate ceremonies.
No helper change or helper-pin change is required.

**Block agents** from the app (⋯ → Block agents, or Settings › Agents) or a **plain human
terminal** (both need Touch ID). Blocking refuses access; it does not stop processes.
`kill`/`revive` still work as aliases.

```sh
karambit block --agent pi      # or --session 'pi:ID', or --all
karambit unblock --agent pi    # or --session 'pi:ID', or --all
```

Block flags persist in optional `config.json` field `killed`; all daemon agent
requests, bound redemption/redaction and AWS endpoint fetches check them, even
with existing leases. For conservative containment, each block also burns **all**
outstanding agent leases, bound launches and credential endpoints (including
unrelated callers' endpoints). Unblock clears flags, never recreates grants;
`unblock --all` clears every flag, whereas a targeted unblock cannot override `--all`.
Session labels and agent detection remain spoofable restrictions, not authority.
Already delivered credentials cannot be recalled; no process is terminated.

A new `deny` policy rule for `run` on an AWS profile also applies to a job that is already running:
every credential fetch re-checks the current policy for that caller and profile, and on a deny the
endpoint answers 403 `PolicyDenied`, is removed and the denial is audited. An `approve` rule does not
prompt again on a fetch; the launch's approval stands. Credentials the job already fetched keep
working at AWS until they expire.
Same-user config tampering and running older builds bypass these new restrictions.

## Offline policy and env checks

These commands never prompt, start a daemon, open plaintext, or contact a backend:

```sh
karambit policy explain get dev/item --as agent:pi
karambit policy validate
karambit policy test cases.json
karambit env check                 # defaults to .karambit.env
karambit policy test cases.json --live   # also compare with the running daemon (read-only)
```

For CI or any machine without a vault, keep the policy in your repo and pass it directly.
`--config FILE` (on `policy validate|test|explain`) reads a full `config.json` or a bare
`{"rules":[...],"tags":{...}}` object; a file with neither shape is an error. `env check
--offline-refs` checks schema and reference syntax only: local refs are reported
`local_unverified` (and refs to sources not defined in a config are
`backend_source_unverified`) instead of failing. Neither flag opens the vault, keys or
daemon, and neither needs `~/.local/share/karambit`. The core builds on Linux, but there is no
Linux release binary yet, so CI has to build `karambit-cli` itself.

Explain reports the **subtractive overlay only**, with a zero-based `rule_index`
(or null for defaults) and stable `reason_code`. An `allow` is not permission:
base secret/credential access, containment and runtime approvals still apply.
Omitting `--as` simulates a human, not the invoking process. `call` subjects are
fixed tool IDs; `egress` subjects are host:port; other actions take secret/ref names.
Validation rejects malformed policy at config load. Invalid daemon reloads fail
closed; its last accepted policy snapshot remains in RAM, never a fallback authority.
Diagnostics read the current file (or `--config FILE`) and refuse invalid config rather
than simulate stale policy. A green `policy test` says what the rules decide, not that the
running system enforces them; use `--live` for that. Existing `policy <pattern> --touch/--agent/--public` remains supported.

Case files are **JSON only**, e.g.:

```json
[{"action":"get","subject":"dev/item","as":"agent:pi","expected":"allow"}]
```

The expected effect is `allow`, `approve` or `deny`; mismatches exit nonzero.
A `.karambit.env` schema is optional and value-free:

```text
# schema: ITEM required dev
# schema: OTHER optional
ITEM=karambit:dev/item
```

Tags are optional `prod`, `preprod`, or `dev` annotations, not authority or value
types. Check rejects missing required assignments, duplicates, missing/invalid
local envelopes, unconfigured backends and invalid adapter-native ref syntax.
Optional variables may be absent but, when present, are checked too. It reports
local-envelope versus backend-reference kinds; **remote existence and value types
remain unverified**, as do encrypted local value types. No backend credentials
are loaded and no values are decrypted. This check does not enforce schema at run.

## Repository profile pins and session labels

Review `.karambit.env`, then run the `profile trust [path]` subcommand from a human
terminal. Fresh Touch ID pins its canonical path and exact SHA-256 in config.
`run` checks the same bytes it parses: unpinned or edited profiles are refused for
agents and warned about for humans. This also covers explicit `--env-file` paths;
explicit `-e` assignments without a file are unchanged. Trusting a `.env.schema` also pins
the SHA-256 of the sibling `package.json` `scripts` object (canonical JSON; a fixed `none`
marker when absent; `nonregular` if it is a FIFO, device or directory, which is never read) in the optional `trusted_scripts` config map. Changing those scripts, or
adding a `package.json` to a schema trusted without one, makes the profile untrusted for
agents (`profile.untrusted`, detail "package.json scripts changed") and warns humans, like an
edited schema. Pins made before this existed stay valid while no `package.json` is next to
the schema; if there is one, agents are refused until you run the `profile trust` subcommand
once more (the old pin has no scripts digest, and it is not guessed). A pin grants no secret
access; existing access policy and leases still apply. Moving or editing the file
requires a new pin. Config remains same-user-writable, not tamper-resistant, and
Older builds ignore these pins.

`PI_SESSION_ID` and `CLAUDE_SESSION_ID` appear as bounded `session_label` audit
metadata. These self-asserted labels grant nothing. The separate `session` field
remains kernel-derived; lease session matching never uses environment labels.
Profiles and labels must not contain secret values (profiles contain refs only).

Platform seams live in `crates/core/src/platform/`: macOS capabilities are unchanged; non-macOS builds refuse identity, helper, service and sandbox operations (not a supported port).

`karambit agents discover [--json]` suggests installed agent harnesses from bounded filesystem hints; it never runs discovered binaries.
In Settings → Agent detection, detect and select suggestions, then Save; additions need no Touch ID, removals do.
Catalog and detection approach adapted from agentic-detector (MIT, Copyright (c) 2026 Karmine).

