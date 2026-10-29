<p align="center">
  <img src="docs/assets/karambit-logo.svg" alt="Karambit logo: a pixel-art karambit knife" width="160">
</p>

<h1 align="center">Karambit</h1>

<p align="center"><strong>Your agent shouldn't eat your secrets. Karambit eats them first.</strong></p>

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange)
![Platform: macOS first](https://img.shields.io/badge/platform-macOS%20first-lightgrey)

Karambit is alpha software, not independently audited, and macOS only for now.

Karambit is a local-first secrets manager for you and the AI coding agents you work with. Your
secrets are encrypted in a vault on your machine instead of sitting in `.env` files. An agent can
run a command that uses a secret. Karambit gives the value only to the program that command starts,
and it replaces exact copies of that value in that program's stdout and stderr with
`[REDACTED:name]`. An agent cannot read a non-public secret with `karambit get`.

You get a CLI (`karambit`) and a desktop app. No cloud service, no account. Any agent that can run
shell commands can use the CLI. Karambit recognises some agents by process name or environment
variable (for example Claude Code, Codex, pi and cursor-agent). That detection is a heuristic, so it
is not a guarantee.

**Platform status:** The security features are implemented for macOS only. Linux and Windows ports
are on the [roadmap](#roadmap).

> **Read this first.** A program that `karambit run` starts gets the secret value in its environment.
> That program can read, copy or send the value.
> Karambit keeps the value out of the agent's context. It does not make the program safe.
> See [Security and limits](#security-and-limits).

## Install

You need git, Rust, the Xcode command line tools (Swift) and Node. `npm ci` needs network access.
Run `install.sh` from a plain terminal, not from an agent session.

```sh
git clone https://github.com/AmazingCarbon/karambit && cd karambit
./install.sh             # installs ~/.local/bin/karambit{,-se-helper} and ~/Applications/Karambit.app
karambit init --paper    # makes a paper backup key
```

To upgrade, pull and run `./install.sh` again. The installed version asks for Touch ID to trust
the new binaries before it replaces them. The upgrade stops the daemon, which ends active leases.

`init --paper` shows a backup key one time. Write it on paper and type it again to confirm.
If you lose your Touch ID keys, `karambit recover` uses this key. It refuses, changing nothing, if
the key cannot open every secret (`--accept-loss` names any you agree to give up).
Run `karambit backup verify` now and then: it checks the sheet against every secret, and it warns if a
`backup rotate` was interrupted (re-run it to finish).

Builds are ad-hoc signed on your computer. They are not notarized yet.

## Quick start

```sh
karambit add stripe/key                      # type the value at a hidden prompt
karambit ls                                  # names and access levels, no values
karambit run -e STRIPE_KEY=stripe/key -- ./deploy.sh
karambit get stripe/key                      # human only: copies to the clipboard
```

If the output of `./deploy.sh` contains an exact copy of the value, Karambit shows `[REDACTED:stripe/key]`.

To tell your agent how to use Karambit, copy the block in [docs/agents.md](docs/agents.md) into your `AGENTS.md` or `CLAUDE.md`. The agent reads the rest with `karambit help agent`.

## Access levels

Each secret has one access level. You set it with `--access` or in the app.

| Access level | `--access` | Agent can use it with `run` | Touch ID |
|---|---|---|---|
| Public (not secret) | `public` | yes, and it is not redacted | no |
| Agents | `agents` | yes | no |
| Agents + Touch ID | `agents-touch` | yes, after you approve | each use, or a lease |
| Only me + Touch ID | `me-touch` | no | yes |

Public and Agents secrets have no Touch ID. Any program that runs as you can read them without
Karambit (see [limits](#security-and-limits)).

A caller that Karambit detects as an agent can list secrets and run commands.
It cannot get a non-public secret, add or remove a secret, relax a policy or grant a lease.
Detection is a heuristic: a caller that evades it is treated as a human.

- **Lease**: temporary access for an agent. You limit it by time, folder, command and number of uses.
  `karambit lease grant 'deploy/*' --hours 3 --cmd curl`
  Shells and bare interpreters (`node`, `python`, ...) can't be a `--cmd`, because they run any code.
  Pin the script instead: `--cmd node --script deploy.js`.
- **Block**: `karambit block --all` refuses all agent requests until you unblock.
  It does not stop processes, and it cannot take back a secret that a program already has.

## Common tasks

**Move a project's `.env` files into the vault.**
`karambit secure` (alias: `karambit eat`) stores each secret and writes a `.env.schema` file with no values.
It also adds `karambit run --` to the `dev`, `start`, `serve`, `test`, `build` and `preview` npm scripts, so `npm run dev` works as before.
`karambit secure rebuild` puts the original files back. Details: [docs/secure.md](docs/secure.md).

```sh
karambit secure --dry-run    # shows names only; agents can run this
karambit eat                 # same as karambit secure
```

**Use AWS.**
Karambit keeps AWS access keys or an IAM Identity Center (SSO) sign-in.
With `karambit aws PROFILE` or `karambit run --aws`, the AWS CLI and SDKs get credentials through a
local endpoint (`AWS_CONTAINER_CREDENTIALS_FULL_URI`), not as AWS keys in the environment. Plain
`run -e` with AWS variables is not covered by this.
You can import all roles from an SSO portal. Details: [docs/aws.md](docs/aws.md).

```sh
karambit sso portal add main --start-url https://acme.awsapps.com/start --region us-west-2
karambit login main
karambit aws import --portal main --dry-run   # imported names are <account id>-<role>
karambit aws import --portal main
karambit aws 111111111111-readonly -- aws s3 ls
```

**Read a CI build status with a fixed call.**
`karambit call ci-status JOB` makes one fixed CI build-status request (Jenkins-compatible API) for the
last build status, using a credential from the vault. Only fixed calls exist today; this is not a general broker.
See [docs/reference.md](docs/reference.md#fixed-tool-calls-mode-c).

## Security and limits

What Karambit does:

- It encrypts each secret with its own key (ChaCha20-Poly1305).
  On macOS, Secure Enclave keys that you cannot export wrap these keys. Public and Agents secrets need no
  Touch ID, so any program that runs as you can read them (see below).
- It asks for Touch ID for secrets that need it. The Secure Enclave enforces this for unwraps that go
  through the helper. The exception is an "Only me + Touch ID" secret while a human self-lease is active.
- It gets the caller's identity from the kernel (process ancestry and audit token).
  This identifies the process, not whether a human started it.
  The CLI also checks the daemon before it sends anything: the process on the socket must run a pinned `karambit` that was not started with `DYLD_*` variables, and the run folder and socket must be yours and not writable by others.
  The daemon itself refuses to start with a `DYLD_*` variable set.
  Until the vault is set up, this check is skipped; once it is, a missing daemon pin is a refusal.
- `karambit run` starts the command through a pinned launcher.
  Each launch is used one time and is bound to the command, its arguments and its folder.
- It writes an audit entry for each action, on a best-effort basis, to a hash-chained log.
- It keeps an offline [age](https://age-encryption.org) copy of the keys for paper-key recovery.

What Karambit does not do:

- **The launched program has the secret value.** For AWS profiles, it has the credentials, which it
  fetches from a local endpoint rather than from the environment.
  While it runs, other processes of the same user can read its environment (for example `ps -E`).
- **Redaction is not a sandbox.** It removes exact copies of non-public values of at least 4 bytes,
  and 16-byte fragments of values of 32 bytes or more, from stdout and stderr. Public values are never redacted.
  It does not catch encoded copies (base64, hex, URL encoding), files the program writes, network traffic,
  or values the program fetches on its own (for example from Secrets Manager).
- **Your environment reaches the program.** The program inherits your shell's variables, so a variable
  that makes it load code (`NODE_OPTIONS`, `PYTHONPATH`, `DYLD_*`, ...) runs inside it with the secret in reach.
  When the caller is an agent, Karambit drops those variables (and says which); you can let some through with
  `karambit config allow-env NAME,...` (human + Touch ID). Your own runs keep them. A `.env.schema` can never set them as plain values.
- **A script lease pins argv[1] only.** `--cmd node --script deploy.js` checks the interpreter, the script file
  and that there is no `-e`/`-c`/`-m` style flag. It does not hash modules the script imports or its config.
- **Policy rules need a current daemon.** A daemon from an older build ignores the `policy` section.
  `karambit policy test FILE --live` fails if the running daemon does not report the same policy.
- **Agent detection is a heuristic.** Karambit uses process names and environment markers.
  A process that double-forks and clears its environment can look like a human.
  Use a Touch ID access level for important secrets: Touch ID is the backstop.
- **`ssh localhost` looks like a human, so Karambit refuses it.**
  If macOS Remote Login is on, a program that adds a key to `~/.ssh/authorized_keys` can run `ssh localhost karambit ...`.
  That process chain starts at `sshd` and has no agent in it.
  Karambit marks callers that come through `sshd` (or have `SSH_CONNECTION`/`SSH_TTY` set) as remote, writes `remote` in the audit log,
  and refuses human-only commands from them unless `karambit config allow-ssh-human on` (a human, with Touch ID).
  The same goes for runs: over SSH, `karambit run` and `karambit get` refuse an Only-me secret (the Touch ID prompt would be answered by nobody at the keyboard)
  and never reuse a cached approval. Secrets that agents may use are still reachable that way, and the SSH_* check is a name check a program can clear.
  Keep Remote Login off; `karambit doctor` warns when it is on.
- **A long-term AWS key lets a program mint its own sessions.**
  A program holding an IAM-user key can call `sts get-session-token` and keep the result for up to 36 hours.
  `karambit aws add NAME --session-mint` (or `karambit aws session-mint NAME on`) makes the daemon trade the key for a one-hour session and give the program only that.
  It is off by default. The program can no longer see the key, but a session it was given still cannot be recalled before it expires.
  The exchange uses only an `aws` CLI at `/opt/homebrew/bin`, `/usr/local/bin` or `/usr/bin` (owned by you or root, not group/world-writable), never one found on `PATH`,
  and runs it with an empty environment and an empty `HOME`. If the `aws` CLI is elsewhere, `session-mint` runs are refused.
- **No-prompt secrets are readable by any program that runs as you.** Treat Public and Agents secrets that way.
- **The audit log is not tamper-proof.** The hash chain has no key.
  A process of the same user can rewrite the whole chain, and `audit --verify` still passes.
  The log rotates at 16 MB into `audit-<time>.jsonl` segments that keep the chain; you may archive or
  delete old segments (`audit --verify` then says the older part was removed).
- **Typed credentials in a command line are masked in the audit log only on a best-effort basis.**
  Values of secrets released in that launch, and obvious `--password`/`--token`/`Authorization:`/URL-password
  patterns (the whole argument after a secret flag, spaces included), are replaced by `[REDACTED]`; a password in an unusual form can still be recorded.
  The log keeps `argv_sha256` of the real command. Pass secrets with `-e`, not as arguments.
- No memory locking, core-dump protection or anti-debug yet.
  Config, the helper pin and the installed binaries are writable by your user.
- **`package.json` scripts are pinned only for agents.** Trusting a `.env.schema` also pins the
  sibling `package.json` `scripts`. If they change, agents are refused (`profile.untrusted`).
  A `package.json` that is a FIFO or other non-regular file is pinned as `nonregular` and never read.
  You get a warning, so read the Touch ID prompt's command line and check `git diff package.json`.
- **Very large environments are refused.** `karambit run` estimates the size of local secrets,
  arguments and your environment before any prompt and refuses what the 1 MB launch frame or the system's
  argument limit cannot take. Linked-source (backend) values are only sized at release, so those can
  still fail late. Keep big values in a file the program reads.
- `run --jail` (a macOS sandbox) is experimental. Do not use it as a security boundary.

If your agent harness has a filesystem sandbox, deny the agent writes to Karambit's files:
see [Run the agent in a sandbox](docs/agents.md#run-the-agent-in-a-sandbox).

Run `karambit doctor --agent-env` from a plain shell and from inside your agent, then compare.
It checks a few things from that environment, for that run only. A pass is not a safety guarantee.

Full analysis: [docs/threat-model.md](docs/threat-model.md).
How it works, with diagrams: [docs/how-it-works.html](docs/how-it-works.html).

## Roadmap

- [ ] **Proxy mode for API keys.** The program gets a placeholder value.
      Karambit adds the real key only on requests to a fixed host.
- [ ] **Daemon hardening.** Memory locking, core-dump protection, anti-debug.
- [ ] **Signed and notarized releases**, and a Homebrew install.
- [ ] **Linux port** (platform): TPM2 keys, fprintd or polkit for presence,
      `SO_PEERCRED`/pidfd for caller identity, a systemd user service.
      The core and the CLI compile for Linux today. The security features are not implemented there yet.
- [ ] **MCP server**, so agents can call Karambit as a tool.
- [ ] **`.env` import in the desktop app.**
- [ ] **Windows port** (platform): TPM/CNG keys and Windows Hello.

Linked sources are a backend interface ([docs/backend-contract.md](docs/backend-contract.md)).
This build has no built-in backends.

## Documentation

| Document | Contents |
|---|---|
| [docs/agents.md](docs/agents.md) | Instructions to copy into your agent's `AGENTS.md` |
| [docs/secure.md](docs/secure.md) | `karambit secure` and the `.env.schema` format |
| [docs/aws.md](docs/aws.md) | AWS profiles, SSO portals, role import |
| [docs/reference.md](docs/reference.md) | All commands, the key model, leases, policy, full limits |
| [docs/threat-model.md](docs/threat-model.md) | What is protected, and what is not |

## Contributing

The code has four parts:

```text
crates/core   Rust: encryption, store, policy, agent detection, redaction, audit
crates/cli    Rust: the karambit command
se-helper/    Swift: Secure Enclave keys and Touch ID (macOS)
app/          Tauri desktop app (plain HTML/JS)
```

```sh
cargo test    # software keys only: no Secure Enclave or Touch ID needed
```

Open an issue before a large change, and read [CONTRIBUTING.md](CONTRIBUTING.md) first. Report security
problems privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Project files

- [SECURITY.md](SECURITY.md): how to report a vulnerability privately
- [CONTRIBUTING.md](CONTRIBUTING.md): build, test and pull request rules
- [CHANGELOG.md](CHANGELOG.md): what changed in each version

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Third-party components, including varlock's @env-spec parser (MIT): [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
