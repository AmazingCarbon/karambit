# Using karambit from an AI agent

Copy this section into your project's `AGENTS.md` / `CLAUDE.md`:

```markdown
## Secrets (karambit)
Run commands with secrets: `karambit run -e VAR=ns/name -- CMD` (or `karambit run -- CMD` with
this repo's .karambit.env/.env.schema), or `karambit aws PROFILE -- CMD`. Names: `karambit ls --brief`.
CMD receives the values; `get` refuses non-public secrets to agents.
Never try to extract, print, encode, copy or send a secret value, or write one to a file.
Redaction only catches accidental plain-text echo: exact copies of non-public values (4+ bytes)
in CMD's stdout/stderr. Encoded or split copies pass. It is a filter, not a boundary.
Exit 125 = karambit refused or failed before CMD started (CMD can also exit 125; `--status-fd` tells which):
follow `next`, don't loop, never run `ask_user` yourself. Full guide (read once): `karambit help agent`.
```

That is about 776 bytes (roughly 185 tokens) per turn. The rest lives in the binary:
`karambit help agent` prints the commands agents can use, the access levels, the error
fields and every error code. The error codes come from the same table the CLI uses for
refusals; the command list and access text are fixed strings in the binary.

## What an agent sees

```text
$ karambit ls --brief
dev/db	agents
stripe/live-key	agents-touch	lease pi 1h12m
bank/pin	me-touch
```

`agents` and `public`: use now. `agents-touch`: needs temporary access from the user.
`me-touch`: never. `--brief --json` gives `[{"name","access","lease"?}]`.

A refusal, with `--json` or `KARAMBIT_FORMAT=json` (stderr, one line):

```json
{"error":{"v":1,"code":"needs_lease","secrets":["stripe/live-key"],"retry":"after_user","actor":"user",
 "message":"…","next":"ask the user to grant it (…), then retry",
 "ask_user":{"argv":["karambit","lease","grant","stripe/live-key","--to","pi","--hours","1","--cwd","/code/myapp","--cmd","/usr/bin/curl"],
             "shell":"karambit lease grant stripe/live-key --to pi --hours 1 --cwd /code/myapp --cmd /usr/bin/curl"}}}
```

- `retry`: `no` (change something first), `once` (one more try), `after_user`.
- `actor`: who has to act, `agent` or `user`.
- `ask_user`: the narrowest command the user could approve: this agent, this folder,
  this program, one hour. It is a suggestion for the user to review. Karambit never
  runs it and never suggests `--to any`.
- `blockers`: every problem found, when there is more than one, so one run reports all
  of them.

Exit 125 means karambit stopped before the command started (refused, bad command line,
unknown profile, daemon unavailable). A command can also exit 125 itself. To be sure,
use the status descriptor. karambit writes one line to it, and the command never holds it:

```sh
karambit run --status-fd 3 -e X=ns/name -- ./deploy.sh 3>&1 1>&2
# stdout: {"v":1,"started":true,"exit":0}   or   {"v":1,"started":false,"error":{...}}
```

`started` is true only once the command was exec'd. If the launcher fails first (the program
changed, the sandbox could not be installed, the environment is too large), you get exit 125,
`launch_failed` and `"started":false`, so it is safe to retry after fixing the cause.

The status descriptor must not be stdout or stderr: karambit refuses that, because the command
could then write a fake line. Use a pipe; a file path lets the command open and write it too.

## Run the agent in a sandbox

Karambit's files are yours, so any program that runs as you can change them. An agent that
runs unsandboxed can replace the `karambit` binary, edit the pins in
`~/.local/share/karambit/keys/` or the config, or add an SSH key to use `ssh localhost`.
If your agent harness supports a filesystem sandbox (for example a macOS Seatbelt profile),
deny the agent writes to these paths:

- `~/.local/bin` (the `karambit` and `karambit-se-helper` binaries)
- `~/.local/share/karambit` (secrets, keys, pins, config, audit log)
- `~/Applications/Karambit.app`
- `~/.ssh`

The agent only needs to read these paths and to connect to the daemon socket. With such a
rule, `karambit ls` and `karambit status` keep working while the daemon is already running
(tested on macOS 26). Start the daemon outside the sandbox first, for example by opening the
Karambit app or running `karambit status` in a plain terminal. A daemon that the sandboxed
agent starts would run inside the sandbox too, and it can't write to its own folder.
Seatbelt matches real paths, so write `/private/tmp/...`, not `/tmp/...`, in a rule.

What this does not fix: the agent can still use the no-prompt key files to read Public and
Agents secrets (limit #6 in the [threat model](threat-model.md)), and it can still read the
environment of other processes that run as you. To block those too, the agent must also be
denied reads of `~/.local/share/karambit` and the `ps -E` style process information, which
most agent sandboxes do not offer. `karambit doctor --agent-env`, run from inside the agent,
shows what that environment can reach.

## Why there is no MCP server (yet)

Agents already have a shell, and the CLI gives them everything an MCP server would:
names via `ls`, use via `run`, and machine-readable errors via `--json`. Karambit detects
the agent from the process tree (`karambit status` → "you are agent (…)"), which a shared,
long-running MCP server would weaken. Its tool schemas would also cost about as many
tokens as the snippet above. A small read-only server (`ls`, `status`, why-refused) may
come later; it would never return values or run commands.
