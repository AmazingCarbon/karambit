# AWS profiles and IAM Identity Center (SSO)

Back to [README](../README.md).

## Profiles with access keys

```sh
karambit aws add prod-admin                     # paste the console's export AWS_... block; verified with STS
karambit aws add prod-admin --force             # refresh expired console credentials
karambit aws ls
karambit aws prod-admin -- aws s3 ls        # agents: keys only in this command, redacted from output
karambit run --aws prod-admin -e T=x/tok -- ./deploy.sh   # combine with other secrets, one prompt
karambit whoami prod-admin
karambit config default-profile prod-admin    # must name a saved profile; none clears it
karambit whoami                               # uses the configured default
karambit whoami --json                        # full STS identity JSON
```

`karambit aws` runs are bound runs like any other: when an agent starts one, variables that make the
program load code (`NODE_OPTIONS`, `PYTHONPATH`, `DYLD_*`, ...) are dropped from its environment, so they can't
run next to the keys. `karambit config allow-env NAME,...` (human + Touch ID) lets chosen names through.

Profile names `add`, `import`, `ls`, `show`, `rm` and `session-mint` are reserved. Run with an optional region
override: `karambit aws prod-admin --region eu-west-1 -- aws s3 ls`.
Without a profile or configured default, `whoami` lists profiles and reports how to choose one.

### Long-term keys: `--session-mint` (opt-in)

A program that holds an IAM-user key can run `aws sts get-session-token` and keep the result (up to 36 hours).
With `session-mint` the daemon makes that call itself and gives the program only a one-hour session:

```sh
karambit aws add ci-user --session-mint        # new profile
karambit aws session-mint ci-user on           # existing profile (human only, Touch ID)
karambit aws session-mint ci-user off          # hands the key to runs again (human only, Touch ID)
karambit aws show ci-user                      # "session_mint": true
```

- Needs an IAM-user key (AKIA…) whose policy allows `sts:GetSessionToken`. Temporary keys and SSO profiles are refused.
- It uses the `aws` CLI on this Mac, found only at `/opt/homebrew/bin/aws`, `/usr/local/bin/aws` or `/usr/bin/aws` (never on `PATH`;
  it must be owned by you or root and not group/world-writable). The key goes to it by environment only, with every other variable cleared and an empty `HOME`.
  If the CLI is not there or the call fails, the run is refused; the key is never used instead.
- The session lasts one hour and the credential endpoint ends a minute earlier. Longer jobs need a re-run.
- The program never sees the key, and `-e VAR=aws/NAME` or an agent `get`, `run`, `copy` or lease use of that profile is refused (`karambit aws show` still works).
  `karambit aws NAME -- COMMAND` is the way to use it.
- What AWS says about these sessions: they cannot call IAM APIs unless MFA was used, and they cannot call
  any STS API except `AssumeRole` and `GetCallerIdentity`, so they cannot call `GetSessionToken` again.
  A program can still call `sts:AssumeRole` if your policy allows it, and a session can't be recalled before it
  expires. Deny `sts:AssumeRole` for that user in AWS if you need that closed.

## AWS SSO (IAM Identity Center)

```sh
# once per Identity Center / org: a short name for each access portal
karambit sso portal add main    --start-url https://acme.awsapps.com/start      --region us-west-2
karambit sso portal add sandbox --start-url https://sandbox.awsapps.com/start --region us-east-1

# profiles name their portal (--portal can be left out while you have only one)
karambit aws add app-staging --sso --portal main    --account 111111111111 --role ReadOnly --access agents
karambit aws add app-prod    --sso --portal main    --account 222222222222 --role Admin    --access me-touch
karambit aws add sandbox-dev --sso --portal sandbox --account 333333333333 --role Dev      --access agents

karambit login main          # browser approval + one Touch ID; other portals unaffected
karambit aws app-staging -- aws s3 ls       # agents: unchanged
karambit sso ls ; karambit sso status
karambit logout main ; karambit logout --all
karambit sso portal limit main 8h          # sign out 8 h after each sign-in (90m, 2d, none)
```

- The SSO token lives only in the daemon's RAM: never on disk, never in `~/.aws`, never in a child's
  environment. Reboot, `daemon stop` or `sso logout` ends it; log in again.
- Each portal has its own login and token. A profile is served only by a session whose name, URL
  and region all match the ones saved in the profile, so editing or renaming a portal in config
  can't redirect existing profiles to a different org.
- An SSO profile is an account + role with the usual access level (Agents, Agents + Touch ID,
  Only me + Touch ID). The daemon refreshes the SSO token (about 2 minutes before it expires, even
  while no agent is using it) and the role credentials as they expire, so a long agent run keeps
  working until that portal's Identity Center session ends. How long that is gets set by your
  organization's IAM Identity Center admin (session duration: 8 hours by default, 15 minutes to
  90 days). Karambit can't extend it.
- Role credentials are redacted from the command's output like pasted keys: before the daemon hands
  a command fresh credentials, the `karambit` that launched it adds them to its output filter. If
  that does not happen within about 2 seconds the daemon answers 503 and the SDK retries.
- A new `deny` policy rule for running a profile cuts off a command that is already running at its
  next credential fetch (403, the endpoint is closed and the denial is audited). An `approve` rule
  is not asked again mid-run.
- When AWS refuses to renew a sign-in (the Identity Center session ended or was revoked), the
  daemon signs that portal out by itself and records why: `sso portals`, the app's banner and the
  agent's error all say it ended and how to sign in again, and an `sso-ended` event is logged.
  Network trouble or an AWS outage doesn't sign you out; the daemon retries every minute.
- Optional **sign-in limit** per portal (`sso portal limit`, or Settings › AWS sign-in › Stay
  signed in for): the daemon stops renewing and signs the portal out that long after each sign-in,
  even if AWS would keep going. It can only make a sign-in shorter than the Identity Center session.
  A change applies to the current sign-in too, counted from when it started (a shorter limit can
  sign out right away). Role credentials handed to agents are marked to expire no later than the
  limit, so the AWS CLI and SDKs stop using them then; a copy already handed out stays valid at AWS
  until its own expiry (the permission set's session duration, 1 hour by default), as after a
  sign-out. Setting or shortening a limit is free; lengthening or removing one costs a Touch ID,
  and the sign-in prompt states the limit it starts with. Human only.
- The daemon enforces SSO access levels from what you approved at login (it shows the Touch ID
  prompt itself), not from vault files, which any process running as you could edit. Adding a
  profile or loosening one while signed in costs a Touch ID; an agent tightening one removes it
  from the session.
- Adding, repointing (Touch ID) or removing a portal is human-only.
- GUI: **Add AWS profile** (AWS SSO or pasted keys) on the Secrets list; portals, sign-in and
  sign-out live in **Settings › AWS sign-in**. Sign-in shows the device code, opens the browser, and
  can be cancelled until you approve there; after that the daemon's Touch ID prompt has its own
  Cancel. A banner on the list offers one-click sign-in when a portal with profiles is signed out,
  and says why when the sign-in ended by itself.

## Import every account/role from a portal

After `karambit login main`, preview and import all assigned roles:

```sh
karambit aws import --portal main --dry-run
karambit aws import --portal main --include '*ReadOnly*' --exclude '*sandbox*'
```

Filters match generated profile names or `account-name/role` (`*` and `?`).
Import previews names and asks for confirmation, then one Touch ID for the batch.
Use `--yes` for non-interactive confirmation, `--region` to override the portal region,
or `--access agents|agents-touch|me-touch` (default: **Only me + Touch ID**).
Existing account/role profiles are skipped, never overwritten; name collisions get a suffix.
In Settings › AWS sign-in, choose **Import all roles** on a signed-in portal, filter/check
roles, choose access, and Import.

