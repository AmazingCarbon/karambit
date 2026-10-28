# Backend contract (contract-v1)

Backend contract for the linked-backend layer (types, fakes, daemon resolve/cache/binding, CLI and redaction), with lifecycle interfaces for later real adapters.
Normative rules are C-1–C-46 plus C-40a; each has a checklist entry in §15.
This is a specification, not a claim that backends already exist.
Changes go through a revision of this contract, not adapter-local exceptions.

Inputs: `docs/threat-model.md`, especially
§2/§4/§5 and its later amendments. Existing code citations below refer to
release 0.1.0; `core/` below abbreviates `crates/core/src/`.
The older threat-model paragraphs contain historical line numbers: use named
functions and later amendments, not those numbers, for implementation seams.

## 1. Scope and non-goals

**C-1.** Implementations MUST restrict this contract to Mode A trusted-tool
injection/export: daemon-authorized resolution, ephemeral RAM values, scoped
access and best-effort upstream containment. No GUI, sandbox (Mode B),
broker/custody (Mode C), arbitrary upstream writes, or new vendor adapters in this layer.
A child receiving a value can copy or exfiltrate it; secrecy is not safety.
Same-user key-blob use, writable pins/config, mutable scripts and redaction
bypasses remain the limits in `docs/threat-model.md`.

**C-2.** The daemon MUST own authorization, source credentials, network calls,
cache and lifecycle tracking. `Req::Resolve` is semantic, not a generic HTTP or
helper forwarding API. A client-supplied grant/session/hash/authenticated flag
is only a selector, never proof. Bound runs retain the verified shim delivery
boundary; raw Resolve cannot bypass command-scoped launch authorization.
Existing seams: `core/daemon.rs:prepare_launch`, `redeem_launch`,
`launch_authorizations`; `core/lib.rs:Karambit::unlock_request`.

**C-3.** The CLI/redaction layer MUST feed every resolved bundle field delivered to a run into
`core/redact.rs:Redactor::new` before output pumping, including dynamic fields,
not just the selected env field. Redaction material goes to the authenticated
supervisor only after child binding (`core/daemon.rs:release_launch_redaction`).
This does not change MIN_REDACT_LEN=4, literal/fragment matching, or coverage of
stdout/stderr only; independently fetched values, encodings and short values
remain unprotected. Exports intentionally return raw bytes to the granted tool.

## 2. Five clocks: separate owners and representations

**C-4.** Status and audit MUST preserve these five separately named clocks,
with `unknown` and `not_applicable` distinct from a timestamp or infinity.
A timestamp is UTC Unix seconds; durations are integer seconds, rounded down.

| Clock / field | Definition and owner | Display / audit meaning |
|---|---|---|
| Permission / `permission_expires_at` | Daemon grant's permission to dispense | Local access ends, not credential death |
| Login / `login_expires_at` | Upstream login/token expiry; adapter observes, daemon schedules refresh | Known timestamp, unknown static login, or not applicable |
| Credential / `credential_expires_at` | Upstream-issued credential's validity; upstream enforces | Static = not applicable; dynamic = mandatory timestamp |
| Freshness / `cache_fresh_until` | Daemon's last validated value plus bounded freshness | Only permission to reuse this copy |
| Revocation / `revocation` | Upstream acknowledgement/observation, not a predicted timer | none, pending, acknowledged, expired-unconfirmed, unsupported |

**C-5.** Dispense MUST require live authorization and a positive remaining
window: `min(permission remaining, known login remaining, known credential
remaining minus margin, cache freshness remaining)` for a cache hit. Unknown
login expiry is not proof of infinite upstream validity; an observed auth
failure blocks reuse. Static credential expiry contributes no bound. On a
miss freshness starts only after successful validation. Pending/acknowledged
revocation forbids dispense independently of this min. Renewing login never
extends permission; refreshing cache never extends upstream credential life.

**C-6.** The daemon MUST retain wall and monotonic deadlines for local windows,
expire when either is reached, and recheck immediately before delivery and
after blocking work. Wall rollback or a wall/monotonic delta discrepancy over
5 seconds invalidates cached entries and suspends dynamic delivery pending
fresh validation; forward jumps expire early. Wake cannot resume stale hits.
Use an injectable clock in fakes. Existing `core/daemon.rs:expire_leases` uses
wall time for leases and Instant for endpoints; that is a seam, not sufficient
implementation of this new dual-clock rule. No claim survives arbitrary
same-user clock/state tampering.

## 3. Revocation reality

**C-7.** Static results MUST have no `UpstreamLease`; their revoke state is
`unsupported`. Ending permission wipes local cache/access only. UI and audit
say “local access ended; copied static credentials remain usable”, never
“credential revoked”. Rotation/deletion upstream is outside this contract.

**C-8.** Dynamic leases MUST transition locally from active to pending-revoke
before attempting upstream revoke; no further reuse or renewal follows that
transition. An acknowledgement means the upstream accepted revoke, not proof
that every relying service has invalidated every copy. Expiry without an
acknowledgement is `expired-unconfirmed`, not successful revocation.

**C-9.** Failed revoke MUST remain in RAM as pending-revoke and retry after
1, 2, 4, 8, 16, 32, then 60 seconds (60 thereafter), bounded by upstream expiry.
RateLimited waits at least its retry-after; no retry is scheduled past expiry.
Audit each attempt/failure and a final `revoke-abandoned-at-upstream-expiry`.
`lease ls`/status exposes pending count, lease IDs and next retry, without values.
Terminal authentication/permission failures still remain pending: do not mint
new authority automatically; retries may succeed after human repair. Audit
failure emits a sanitized diagnostic and never blocks containment.

## 4. Failures and deterministic fake proofs

**C-10.** Crash/restart MUST discard all cache, grants for backend resolution,
in-flight state and upstream tracking; no disk snapshot or recovery journal.
Already issued credentials survive until server expiry. A startup status note
says “prior upstream tracking lost; prior credentials may remain valid up to
configured TTL cap”. No invented revoke success or reconstruction from audit.

**C-11.** Cancellation MUST prevent delivery/cache publication. If issuance has
started, continue bounded response collection to discover a lease ID and queue
revoke; a lost response is `Indeterminate`, with potential orphan audited. Never
blindly repeat a dynamic issue after timeout/cancel/connection loss. If the
caller disappears, the daemon, not that caller, still owns cleanup.

**C-12.** Resolve single-flight MUST be per cache key and owner session; login
refresh single-flight is per source binding. Waiters recheck authorization
individually after waking. Cancellation of one waiter does not cancel others;
no authorized waiters remaining triggers C-11. No global State mutex spans
network/helper/audit I/O. Recheck binding generation, login generation, grant
revision and session at publish/delivery; a stale result is discarded/revoked.
`core/daemon.rs:sso_renew` and `sso_fresh_creds_bound` illustrate snapshot,
unlocked I/O and generation checks, not a ready-made backend implementation.

**C-13.** One `(grant id, kernel session)` MUST own each issuance. Multiple
consumers within that owner can share the bundle; an individual consumer exit
only removes its subscription. Owner end/expiry revokes irrespective of live
consumers. There is no cross-grant or cross-session lease sharing; a one-shot
launch grant ends with the bound launch. Daemon alone calls revoke, exactly one
in-flight revoke per upstream lease; retries may repeat that idempotent action.

**C-14.** Source removal/retarget MUST atomically disable the old generation,
invalidate its grants/cache and reject in-flight publication before exposing
the replacement. Queue old dynamic leases for revoke using the OLD endpoint
and credential snapshot held only for cleanup until expiry. Never revoke on
the new endpoint or discard pending cleanup on deletion. Config deletion is an
audited mutation; local containment remains possible if persistence fails.

**C-15.** The fakes and daemon lifecycle MUST prove the following matrix using synthetic fakes and
barriers/injected clocks, not real network, sleep delays or live credentials.
Group scenarios into one smoke test plus 1–3 parameterized negative tests.

| Scenario / fake | Required observable proof |
|---|---|
| ok | One issue, coherent fields, authorized hit, complete audit pair |
| slow | Deadline produces Timeout for safe read; dynamic sent request is Indeterminate; no delivery |
| throttle | RateLimited carries bounded retry-after; no immediate spin |
| flapping | Changes value and version each resolve; one bundle has one issue counter |
| dies-mid-issue | Server creates lease then loses response; no automatic second issue; server TTL ends orphan. Variant: returns lease ID without TTL ⇒ KnownId reaches pending-revoke (C-40a) |
| crash | Drop daemon state, retain fake server; restart has zero hits/owners; server expires lease within cap |
| sleep/wake | Advance wall beyond expiry with frozen monotonic clock; zero post-wake delivery; rollback invalidates |
| cancel | Pause before/after server issue; cancel; no delivery, known ID revoked, unknown ID audited |
| refresh race | Two waiters, one refresh/issue; invalidate source/grant while paused; stale response never publishes |
| revoke-fails | Local use stops immediately; attempts follow 1/2/4…60; audit failures and final expiry record |
| shared owner | Two consumers same owner: first exit no revoke; owner end one revoke; other grant cannot hit |
| remove/retarget | Paused old request rejected; new grant required; cleanup uses old endpoint/identity |

## 5. Atomic bundles

**C-16.** One issuance MUST return one `Bundle` with typed named fields and
one shared version/change token/lease. Field projections are local; DB username
and password cannot come from separate fetches. Group refs differing only in
`#field` within one resolve batch into one issuance, even with cache disabled.
The cache ref key is this issuance ref (selector removed); requested selectors
remain in authorization/audit. Authorize every selector before issue/delivery;
return only authorized projections, never the whole map to a narrow caller.

**C-17.** Bundle fields MUST be `Text` (UTF-8) or `Bytes`, held in zeroizing
buffers, with unique nonempty names. Env injection accepts Text without NUL;
Bytes or missing selectors fail before child exec, without implicit base64 or
lossy conversion. Scalar refs use field `value`. No Debug/Display of values,
no value-derived version/hash; invalid or partial bundles are rejected whole.
Adapters label whether resolve is static read or dynamic issue before calling
upstream, so retry safety is known before a response exists.

## 6. Source binding

**C-18.** Source binding MUST be lowercase hex SHA-256 of this ordered byte
sequence: `frame("karambit-source-v1")`, kind, canonical endpoint, auth method,
credential entry name, credential store revision, canonical policy, random
source generation. Each field is `frame(x) = u64 big-endian byte length || UTF-8
bytes`; generation is 32 lowercase hex chars from 128 random bits. Never hash
credential bytes. Include non-secret adapter options (namespace, region, mount,
server identity) in policy as well as ref permissions, TTL/cache limits and
Mode-A/export restrictions. This binds address, identity and policy together.

**C-19.** Canonicalization MUST reject ambiguous config: endpoint is absolute
HTTPS, lowercase DNS host, explicit effective port, no userinfo/query/fragment,
no dot segments; trailing slash removed except root. Policy/options use sorted
JSON object keys recursively, compact UTF-8 JSON, integer numbers only, arrays
in declared order. Credential revision is a daemon-controlled random revision
rotated on replacement, not mtime or client input. Token renewals retaining the
same principal use a separate RAM login generation; replacing credential or
changing principal is retarget. Test framed concatenation ambiguity and each
field independently changing the hash.

**C-20.** Add/retarget MUST require human-only fence plus fresh daemon-mediated
Touch ID, with prompt bound to old/new non-secret configuration. Credential
replacement, endpoint/policy change and remove/re-add rotate source generation
and invalidate old grants. Direct config/store edits cannot silently authorize
new binding: mismatch returns NeedsHuman. `sources/<name>/cred` is reserved for
source management: generic add/rm/policy operations cannot bypass this route.
The hash detects configuration mismatch, not hostile same-user file rewriting.

## 7. Cache and authorization

**C-21.** Cache MUST be RAM-only, keyed exactly by `(binding hash, issuance ref,
grant id)` with kernel-session ownership stored and checked on each entry.
Grant IDs are daemon-issued unique per boot and session; even a matching key
from another session is a miss/denial, never a transfer. Unknown/missing grant
requires normal human approval to create a new scoped grant, not fallback to
source-credential permission. Human fresh approvals use ephemeral grant IDs.

**C-22.** Every hit MUST rerun grant checks (ref/selector, mode, owner PID/start
and session ancestry, command binding, expiry, use limits, revocation, source
and policy revision), then consume a use atomically at delivery. Waiting and
cache lookup do not consume uses. Cache is not a human self-lease bypass.
`core/daemon.rs:check_lease_snapshot`, `human_cache_key`, `launch_authorizations`
are existing authorization seams; backend grants add metadata, not client DEKs.

**C-23.** Freshness MUST default to 30s, hard maximum 60s; source policy may
lower it to zero (no retained hit). Bound it by C-5 and C-38. At freshness end,
validate version/etag through metadata when supported; unchanged renews only
freshness, changed evicts and resolves anew. Metadata unknown/unsupported
requires a fresh read; an upstream error never permits stale-while-error.
Version pinning does not bypass checks. 60s is the maximum LOCAL reuse window
after a validation completes; it is not a bound on upstream visibility. An
upstream change can stay unobserved for up to transport latency (C-43, at most
30s) plus 60s, while local clocks function. No instantaneous rotation detection
is claimed.
Dynamic metadata/renew checks never accidentally issue a new credential.

**C-24.** Metadata validation and refreshed values MUST be committed against
the same source/login/grant revisions checked at start. Comparison uses opaque
upstream version/etag, never secret hashes. A changed token between metadata
and value fetch uses the value response's token; never attach a separately
fetched version to a bundle. If no token exists, retain `None`, not a fabricated
“unchanged”. Cache/credential bytes are dropped on invalidation.

## 8. Explicit Mode-A exports

**C-25.** Token-helper `get` and key-cmd MUST require a distinct `Export` grant
on `sources/<name>/cred`, binding source hash, kernel session, tool/command,
expiry and export purpose. A Resolve grant on any narrow ref, even `#token`,
never releases source-wide token/identity. Export creation is human-only plus
Touch ID; each export rechecks it and audits before returning bytes. This contract defines
the grant distinction; token-helper and key-cmd exports are later work.

**C-26.** Export integrations MUST label their output Mode A, avoid disk/token
fallbacks, and keep store/erase separate from get. Store changes identity via
source retarget; erase contains and then performs audited credential deletion.
No automatic reading/deletion of `~/.vault-token` or ambient credential env.
Test a narrow ref grant denied export and an explicit export grant accepted;
never describe the accepted case as custody or redacted export stdout.

## 9. Typed errors and retries

**C-27.** All adapter failures MUST map to this closed enum; Display uses the
fixed text column, optionally a validated source name and local correlation ID.
No upstream body, curl stderr, arbitrary error chain, URL query, credential or
value may reach user output/audit. Metadata identifiers are bounded to 256
printable characters; adapters cannot designate credential-bearing data as
metadata. Invalid identifiers become a fixed invalid-metadata error.

| Variant | Fixed text | Automatic retry semantics |
|---|---|---|
| RateLimited { retry_after } | Backend rate limited; try later | Safe read only, after bounded delay; no issue replay |
| NotFound | Source or reference not found | None |
| AuthExpired | Backend login expired; authenticate again | One single-flight refresh if renewable; one safe-read retry |
| NeedsHuman | Human approval required | None; no background prompt |
| Unsupported | Operation unsupported by this source | None |
| Transient | Backend temporarily unavailable | Safe read only, bounded backoff |
| Timeout | Backend request timed out | Safe read only; sent issuance instead Indeterminate |
| Cancelled | Request cancelled | None; cleanup still runs |
| Denied | Access denied | None, including upstream authorization denial |
| InvalidRef | Invalid reference | None |
| InvalidConfig | Invalid source configuration | None |
| InvalidResponse | Invalid backend response | None; known lease cleanup |
| TtlExceeded | Backend credential lifetime exceeds limit | None; known lease cleanup |
| Indeterminate | Issuance outcome unknown; credential may remain active until TTL | Never replay automatically |
| BindingChanged | Source or grant changed; obtain new approval | None |
| AuditUnavailable | Audit unavailable; operation refused before any upstream call | None; zero effect (intent write failed, C-32) |
| DeliveryRefused | Audit unavailable; value delivery refused | None; zero delivery, never replay; a result carrying a known dynamic lease (fresh issue or dynamic cache hit) goes to pending-revoke per C-33/C-40a; results without one (static reads, static cache hits) need no cleanup |

**C-28.** Safe-read retry MUST be limited to two retries, at 1s then 2s unless
retry-after is longer, within the original request deadline (30s maximum).
`retry_after` is clamped to 1..300s; if it exceeds remaining deadline, return
RateLimited without waiting. Resolve declared dynamic is non-idempotent even
if implemented as HTTP GET. Renew/revoke use lifecycle-specific rules; no curl
`--retry`. Failure after a committed effect/outcome-write failure never replays
it. AuthExpired cannot trigger an unbounded login loop.

## 10. Reference grammar and coexistence

**C-29.** The types/parser/registry MUST implement this envelope grammar offline, splitting only the
FIRST colon. Source names are case-sensitive; literal `aws` is reserved. Native
syntax is adapter-owned, but empty native, NUL/control/whitespace, backslash,
`..` path segments (also percent-decoded once) and malformed percent escapes
are rejected. Do not normalize away traversal. Percent-decoded slash/dot tests
run before adapter dispatch; do not repeatedly decode. No filesystem lookup.

```ebnf
reference   = backend-ref | legacy-ref ;
backend-ref = source, ":", native ;
source      = lower, { lower | digit | "-" } ; (* 1..32 bytes; not aws *)
native      = native-char, { native-char } ;
native-char = ? printable ASCII except whitespace and backslash ? ;
legacy-ref  = segment, "/", segment, { "/", segment } ;
segment     = (lower | upper | digit | "_" | "-" | "."),
              { lower | upper | digit | "_" | "-" | "." } ;
lower       = "a" … "z" ; upper = "A" … "Z" ; digit = "0" … "9" ;
```

**C-30.** Legacy no-colon refs MUST continue through the existing store resolver,
with existing validation (the legacy production above describes portable
examples, not a rewrite of store naming rules). `aws/` remains the legacy AWS
profile namespace, never a backend alias. `karambit:` remains the optional env
file wrapper stripped once by `core/lib.rs:parse_env_file`, not a source name
available for registration. `-e` uses the same wrapper/envelope classification.
Env `#` within a value is a field selector, not an inline comment; lines starting
`#` remain comments. Unknown sources fail NotFound; no fallback to legacy lookup.

**C-31.** Registry validation MUST reject unknown/unregistered kinds at source
add and config load with InvalidConfig. Kind is NOT parsed out of native text.
This layer registers `fake` (tests only); the open core registers no production kinds.
Native examples below are grammar fixtures, not proof of runtime availability. `ref check` is offline, value-free, checks
source existence/kind/native syntax, and never authenticates or issues secrets.

| Input / context | Accept or reject | Reason |
|---|---|---|
| `f:ok/a` with source f kind fake | Accept | Smoke test |
| `f:ok/a#value` | Accept | Local field projection |
| `vault-prod:secret/data/app#db_pass?version=3` | Envelope accept | Adapter validates path/query |
| `arn:arn:aws:service:eu-west-1:123456789012:secret:app#key?stage=CURRENT` | Envelope accept | Colons after first retained |
| `op:op://Prod/db/password` | Envelope accept; kind unavailable in this layer | Native URI retained |
| `ns/name` | Accept legacy | Existing store lookup |
| `aws/staging` | Accept legacy only | Reserved AWS namespace |
| `X=f:ok/a` in `-e` or env file | Accept assignment | Same ref parser |
| `X=karambit:f:ok/a` in env file | Accept assignment | Strip wrapper once |
| `:ok/a` / `f:` | Reject InvalidRef | Empty source/native |
| `f:ok/../a` / `f:ok/%2e%2e/a` | Reject InvalidRef | Traversal |
| `f:ok/%2F../a` / `f:ok/%ZZ` | Reject InvalidRef | Decoded traversal / invalid escape |
| `F:ok/a` / `aws:ok/a` | Reject InvalidRef | Uppercase / reserved source |
| source name `karambit` | Reject InvalidConfig | Wrapper collision |
| source `f`, kind `mystery` | Reject InvalidConfig | Unknown kind, not a ref error |
| `missing:ok/a` | Reject NotFound at registry lookup | No fallback |
| `f:ok/a b` / `f:ok\\a` | Reject InvalidRef | Whitespace / backslash |

## 11. Audit ordering and fields

**C-32.** Daemon resolve (including cache hit), issue, refresh, renew, export,
grant and source mutation MUST append local intent before helper/auth/network
or value delivery. Failure refuses before effect. Each operation appends an
outcome after its effect; failure to append outcome reports a sanitized warning
and never replays. Client correlation is untrusted, never evidence of intent.
Existing patterns: `core/audit.rs:intent`, `run`, `outcome` and
`core/daemon.rs:handle_as_scoped`.

**C-33.** Backend audit detail MUST carry action, operation ID, source name,
kind, binding hash, requested ref/selectors, grant ID, daemon-derived session,
mode, cache hit/miss, five clocks, version/etag, upstream lease_id, outcome and
safe error code. Unknown pre-issue version/ID is null in intent, not guessed.
On success record the returned metadata in a correlated value-free result
event before delivery; outcome follows delivery. Existing `audit::outcome`
accepts no detail, so a separate result event via `audit::log` is the seam;
result-event failure (static read, cache hit or dynamic issue alike) refuses
delivery with `DeliveryRefused` (not `AuditUnavailable`: an upstream effect may
exist); only when that result carried a known dynamic lease is it queued for
cleanup, whose containment audit follows C-34. Fake proofs: inject result-event
failure (a) after an ok dynamic issue: no delivery, no second issue, lease
pending-revoke; (b) after an ok static read: no delivery, no revoke call;
(c) on a dynamic cache hit: no delivery, the shared lease goes to pending-revoke
(the owner's other consumers lose it too: refusal is fail-closed). Never serialize Bundle or backend error bodies into audit detail.

**C-34.** Revoke, expiry, cancellation cleanup and local invalidation MUST run
even if audit is unavailable, then attempt containment audit and report failure
without blocking. Config deletion/retarget persistence is not exempt merely
because it also contains old access (`core/audit.rs:containment`). Audit remains
an unkeyed same-user-writable hash chain, not tamper-proof evidence.

## 12. TTL caps and orphan bound

**C-35.** Dynamic issuance MUST request an explicit TTL: default 300s, hard cap
900s, further limited to remaining grant lifetime. Per-source policy can only
lower default/cap. Before issue the adapter requires a configured upstream
maximum enforcing at most that cap, including lost-response cases; if it cannot
establish such a bound, dynamic resolution is Unsupported. Local timeout alone
cannot bound an orphan credential's life.

**C-36.** A dynamic result MUST provide a positive server TTL/expiry and lease
ID. Missing TTL or returned duration above the requested cap is never served:
queue immediate revoke of a known ID, audit and return TtlExceeded (malformed
ID is InvalidResponse). Unknown ID yields an orphan warning. This is an upstream
contract violation: no claim of a 900s bound is made for a server ignoring its
configured maximum. Expiry is conservatively measured from request start,
not receipt; server absolute expiry can only shorten that local deadline.

**C-37.** Renew MUST require a live owner grant and unchanged binding; each
requested renewal is at most 900s and at most remaining permission, with the
same over-cap rejection as issue. No renewal after owner end or pending-revoke;
no automatic renewal after daemon restart. Maximum total renewed lifetime ends
at the Karambit permission deadline. Renewal changes expiry, not bundle fields;
a backend rotating fields returns a new Bundle through resolve, not a mixed pair.

**C-38.** Credential usability MUST subtract a safety margin of
`min(30s, max(1s, floor(server TTL / 10)))`; zero usable remainder refuses delivery.
The 5-minute default limits normal crash exposure; 15 minutes is the maximum
orphan window for a conforming upstream, not a static-secret guarantee. The
30/60s cache bounds trade API quota for bounded staleness independently of TTL.
Existing SSO endpoint/login durations are not changed by these backend caps.

## 13. Synchronous trait, types, credentials and registry

**C-39.** The implementation MUST expose the following synchronous `Send + Sync` interface
and type semantics (derives/visibility helpers may vary without changing wire
or safety meaning). Optional methods return Unsupported by default. Backend
instances represent one immutable binding; no async runtime/vendor SDK crates.
Types below are Rust declarations, not existing implementation claims.

```rust
use std::{collections::BTreeMap, sync::Arc, time::{Duration, Instant}};
use zeroize::Zeroizing;
type BResult<T> = Result<T, BackendError>;
type BindingHash = String; // validated 64 lowercase hex bytes
struct BackendRef { source: String, native: String }
struct NativeRef { issuance: String, field: Option<String> }
struct SourceConfig {
    name: String, kind: String, endpoint: String, auth_method: String,
    credential_ref: String, credential_revision: String,
    generation: String, policy: serde_json::Value, // C-18/C-19, non-secret
}
enum SecretField { Text(Zeroizing<String>), Bytes(Zeroizing<Vec<u8>>) }
struct ChangeToken { version: Option<String>, etag: Option<String> }
/// Validated upstream lease ID (adapter `parse`-checked, bounded length, no
/// control chars). The only revoke argument; carries no lifetime claims.
struct LeaseId(String);
struct UpstreamLease {
    id: LeaseId, issued_at: u64, expires_at: u64,
    server_ttl: Duration, renewable: bool,
}
struct Bundle {
    fields: BTreeMap<String, SecretField>, change: ChangeToken,
    lease: Option<UpstreamLease>, fresh_for: Duration,
}
enum ResolveKind { StaticRead, DynamicIssue }
/// What upstream may hold after a resolve attempt, independent of success.
enum IssueEffect {
    None,                         // nothing issued (static read, or refused before send)
    Known(UpstreamLease),         // an issued lease the daemon must own and clean up
    KnownId { id: LeaseId },      // lease ID seen but TTL/fields unusable (C-36)
    Unknown,                      // request sent, outcome lost (Indeterminate)
}
struct Resolved { result: BResult<Bundle>, effect: IssueEffect }
struct ResolveOpts { requested_ttl: Duration }
struct Meta { change: ChangeToken, credential_expires_at: Option<u64> }
struct AuthState { expires_at: Option<u64>, renewable: bool, needs_human: bool }
struct AuthUpdate { state: AuthState, replacement: Option<Zeroizing<Vec<u8>>> }
struct Capabilities {
    metadata: bool, list: bool, renew: bool, revoke: bool,
    interactive_auth: bool, refresh_auth: bool,
}
struct RefMeta { native: String, change: ChangeToken }
struct Page { refs: Vec<RefMeta>, next: Option<String> }
struct Health { reachable: bool, authenticated: bool, sealed: Option<bool> }
struct CallContext<'a> {
    credential: &'a [u8], deadline: Instant,
    cancelled: &'a (dyn Fn() -> bool + Send + Sync),
}
trait HumanPrompt: Send + Sync {
    fn approve_login(&self, source: &str) -> BResult<()>;
}
trait SecretBackend: Send + Sync {
    fn id(&self) -> &str;
    fn capabilities(&self) -> Capabilities;
    fn parse_ref(&self, native: &str) -> BResult<NativeRef>; // offline
    fn resolve_kind(&self, r: &NativeRef) -> BResult<ResolveKind>; // offline
    fn auth_status(&self) -> AuthState; // RAM observation, no network
    fn authenticate(&self, c: &CallContext<'_>, ui: &dyn HumanPrompt)
        -> BResult<AuthUpdate>;
    fn refresh_auth(&self, c: &CallContext<'_>) -> BResult<AuthUpdate>;
    /// Effect-aware: `effect` is set whenever upstream may have issued
    /// anything, including on `Err` (C-40a). Never `BResult<Bundle>` alone.
    fn resolve(&self, c: &CallContext<'_>, r: &NativeRef, o: &ResolveOpts)
        -> Resolved;
    fn metadata(&self, c: &CallContext<'_>, r: &NativeRef) -> BResult<Meta>;
    fn list(&self, c: &CallContext<'_>, prefix: &str, page: Option<&str>)
        -> BResult<Page>;
    fn renew(&self, c: &CallContext<'_>, l: &UpstreamLease, increment: Duration)
        -> BResult<UpstreamLease>;
    /// Revoke by upstream lease ID only (C-40a): works for `Known` and
    /// `KnownId` alike; never needs fabricated TTL/expiry fields.
    fn revoke(&self, c: &CallContext<'_>, lease_id: &LeaseId) -> BResult<()>;
    fn health(&self, c: &CallContext<'_>) -> BResult<Health>;
}
type Factory = fn(&SourceConfig) -> BResult<Arc<dyn SecretBackend>>;
struct Registry { factories: BTreeMap<String, Factory> }
```

**C-40a.** Every `resolve` return MUST carry `IssueEffect`, set by the adapter
from what upstream returned before any validation, and on every error path
(timeout, cancel, malformed body, missing TTL, over-cap TTL, missing field).
The daemon, never the adapter, takes ownership and starts TRACKING every
reported effect immediately (before validation, publication or delivery):
- `Known` with `Ok` that is publishable and deliverable to a live owner enters
  ACTIVE owner tracking (C-13); it moves to pending-revoke only on an actual
  containment trigger (C-8: owner end, revoke, retarget, expiry, invalidation).
- `Known` with `Err`, or with `Ok` that is cancelled, stale (C-24), rejected,
  undeliverable (incl. `DeliveryRefused`) or ownerless, enters pending-revoke.
- `KnownId` always enters pending-revoke, cleanup expiry taken as request start
  + requested TTL (the cap, C-35) since no server TTL is trusted.
- `Unknown` records an orphan warning bounded by C-35.
Adapters MUST NOT call revoke on their own initiative; they only report what
they discovered, and every revoke goes through the daemon's single-in-flight
containment path (C-13, C-34). `Ok` with `effect = None` is valid only for
`StaticRead`; `DynamicIssue` + `Ok` requires `Known` matching `Bundle.lease`.
Fake proofs: (a) dies-mid-issue variant returns lease ID L without TTL; L
reaches pending-revoke, the daemon calls `revoke(L)` (ID only), a failing
revoke is retried per C-9, and abandonment at the fallback deadline is audited;
(b) an ordinary successful dynamic issue stays active (zero revoke calls) until
the owner ends, then exactly one revoke.

**C-40.** `BackendError` MUST have exactly the variants in §9, with
RateLimited's `retry_after: Duration` and all other variants unit-like (no raw
message). Trait methods take bounded daemon-created CallContext, not wire
credentials. HumanPrompt is daemon-implemented and operation-bound; an adapter
cannot invoke arbitrary helper verbs or supply its own prompt text. AuthUpdate
replacement stays in daemon RAM pending authorized storage; refresh of the same
identity increments login generation, not source binding.

**C-41.** Backend credentials MUST be fetched daemon-internally from the
Karambit encrypted secret `sources/<name>/cred`, never env, default vendor files,
client-provided plaintext on Resolve, or SourceConfig. Source add takes hidden
input over the existing protected local request path and stores through normal
encryption/helper authorization; no recursive public unlock RPC. Backend use is
a separate daemon-only permission from export of that secret. A backend can
use a non-secret SSO profile binding plus daemon-held role credentials instead
of duplicating keys; profile identity/revision then supplies credential identity.
Missing credentials return NeedsHuman. Config/status contains no auth bytes.

**C-42.** Registry MUST validate config before construction, reject duplicate
kind/name registrations and missing kind, and construct only immutable
binding-specific instances. `parse_ref`/`ref check` do not fetch credentials.
List/health are optional trait capabilities, not additional CLI commands;
no listing of upstream names through a narrow Resolve grant. The fake supports
`ok`, `slow`, `throttle`, `flapping`, `revoke-fails`, `dies-mid-issue` native
first path segments, followed by `/` and a nonempty item; selectors `#value`, `#username` and
`#password` select synthetic fields sharing an issue counter, unknown selectors
are NotFound. Fakes expose test-controlled static/dynamic and barrier modes;
production inputs cannot enable test barriers. Fake config can default to the
non-network endpoint `https://fake.invalid:443/`; the fake never performs HTTP.

**C-43.** Backend HTTP MUST use `/usr/bin/curl -q --config -`, secret-bearing
URL/headers/body in zeroizing stdin config only, as `core/sso.rs:http` and
`curl_quote` demonstrate. No shell, secret argv/env, default curlrc, disk
response/config files, redirects or TLS verification bypass. HTTPS only in
release; synthetic loopback HTTP overrides are debug/test-only. Clear inherited
proxy/auth variables, bound call duration to min(context deadline, 30s), bound
response collection to 1 MiB, and kill/reap on timeout. Poll cancellation while
collecting bounded output; C-11 governs issuance cleanup. Unlike existing SSO
error formatting, never echo curl stderr/upstream body. Do not refactor SSO here.

## 14. Fence and human-only verbs

**C-44.** Integration MUST add `SourceAdd`, `SourceRemove`, `SourceRetarget`,
`SourceList` and `ExportGrant` to `core/fence.rs:Verb`, `Verb::ALL` and
`AGENT_DENIED_VERBS`, with both CLI and daemon flags true; exhaustively classify
new requests in `request_verb`. ExportGrant applies when that operation lands;
unimplemented export requests cannot be accepted meanwhile. Source ls is
human-only, but read-only and needs no Touch ID. Resolve/ref check
are policy-governed, not categorically human-only.

**C-45.** Source add/rm/retarget and export-grant MUST require fresh daemon
Touch ID after intent and before effect, even for an undetected caller. Fence
lookup (`core/fence.rs:require_human`) only refuses detected agents, not proves
humanity. Test each verb at CLI and raw daemon layers, plus an undetected peer
with rejected biometric proof producing no mutation. Lifecycle revoke remains
containment and does not prompt. No GUI authority fallback is added here.

## 15. Conformance checklist

**C-46.** Review MUST map every checklist line to code/tests or an explicit
deferral to later work; deferred real-adapter and export operations stay unavailable,
while their type, error and fake lifecycle semantics are checked now.
Ownership: types/parser/registry, fakes, daemon lifecycle/cache/binding, and
CLI/lint/redaction. Fence integration is a named ownership seam;
this document changes no code ownership.

- [ ] C-1 Mode A scope and limits only.
- [ ] C-2 Daemon authority and bound child boundary retained.
- [ ] C-3 All delivered bundle fields enter Redactor before pumping.
- [ ] C-4 Five clocks separately displayed/audited.
- [ ] C-5 Minimum window and revocation gate enforced.
- [ ] C-6 Dual-clock/wake/rollback fake passes.
- [ ] C-7 Static end never claims recall.
- [ ] C-8 Dynamic state transitions deny reuse before revoke.
- [ ] C-9 Retry schedule, pending status and abandonment audit proven.
- [ ] C-10 Restart loses local state, never fabricates cleanup.
- [ ] C-11 Cancellation/unknown issuance never delivers or blindly retries.
- [ ] C-12 Single-flight plus generation rechecks, no global I/O lock.
- [ ] C-13 One grant/session owner, correct consumer/end behavior.
- [ ] C-14 Removal/retarget preserves old-binding cleanup.
- [ ] C-15 All failure-matrix cases covered with deterministic fakes.
- [ ] C-16 One issuance per bundle, selector authorization retained.
- [ ] C-17 Typed complete bundle, no lossy env conversions.
- [ ] C-18 Length-framed binding hash fields tested.
- [ ] C-19 Canonicalization/revisions exclude secrets and ambiguity.
- [ ] C-20 Human retarget, no generic credential mutation bypass.
- [ ] C-21 Exact cache key and no cross-session hit.
- [ ] C-22 Every hit reauthorizes and consumes use at delivery.
- [ ] C-23 30/60s freshness, metadata change and error behavior proven.
- [ ] C-24 Value-response token and revision-safe publication.
- [ ] C-25 Export grants separate from narrow resolve grants.
- [ ] C-26 Export get/store/erase no vendor-file fallback (later work).
- [ ] C-27 Fixed safe error messages, no upstream echo; AuditUnavailable only pre-effect.
- [ ] C-28 Bounded safe-read retries, no dynamic replay.
- [ ] C-29 Offline envelope parser passes traversal cases.
- [ ] C-30 Legacy/env wrapper/AWS coexistence preserved.
- [ ] C-31 Unknown kinds/sources and offline lint follow table.
- [ ] C-32 Intent failure before effect, outcome failure no replay.
- [ ] C-33 Result metadata correlated and value-free before delivery; result-event failure ⇒ DeliveryRefused, plus cleanup only when a known dynamic lease is carried (fresh or cache hit).
- [ ] C-34 Containment works under audit fault.
- [ ] C-35 Explicit bounded dynamic TTL and upstream maximum required.
- [ ] C-36 Missing/over-cap TTL refused and cleanup queued.
- [ ] C-37 Renewal bounded by grant and per-renewal cap.
- [ ] C-38 Credential margin and honest orphan rationale retained.
- [ ] C-39 Sync Send+Sync trait/types compile without vendor runtime.
- [ ] C-40 Closed error enum and daemon-owned auth context.
- [ ] C-40a Resolve carries IssueEffect on every path; daemon tracks it (active vs pending-revoke); adapters never self-revoke.
- [ ] C-41 Encrypted credential storage and no ambient fallback.
- [ ] C-42 Registry and fake grammar enforce offline validation.
- [ ] C-43 Curl transport limits and no secret argv/config files.
- [ ] C-44 Fence table and exhaustive request classification.
- [ ] C-45 Human proof independent of detection, per-verb negative tests.
- [ ] C-46 Every item has evidence or named unavailable future operation.

## 16. Open questions and defaults

No unanswered question blocks this specification. Defaults chosen for it: 300/900s dynamic TTL, 30/60s cache, 1..60s
revoke backoff, one grant/session owner, length-framed binding hash, first-colon
grammar and reserved `aws`. These favor bounded orphan exposure, isolation and
stable parsing rather than maximizing compatibility or cache reuse.

Not decided yet: which dynamic engine to prototype first (AWS/moto or Postgres),
which Vault read/token scope a real adapter would use, and whether any pre-existing
plaintext vendor credential file should be removed. GUI design and Mode C are not
part of this layer. Backend server-specific TTL enforcement is verified during
adapter conformance, not assumed from a generic HTTP success.
