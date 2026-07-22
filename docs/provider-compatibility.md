# Provider compatibility notes

This document records the upstream contracts behind Calcifer's resume and usage behavior. It is not a promise that an undocumented provider implementation will remain stable.

## Verification baseline

Upstream source behavior was verified on 2026-07-15 and the packaged process
contracts were last reviewed on 2026-07-16 against:

- installed and released Codex CLI `0.144.4`, tag [`rust-v0.144.4`](https://github.com/openai/codex/releases/tag/rust-v0.144.4), commit [`8c68d4c87dc54d38861f5114e920c3de2efa5876`](https://github.com/openai/codex/commit/8c68d4c87dc54d38861f5114e920c3de2efa5876);
- OpenAI Codex `main` commit [`f90e7deea6a715bbd153044af6f475eefa749177`](https://github.com/openai/codex/commit/f90e7deea6a715bbd153044af6f475eefa749177), where the fields used here were unchanged;
- Orca `main` commit [`e0edc8ef76d341f7ab8083a006f785322bcaeb23`](https://github.com/stablyai/orca/commit/e0edc8ef76d341f7ab8083a006f785322bcaeb23).

The official Codex App Server command is still marked experimental as a whole. Calcifer negotiates its stable protocol subset with `experimentalApi: false`. On-demand status accepts exactly Codex `0.144.4`; adding a release requires generated-schema fixtures, synthetic protocol coverage, and a live initialize smoke test before the allowlist changes.

## Managed Codex profile configuration

Codex 0.144.4 stores user configuration in the selected
`CODEX_HOME/config.toml`. A new Calcifer profile starts with file-backed
credential storage only. When the user accepts Codex's first project-trust
prompt, the official TUI legitimately adds a
`projects."<absolute-path>".trust_level` entry to that same file.

Calcifer therefore validates profile configuration semantically rather than
requiring the original bytes. The known top-level key set is pinned to
0.144.4's `core/config.schema.json`; unknown future keys fail closed.
File-backed Codex account credentials remain mandatory, and MCP OAuth storage
is either absent or `file` in the profile; runtime overrides force both stores
to `file`. Project entries may contain only a trusted or untrusted decision for
an absolute path. Keys that replace account/provider routing, remote
configuration, managed state locations, project-root discovery, dynamic
features, marketplaces, MCP servers, plugins, or role definitions are rejected.
MCP OAuth callback URL and port settings are rejected as authentication endpoint
overrides even though they are known schema keys.
Calcifer also rejects any `CODEX_HOME/agents` filesystem node because Codex
auto-discovers complete role-specific configuration layers there. Managed role
configuration is unsupported until Calcifer can discover and mediate every
referenced layer. Other reviewed known user settings remain the official CLI's
value-validation responsibility. The read is bounded to 1 MiB and errors do not
include parser details, role names, or paths. Calcifer never rewrites a valid
provider-owned configuration.

Relevant sources and local policy:

- [Codex 0.144.4 configuration schema](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/core/config.schema.json);
- [project trust config update](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/tui/src/config_update.rs#L45-L82);
- [trust prompt persistence](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/tui/src/onboarding/onboarding_screen.rs#L560-L600);
- [Calcifer managed profile config specification](../specs/managed-codex-config.md).

## Codex repository configuration

Interactive Codex 0.144.4 loads repository configuration from the nearest
project root through the current working directory. Calcifer mirrors the
default `.git` root boundary, accepts directory and worktree-file markers, and
checks each `.codex` layer before `run` or `resume`. Every `.codex/agents`
filesystem node is rejected because the discovered role files are complete
indirect configuration layers; this applies even when no sibling `config.toml`
exists. The current config policy is
an explicit safe-key allowlist: unknown future top-level keys and settings that
can alter managed authentication, provider routing, dynamic feature policy,
root discovery, or state locations fail closed.

Codex 0.144.4 has one linked-worktree special case: it can read the primary
checkout's `.codex/config.toml` and merge only its `hooks` field. Calcifer does
not resolve or inspect that external hook source. This does not import a second
account/provider/state layer, and repository hooks remain outside Calcifer's
sandbox guarantee; a future upstream expansion beyond `hooks` must fail the
compatibility review before support is claimed.

The policy is intentionally version-scoped. Calcifer does not claim equivalent
coverage for an unaudited Codex release merely because the TOML parses. A
separate executable/schema compatibility gate remains required before
automatic failover is enabled.

Login and account-rate-limit reads intentionally have no repository semantics.
Calcifer starts them with the selected profile home in `CODEX_HOME`, but uses a
private runtime cwd containing its own `.git` boundary. This prevents an
ancestor repository from contributing configuration even when the user places
`CALCIFER_HOME` inside that repository.

Relevant sources and local policy:

- [Codex 0.144.4 configuration loader](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/config/src/loader/mod.rs);
- [managed repository configuration specification](../specs/managed-codex-project-config.md).

## Codex private provider identity

Codex `0.144.4` has no stable public account read that returns the effective
account/workspace routing scope: `account/read` exposes email and plan type,
and `codex login status` exposes only the authentication kind. Neither is a
safe uniqueness key. For this one allowlisted release, the provider-owned
file-backed auth model contains `auth_mode` and optional
`tokens.account_id`; the official login flow derives that value from the
selected ChatGPT account/workspace and uses it as `ChatGPT-Account-ID` on
backend requests.

Calcifer therefore treats this as a version-scoped persisted compatibility
surface, not a cross-version API. Before registration or explicit legacy
verification it performs the normal App Server initialize/home/version gate,
but sends no account request. It then reads at most 1 MiB from the private
regular `auth.json` and decodes only `auth_mode` plus `tokens.account_id`.
Missing, empty, malformed, oversized, unsupported-auth, or untested-version
state fails closed. JWT claims, email, plan type, API-key modes, and `codex
login status` are not used.

The account scope is immediately reduced with an installation-local,
domain-separated HMAC over a length-delimited tuple containing provider,
supported auth kind, adapter version, and scope. The raw scope is never
persisted outside `auth.json`; the key ID and fingerprint are private marker
fields and never public output. Equal fingerprints prove that two aliases use
the same effective routing scope and are rejected. Different fingerprints do
not prove independent provider quota.

New registration writes the binding inside staging before the profile
directory and registry entry become visible. Existing unbound profiles remain
usable for explicit run, resume, and status; `calcifer auth verify
codex@<alias>` adds the binding without login, credential copying, or direct
OAuth refresh. Verification holds the profile lease through the compatibility
probe and auth read, then serializes the uniqueness check and marker commit
against registration. Future automatic selection must rederive and compare the
binding under the same retained lease. Key loss/replacement, credential drift,
or ambiguous legacy duplicates stop selection and require explicit recovery.

Relevant upstream sources:

- [Codex 0.144.4 persisted token model](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/login/src/token_data.rs#L10-L41);
- [official login persistence](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/login/src/server.rs#L860-L900);
- [account request routing header](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/model-provider/src/bearer_auth_provider.rs#L28-L45);
- [account/read response](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server-protocol/src/protocol/v2/account.rs#L479-L495).

## Codex resume

Codex persists sessions beneath the selected `CODEX_HOME`, normally as:

```text
sessions/YYYY/MM/DD/rollout-...-<thread-id>.jsonl
archived_sessions/
state_5.sqlite
```

The stable same-home operations are the CLI's `codex resume <thread-id>` and App Server's `thread/resume {threadId}`. The exact thread ID is preferred over `--last`; `--last` is affected by cwd filtering and can select an unintended conversation when several sessions exist.

Calcifer's current profile-specific `CODEX_HOME` preserves these files across wrapper restarts. Resume restores persisted conversation state, not the terminated process, live stream, or an in-flight tool call. Calcifer does not replay the previous prompt.

Calcifer supports three same-home restore modes:

```text
calcifer resume codex@<alias> <thread-id>  # direct validation and exact adoption
calcifer resume codex@<alias>              # explicit official --last convenience
calcifer resume                            # exact Calcifer-owned workspace head
calcifer run --untracked codex@<alias>     # explicit no-capture provider launch
calcifer resume --untracked codex@<alias>  # explicit no-capture --last launch
```

For automatic capture, the 0.144.4 adapter initializes with `experimentalApi: false`, then pages both active and archived `thread/list` results filtered to the exact canonical cwd and `cli` source. It admits only canonical UUID root threads with no parent, non-ephemeral persistence, matching recorded CLI version, and a rollout canonically contained in the selected private managed home's `sessions` or `archived_sessions`. Nested legacy directories/files created under a prior caller umask may be `0755`/`0644`, but they must be owned by the current user, real non-symlink nodes, non-writable by group/other, and single-linked for files. New Calcifer processes set umask `0077` before creating state or spawning login, App Server, coordinator, guardian, or TUI children. It drops preview, turns, model/provider fields, and rollout content before constructing Calcifer metadata. An authoritative explicit thread uses direct `thread/read(includeTurns=false)` and never scans every old session.

`run` and explicit `--last` capture a private pre-launch inventory before the TUI starts. After the TUI exits, exactly one new or uniquely changed thread may update the workspace head. Change detection combines App Server timestamps with a path-free rollout fingerprint containing device/inode, length, and nanosecond mtime/ctime, because upstream `updatedAt` and `recencyAt` are Unix seconds; ctime also detects a same-inode rename without storing the path. Zero candidates preserve the previous head only when no baseline ID disappeared; deletion, deletion plus a new thread, multiple candidates, active/archive inconsistency, duplicate IDs, pagination-cap exhaustion, wrong cwd/source/profile, malformed protocol, or unsupported schema fail closed. A pending pre-launch inventory survives a guardian crash and is reconciled under the same profile lease. Only the first `session_meta` identity and bounded persisted task-start, task-complete, and turn-aborted tags are used to classify `clean`, `interrupted`, or `unknown_crash`; transcript payloads are ignored and never replayed.

An incomplete or unavailable inventory never authorizes an implicit provider launch. Users may explicitly opt into `--untracked` for `run` or profile-specific `resume --last`; this skips App Server entirely, but only after one transaction writes a durable `needs_selection` marker plus a version-free, inventory-free ownership record and verifies that no pending launch exists for the canonical workspace. The record blocks cross-profile exact adoption until the official child exits, and exact lifecycle refresh cannot overwrite a marker created after that exact process started. There is no post-exit capture; cleanup only removes ownership and preserves `needs_selection`. Bare resume remains ambiguous until the user supplies an exact same-profile thread ID, while registry failure or uncertain durability prevents the provider from spawning at all.

The upstream rollout walker stops after 10,000 files per active/archived scan and records `reached_scan_cap`, but App Server v2's `ThreadListResponse` omits that flag. Calcifer cannot infer completeness from `nextCursor`. It instead takes stable filesystem snapshots before and after `thread/list`, requires each active and archived root to have strictly fewer than 10,000 regular files, maps every wire path to the matching snapshot fingerprint, and rejects symlinks, special or writable nodes, unreadable traversal, and any pre/post mutation. Missing and empty roots are equivalent. Calcifer deliberately keeps `useStateDbOnly: false`: Codex's own tests show that DB-only listing can omit a rollout until repair/indexing, and a fresh session can exist before its first user message is committed to the database.

The final restore is always official `codex resume <exact-thread-id>` with no automatically supplied prompt. Stable thread lookup is profile-local: a thread captured from profile A cannot be resumed through profile B. Explicit exact resume first runs a sanitized, 256-byte-output, two-second `codex --version` probe from the neutral cwd. A clearly non-allowlisted canonical SemVer, including a valid prerelease such as `0.145.0-alpha.11`, preserves the official exact CLI fallback without starting App Server or mutating provider-owned sessions or Calcifer's registry. Malformed or noncanonical version output fails closed instead of being mistaken for an unsupported release. For allowlisted `0.144.4`, malformed App Server/session protocol also fails closed; authentication, spawn, timeout, transport, and otherwise unclassified provider availability failures remain retryable.

Relevant upstream sources:

- [official App Server documentation](https://developers.openai.com/codex/app-server/);
- [non-experimental `thread/list` and `thread/read` request types](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server-protocol/src/protocol/common.rs#L621-L648);
- [profile-local session inventory lookup](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/rollout/src/list.rs#L1515-L1533);
- [the internal 10,000-file scan cap and `reached_scan_cap`](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/rollout/src/list.rs#L118-L120);
- [v2 `ThreadListResponse`, which omits the scan-cap flag](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server-protocol/src/protocol/v2/thread.rs#L1191-L1201);
- [DB-only listing skips rollout repair](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/rollout/src/recorder_tests.rs#L776-L829);
- [thread resume types and experimental-field markers](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server-protocol/src/protocol/v2/thread.rs#L310-L438);
- [session layout](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/rollout/src/list.rs#L418-L421).

### Cross-profile conversation handoff

A stable thread-ID lookup is scoped to the current `CODEX_HOME`, but credential profile and conversation identity are not intrinsically the same thing. Calcifer's successful automatic-failover path will continue the same user-visible conversation under the next profile.

Codex 0.144.4 provides two experimental external-rollout fields:

- `thread/resume.path` loads the external rollout and continues appending to that supplied path. It preserves the Codex thread ID but requires a cross-profile writer lease for the source rollout's lifetime.
- `thread/fork.path` loads the external rollout as history and materializes a new persistent thread and rollout under the target profile. It changes the provider thread ID while keeping the transcript and source lineage.

Calcifer prefers `thread/fork.path` for automatic handoff. One logical Calcifer conversation can contain multiple profile-local Codex thread generations, and each generation has one writer. The target profile's App Server owns authentication and persistence; the official TUI attaches with `codex resume --remote <local-socket> <target-thread-id>`. The source rollout remains unchanged after import. Because a newly forked thread is already loaded, its effective model, cwd, sandbox, and approval settings must be fixed in the fork request; the later TUI rejoin is not used to change credential or provider routing.

The connection that creates or resumes a thread is subscribed to thread events. A future Calcifer monitor may stay subscribed for structured usage signals, but it must never answer approvals or other server-initiated requests; the official TUI is the sole responder and must be attached before user input is accepted. `thread/fork` has no Calcifer-supplied idempotency key, so a prepared transition is synced before the request and crash recovery adopts only one uniquely matching fork.

The path must come only from Calcifer-owned lineage metadata, remain canonically contained in a registered source profile's sessions root, pass type/hard-link/symlink/owner/mode checks, and be read only after the source TUI/App Server are stopped and reaped while Calcifer retains the source lease. Source and target profiles must share an explicitly configured trust domain. The installed Codex version and `codex app-server generate-json-schema --experimental --out <dir>` output must match a tested adapter because the default generated schema omits these unstable fields. CI must also perform a synthetic fork-by-path protocol smoke test; schema presence alone does not prove runtime acceptance or materialization semantics.

`ThreadForkParams.threadId` remains a required string even for a path-based fork. Calcifer sends `threadId: ""` together with a non-empty validated `path`; Codex then ignores the empty lookup ID and imports by path.

Calcifer now has a private Unix compatibility gate for exactly Codex `0.144.4`.
The gate does not trust a version string or schema presence by itself. It must
complete all of these checks before its private, unforgeable handoff capability
can be constructed:

1. Open the absolute, canonical executable without following its final
   component, reject an empty, oversized, non-executable, setuid/setgid, or
   group/other-writable file, and bind the probe to its device, inode, length,
   mode, owner/group, link count, nanosecond mtime/ctime, and SHA-256 digest.
2. Copy those verified bytes once into a mode-`0500` executable below a retained
   mode-`0700` scratch directory. Every version, schema, fork, App Server, and
   TUI phase executes that staged copy, so an installer replacing the original
   pathname cannot mix two legitimate Codex builds within one proof. The copy
   is length- and SHA-256-equal to the original; both the staged copy and the
   original executable are fully rehashed before capability minting. A changed
   original install path therefore fails closed rather than authorizing the
   staged bytes for future production use.
3. Run the exact-version probe from a private workspace and reject every other
   version.
4. Generate both default and `--experimental` App Server schemas. The default
   schema must omit `path` from `ThreadForkParams` and `ThreadResumeParams`; the
   experimental schema must match the reviewed unstable path fields and the
   reviewed fork, resume, and thread-response projections pinned for `0.144.4`.
   This is deliberately not a byte-for-byte equality claim for either complete
   protocol document. The separately generated `JSONRPCError` and
   `JSONRPCErrorError` documents must match their complete pinned schemas
   exactly in both variants.
5. Start an experimental stdio App Server and fork a bounded synthetic rollout
   by path. The returned thread must have a new UUID, the expected
   `forkedFromId`, CLI version, model provider, cwd, preview, and persisted
   turns. The fork response must also return the requested model, provider,
   cwd, `never` approval policy, and read-only/no-network sandbox plus the
   expected `user` reviewer. Its canonical rollout must be a
   current-user-owned, single-link regular file, non-writable by group or
   other, below the synthetic target `sessions` root, and contain the known
   history sentinel. Exact source and target fingerprints cover device, inode,
   length, mode, owner, link count, nanosecond mtime/ctime, and SHA-256.
6. Start a real `codex app-server --listen unix://...`, then attach the official
   TUI in a PTY with
   `codex resume --no-alt-screen --remote unix://... <target-thread-id>`.
   A private transparent WebSocket proxy requires, in order: a successful
   `thread/read` for the exact target; a successful `thread/resume` for that
   target with the same model, provider, cwd, approval/reviewer, and
   sandbox/network settings proven at fork; then a `thread/read` for the exact
   source-parent ID with `includeTurns` absent. The parent exists only in the
   isolated source home, so the target App Server must return an error for that
   final lookup. Readiness is emitted only after that error is forwarded to the
   TUI, proving that the official TUI parsed the resumed fork lineage and
   completed its parent-title round trip. Socket existence or process liveness
   alone is not sufficient; the TUI, App Server, and proxy connection must also
   still be alive after readiness.

The capability retains the executable identity rather than exposing a raw
launch path. Source and target directory descriptors plus both rollout
fingerprints remain live through the remote-TUI phase and are revalidated before
and after it; a fork response is not enough to authorize a later, mutated file.
A hostile same-UID process can still attack the installation or scratch
namespace and remains outside this compatibility gate's guarantee.

Every probe command starts with `env_clear` and receives only an explicit
allowlist: fixed `PATH`, locale, shell and terminal values plus synthetic,
private `CODEX_HOME`, `HOME`, XDG config/data/cache/runtime, and
`TMPDIR`/`TMP`/`TEMP` locations. Ambient credentials, proxy settings, provider
endpoints, `CALCIFER_HOME`, and test hooks therefore cannot be inherited. The
probe uses no profile credentials, writes only synthetic source and target
state, and checks its bounded scratch tree for credential filenames. A static
synthetic model catalog prevents online model discovery; the only configured
model endpoint is a loopback sentinel, and any connection to it fails the gate.

The owner-only mode-`0700` scratch root and its source, target, environment,
workspace, and schema directories are retained by identity and open directory
descriptors. Config, catalog, schema, and rollout access accepts only normal
relative components, opens every directory component with descriptor-relative
`openat(O_DIRECTORY | O_NOFOLLOW)`, and opens the final file with `O_NOFOLLOW`.
The provider cannot turn a schema or rollout component into a followed symlink
between pathname validation and readback.

The bind-created App Server and readiness-relay Unix sockets live inside the
retained, current-user-owned mode-`0700` scratch root. The extracted relay sets
its own socket to mode `0600`, reads back its owner, type, and mode, records its
pathname device/inode, and unlinks it only after an identity match. A collision,
symlink, mode change, or pathname replacement is preserved and fails closed.
The separately provider-created App Server socket is also validated before use.
AF_UNIX descriptor metadata is not a portable identity for its bound pathname,
so the relay instead verifies its local address, the private parent, and the
pathname repeatedly. A hostile process already running as the same UID can
still race pathname operations; this same-UID namespace race is outside the
gate's guarantee.

The relay has a 16 KiB WebSocket handshake limit, a 1 MiB message and frame
buffer limit, 256-byte thread/method/request-ID limits, a 32-event synchronous
backpressure channel, and the caller's overall deadline. It rejects duplicate
JSON keys and validates framing, mask direction, fragmentation,
request/response order, resume-source precedence, IDs, errors, lineage, target
identity, and effective settings only until readiness, then becomes an opaque
byte relay. Provider requests are classified and forwarded but never answered
by Calcifer. Forwarding and observation are serialized so the TUI cannot issue
resume based on a response before Calcifer has recorded that response. An
atomic `RUNNING`, `DISCONNECTED`, or `STOPPING` relay lifecycle distinguishes
peer loss from intentional shutdown. The final health check actively polls both
retained stream endpoints for error/hangup and uses non-consuming, non-blocking
`PEEK` reads to detect EOF; checked shutdown fails if the relay disconnected
before it entered `STOPPING`. TUI output is also capped at 1 MiB.

Issue #48 adds a separate same-profile exact-resume readiness policy and typed
effective-setting projection. It does not add the persistent monitor, App
Server/process owner, lease lifecycle, terminal bridge, usage polling, or a
public command required by the supervised-session design in
[ADR 0003](adr/0003-supervised-codex-session.md).

Issue #54 adds the default-unused pinned same-profile integration. Its App
Server shutdown contract is deliberately different from the synthetic
compatibility probe: Calcifer sends exactly one `SIGTERM` to the exact direct
App child and can mint `PinnedAppGracefulDrain` only after that same child is
exactly waited with code zero. There is no App `SIGKILL` fallback, no second
`SIGTERM`, and no conversion of an early, nonzero, signalled, timed-out, or
otherwise ambiguous exit into release evidence. Those cases retain the direct
wait/runtime/lease/completion authority; an accidental ambiguous-owner Drop
aborts without sending another signal.

The guardian carries that evidence through runtime cleanup in a non-copyable
lifecycle projection. Only that projection, or an equally move-only
`ProviderNeverStarted` proof, can publish the fixed eight-byte
`CFCMP\x01\r\n` provider-release record. That record is never owner, session,
anchor, or shell success by itself. The persistent anchor and package owner must
still independently establish their exact waits and exact record-plus-EOF
checks; missing, invalid, or trailing data restores the tty but retains the
generation.

A malformed or cross-wired `CFRCR\x01` recovery frame grants no authority and
cannot initiate cleanup. Independently observed exact peer EOF, including EOF
after rejected bytes, may enter typed owner-loss cleanup, but the authority
comes from the EOF rather than the rejected frame and does not itself mint
release or normal disposition. `CFRET\x01\r\n` is a terminal boundary whether
the owner was nonrecoverable, recovery transport failed, or the sole eligible
retry was consumed. No retry follows `CFRET`: the guardian deliberately keeps
the exact typed provider/terminal owner reachable in its non-returning park loop
for the rest of the process lifetime.
A, B, lifecycle, transfer, completion, terminal, recovery, and unrelated PTY
descriptors are all forbidden in App Server, official TUI, and tool process
groups.

This recovery authority is live and generation-local. It is carried only by the
anonymous endpoint retained by the running owner/guardian generation, is not
persisted, and does not survive loss of both authorities or a machine restart.
It is separate from cold conversation resume, which reopens persisted history
but cannot restore a dead process or in-flight operation. Automatic scratch
deletion still requires four independent proofs: exact coordinator-child wait;
the exact provider-release-only `CFCMP\x01\r\n` record followed by EOF, which is
not session or shell success; absence of every reported known process group; and
an identity-checked empty runtime with zero retained FD and socket references.

Independently budgeted checksum-pinned normal-session and retained-recovery
official-TUI scenarios are configured to exercise the production coordinator,
guardian, provider-session, PTY, input-gate, resize, and group-wide stop/continue
implementations under a test-owned outer-terminal harness. The normal scenario
passed twice consecutively and retained recovery once on the exact local Apple-
silicon tree; Ubuntu 24.04/macOS matrix readback remains pending. They use the production same-
profile A-to-B admission path across their coordinator and guardian helpers, and
the guardian helper enters the shared production guardian-bootstrap core through
a package-only post-admission loopback rewrite and fixed observation root. The
package parent is designed to create the completion endpoint, pass it across
real parent-to-coordinator and coordinator-to-guardian `exec` boundaries, and
accept only the exact frame plus EOF after the guardian consumes provider-
release proof. The test-only package role dispatcher and outer-terminal harness
do not execute the production `CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE`
dispatcher/parser or persistent shell-anchor role, and these scenarios make no
parser coverage claim. Those package roles remain libtest subprocesses, but the
TUI launcher does not: the CI job builds the ordinary
`calcifer-supervisor-fixture` binary, copies its exact bytes into an
owner-private single-link staging path, verifies byte equality and file
identity, and passes the canonical staged path through a `cfg(test)`-only
package seam. This keeps Cargo's multiply-linked Linux output outside the
launcher authority without weakening the runtime validator. The launcher
binary then dispatches the production internal-launcher path before `exec`ing
Codex. The seam fails closed unless the path is absolute and canonical,
owner-matched, a non-empty regular file with one link, owner-executable, and
neither set-ID nor group/other-writable. Production builds do not parse that
override. Every `CALCIFER_*` value is removed by the managed-
provider environment sanitizer, while sanitizer-approved ambient values are
projected explicitly from an empty base. The launcher copies that sealed
effective environment onto another empty base, so neither Calcifer authority
nor test control reaches the App Server or TUI and safe `PATH`, `HOME`,
terminal, locale, XDG, and tool context remains identical.

A separate non-ignored deterministic fixture covers all seven
closed recovery checkpoints: startup queued, ready, active, suspended, retained
quiescing, retained restore pending, and retained cleanup pending. It is designed
to execute the exact production coordinator/guardian/session graph while a
sealed `cfg(test)` compatibility seam and strict owner-private wrapper replace
only official compatibility/provider behavior. The fixture is credential-free
and loopback-only, and production builds parse neither its selector nor its
compatibility override. A checkpoint is observation only: the fixture must prove
that it neither completes nor terminates the coordinator before sending the sole
generation-bound `CFRCR` request. The first four checkpoints expect failed-clean
with zero inference calls; the three retained checkpoints expect completed-clean
with exactly one validated loopback inference call. Its fourth namespace proof
also requires the identity-checked private compatibility stage parent to be
empty. This is deterministic recovery-phase evidence, not Codex-version
compatibility evidence. All seven cases passed three consecutive local runs on
the 2026-07-20 Issue #54 candidate source; cross-platform CI readback remains pending.

`PinnedAppGracefulDrain` proves only the reviewed behavior of the direct Codex
`0.144.4` App child. It is not proof that every arbitrary detached descendant is
absent. Issue #55's zero-residue scope is Calcifer-owned direct children and
recorded known process groups plus identity-checked runtime, FD, and socket
evidence. A child can change session and process group with `setsid(2)`, and a
generic process-group sweep neither waits such a non-child nor establishes its
nonexistence. Calcifer therefore does not describe this contract as whole-tree
reaping. Containment and accounting for descendants that escape with
`setsid(2)` is tracked separately by issue #56.

The synthetic #28 compatibility-probe subprocesses remain separate
process-group leaders. That probe observes a leader exit with non-reaping
`waitid(..., WNOWAIT)`, kills the process group so ordinary descendants cannot
keep its pipe or PTY drain open, and then waits for the direct child leader. Its
explicit shutdown path propagates group-kill, direct-wait, and reader/pump join
failures. macOS `EPERM` is tolerated only when killing a group whose leader was
already observed exited with `WNOWAIT` (the zombie-only case); a live-tree kill
still treats it as an error. This is synthetic probe containment, not App
release evidence. Cleanup removes only socket and scratch paths whose recorded
identity still matches at the cleanup check; non-child descendants are
signalled, not claimed as reaped.

Ubuntu 24.04 and macOS CI jobs are configured to download the pinned official `0.144.4`
release archives and verify their fixed architecture-specific SHA-256 digests
plus the archive's single expected executable. Three independently budgeted
matrix scenarios sit behind one aggregate gate. `contracts` runs the complete
ignored-by-default handoff probe, a real-running-turn one-`SIGTERM` App drain, an
official `thread/shellCommand` probe whose child calls `setsid(2)` and observes
neither any of eight live supervisor authority/control descriptors nor denied
supervisor/authentication environment, and a typed-monitor exchange covering
normalized rate-limit/reset-credit success followed by a redacted provider
error. `official-tui-normal` is designed to run the official remote TUI through
the production coordinator/guardian session, PTY, fresh input gates, resize, and
stop/resume job-control path. `official-tui-recovery` independently targets
#55's retained-cleanup recovery and four-proof deletion gate. Both official
scenarios are designed to cross real package-parent-to-coordinator and
coordinator-to-guardian `exec` boundaries with the completion endpoint; the
package parent is configured to check the provider-release-gated exact frame
plus EOF. Two consecutive normal executions and one retained-recovery execution
passed from that candidate source on Apple silicon; the Ubuntu 24.04/macOS matrix
remains pending. Linux executes the prebuilt exact libtest in a mandatory fresh
loopback-only namespace after clearing direct environment and inherited-socket
authority and dropping every capability with `NoNewPrivs`; macOS is native
functional evidence. There is no Linux native-network fallback. This is direct
IPv4/IPv6 confinement for the trusted checksum-pinned scenario, not a malicious
binary sandbox or a claim about AF_UNIX and same-UID authority. Their test-only
role dispatcher does not execute the production
`CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE` dispatcher/parser or persistent shell-
anchor role. The handoff probe
has a 180-second budget; the ignored schema/fork-only diagnostic uses 120
seconds. The detached probe is released before App shutdown, so it verifies
inheritance isolation rather than detached-descendant absence. Windows remains
unsupported and fails closed. A new Codex release requires a new reviewed
projection, pinned package, and complete runtime smoke; editing the
supported-version label alone cannot mint the capability.

This compatibility gate is implemented, but the production handoff transaction
described in [ADR 0001](adr/0001-cross-profile-conversation-handoff.md) is not.
No command currently switches a user's profile or imports a user's rollout.
The gate receives no Calcifer profile, conversation registry, credential, or
user rollout, and incompatibility therefore cannot mutate those states.
The internal Linux/macOS no-gap target-reservation and guardian lease-transfer
primitive is implemented. Supervisor wiring, transition journaling,
authoritative exhaustion selection, target-fork integration, and cross-profile
transition crash recovery remain prerequisites before automatic handoff is
enabled.

Relevant upstream sources:

- [`ThreadForkParams.path` and `ThreadResumeParams.path`](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server-protocol/src/protocol/v2/thread.rs#L310-L600);
- [fork implementation and target rollout materialization](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server/src/request_processors/thread_processor.rs#L3444-L3721);
- [external rollout resolver](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/thread-store/src/local/read_thread.rs#L150-L188);
- [resume recorder appends to the supplied path](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/rollout/src/recorder.rs#L813-L826).

## Codex rate limits and reset credits

Calcifer sends the following read-only request after the App Server initialization handshake:

```json
{
  "method": "account/rateLimits/read",
  "id": 1,
  "params": null
}
```

Before sending that request, Calcifer validates the version-specific initialize
response. The client-scoped user-agent must contain a normalized numeric
`0.144.4` release, all required initialize fields must have the expected types,
and the returned absolute `codexHome` must canonicalize to the selected managed
profile home. A missing or malformed field returns redacted `protocol_error` /
`incompatible` status; an untested release or different home returns
`unsupported` / `incompatible`. Both close the probe before `initialized` or
`account/rateLimits/read` is sent. Canonical comparison deliberately accepts
platform aliases such as macOS `/tmp` and `/private/tmp` while preventing a
different profile from being observed.

After the gate, Calcifer accepts only a JSON-RPC response containing exactly
one of `result` or `error`. For the `0.144.4` adapter, `result.rateLimits` is a
required non-null object even when `rateLimitsByLimitId` contains usable named
buckets. Missing/null legacy limits and ambiguous envelopes (both fields or
neither field) fail closed as redacted `protocol_error` / `incompatible`.
Otherwise, the response is decoded into required typed window and credit fields
while allowing unknown additive fields. A successful read reports the detected
Codex version, Calcifer adapter version, protocol name, explicit tested version
set, and `compatible` state. Protocol drift is `incompatible`; failures where
the contract could not be observed are `unverified`. Both states have
`availability: unknown` and cannot become a failover signal.

The normalized response can contain:

- legacy `rateLimits` and all `rateLimitsByLimitId` buckets;
- primary and secondary `usedPercent`, window duration, and Unix reset time;
- workspace credit availability, unlimited state, and balance;
- individual spend-control limit, used value, remaining percentage, and reset time;
- reset-credit authoritative `availableCount`;
- optional reset-credit status, grant time, and expiry.

Reset-credit detail arrays may be absent or shorter than `availableCount`; the count is authoritative. A missing summary means unavailable, not zero. Calcifer intentionally discards opaque reset-credit IDs and backend-provided title/description before constructing its public output.

Each read is attached to the local profile ID, canonical managed home, and exclusive lease—not to an email address. New profiles also have the private version-scoped identity binding described above; legacy unbound profiles can still be read but cannot participate in automatic selection until explicit verification. A profile with an active `run` or `resume` child reports busy/unknown; Calcifer does not start a second app-server against the same refreshable `auth.json`.

`account/usage/read` is a different token-activity report. It is not a quota or exhaustion signal and is not used for profile selection.

Relevant upstream sources:

- [account methods and examples](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server/README.md#L2038-L2123);
- [rate-limit and reset-credit types](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server-protocol/src/protocol/v2/account.rs#L289-L390);
- [window, spend-control, and reached-state types](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server-protocol/src/protocol/v2/account.rs#L520-L657).

### Why displayed zero is not an automatic switch signal

Codex rounds the upstream floating-point used percentage before exposing it as an integer. An upstream value such as `99.5` can therefore appear as `100`. Calcifer may display a derived `0% remaining`, but a future selector must not interpret that alone as exhaustion.

The safe future decision path is:

1. observe a structured turn failure classified as `usageLimitExceeded`;
2. refetch `account/rateLimits/read` under the same profile lease;
3. require a recognized explicit `rateLimitReachedType`;
4. verify that the next profile has a fresh usable snapshot;
5. stop and reap the old process before reopening any transcript;
6. never replay the failed prompt.

Context-window exhaustion, session budgets, unauthorized responses, 5xx errors, timeouts, disconnects, parser failures, and rounded 100% are not account failover signals. See the [structured Codex error enum](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server-protocol/src/protocol/v2/shared.rs#L64-L113).

Same-profile `calcifer resume` still delegates the final restore to the official
CLI inside the selected `CODEX_HOME`. Its pinned metadata adapter never
constructs a prompt or parses transcript message/tool payloads. Experimental
cross-profile `thread/fork.path` and remote-TUI resume remain disabled behind
their separate Phase 4.5 runtime/schema gate.

## What Orca currently does

Orca informed the product direction, but Calcifer does not assume every Orca behavior is a provider contract.

At the verified commit, Orca captures an exact Codex `session_id` and uses `codex resume <id>` for application/PTY cold restore. However, its account-switch “Restart Session” path starts a fresh `codex` command rather than resuming the old thread, and it does not replay the prompt. See Orca's [resume argv builder](https://github.com/stablyai/orca/blob/e0edc8ef76d341f7ab8083a006f785322bcaeb23/src/shared/agent-session-resume.ts#L147-L205) and [account-switch restart path](https://github.com/stablyai/orca/blob/e0edc8ef76d341f7ab8083a006f785322bcaeb23/src/renderer/src/components/terminal-pane/TerminalPane.tsx#L1704-L1739).

Orca queries inactive Codex accounts with a profile-specific home and the same App Server rate-limit method. Its internal data model includes reset timestamps and reset-credit detail, although the inactive-account row does not display every field. Orca does not currently provide Calcifer's proposed “confirmed exhaustion, automatically choose another profile, then reopen history” behavior.

## Claude direction

Claude support is not implemented in Calcifer. Current official Claude Code surfaces support same-profile resume by explicit session ID and expose rate-limit observations to a status-line command after an API response. They do not provide a standalone structured query that can refresh every inactive account on demand, nor a documented reset-credit entitlement count/expiry equivalent to Codex.

The intended design is therefore:

- bind `session_id` to one profile-specific `CLAUDE_CONFIG_DIR` and cwd;
- resume by explicit ID, not an ambiguous latest-session lookup;
- collect status-line or SDK rate-limit events with `observed_at` and freshness;
- treat missing or expired observations as unknown;
- keep cross-account transcript resume and prompt replay out of automatic failover;
- use only provider-supported authentication surfaces and avoid direct undocumented OAuth refresh.

Official references: [Claude Code sessions](https://code.claude.com/docs/en/sessions), [CLI reference](https://code.claude.com/docs/en/cli-reference), and [status-line rate-limit usage](https://code.claude.com/docs/en/statusline#rate-limit-usage).
