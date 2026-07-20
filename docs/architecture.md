# Architecture

> Status: evolving pre-alpha architecture. Unix Codex profile registration with private provider-identity binding, pinned launch, same-profile resume, structured on-demand status, a synthetic Codex 0.144.4 handoff compatibility gate, and an internal Linux/macOS no-gap target-reservation primitive are implemented. A default-unused pinned App Server/typed-monitor/official-TUI supervisor implementation is present. Deterministic recovery and official-package normal/recovery scenarios are green from the 2026-07-20 Issue #54 candidate source on Apple silicon; Ubuntu 24.04/macOS matrix acceptance is pending. Public supervised run/resume, the production cross-profile handoff transaction, active-session failover policy, and automatic failover remain future work.

Calcifer is designed as a local orchestrator around official coding-agent CLIs. It selects an isolated profile, constructs a provider-specific child environment, and launches the official executable directly without a shell.

## Trust boundaries

```text
User
  |
  v
Calcifer parser and selector
  |---- local registry and quota observations
  |---- OS credential store, where supported
  |---- profile-specific CODEX_HOME
  |
  v
Resolved official CLI binary
  |
  v
Provider API

Untrusted inputs:
- the current repository, hooks, and configuration
- profile names and child arguments
- PATH and executable resolution
- provider CLI output and exit status
- quota observations
- filesystem state after interruption or a crash
- public GitHub release metadata, redirects, manifests, and checksums
```

A repository-local file must never be able to select an account or failover pool. Account routing is user-level security policy because changing profile may change the organization that receives source code, prompts, and conversation history.

## Planned components

| Component | Responsibility | Must not do |
| --- | --- | --- |
| CLI parser | Parse explicit commands and the `--` provider-argument boundary | Accept implicit external subcommands or an arbitrary executable |
| Registry | Store non-secret opaque profile metadata | Store raw tokens in diagnostics or logs |
| Private identity store | Detect equivalent Codex account/workspace scopes without exposing provider identifiers | Claim that different scopes have independent quota |
| Conversation lineage registry | Bind one logical conversation to ordered profile-local thread generations | Treat a credential profile ID as the conversation ID |
| Provider adapter | Build an isolated environment and classify supported structured signals | Reimplement undocumented OAuth flows or scrape TUI text |
| Profile lease | Serialize profile mutation, usage probes, and child lifetime | Rely on PID files as the lock authority |
| Conversation lease | Serialize lineage transitions and rollout imports across profiles | Allow two generations to write one rollout |
| Selector | Choose one profile from an explicit pool | Cross trust domains or loop indefinitely |
| Process supervisor | Own the profile App Server, attach the official TUI, observe events, forward signals, and preserve exit semantics | Replay prompts or commands, or answer provider approval requests |
| Observation cache | Record bounded, timestamped usage state | Treat stale or unknown data as exhaustion |
| Update verifier | Select one immutable strict-channel release and verify local manifest/checksum bytes for the exact compile target | Read credentials/config, follow arbitrary redirects, substitute an ABI, or claim an un-downloaded archive is verified |

## Normative invariants

Future code that violates one of these invariants requires an architecture decision record and a security review.

1. **One process, one profile.** Profile identity is immutable for the entire child lifetime.
2. **No global credential mutation.** Managed profiles are never activated by overwriting global Codex or Claude state.
3. **No implicit trust crossing.** Automatic selection stays within one provider and an explicitly configured trust domain.
4. **No automatic replay.** A command or prompt is launched at most once by one Calcifer invocation.
5. **Unknown means stop.** Unknown, stale, or unparseable usage state never authorizes failover.
6. **Authentication is not exhaustion.** Login, policy, suspension, network, and provider failures fail loudly.
7. **State transitions are atomic and bounded.** Partial registration or selection must be recoverable.
8. **Newer credentials win.** Rotated credentials are never replaced with an older backup during rollback.
9. **Secrets are not output.** Tokens and credential payloads never enter logs, diagnostics, arguments, telemetry, or fixtures.
10. **Providers own authentication.** Login and refresh stay in official, supported provider flows.
11. **Provider executable only.** Credential-bearing environments are passed only to the selected adapter's validated executable, never to an arbitrary user-supplied command.
12. **Selection is visible.** Before launch, Calcifer reports the local profile alias, provider, trust domain, and reason code without exposing stable provider identifiers.
13. **Conversations have lineage.** Every provider thread is bound to its credential profile and canonical working directory, while one user-visible conversation may advance through multiple profile-local thread generations in one trust domain.
14. **Resume is not replay.** Restoring persisted conversation history never resubmits an interrupted prompt, command, or tool action.
15. **Repository configuration cannot route accounts.** Interactive launch accepts only version-reviewed repository settings and binds the final provider to the canonical working directory that was inspected.
16. **Provider identity stays private.** A bounded provider-owned scope is immediately reduced to an installation-local HMAC fingerprint; raw scopes, fingerprints, and identity-key IDs never enter public DTOs or diagnostics.
17. **Update evidence stays precise.** An update recommendation requires an immutable release and canonical v1 manifest/checksum agreement for the exact compile target. Published attestation evidence and locally verified bytes are reported separately; an un-downloaded archive is never called verified.
18. **Transferred leases are close-only and non-inheritable.** After a lease descriptor is shared, ownership is released only by closing the exact descriptor, never by explicitly unlocking it. A received descriptor must be marked and read back as close-on-exec before the guardian may acknowledge it or start a child.
19. **Terminal authority is gated and recoverable.** Lifecycle control,
    optional lease transfer, and terminal bytes use distinct close-on-exec
    channels. The guardian creates no runtime, worker, PTY, or child before the
    coordinator accepts an exact semantic pre-raw snapshot fingerprint. Outer
    input has no worker before typed readiness, raw-mode readback, and
    `OPEN_GATE` ACK, and no final child disposition is trusted before exact
    waits and terminal restoration.
20. **Provider release requires a move-only proof.** A successful internal
    supervisor completion consumes either proof that no App Server was spawned
    or the pinned one-`SIGTERM`, direct-child code-zero graceful-drain proof.
    Missing or ambiguous evidence retains authority; ordinary cleanup status,
    PID disappearance, and a group signal are not release authorization.

## Codex profile model

The planned Codex adapter gives each profile its own managed home and launches Codex with that home directly:

```text
managed root/
  conversations.json  <- private same-profile thread bindings and workspace heads
  conversations.lock
  profiles/
    codex/
      <opaque-profile-id>/
        home/       <- CODEX_HOME, auth, sessions, and Codex state for this profile
        .calcifer-profile <- ownership marker
        profile.lock      <- coordinator side of the lifetime lease
        provider.lock     <- provider-guardian side of the lifetime lease
```

The display name is not used as a filesystem path. A generated opaque ID is
mapped from a validated display name. That opaque ID is the durable ownership
key; the alias is mutable local metadata. `auth rename` acquires the published
profile lease and then the registry lock, revalidates the ID-to-alias mapping,
and atomically replaces only the registry document. It never reads or rewrites
credentials, provider-identity markers, session state, or conversation state,
and it never renames the managed directory. Run, resume, status, identity, and
conversation references continue to resolve to the immutable profile ID. A
public run/resume reference is converted to that ID before the internal
coordinator starts; the coordinator rechecks the expected alias while holding
its profile lease, and the provider guardian receives only the immutable ID.
Consequently, a rename that wins the race makes a stale launch fail before its
notice or provider spawn, while a coordinator that wins keeps rename busy.

Calcifer writes a minimal
managed `config.toml` and revalidates it with a Codex-version-scoped semantic
policy. Supported project trust and reviewed user settings may change, while
account/provider routing, state locations, dynamic extensions, and project-root
discovery remain Calcifer-owned. Top-level role definitions and any
auto-discovered `CODEX_HOME/agents` node are rejected because role files are
indirect complete configuration layers; managed role configuration requires a
future provenance-aware mediation design. MCP OAuth callback URL and port are
also rejected because they alter the reviewed connector authorization route.
Existing pre-alpha profiles with
only `cli_auth_credentials_store="file"` remain accepted during upgrade, while
new profiles persist both file-store settings. Calcifer forces both credential
stores to `file` on every provider invocation and rejects child arguments that
can change account/provider routing. Codex then updates its own profile-local
credentials. No managed-to-runtime credential copy-back step is needed. See
the [managed config specification](../specs/managed-codex-config.md).

Different profiles may run concurrently. The same profile has at most one official CLI child or usage probe because either operation may refresh profile-local credentials.

The public registry proves only local profile provenance. Separately, each new supported Codex profile has a private `.calcifer-identity` marker bound to an installation-local `identity.key`. Calcifer derives a versioned HMAC-SHA-256 fingerprint over length-delimited provider, supported auth kind, adapter version, and effective `tokens.account_id`; the raw account/workspace scope remains only in provider-owned `auth.json`. Registration rejects an equal verified fingerprint under another alias. Distinct fingerprints establish only different effective routing scopes, not independent quota.

Profiles created before this binding remain valid for explicit `run`, `resume`, and status. `calcifer auth verify codex@<alias>` acquires the profile lease, performs the exact `0.144.4` initialize/home/version gate without an account request, parses the same bounded auth projection, and serializes its uniqueness check and marker publication under the registry lock. It never opens a login flow or rewrites credentials. A future selector must use the lease-retaining revalidation API: missing markers, key loss/replacement, unsupported adapters/auth modes, malformed auth, and fingerprint drift stop the whole selection attempt. See [ADR 0002](adr/0002-private-provider-identity-binding.md).

## Implemented same-profile resume

Codex owns its rollout files and state database inside the profile-specific `CODEX_HOME`. Calcifer currently exposes:

```text
calcifer resume codex@<alias> <thread-id>
calcifer resume codex@<alias>              # delegates to codex resume --last
calcifer resume                            # validates and resumes the exact workspace head
calcifer run --untracked codex@<alias>     # explicit no-capture/manual-recovery mode
calcifer resume --untracked codex@<alias>  # official --last without capture
```

The exact thread ID is the reliable resume key. `--last` remains an explicitly requested convenience because Codex filters it by the current working directory and multiple sessions may be eligible. Automatic restore never falls back to it.

For the pinned Codex 0.144.4 adapter, the provider guardian captures bounded active and archived `thread/list` inventories before and after an interactive `run` or explicit `--last` resume. Exactly one new or uniquely changed root CLI thread is confirmed with direct `thread/read(includeTurns=false)` and atomically bound to immutable `{profile_id, canonical_cwd, thread_id}` metadata. A changed thread is detected from both the App Server's second-resolution timestamps and a path-free rollout fingerprint (`device`, `inode`, length, and nanosecond mtime/ctime); this covers a same-second resume or same-inode rename that leaves `updatedAt` unchanged. Zero candidates preserve the old head only when every baseline ID is still present. A deleted baseline, multiple candidates, pagination or upstream filesystem-scan cap exhaustion, a rollout-store mutation during observation, overlapping launches, or inconsistent metadata requires explicit selection. Explicit exact resume skips the inventory and adopts only the directly validated thread.

Capture failure never degrades implicitly into an ordinary provider launch. The explicit `--untracked` mode is available only for `run` and profile-specific `resume --last`. Under the same credential, repository-policy, coordinator, guardian, and profile-lease boundaries, it refuses any pending launch in the canonical workspace and atomically changes the workspace head to `needs_selection` before provider authorization. The same transaction adds a metadata-only pending ownership record with no Codex version or inventory; registry I/O or uncertain directory durability therefore stops before spawn. Ownership remains until the official child exits or spawn definitively fails, so another profile cannot use exact adoption to clear the marker while the uncaptured provider is active. Exact lifecycle refresh is conditional on its pre-spawn head still being authoritative, which also prevents an older exact process from restoring `ready` after a later untracked launch finishes. The official provider runs exactly once without pre/post inventory or lifecycle capture; provider exit failure or spawn failure cannot restore the old ready head. A crash-stale owner is cleared only under its source-profile lease and still leaves `needs_selection`. Bare resume therefore fails until explicit exact recovery validates a thread and replaces the marker. `--untracked` with bare resume or an exact thread ID is rejected at CLI parsing.

Codex 0.144.4's rollout scanner has an internal 10,000-file cap, but the v2 `thread/list` response does not expose its `reached_scan_cap` flag. Calcifer therefore snapshots each of `sessions` and `archived_sessions` before and after the App Server call, requires each root to contain strictly fewer than 10,000 regular files, and compares canonical relative path, type, owner-safe identity, length, and nanosecond mtime. A symlink, special or writable node, unreadable traversal, cap hit, or pre/post mismatch makes the inventory incomplete. Missing and empty roots normalize identically. `useStateDbOnly` is not used because a rollout can legitimately exist before the state database has indexed or repaired it.

The separate schema-v1 `conversations.json` contains opaque local IDs, versions, timestamps, path-free rollout change fingerprints, lifecycle state, pending launch baselines or metadata-only untracked ownership, and workspace-head references. It never contains profile aliases, provider account IDs, rollout paths, previews, prompts, responses, tool arguments, terminal output, or credentials. A whole-document update uses a private same-directory temporary file, file fsync, atomic rename, and parent-directory fsync under `conversations.lock`. A post-rename directory-sync failure is read back and reported as `conversation_commit_uncertain`; it never authorizes relaunching the provider.

Bare `calcifer resume` reads and releases the workspace-head lock, acquires the immutable source profile by UUID, and revalidates the same binding under the profile lease before executing `codex resume <exact-uuid>`. If a guardian crash left a pending launch, the command first reacquires both profile locks and reconciles its before/after inventory; one candidate becomes `interrupted` or `unknown_crash`, while ambiguity stops. Bare and explicit exact resume look up an already-bound immutable `{profile_id, thread_id, canonical_cwd}` directly even when pending or needs-selection state hides the mutable workspace head. A clean pre-launch rollout observation cannot erase its persisted interrupted or unknown-crash marker; only lifecycle readback after the provider completes may clear that uncertainty. Retryable authentication, spawn, timeout, transport, or provider availability failures retain the pending launch without destroying the previous ready head; malformed protocol, unsupported schema/version, missing/archive, immutable profile/cwd ownership conflicts, or deleted-baseline results atomically clear the pending launch and require explicit selection. Restored state is the persisted conversation transcript; a dead process, stream, in-flight tool call, prompt, command, approval, or tool action is not restarted or replayed.

Stable `thread/resume` lookup is scoped to the current `CODEX_HOME`. Codex 0.144.4 also exposes experimental external rollout paths for resume and fork, but Calcifer does not enable them for user state yet. A private compatibility gate exercises fork-by-path and official remote-TUI resume only against isolated synthetic homes and rollouts; it receives no profile, credential, conversation registry, or user rollout. The accepted production design uses a target-profile App Server to fork validated source history into a new target-profile rollout. It requires same-trust-domain policy, source-profile provenance, canonical containment under a Calcifer-managed sessions root, one writer per lineage generation, version gating, and no prompt replay; see [ADR 0001](adr/0001-cross-profile-conversation-handoff.md). The staged same-profile supervisor and guardian-loss policy are defined by [ADR 0003](adr/0003-supervised-codex-session.md).

That compatibility gate starts each command from an empty environment and adds
only fixed process basics plus synthetic `CODEX_HOME`, home, XDG, and temporary
paths. It binds the original canonical executable to safe mode/identity
metadata and SHA-256, creates a byte-identical mode-`0500` staged executable
inside the retained private scratch tree, and runs every probe phase from that
copy. This prevents a legitimate installer path replacement from mixing builds;
both staged and original binaries are fully rehashed before the original-bound
capability is minted, so an update during the probe fails closed. Default and
experimental protocol output must match the reviewed fork, resume, and
thread-response projections; only the separate `JSONRPCError` and
`JSONRPCErrorError` documents are required to equal their complete pinned
schemas. Private directory descriptors are retained while config, catalog,
schema, and source/target rollout files are reached by a component-wise
descriptor-relative `O_NOFOLLOW` walk. The synthetic fork's source and target
fingerprints remain live through the remote-TUI proof.

Remote readiness requires the official TUI to complete three ordered exchanges:
successful target `thread/read`, successful target `thread/resume` with the
fork's effective model/provider/cwd/approval/reviewer/sandbox settings, and an
exact source-parent `thread/read` with `includeTurns` absent. The source parent
does not exist in the target home, so the final expected error response proves
the TUI parsed and followed the fork lineage after resume. Readiness is not
emitted until that error has been forwarded back to the TUI.

The local App Server and readiness sockets are protected by their retained
owner-only mode-`0700` scratch directory. The readiness relay additionally sets
its socket to mode `0600`, reads back UID/type/mode, and records the pathname
device/inode. Cleanup unlinks only that matching socket; collisions and
replacements fail closed. The provider-created App Server socket is validated
separately. Path inspection and unlink are not atomic against a hostile
same-user process, which remains outside the local threat guarantee.
The proxy's atomic `RUNNING`/`DISCONNECTED`/`STOPPING` lifecycle, active
poll-hangup plus non-consuming `PEEK` health checks, and checked shutdown prevent
an unexpected EOF from being relabelled as normal teardown. Every probe child
is a separate process-group leader. Non-reaping `WNOWAIT` observation preserves
an exited leader until Calcifer has killed the group and can wait for that
direct child, so descendants cannot indefinitely hold a pipe or PTY drain open.
Explicit cleanup propagates group-kill, direct-wait, reader-join, pump, and
cleanup errors. macOS zombie-only group `EPERM` is accepted only after the
leader was observed exited; live-tree `EPERM` remains fatal. These are synthetic
compatibility proofs only: production leases, transition journaling and
recovery, pool policy, authoritative exhaustion selection, and user-state
handoff remain unimplemented.

## Default-unused Unix supervisor implementation

The internal supervisor first composed fake-child process authority with a real
PTY and outer terminal on Linux and macOS. Issue #54 now also connects that
kernel to the pinned Codex `0.144.4` App Server, a separately typed monitor, the
readiness relay, and the official remote TUI. It remains an internal,
default-unused integration: no public command selects it, and it changes no
registry or conversation schema.

Independently budgeted checksum-pinned normal-session and retained-recovery
package scenarios are configured to exercise the production coordinator,
guardian, provider-session, PTY, input-gate, resize, and stop/resume job-control
implementations under a test-owned outer-terminal harness. The normal scenario
passed twice consecutively and retained recovery once on the exact local
Apple-silicon tree; Ubuntu 24.04/macOS CI readback remains pending. Selected-
profile admission uses the
production A-to-B lease path across the coordinator and guardian helpers, and
the guardian helper enters the shared production guardian-bootstrap core. Its
only bootstrap variations are a package-specific post-admission loopback rewrite
and fixed observation root; production supplies neither. The package parent is
designed to create the completion endpoint and pass it across real package-
parent-to-coordinator and coordinator-to-guardian `exec` boundaries. The
guardian may publish only after consuming provider-release proof; the parent is
configured to check the exact frame and EOF. The test-only package role
dispatcher and outer-terminal harness are not production entry routing: they do
not execute the production `CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE`
dispatcher/parser or persistent shell-anchor role, and these scenarios make no
parser coverage claim.

The coordinator/guardian exec boundary keeps three channel classes physically
separate:

```text
lifecycle socketpair       -> bounded typed state, failure, signal, and cleanup frames
optional transfer socket   -> one lease descriptor plus one ACK
terminal socketpair        -> fixed-buffer full-duplex bytes only
```

The still-single-threaded guardian exec entry moves lifecycle fd 0, terminal fd
1, and recovery fd 2 into separate owned close-on-exec duplicates. For each
class it first requires exactly the inherited standard fd plus the new
duplicate, atomically replaces the standard fd with access-appropriate
`/dev/null`, and reads back `/dev/null` type/access/close-on-exec, changed
identity, and exactly one surviving reference to the original identity. The
owned duplicate is therefore the sole authority; dropping recovery must reduce
its original identity count from one to zero. Marking the inherited fd
close-on-exec without replacing it is not a recovery-disarm boundary.

The guardian then advertises a fixed, domain-separated SHA-256 fingerprint of
its full semantic pre-raw target state in `TERMINAL_ARMED`. The fingerprint
covers the platform and format version, terminal identity, PENDIN-masked
termios fields, initial character and pixel size, and foreground process group.
The coordinator compares it in constant time with its immutable snapshot and
sends `TERMINAL_ARM_ACCEPTED` only on an exact match; descriptor identity or
foreground process group alone is not enough. The guardian creates no private
runtime, fixture worker, PTY, or child before that ACK. The fingerprint remains
wire-only and redacted in debug output and failures.

The synthetic fixture TUI and the pinned official TUI each receive readiness
through the same one-shot typed boundary. All provider-style children lack the
lease, lifecycle, transfer, completion, terminal, recovery, unrelated
PTY-master, and outer-tty descriptors after exec.

The terminal gate is ordered and linear:

```text
TERMINAL_ARMED { redacted semantic fingerprint }
  -> constant-time coordinator match
  -> TERMINAL_ARM_ACCEPTED; runtime/worker/child creation now authorized
  -> selected TUI on controlling PTY; output-only pump
  -> exact READY capability; input workers still absent
  -> outer tty identity and foreground revalidation
  -> discard queued input; enter raw mode and read it back
  -> OPEN_GATE / INPUT_GATE_OPENED
  -> create outer-input worker
```

Every pump moves only one fixed 8 KiB fragment at a time and relies on kernel
backpressure. There is no terminal transcript, unbounded payload queue, or
payload-bearing diagnostic. Pre-ready and suspended input is discarded instead
of replayed.

Only the live guardian direct-child handle may signal the TUI process group.
INT/QUIT may be handled without ending the session; HUP/TERM are forwarded once
before bounded shutdown; WINCH retains only the latest size. TSTP first
quiesces ingress and restores the user's tty before the coordinator stops.
CONT requires foreground and identity revalidation, a fresh size, raw-mode
readback, TUI continuation, and a new gate ACK.

Normal completion stops pumps, exactly waits children, restores the outer tty,
disarms guardian recovery, emits one terminal `CHILDREN_REAPED` frame, exactly
waits the guardian, and only then reproduces the TUI's zero, nonzero, or signal
disposition. Infrastructure, PTY EOF/EIO, signal, identity, restoration, and
cleanup failures cannot be rewritten as a successful TUI exit.

The production-shaped entry adds a persistent terminal anchor and a physically
separate completion socket. A and B, lifecycle, terminal, completion, recovery,
and optional transfer descriptors are close-on-exec and checked as absent from
the real provider process groups. The anchor accepts exactly one fixed
eight-byte terminal record and then requires EOF. `CFCMP\x01\r\n` carries only
provider-release proof; by itself it is not owner, session, anchor, or shell
success and authorizes no release. A consuming owner must independently satisfy
its exact-child/coordinator waits and exact frame-plus-EOF checks. Missing,
invalid, or trailing bytes restore the tty but park the anchor instead of
releasing an uncertain generation. The separate `CFRET\x01\r\n` record is
terminal retained evidence and carries no reason, identity, secret, or provider
payload. Exact retained record plus EOF parks the direct child, immutable tty
snapshot, and completion
receiver without returning success or a nonzero shell status.

The same anonymous socket has one bounded reverse operation for the internal
package owner: one exact 25-byte request followed by write-half shutdown. The
frame contains `CFRCR\x01`, the fixed retained-generation reason, the transit
endpoint's big-endian device/inode identity, and `\r\n`. The anchor captures
the identity directly from the socketpair, and the guardian compares it with
its own inherited endpoint after exec; it is not supplied through another
environment value or raw descriptor number. No pathname, marker, reusable
token, or numeric process identity becomes authority. A valid request or exact
owner EOF enters the guardian's existing typed cleanup state machine. It may
retry one eligible retained deadline/cleanup owner, but cannot repeat an App
signal, skip restore, mint provider release, or publish success. A malformed or
cross-wired frame alone authorizes nothing; malformed data followed by EOF is
still only owner-loss cleanup. When recovery races one already-written
lifecycle command, the guardian can drain at most one command from the prior
state's closed set after quiescence, without creating an ACK, command proof, or
normal termination cause. Replay and cross-state commands remain protocol
failures.

This recovery authority is live and generation-local. It exists only on the
anonymous endpoint retained by that running owner/guardian generation, is not
persisted, and does not survive loss of both terminal authorities or a machine
restart. It is separate from cold conversation resume, which reopens persisted
history but cannot restore a dead process or in-flight operation.

Only a non-copyable provider-release capability can authorize that record. It
has two closed construction paths: the App Server provably never started, or
the exact pinned App direct child was sent its first and only shutdown
`SIGTERM`, was exactly waited, and exited with code zero. Early exit, nonzero or
signalled exit, send failure, deadline, a second signal, or forced kill cannot
mint it. Structured failure owners park with B, the child/runtime authority,
terminal recovery, and completion sender retained. Accidental Drop of an
ambiguous App authority aborts without sending another signal.

When a retained owner is nonrecoverable, recovery transport fails, or the sole
retry returns another retained owner, the guardian consumes the completion
endpoint and attempts the retained record and write-half shutdown exactly once.
It then deliberately keeps the concrete typed provider/terminal owner reachable
inside the parked guardian's non-returning loop even after `EPIPE` or shutdown
ambiguity. This is a
terminal, non-retryable state after the sole recovery retry is consumed. It has
no `ProviderReleaseProof` input and cannot publish `CFCMP`.

This direct-child drain is the reviewed `0.144.4` cooperative shutdown
contract, not a general process-tree absence theorem. In particular, it does
not establish that an arbitrary non-child descendant which called `setsid(2)`
has exited. Issue #55's zero-residue gate is limited to Calcifer-owned direct
children and recorded known process groups plus identity-checked runtime, FD,
and socket evidence. The checksum-pinned package smoke is intended
to verify the narrower boundary Calcifer depends on: the official shell-command
path can create such a detached probe without leaking eight live supervisor
authority/control descriptors or denied supervisor/authentication environment
into it. Accounting and containment for descendants that escape with
`setsid(2)` is tracked separately by issue #56.

Ubuntu 24.04 and macOS package CI jobs are configured to verify the official archive's
architecture-specific SHA-256 and single executable before running three
independently budgeted matrix scenarios behind one aggregate gate. `contracts`
runs the complete #28 handoff probe plus the #54 live-turn drain, `setsid(2)`
descriptor/environment-isolation, and typed-monitor success/redacted-error
probes. `official-tui-normal` is designed to exercise the production
coordinator/guardian session, PTY, fresh input gates, resize, and group-wide
stop/continue path. `official-tui-recovery` independently targets #55's retained-
cleanup recovery and four-proof deletion gate. Both official scenarios are
designed to carry the completion endpoint across real package-parent-to-
coordinator and coordinator-to-guardian `exec` boundaries; the parent is
configured to check the provider-release-gated exact frame and EOF. The guardian
helper shares the production guardian-bootstrap core, but the test-only role
dispatcher does not execute the production
`CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE` dispatcher/parser or persistent shell-
anchor role. These tests use synthetic non-production state or credential-free
loopback providers and do not authorize public supervised use by themselves.
The normal scenario passed twice consecutively and retained recovery passed once
from the 2026-07-20 Issue #54 candidate source on Apple silicon; the Ubuntu 24.04/macOS matrix remains
pending. Both OS lanes execute the same prebuilt, exactly discovered libtest.
The Linux lane has no native fallback: it runs inside a fresh namespace after
proving only loopback is present, then drops groups and every capability, sets
`NoNewPrivs`, clears ambient environment authority, rejects inherited sockets,
and revalidates those invariants before execution. The macOS lane is native
functional evidence only.

A separate non-ignored, credential-free deterministic fixture is configured for
all seven closed recovery checkpoints: startup queued, ready, active, suspended,
retained quiescing, retained restore pending, and retained cleanup pending. It is
designed to use the exact production coordinator/guardian/session graph while a
sealed `cfg(test)` compatibility seam and strict owner-private wrapper replace only
official compatibility/provider behavior. Production builds parse neither the
fixture selector nor compatibility override. A checkpoint is observation only:
the fixture must first prove that it neither completes nor terminates the
coordinator, then send the sole generation-bound `CFRCR` request. The first four
checkpoints expect failed-clean with zero inference calls; the three retained
checkpoints expect completed-clean with exactly one validated loopback inference
call. Its fourth namespace proof also requires the identity-checked private
compatibility stage parent to be empty. This is deterministic recovery-phase
evidence, not Codex-version compatibility evidence. All seven cases passed three
consecutive local runs from that candidate source; cross-platform CI readback remains
pending.

The package generation records one internal monotonic fence before spawn. Its
cleanup path polls for normal completion, sends the one recovery request, wakes
the exact coordinator only after a fresh stopped-state readback, waits the
healthy lifecycle budget, and uses retained-`Child` TERM/KILL fallback only
after that grace. Exact retained or otherwise unproved evidence interrupts this
sequence immediately in the `cfg(test)` package harness: it emits a fixed,
redacted failure subtype and terminates libtest with a fixed nonzero
`_exit`-equivalent status while the exact coordinator `Child`, completion
receiver, PTY, backend, and scratch Rust owners are still live. It runs no
destructors, unproved TERM/KILL fallback, completion proof, deletion, or
cleanup-success publication and produces no signal-driven core dump. This
test-only exit closes the libtest descriptor table and makes hosted CI fail
promptly; it is not production retained-owner behavior and proves nothing about
descendants in another session. A bounded regression parent observes the parked
helper's fixed readiness handshake before killing and reaping only that exact
child. Production guardian/anchor retained owners continue to park concrete
typed authority. A recovery-send error records only a consumed attempt with an
unknown boundary; it does not claim write-half closure. Deletion still requires
four independent proofs: exact coordinator-child wait; the exact
provider-release-only
`CFCMP\x01\r\n` record followed by EOF, which is not session or shell success;
absence of every reported known process group; and an identity-checked empty
runtime with zero retained FD and socket references. This is the full #55
zero-residue scope; escaped sessions remain #56 work. CI is configured to
isolate pinned contracts
and the two official-TUI scenarios into dedicated Linux/macOS jobs behind one
aggregate gate. The later command watchdog bounds the cargo/libtest process
group, not provider descendants that
call `setsid(2)`; catastrophic timeout delegates those escaped sessions to the
ephemeral runner teardown and makes no Calcifer process-tree cleanup claim.

If the coordinator dies while raw mode may be active, the guardian restores
through its recovery tty before releasing B. If the guardian dies, the
coordinator restores before retained-A parking and never promotes a reported
PID/PGID into stale authority. If both are killed with uncatchable `SIGKILL`,
in-process restoration is impossible and the shell or terminal emulator is the
external recovery boundary. The complete state machine and release gates are
normative in [ADR 0003](adr/0003-supervised-codex-session.md).

## Implemented Codex usage observation

For every selected idle profile, Calcifer holds the exclusive profile lease and
starts the resolved, permission-checked executable named `codex` with the
verified profile home as `CODEX_HOME` and a private neutral runtime directory
as its cwd:

```text
CODEX_HOME=<managed-home> codex \
  -c 'cli_auth_credentials_store="file"' \
  -c 'mcp_oauth_credentials_store="file"' \
  app-server --stdio
```

It completes the stable JSONL initialization handshake with `experimentalApi: false`, requires the explicitly tested Codex `0.144.4` client-scoped user-agent, and canonicalizes the returned `codexHome` against the selected managed home. Only then does it call `account/rateLimits/read`. An untested version, changed initialize schema, or different home closes the probe before the usage request. Calcifer closes stdin, waits briefly for a clean provider exit, and only then kills/reaps a stuck probe. The bounded no-turn app-server inherits only the provider side of the lease; if the status parent is killed, a second writer remains blocked until that app-server exits on stdio EOF. On Unix the parent descriptor remains close-on-exec at all times: an audited spawn boundary atomically creates a `F_DUPFD_CLOEXEC` child duplicate and clears that duplicate only after fork. The command is consumed after one spawn, the parent reads back both descriptor flags, and any failed invariant kills and reaps the child while preserving parent A+B ownership. An unrelated concurrent exec therefore cannot retain the lease after its exec boundary. This exception is restricted to bounded metadata probes that do not start turns, tools, or descendants; interactive App Server, TUI, and guardian launches inherit no lease descriptor. Input is bounded to a 1 MiB JSONL line. Normalized output includes all returned metered buckets, primary and secondary windows, reset timestamps, workspace credits, individual spend controls, and safe reset-credit count/status/expiry fields. Opaque reset-credit IDs and backend display copy are discarded before the public model is constructed.

The app-server command is still marked experimental at the CLI level even though these request types are on its stable protocol subset. Status output records the detected Codex version when safely parseable, the Calcifer adapter version, protocol, tested version set, and `compatible | incompatible | unverified` state. Unknown methods, malformed schemas, auth errors, timeouts, and spawn failures are explicit `unknown` observations. Calcifer does not fall back to `/status` text scraping or undocumented backend endpoints. Binary provenance is not yet cryptographically verified and remains a user-level `PATH` trust assumption.

`usedPercent` is rounded by Codex. Calcifer derives `remainingPercent = clamp(100 - usedPercent)` for display only. A recognized `rateLimitReachedType` is required to classify a snapshot as exhausted; rounded 100%, null fields, and errors remain unknown for automatic-selection purposes.

The one-shot probe cannot inspect a profile while its `run` or `resume` child owns the exclusive lease. Such a profile reports `profile_busy` / `unknown`. Multiple profiles are currently probed sequentially with a per-profile timeout. Continuous active-session observations, bounded parallel refresh, TTL/backoff, and cached last-known state belong in a future profile-owned app-server/supervisor so credential refresh retains exactly one owner.

The verified upstream versions, exact fields, and source links are recorded in [Provider compatibility notes](provider-compatibility.md).

## Planned supervised failover and conversation handoff

The staged process topology, separate lifecycle/lease-transfer channels,
readiness contract, macOS guardian-loss constraint, and public release gates
are specified in [ADR 0003](adr/0003-supervised-codex-session.md).
Its fake-child process and readiness-gated PTY foundations are implemented and
the pinned same-profile App Server/monitor/TUI integration is implemented and
default-unused. The following pool, journal, handoff, and public-UX transaction
remains planned.

```text
resolve pinned profile or explicit pool
  -> reject cross-provider or cross-trust-domain candidates
  -> launch a profile-owned App Server and attach the official TUI locally
  -> observe structured turn and rate-limit events
     -> ordinary completion/error: keep the current profile or stop
     -> confirmed exhaustion: revalidate under the current lease
  -> acquire handoff/conversation leases, retain the source lease, reserve a fresh target
  -> stop and reap the source TUI and App Server while retaining source ownership
  -> validate the source rollout and fsync a prepared handoff
  -> start the target profile App Server
  -> version-gated thread/fork(path=source rollout, effective settings)
  -> verify new lineage ID, target containment, and unchanged source
  -> atomically commit the new lineage generation
  -> attach the official TUI to the target thread before accepting input
  -> release source/transition leases; retain the target lifetime lease
  -> continue monitoring; never replay the failed turn

A pool is traversed at most once per invocation.
```

The implemented target-reservation primitive gives the future supervisor an
ephemeral, no-gap ownership transition on Linux and macOS:

```text
verified target reserved: parent owns target A + B
  -> B descriptor sent once: parent still owns A + B;
     guardian provisionally holds a descriptor for the same locked open-file description
  -> guardian validates the exact visible lock, proves that descriptor owns its lock,
     sets and reads back close-on-exec, then sends an ACK on the same control socket
  -> sender strictly parses that ACK and closes its B descriptor without LOCK_UN
  -> split ownership: parent owns target A / guardian owns target B
```

Sending consumes the reservation, and the awaiting-ACK state has no resend or
commit-without-ACK operation. A send failure returns the complete A+B
reservation. An invalid descriptor or ACK cannot advance either side. These
states are internal and ephemeral; they add no registry schema, journal event,
provider protocol, or public CLI operation.

The complete supervisor must respect one global acquisition order:

```text
already-held source lifetime lease
  -> handoff coordinator
  -> conversation transition
  -> target coordinator lease A
  -> target provider lease B
```

The primitive in this slice acquires only the target A+B pair. Issue #33 is
responsible for placing it after the handoff and conversation-transition locks
and for retaining every required owner across the non-idempotent handoff.

The current `run` command does not restart or re-submit a command after the child begins execution. The planned supervisor treats credential profiles and conversation lineage as separate aggregates. It continues the same user-visible conversation after failover by creating a target-profile Codex thread from the validated source rollout, but it must not resubmit the failed turn. The wrapped agent may already have produced external side effects before reporting quota exhaustion. The supervisor connection remains event-only and never races the official TUI to answer approvals or other server-initiated requests; no new turn is admitted without an attached TUI. The full decision and recovery model is in [ADR 0001](adr/0001-cross-profile-conversation-handoff.md).

## Filesystem and credential mutations

On Unix, the implemented managed root uses directory mode `0700`; Calcifer-owned files and locks use `0600`. Discovery canonicalizes the deepest existing prefix of the configured data root and appends only missing normal components. Calcifer stores that physical path and injects it as `CALCIFER_HOME` into coordinator and guardian self-execs, so one launch tree cannot rediscover a different mutable alias. Interactive removal likewise retains one discovered registry across preview, confirmation, and mutation. Creation and later verification require the operational parent to remain canonical, reject every symlink ancestor, and require every real directory ancestor to be root/current-user-owned and non-replaceable by ordinary mode checks (or sticky). On macOS, one acceptance decision reads type, owner, mode, file flags, extended ACL, and device/inode from the same no-follow descriptor and compares that identity with the visible pathname. Creation additionally rejects parent ALLOW/inheritable ACL entries, deletion-blocking DENY entries, ACL-level or unknown policy bits, and append, immutable, inherited-restrictive, or unknown parent flags. A new private inode has inherited ACL state cleared and read back through the same open descriptor before secret bytes are written. The standard non-inheritable `everyone deny delete` home ACL and parent-only `SF_NOUNLINK` temp ancestry remain compatible; `deny delete_child` does not. Pre-existing extended ACLs and unsupported flags fail closed instead of being normalized. This descriptor binding prevents one decision from mixing different vnodes, but it cannot permanently pin the pathname against another OS principal that already has ACL-granted namespace or security-metadata authority; such an active race is outside the guarantee because the official CLI accepts `CODEX_HOME` only as a pathname. On Windows, registration currently fails closed because equivalent current-user-only ACL creation has not been verified. The current slice rejects invalid aliases, non-canonical opaque IDs, symlinked or non-regular managed files, permissive Unix modes, and ownership-marker mismatches. Destructive profile removal additionally enforces owner-UID, single-link, inode/device, and hardened directory-relative traversal checks; migrating every remaining storage path to the same boundary remains a release gate.

Calcifer-owned metadata updates follow a same-filesystem atomic-write sequence:

1. Create a random temporary file in the managed directory with exclusive creation and Unix mode `0600` or a verified Windows current-user-only ACL.
2. Write all content and `fsync` the file.
3. Atomically rename it to the destination.
4. `fsync` the parent directory.

Registration happens in a staging directory and becomes visible only after the official login exits successfully; private `auth.json`, managed config, and ownership metadata pass revalidation; the installed Codex adapter passes its exact initialize/home/version gate; and a unique private identity marker has been written and synced. Credentials and binding are then published with one profile-directory rename before registry publication. The registry rename is the public visibility point: if the following directory sync fails, Calcifer preserves both the visible entry and credentials, reports `registry_commit_uncertain`, and tells the user to read back `auth list` rather than retry blindly. An identity key or marker rename followed by uncertain parent sync is read back; the same registration retries only that idempotent directory sync and adopts the complete state without invoking login again. If durability remains uncertain, Calcifer reports `identity_commit_uncertain`, keeps the profile unpublished, preserves the complete staging credentials for explicit recovery, and blocks every later registration before provider login while any orphan staging directory remains. Re-authentication, re-key, and orphan-staging cleanup flows are not implemented yet. A failed normal login performs checked cleanup; a hard crash can leave a private orphan staging directory for later recovery tooling and likewise blocks a second login.

For a published-profile alias change, failures before the atomic-rename
visibility point leave the old complete registry visible. Failure while syncing
the parent directory occurs after the visibility point and therefore returns
`registry_commit_uncertain`; a read-back sees one complete old-or-new document,
never a partial registry. Published-profile lifecycle operations use the lock
order profile coordinator, profile provider, then registry. This makes an
active run/resume/status probe and a rename choose exactly one winner and keeps
identity verification and future remove/reauth flows from deadlocking.

Cross-profile handoff adds higher-level locks but does not change that local
order: retain the source lifetime lease, acquire the handoff coordinator, then
the conversation transition, and finally reserve target coordinator A followed
by target provider B. A caller must never reserve a target before either
higher-level lock and then wait for them.

Confirmed profile removal uses the same published-profile lock order:
coordinator lease, provider lease, removal lock, then registry lock. Stable
`profiles.json` remains the exact schema-v1 shape published by alpha.4; it does
not gain a revision field. A removal uses two bounded proof objects instead:

- a self-contained transient schema-v2 registry barrier containing the
  prepared removal proof and expected stable v1 registry; and
- a matching private schema-v1 sidecar used after the stable registry becomes
  visible again.

The proof records only bounded local profile metadata, old/new canonical
registry digests, filesystem object identities, an entry count, and a SHA-256
digest of the relative tree manifest. It contains no paths, filenames,
credentials, raw provider identity, rollout metadata, conversation content, or
mount token. The transaction is:

1. Acquire and durably sync both lifetime lock files, then revalidate the exact
   registry entry, data/profiles/provider roots, ownership marker, owner UID,
   private root modes, non-group/other-writable traversed-directory and
   regular-file modes, types, device, mount boundary, and single-link regular
   files. Every macOS removal-tree entry, including non-followed symlinks,
   sockets, and FIFOs, must have no extended ACL entries; roots, directories,
   and regular files must also have no deletion-blocking
   immutable/append/no-unlink flags.
   Provider-created readable or executable descendants such as `0755`
   directories and `0644` files remain valid because every ancestor through
   the profile root is owner-only `0700`. Traversed directories must retain
   owner `rwx`; provider-created symlinks, sockets, FIFOs, and other
   non-directory leaves are manifest entries but are never followed or opened.
   Ownership-marker and lifetime-lock names remain control-plane state and must
   be private single-link regular files. Every managed lock is opened no-follow,
   matched to its visible inode, and checked for private mode, owner, and one
   link before flock or fsync.
2. Atomically replace stable schema-v1 `profiles.json` with the self-contained
   transient schema-v2 barrier and fsync its parent. This is the first durable
   transaction state, before any profile path moves.
3. Atomically write and fsync a sidecar exactly matching the embedded proof.
   Every later read opens it no-follow and matches the opened descriptor to the
   visible private, single-link inode before parsing bounded bytes.
4. Rename the UUID profile directory to `.removing-<profile-id>` under the same
   provider root, revalidate the complete manifest, then fsync that root.
5. Atomically replace the barrier with the normal schema-v1 registry without
   that immutable ID. This stable-v1 rename is the deletion visibility point.
6. Read back the removed ID as absent, retain both metadata locks, unlink the
   tombstone through constrained descriptors, fsync the provider root, then
   remove and sync the sidecar before releasing either lock.

Every normal registry writer rechecks for a barrier, sidecar, tombstone, or
sidecar temporary immediately after acquiring the registry lock. Registration
retains that guarded lock through publication. Alpha.4's strict schema-v1
reader rejects the transient schema-v2 barrier, so an older writer cannot
change the registry while a destructive pre-visibility state exists. Once the
transaction completes or rolls back, `profiles.json` is schema-v1 again and the
previously verified alpha.4 artifact can read the preserved state.

Before deletion visibility, the barrier is authoritative. Recovery accepts
only the exact complete original tree or an inode-preserving tombstone whose
entry count and metadata-manifest digest match, restores the old directory if
needed, removes the sidecar, and publishes the embedded expected v1 registry
last. It never restores a partially deleted tree. After visibility, stable v1
plus the sidecar is authoritative: the immutable target ID must be absent, but
unrelated alpha.4-compatible registry changes may remain. Recovery never
republishes credentials and may finish a partially unlinked tombstone because
the proof pins its root inode/device and every remaining entry is revalidated
before deletion. A missing, linked, malformed, or ambiguous registry, a
mismatched barrier/sidecar, or any state that proves neither side fails as
`removal_recovery_required` with the tombstone intact.

Linux validation requires `statx(STATX_MNT_ID)` and cleanup opens every
directory and regular-file edge with `openat2(RESOLVE_BENEATH |
RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)`. The
removal/recovery contract therefore requires Linux kernel 5.8 or newer and has
no weaker `st_dev` or ordinary-`openat` fallback. macOS opens those entries
relative to their parent with `O_NOFOLLOW` and compares raw descriptor-derived
`fstatfs` mountpoint, source, and filesystem-type fields. Non-directory special
leaves are instead checked with no-follow metadata and removed only by
descriptor-relative `unlinkat`, which cannot follow their target. Mount tokens
are ephemeral, redacted, and never written to a journal, JSON response, or log.

Removal does not edit `conversations.json`; the immutable profile ID, not its
alias, establishes lineage. References to a removed ID become unresolved, and
registering the same alias later creates a new UUID that cannot adopt them. The
installation-wide identity key and every unrelated profile remain outside the
deletion tree. Filesystem unlinking is not a claim of cryptographic secure
erasure from snapshots, backups, filesystem journals, or SSD media.

## Process execution

The current process launcher:

- let the provider adapter select the executable; `--` accepts provider arguments, not a command;
- resolve and canonicalize the `codex` executable found on `PATH`;
- reject executables inside the current repository, untrusted Unix owners, group/other-writable executable files, and non-sticky writable parent directories;
- spawn the executable and argument vector directly, never through `sh`, `eval`, or string concatenation;
- make the `--` provider-argument boundary explicit;
- delegate interactive launch to a coordinator plus provider guardian, each holding one side of a fixed-order split lease for the entire official provider lifetime;
- keep both interactive lease descriptors out of the provider process tree, so provider-started background tools cannot pin the profile after Codex exits;
- retain the provider-side lease if the coordinator is selectively killed, and
  retain the coordinator-side lease if the guardian is selectively killed;
- treat provider PIDs and process groups only as live containment handles: the
  internal supervisor releases only through a consumed provider-release proof,
  an exact guardian wait, the fixed provider-release record, and EOF; `CFCMP`
  alone is never owner/session success; unexpected or
  ambiguous loss parks with the relevant lease and process authority held, and
  the coordinator never turns a previously reported numeric PID into delayed
  signal authority;
- exercise through the default-unused Unix supervisor that only the live
  guardian signals the TUI group, HUP/TERM are forwarded once, INT/QUIT can
  remain attached, WINCH is coalesced, and TSTP/CONT uses
  restore-before-stop plus a fresh gate; the checksum-pinned
  `official-tui-normal` scenario covers resize and group-wide stop/continue with
  the official TUI and passed twice from that candidate source on Apple silicon, while
  public supervised resume remains a release gate;
- preserve ordinary child exit codes; the terminal fixture additionally
  preserves nonzero and terminating-signal disposition only after exact waits,
  restoration, recovery disarm, and final guardian proof;
- avoid persisting child stdout or stderr by default;
- force profile-local file storage for CLI and MCP OAuth credentials on every
  operation and reject provider arguments that can override the account,
  provider, endpoint, profile, or remote route;
- reject child working-directory and dynamic-feature overrides, and reject
  non-UTF-8 provider arguments that cannot be mediated safely;
- after acquiring the profile lease, canonicalize the interactive working
  directory and inspect every real, bounded `.codex` layer from the nearest
  `.git` root to that directory against a Codex-version-scoped safe-key policy,
  rejecting every `.codex/agents` node before reading an optional
  `config.toml`;
- repeat that inspection in the provider guardian after spawn authorization,
  then set the final Codex process cwd explicitly to the inspected canonical
  directory;
- sanitize the internal run/resume coordinator and guardian before spawn, then
  construct every final login, run, resume, and App Server process through one
  managed command policy that removes ambient Codex credentials, authentication and
  endpoint overrides, alternate config/state paths, remote execution routes,
  connector credentials, transcript/trace paths, provider test hooks, and
  future override families;
- run login and status from a private neutral runtime directory with its own
  `.git` boundary, independently of `CALCIFER_HOME`, so account-only operations
  cannot discover repository-local configuration through an ancestor;
- avoid logging raw arguments or the child environment.

Ordinary `run` and `resume` keep their existing guardian path: the guardian
directly acquires provider lease B during the authenticated launch handshake.
The Linux/macOS `SCM_RIGHTS` transfer is a separate internal primitive for the
future supervised target handoff, where A+B must be reserved before a target
guardian exists. No public command currently calls it, and the ordinary
run/resume/status behavior and persisted schemas are unchanged.

The official CLI still receives ordinary terminal, locale, proxy, and CA
environment needed for interactive and enterprise operation. Calcifer does not
claim to protect credentials from a hostile same-user proxy or trust store.

The wrapped CLI, repository hooks, tools, and provider remain outside Calcifer's sandbox because Calcifer does not provide one.

The coordinator and guardian checks reduce replacement races but cannot stop an
actor that can mutate the repository tree, including same-user malware or a
different writer in a shared workspace, from changing files between the final
check and Codex's own read. A supported upstream switch that disables project
configuration, or an effective-configuration API with source provenance, would
be required to remove that residual boundary completely.

## Error and rollback boundaries

Failures that must not trigger another account include:

- expired or invalid credentials;
- a required browser re-authentication;
- HTTP 5xx, DNS, timeout, or offline state;
- unsupported CLI versions or changed output formats;
- account suspension or policy denial;
- stale usage data or a failed status source.

Rollback applies to Calcifer metadata, default pointers, observation caches, and staged registration. It does not overwrite a newer credential with an older copy.

Target-reservation rollback is ownership-based rather than PID-based:

- failure before reservation completes leaves no target ownership;
- descriptor-send failure returns the complete A+B reservation to the caller;
- after a successful send and before a valid ACK, the parent keeps A+B and
  cannot commit the split;
- a malformed frame, wrong descriptor, failed lock-ownership proof, or failed
  close-on-exec check is rejected and closed by the guardian without an ACK;
- an invalid or missing ACK leaves the sender's awaiting state in possession of
  A+B, while a guardian that already received B can independently keep B live;
- after a valid ACK, the parent releases only its B descriptor by closing it,
  without `LOCK_UN`, and retains A; and
- a coordinator-only or guardian-only crash leaves the other exact descriptor
  authoritative until that owner exits or explicitly closes it.

The #33 supervisor must terminate and reap the guardian, or otherwise establish
the exact descriptor disposition, before abandoning an ambiguous ACK and
releasing the reservation. PIDs may be used to signal and reap a known child,
but never to infer lease ownership or authorize another writer.

## Open design work

Before the first stable release, the project still needs reviewed decisions or
completed implementations for:

- deliberate all-profile re-key recovery after identity-key loss;
- public Linux/macOS supervised resume and active-session monitor/failover UX
  on top of the default-unused pinned integration in
  [ADR 0003](adr/0003-supervised-codex-session.md), plus a separate Windows
  terminal and process-authority design;
- additional Codex version/schema gates and observation cache TTL/backoff;
- cross-platform exact-thread capture ACLs and future Codex session-schema adapters;
- cross-profile conversation handoff implementation following [ADR 0001](adr/0001-cross-profile-conversation-handoff.md);
- OS credential-store support for Claude setup tokens;
- trust-domain configuration and failover pool UX.

Credential-management support is a separate platform guarantee from the portable diagnostic surface. Each provider and OS combination must pass its permission, credential-store, process, and recovery tests before being marked supported.
