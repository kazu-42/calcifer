# Security model

Calcifer will handle high-value local credentials. Its safest useful design is a small process wrapper with explicit trust boundaries, strict profile isolation, redacted diagnostics, and fail-closed provider adapters.

This document covers both implemented and intended guarantees. The current
Unix Codex slice creates isolated file-backed credentials through the official
login flow, may let the official CLI refresh them during run, resume, or status,
captures an exact same-profile thread key for crash-safe cold restore, and can
remove one owned local profile through a confirmed crash-safe tombstone
transaction. A private, credential-free compatibility gate proves the pinned
Codex `0.144.4` fork-by-path and remote-TUI behavior against synthetic state;
issue #48 extracts its bounded readiness relay, issue #50 adds default-unused
coordinator/guardian process authority with fake children, and issue #52 adds a
default-unused Unix terminal kernel with a real PTY, typed input gate,
fixed-buffer streaming, signal/job-control policy, and redundant restoration.
Issue #54 connects that kernel to the pinned real App Server, a separate typed
monitor, and the official remote TUI behind an internal, default-unused
entrypoint. It separately implements the persistent shell anchor and a move-
only completion gate. Independently budgeted checksum-pinned normal-session and
retained-recovery package scenarios are configured to exercise the production
coordinator, guardian, provider-session, PTY, and signal/job-control
implementations under a test-owned terminal harness. On 2026-07-20, the final
Issue #54 candidate source passed the normal scenario twice and retained
recovery once on Apple silicon; the required Ubuntu 24.04/macOS matrix readback
remains pending. They perform selected-profile admission through
the production A-to-B lease path, and their guardian helper enters the shared
production guardian-bootstrap core with only a package-specific post-admission
loopback rewrite and fixed observation root. The package parent is designed to
create the completion endpoint, pass it across real parent-to-coordinator and
coordinator-to-guardian `exec` boundaries, and accept only the exact record plus
EOF after the guardian consumes provider-release proof. The package role
dispatcher and outer-terminal harness remain test-specific; they do not
execute the production `CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE`
dispatcher/parser or persistent shell-anchor role, and these scenarios make no
parser coverage claim. Package tests use no real credential, token, account ID,
or provider identifier. The deterministic provider fixture described below is
credential-free and loopback-only. No public supervised command calls this path,
and it persists no terminal transcript. Automatic failover, public supervised
run/resume, and the production cross-profile conversation handoff transaction
remain unimplemented;
[ADR 0001](adr/0001-cross-profile-conversation-handoff.md) defines handoff
semantics and [ADR 0003](adr/0003-supervised-codex-session.md) defines the
staged supervisor.

## Assets

- Codex and Claude access, refresh, ID, and setup tokens
- account, workspace, and organization identity
- profile selection and trust-domain policy
- source code, prompts, conversation context, and child process output
- outer-terminal identity, modes, foreground ownership, and interactive stream
  privacy
- Calcifer registry integrity
- installation-local provider-identity HMAC key and private profile bindings
- public release metadata, manifests, checksums, and update recommendations

## Threats in scope

- accidental credential disclosure through logs, errors, diagnostics, fixtures, or Git
- one profile receiving another profile's refreshed credentials
- malicious profile names escaping the managed root
- symlink, ownership, permission, and partial-write attacks on managed state
- concurrent refresh or mutation corrupting one profile
- PATH hijacking or shell injection when launching a provider CLI
- repository configuration forcing a more privileged or differently governed account
- ambient provider authentication, endpoint, config, state, or session-log overrides replacing the selected managed profile
- automatic failover causing organization-boundary data disclosure
- incorrect quota classification causing failover loops
- automatic replay duplicating file, Git, deployment, billing, or messaging side effects
- one conversation lineage being written concurrently, handed to an account outside its configured trust domain, or imported from an attacker-selected path
- a compatibility probe reading a real profile or rollout, inheriting ambient credentials or routing, declaring a remote TUI ready from socket liveness alone, or deleting a replaced cleanup path
- a terminal supervisor forwarding or replaying input before exact readiness,
  retaining a transcript, growing an unbounded payload queue, signaling through
  a stale numeric PID/PGID, or leaving the outer tty raw after one authority dies
- mutable, redirected, oversized, partial, or digest-mismatched release metadata causing installation of the wrong target

## Threats outside the guarantee

Calcifer cannot protect credentials from:

- root, administrator, or malware running as the same OS user;
- a same-user process racing the handoff probe's identity-checking `lstat` and
  subsequent socket-path `unlink`; the private `0700` parent prevents other
  unprivileged users from entering that namespace, but the two operations are
  not an atomic descriptor-relative unlink;
- a compromised official provider CLI, plugin, hook, or child tool;
- a malicious repository executed by the wrapped agent;
- provider compromise or provider-side account recovery;
- on macOS, a different OS principal that already has mode- or ACL-granted
  authority to alter a managed node, its security metadata, or its namespace
  and races validation or mutates the pathname after the final check. This
  includes node `DELETE`, parent `DELETE_CHILD`/`ADD_FILE`/`ADD_SUBDIRECTORY`,
  `WRITE_SECURITY`, and ownership-change authority. The official Codex CLI
  accepts `CODEX_HOME` only as a pathname and exposes no supported
  descriptor-based handoff;
- all exposure through OS swap, crash dumps, or debugging facilities.

If both coordinator and guardian receive uncatchable `SIGKILL` while the outer
tty is raw, no in-process authority survives to restore it. The invoking shell
or terminal emulator is the external recovery boundary and may require an
explicit terminal reset. Calcifer must never turn that limitation into a false
restoration claim.

Calcifer is not a sandbox and does not make an untrusted repository safe.

## Secret-handling requirements

- Managed profile roots and homes are private to the current user; secret files are private at creation time. Provider-owned nested rollout directories/files from older installations may retain non-writable `0755`/`0644` modes behind that private home boundary.
- Tokens and reset-credit IDs are never accepted as ordinary command-line flags because process listings and shell history can expose them.
- Raw arguments, child environments, credential files, account email, and stable provider IDs are not logged.
- Conversation metadata stores only Calcifer/profile/thread UUIDs, canonical cwd, tested adapter versions, bounded inventory timestamps, path-free file identity/size/mtime/ctime fingerprints, and lifecycle state. It excludes aliases, rollout paths, App Server previews, transcript bodies, prompts, responses, approvals, tool arguments, terminal streams, credentials, and provider identity.
- The internal terminal kernel moves bytes only through one fixed 8 KiB buffer
  per active direction, retains no transcript or payload queue, zeroes reported
  and otherwise unreported bytes before reuse, and emits only fixed redacted
  diagnostics. Its pre-raw SHA-256 snapshot fingerprint is ephemeral lifecycle
  evidence and is never rendered or persisted.
- Diagnostics report capability and redacted status, not secret values or credential paths.
- Test credentials are synthetic and contain obvious non-production markers.
- Profile aliases are mutable display metadata, never filesystem ownership
  keys. Rename holds the published profile lease and registry lock, updates
  only the bounded atomic registry document, and leaves credentials, identity
  markers, managed homes, sessions, and conversation records untouched.
- Claude token storage fails closed when a supported OS credential store is unavailable. Plaintext fallback is a non-goal unless a later ADR and security review define it.
- Export, backup, telemetry, and crash-report features exclude credentials by design.
- Update checks do not open profiles, provider state, configuration, credential
  stores, or token sources. Ambient proxy configuration is explicitly disabled;
  requests send only fixed public GitHub media-type, API-version, and user-agent
  headers.
- Credential-bearing environments are passed only to a provider adapter's validated executable, never to an arbitrary command supplied after `--`.
- Every managed Codex login, run, resume, and App Server process is built by one
  environment policy. It removes ambient API/access tokens, authentication and
  endpoint overrides, cloud-task and remote-execution routes, connector and
  remote-auth tokens, App Server config hooks, alternate state homes,
  transcript/trace paths, provider test hooks, and future override families
  before the official CLI starts. This keeps the selected profile authoritative
  and prevents implicit transcript recording.
- On Unix, Calcifer sets process umask `0077` before parsing commands, creating
  state, or spawning coordinator, guardian, login, App Server, or interactive
  provider children. This is process-global and happens before worker threads;
  no around-spawn umask race or unsafe post-fork callback is used.
- The same policy is applied before Unix run/resume coordinator and guardian
  helpers start; ambient `CODEX_HOME` returns only on the final provider command.
- Calcifer revalidates the private `auth.json` and managed `config.toml` after
  acquiring the profile lease. The bounded, version-scoped semantic policy
  requires file-backed Codex account credentials, accepts absent or file-backed
  MCP OAuth storage and official project-trust state, and rejects unknown,
  OAuth callback endpoint, account/provider/state-routing, root-discovery,
  dynamic-extension, and role keys. Any auto-discovered `CODEX_HOME/agents`
  node is also rejected before provider spawn because it can introduce indirect
  full configuration layers.
  Both stores are forced to `file` on every invocation, so previous pre-alpha
  managed configs remain safe and usable during upgrade.
- Interactive run/resume canonicalizes its cwd and validates every repository
  `.codex` layer from the nearest real `.git` root to that cwd. Any
  `.codex/agents` filesystem node fails closed independently of whether
  `config.toml` exists. Unknown keys and settings that can own authentication,
  provider routing, dynamic feature policy, root discovery, or managed state
  fail before spawn. Reads are bounded to 1 MiB, symlinks and special nodes fail
  closed, and public errors omit paths, keys, values, and parser diagnostics.
- In a linked worktree, Codex 0.144.4 can additionally merge only the `hooks`
  field from the primary checkout's `.codex/config.toml`. Calcifer does not
  resolve or inspect that external hook source. This does not add an unvalidated
  account/provider/state layer, and repository hooks are already outside
  Calcifer's sandbox guarantee, but compatibility review must track this
  upstream special case.
- The coordinator performs the check after acquiring its profile lease and
  before publishing the lifecycle socket. The guardian independently repeats
  it after spawn authorization and starts Codex with the inspected canonical
  cwd. Child cwd and feature-policy flags, including non-UTF-8 forms that cannot
  be parsed safely, are rejected at every wrapper boundary.
- Login and status probes use a verified private runtime directory with its own
  `.git` boundary rather than either the caller's repository cwd or a profile
  home below user-selected `CALCIFER_HOME`.
- Interactive launch uses a coordinator/provider-guardian pair with two fixed-order lease files. Either surviving process blocks a second writer after a selective crash, while the official provider and its background tools inherit neither descriptor.
- Future supervised target handoff has an internal Linux/macOS no-gap transfer
  primitive. The future supervisor must first supply an already-authenticated
  private Unix control socket; stream authentication and lifecycle deadlines
  are integration requirements for issue #33, not properties inferred by the
  descriptor primitive. It then sends exactly one sentinel byte and exactly
  one provider-lease descriptor. Missing, duplicated, unknown, or truncated
  ancillary data fails closed. The guardian compares the received and visible
  lock's device/inode, requires a current-UID private single-link regular file,
  proves that the received open-file description owns the active advisory lock,
  and sets and reads back `FD_CLOEXEC` before it may acknowledge the transfer.
  No App Server, TUI, or provider tool may start from the provisional pre-ACK
  state. The ACK is one-shot, strictly parsed, and bound to the same socket; the
  sender releases its provider descriptor only by close, never explicit
  unlock. Descriptor-held flock state is the authority; a PID is not.
- In the internal #50/#52/#54 supervised-session path, provider PIDs and
  process groups are observation and live-guardian containment metadata, not
  lease or reap authority. Normal release requires stopped terminal pumps,
  exact direct-child waits, `TERMINAL_QUIESCED`, coordinator restoration with
  semantic readback, `TERMINAL_RESTORED`, guardian recovery disarm, a trusted
  `CHILDREN_REAPED` frame, exact guardian wait, and lifecycle EOF. If the
  guardian disappears without that proof, including after reporting provider
  PIDs, the coordinator restores the tty and parks with lease A held rather
  than inferring safety from PID disappearance; see
  [ADR 0003](adr/0003-supervised-codex-session.md). Foundation fixtures launch
  fixed synthetic children; #54 can instead launch the pinned App Server and
  official remote TUI. Both paths remain unavailable to the public CLI.
  Reported numeric PID/PGID values are never reused by the coordinator as
  delayed signal authority; the fake children instead receive a dedicated
  guardian-liveness pipe whose EOF lets them exit after abrupt guardian death.
  The pinned App path has a narrower positive release rule: the guardian sends
  its exact direct child exactly one `SIGTERM`, never escalates App shutdown to
  `SIGKILL`, and can construct `PinnedAppGracefulDrain` only after exact wait
  returns code zero. Early/nonzero/signalled exit, timeout, signal-send failure,
  a second signal, forced kill, or any other ambiguity retains authority and
  parks; accidentally dropping that ambiguous App owner aborts without sending
  another signal. This proves the reviewed direct-child contract, not the
  absence of arbitrary non-child descendants that escaped with `setsid(2)`.
  Issue #55 therefore claims zero residue only for Calcifer-owned direct
  children and recorded known process groups plus identity-checked runtime, FD,
  and socket evidence. Escaped-session containment is tracked
  separately by issue #56.
- At guardian exec entry, lifecycle fd 0, terminal fd 1, and recovery fd 2 are
  each moved into one owned close-on-exec duplicate while the guardian is still
  single-threaded. The boundary requires exactly two references to the original
  identity before replacement, atomically replaces the inherited standard fd
  with access-appropriate `/dev/null`, validates type/access/close-on-exec and
  changed identity, and requires exactly the owned duplicate afterward.
  Dropping recovery must reduce that identity count from one to zero. Merely
  setting `FD_CLOEXEC` on an inherited second recovery fd is not disarm proof.
- Before the #52/#54 guardian can create a private runtime, worker, PTY, or child,
  it sends a fixed, domain-separated SHA-256 fingerprint of its full semantic
  pre-raw terminal snapshot. The coordinator compares it in constant time with
  its own immutable snapshot and returns `TERMINAL_ARM_ACCEPTED` only on an
  exact match. A mismatch starts nothing, keeps input closed, restores and reads
  back the tty, exactly waits the guardian, and fails cleanly. A missing or
  ambiguous ACK also starts nothing but retains coordinator authority and
  evidence after restoration and guardian containment.
- The outer-input worker is physically absent until exact selected-TUI
  readiness, foreground and terminal-identity revalidation, input flush,
  raw-mode semantic readback, and `OPEN_GATE` acknowledgement all succeed.
  `TSTP` restores before stopping and `CONT` requires a fresh gate; HUP/TERM are
  forwarded once, WINCH retains only the latest size, and only the guardian's
  live direct-child handle may signal the selected TUI group. Normal and
  fallback restoration re-read foreground ownership immediately before
  changing termios; a mismatch means another owner may have reclaimed the tty,
  so Calcifer performs no restore, emits no restored proof, and retains its
  lease/evidence. The production-shaped persistent anchor remains the
  controlling-terminal session leader while each coordinator generation owns
  the foreground process group. It accepts only one exact eight-byte terminal
  record followed by EOF. The guardian can publish the provider-release-only
  `CFCMP\x01\r\n` record
  only by consuming a move-only `ProviderNeverStarted` or direct-App graceful-
  drain proof; missing, malformed, or trailing data restores when possible and
  then contains instead of returning ordinary success. `CFCMP` is never owner,
  session, anchor, or shell success by itself; exact owner/coordinator waits and
  the exact record-plus-EOF check remain independently required. The anchor owns
  no profile lease and cannot mint provider cleanup or terminal-restoration
  proof.
  The same anonymous socket is duplex, but the reverse direction is not a
  second success channel. The internal package owner may send at most one exact
  25-byte recovery request and then shuts down its write half. The frame is
  `CFRCR\x01`, the fixed retained-generation reason, the transit endpoint's
  big-endian device/inode identity, and `\r\n`. The anchor records that peer
  identity when the socketpair is created; after exec, the guardian accepts
  only the identity of its own inherited endpoint. No extra environment value,
  raw descriptor number, pathname endpoint, marker token, reusable bearer
  value, or numeric PID supplies the identity. A malformed or cross-wired
  request alone authorizes nothing. Exact peer EOF, including EOF after a
  rejected partial frame, is only an owner-loss trigger for the guardian's
  existing typed cleanup state machine; it never grants signal, reap, release,
  or successful-disposition authority. Recovery can resume one eligible
  retained deadline/cleanup owner once. A distinct fixed
  `CFRET\x01\r\n` record is terminal retained evidence, not completion: it
  carries no reason, identity, secret, or provider data, and exact record plus
  EOF makes the anchor park with its direct child, completion receiver, and tty
  snapshot. A nonrecoverable retained state, recovery-transport failure, or
  second retention consumes the guardian endpoint, attempts that record and
  write-half shutdown once, then deliberately keeps the concrete typed owner
  reachable inside the parked guardian's non-returning loop. That terminal
  state is not retryable after
  the sole recovery retry is consumed. `EPIPE` or shutdown ambiguity does not
  release the owner and cannot produce `CFCMP`.
  This recovery authority is live and generation-local. It is carried only by
  the anonymous endpoint retained by that running owner/guardian generation, is
  not persisted, and does not survive loss of both terminal authorities or a
  machine restart. It is separate from cold conversation resume, which reopens
  persisted history but cannot restore a dead process or in-flight operation.
  If recovery wins a race with an already-written lifecycle control, the
  guardian may drain at most one state-valid superseded command after terminal
  quiescence. That drain creates no command proof, acknowledgement, forwarded-
  signal disposition, or coordinator-stop cause, and expires at
  `TERMINAL_RESTORED`.
  The package harness fixes one internal deadline fence before generation
  spawn, requests recovery before coordinator termination, and caps every
  cleanup sub-deadline inside that original fence. It wakes a coordinator only
  after a fresh exact-child stopped-state readback and otherwise leaves the
  child unsignalled for the healthy recovery grace. Automatic scratch deletion
  still requires four independent proofs: exact coordinator-child wait; the
  exact provider-release-only `CFCMP\x01\r\n` record followed by EOF, which is
  not session or shell success; absence of every reported known process group;
  and an identity-checked empty runtime with zero retained FD and socket
  references.
  These Calcifer-owned direct-child/known-group and identity proofs are the #55
  zero-residue scope; escaped `setsid(2)` descendants remain issue #56. Exact
  retained or otherwise unproved cleanup evidence in the `cfg(test)` package
  harness emits one fixed, redacted subtype and terminates libtest with a fixed
  nonzero `_exit`-equivalent status while its Rust owners remain live. It runs
  no destructors, unproved TERM/KILL fallback, completion proof, deletion step,
  or cleanup-success publication, and it produces no signal-driven core dump.
  This test-only exit closes the libtest descriptor table so hosted CI fails
  promptly instead of parking until its outer timeout; it does not prove
  descendant cleanup or grant authority over a process that created another
  session. A bounded regression parent observes a fixed readiness handshake
  from a deliberately parked helper before killing and reaping only that exact
  child. Production guardian/anchor retained owners still park their concrete
  typed authority. A recovery-send error proves only that the one-shot attempt
  was consumed, not that write-half shutdown reached the kernel boundary. The
  later CI watchdog bounds the cargo/libtest parent group only; it is not
  authority over descendants that create another session, and catastrophic
  runner-timeout cleanup is not reported as Calcifer process-tree proof.
  A separate non-ignored deterministic fixture is configured for startup
  queued, ready, active, suspended, retained quiescing, retained restore pending,
  and retained cleanup pending. It is designed to execute the exact production
  coordinator/guardian/session graph while a sealed `cfg(test)` compatibility
  seam and strict owner-private wrapper replace only official compatibility and
  provider behavior. Production builds parse neither the fixture selector nor
  compatibility override. The fixture must first prove that its checkpoint is
  observation-only and has neither completed nor terminated the coordinator,
  then send the sole generation-bound `CFRCR` request. The first four checkpoints
  expect failed-clean and zero inference calls; the three retained checkpoints
  expect completed-clean and exactly one validated loopback inference call. It
  uses no credential or provider identifier. Its fourth namespace proof also
  requires the identity-checked private compatibility stage parent to be empty.
  This is deterministic recovery-phase evidence, not Codex-version compatibility
  evidence. All seven cases passed three consecutive local runs on the exact
  tree; cross-platform CI readback remains pending.
  Public supervised UX remains disabled until its operational recovery and
  cross-profile transaction gates are complete.
- The public wrapper, coordinator, and guardian catch `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT`; caught dispositions reset to child defaults on each `exec`, so terminal cancellation still reaches Codex while every wrapper remains attached if Codex handles the signal and continues.
- Bounded metadata-only App Servers for status and thread capture inherit only
  the provider-side lease. On Unix the multithreaded parent never clears
  close-on-exec: Calcifer atomically duplicates B with `F_DUPFD_CLOEXEC`, then
  clears only the selected post-fork child's duplicate before its one consumed
  spawn. Parent flag readback, child kill/reap on failure, and exact
  device/inode exec tests prevent unrelated children from retaining B. These
  probes issue no turn/tool methods or descendants and start only while
  Calcifer owns the profile coordinator/provider order. This keeps a killed
  probe parent from admitting a second credential writer until stdio EOF
  terminates the probe without exposing B to interactive App Servers or tools.
- Automatic same-profile restore never guesses the newest thread. A private pending baseline is synced before provider spawn; only one new or uniquely changed root CLI thread can be adopted after direct metadata validation. Same-second changes use a path-free device/inode/length/nanosecond-mtime fingerprint in addition to provider timestamps. Zero candidates preserve the previous head only when every baseline ID remains present. Deleted, multiple, archived, wrong-profile/cwd, missing, corrupt, unsupported, capped, pre/post-mutated, or inconsistent results stop before automatic provider launch.
- Codex 0.144.4 hides its 10,000-file rollout scan cap from the v2 App Server response. Calcifer proves a conservative upper bound by snapshotting active and archived roots separately before and after listing, requiring each root to remain below the cap, and mapping every wire path to the stable snapshot. Nested nodes must remain owned, real, non-symlink, and non-writable by group/other; files must have one hard link. The enclosing managed home remains owner-private.
- Bare resume releases its initial conversation lock before waiting for a profile lease, then revalidates the unchanged UUID binding under that lease. Registry mutation order is coordinator lease, provider lease, then a short conversation lock; no conversation lock spans App Server or interactive provider I/O.
- A conversation document update uses create-only private same-directory temporary files, file fsync, rename, and directory fsync. Post-rename sync uncertainty is read back and reported without retrying a provider launch. Newer schemas and unsafe owner/type/mode/hard-link state are never rewritten.
- Profile removal is local-only and requires an explicit TTY `yes` or `--yes`;
  JSON requires `--yes`. Before confirmation, non-TTY invocations perform no
  managed-state read, recovery, or mutation. Removal never starts a provider or
  browser process and never calls a token endpoint.
- Removal holds both profile lifetime leases before removal or registry locks,
  durably syncs those lock files, then validates root and tree inode/device,
  current owner, owner-only profile-root mode, absence of group/other write on
  traversed directories and regular files, validated no-follow leaf types,
  single-link non-directory entries, exact marker, mount identity, depth, and
  entry budget. macOS additionally requires no extended ACL entries on every
  tree entry, including non-followed symlinks, sockets, and FIFOs, and no
  immutable, append-only, or no-unlink file flags on managed roots and tree
  entries. Readable provider-created descendants remain safe behind the `0700`
  profile root, while traversed directories must retain owner `rwx`.
  Ownership markers and lifetime locks are control-plane entries and remain
  private single-link regular files. Locks are opened no-follow and their
  opened/visible inode, owner, mode, and link count are matched before flock or
  fsync, so symlink and hard-link replacements fail before transaction
  preparation. A path-free
  manifest digest and entry count prevent pre-visibility recovery from
  restoring a tree with missing credentials or session state.
- Stable `profiles.json` remains alpha.4-compatible schema v1. The first durable
  removal state is a self-contained transient schema-v2 registry barrier that
  embeds the expected v1 registry and prepared proof before any tree rename. A
  strict alpha.4 reader rejects that barrier, preventing an old writer from
  invalidating recovery. A matching sidecar is persisted next; the later stable
  v1 registry without the immutable ID is the deletion visibility point.
- Credentials are recursively unlinked only after stable-v1 readback proves
  the ID absent. On Linux, every traversed directory and regular file uses
  `openat2` beneath the provider descriptor with no-symlink, no-magic-link, and
  no-cross-mount constraints; `statx` mount IDs make kernel 5.8 the minimum for
  removal and recovery. macOS compares `fstatfs` identity for every opened
  descriptor. Provider-created symlinks, sockets, FIFOs, and other special
  leaves are never opened or followed; a no-follow metadata proof is recorded
  and descriptor-relative `unlinkat` removes only the in-tree name. Unsupported
  kernels and platforms fail closed without an unconstrained fallback. Mount
  tokens may contain local path or server information, so they remain ephemeral
  and are neither serialized nor logged.
- Before Unix creation or acceptance, Calcifer canonicalizes the deepest
  existing prefix of the configured data root once and appends only missing
  normal components. The physical path is stored and passed explicitly to
  coordinator and guardian self-execs. Operational paths must remain canonical;
  every symlink ancestor is rejected, and every real directory ancestor must
  be owned by root/current user and must not be group/other replaceable unless
  sticky. On macOS, each existing managed regular file or directory and each
  creation ancestor is opened with no-follow semantics. Type, owner, mode, file
  flags, extended ACL, and device/inode identity used by one acceptance
  decision are read from that same descriptor with `fstat` and
  `acl_get_fd_np(ACL_TYPE_EXTENDED)`; the descriptor identity must also match a
  no-follow lookup of the visible pathname. Any open, ACL, metadata, identity,
  unsupported tag/bit, or malformed native representation fails closed. No
  pathname ACL result is combined with metadata from a different vnode. This
  binds one validation decision, but it is not a globally atomic snapshot and
  does not permanently pin the pathname against an already-authorized active
  mutator described above. Every ALLOW entry, every inheritable ACL entry, DENY permissions other than a
  non-inheritable DELETE-only entry, and append, immutable,
  DATAVAULT/RESTRICTED, or unknown parent flags fail before an inode exists. The
  DELETE-only exception keeps the standard macOS home `everyone deny delete`
  ACL compatible without admitting `deny delete_child`; parent-only
  `SF_NOUNLINK` remains compatible with standard temp ancestry. Each new managed
  directory or private file must then read back through its open descriptor
  with an empty extended ACL and supported flags before credential bytes are
  written. Existing extended ACL state is never silently normalized.
- Removal-sidecar reads use a no-follow descriptor and match its inode, owner,
  private mode, and single-link state to the visible path before bounded JSON
  parsing.
- Recovery restores only a complete pre-visibility tree and only completes
  deletion after visibility; removal and registry locks remain held through
  tombstone and sidecar durability. Missing or hard-linked registries,
  mismatched barriers/sidecars, mount crossings, allocation-budget failures,
  and all other ambiguity leave credential bytes intact and report a bounded
  safe error. Normal registry writers recheck every removal artifact after
  acquiring the registry lock.
- Removal does not edit global Codex state, provider tokens, the installation
  identity key, unrelated profiles, or conversation lineage. Reusing an alias
  receives a fresh UUID. Filesystem unlinking does not guarantee secure erasure
  from snapshots, backups, filesystem journals, or SSD wear leveling.
- Lifecycle inspection is a version-pinned metadata projection. It validates the first session identity and recognizes only persisted start, complete, and abort tags; every response/tool payload is ignored. `interrupted` and `unknown_crash` may reopen the exact history with a warning, but no prompt, command, approval answer, or tool call is reconstructed or submitted. Bare and explicit exact resume retain lifecycle from a matching immutable binding even when pending or needs-selection state hides the workspace head. A clean pre-launch observation cannot clear persisted uncertainty; only lifecycle readback after the provider completes can do so. Immutable profile/cwd ownership conflicts terminalize the pending launch and require explicit selection instead of retrying forever.
- Capture failure never silently downgrades to an uncaptured launch. Explicit `--untracked` run or profile-specific `resume --last` refuses a pending launch in the canonical workspace, atomically records metadata-only in-flight ownership and `needs_selection` before spawn, performs no inventory or post-capture, and leaves the marker intact across provider or spawn failure. Active ownership blocks cross-profile exact adoption, and exact post-exit refresh requires its original head to remain authoritative, closing both concurrency orderings. Registry errors and uncertain durability stop before spawn; bare resume remains unavailable until exact recovery.
- Standard proxy and CA environment variables remain available for legitimate
  enterprise networks. Calcifer does not defend against a hostile proxy, trust
  store, root, administrator, or same-user malware; managed provider endpoints
  still rely on normal TLS verification by the official CLI.
- Repository preflight narrows Calcifer's account-routing boundary; it does not
  make a malicious trusted repository safe. Mutation by any actor able to write
  the repository tree, including same-user malware or another writer in a
  shared workspace, between the guardian's final check and the official CLI's
  own file read remains outside the guarantee until Codex exposes a supported
  project-config disable or provenance-checked effective-config interface.

### Private provider identity binding

Provider identity binding is supported only on Unix and only for the tested
Codex `0.144.4` managed ChatGPT auth projection. Windows fails closed until a
current-user-only ACL implementation exists; Calcifer never creates a normally
accessible fallback key there.

One 256-bit installation key is generated from the OS CSPRNG and stored as a
private, owner-checked, single-link regular file. A non-provider UUID key ID
distinguishes key loss/replacement from credential drift. Each profile marker
contains only its schema, key ID, adapter ID, supported auth kind, and HMAC
fingerprint. The HMAC input is domain-separated and length-delimited across
provider, auth kind, adapter version, and effective account/workspace scope.
Email, access/refresh/ID tokens, API keys, and reset-credit identifiers are
never inputs.

The raw scope is read through a bounded minimal projection of provider-owned
`auth.json`, reduced immediately, and never copied to the registry, marker,
stdout/stderr, JSON, logs, or error text. Equality rejects duplicate aliases;
inequality is not evidence of independent quota. Existing unbound profiles are
manual-only until explicit `auth verify` succeeds under their profile lease and
the registry mutation lock. A changed credential produces
`provider_identity_mismatch`; Calcifer never silently rebinds it. Missing,
corrupt, replaced, unsafe, or unreadable key state produces
`identity_key_unavailable` and disables identity-dependent selection.

`VerifiedTargetReservation` keeps the installation-local identity fingerprint
inside its private guard and exposes only internal equality comparison. The
fingerprint, provider account/workspace scope, and identity-key ID do not enter
the guardian transfer frame, public DTOs, diagnostics, or transition journals.

Key and marker writes use private same-directory temporary files, file fsync,
atomic rename, and parent-directory fsync. A complete destination observed
after parent sync failure is adopted only after an idempotent parent-sync
retry; it is never an invitation to repeat login. Persistent uncertainty is
reported as `identity_commit_uncertain` while the unpublished staging
credentials remain preserved for explicit recovery. Any orphan staging
directory blocks subsequent registration before provider login. Readers ignore
stale temporary names. Deliberate re-key and stale temporary cleanup remain
future recovery commands and must validate every selected binding as one
transaction.

### Codex handoff compatibility probe

The implemented compatibility probe is deliberately separate from profiles and
the future handoff transaction. Its API accepts only an absolute Codex
executable and a timeout. It cannot receive a Calcifer profile, conversation
binding, credential, or user rollout, so an unsupported version, malformed
schema, protocol error, timeout, transport failure, or spawn failure returns a
redacted error without committing Calcifer state.

The probe supports exactly Codex `0.144.4` on Unix. A private handoff capability
is constructed only from three typed proofs: the pinned schema projection, a
successful synthetic fork-by-path, and a successful official remote-TUI
rejoin. The default generated schema must not authorize `thread/fork.path` or
`thread/resume.path`; only the `--experimental` schema may contain their
reviewed unstable `0.144.4` path fields. Calcifer validates reviewed fork,
resume, and thread-response projections rather than claiming equality with the
entire generated protocol document. The generated default and experimental
`JSONRPCError` and `JSONRPCErrorError` files must also equal the pinned complete
error schemas, including required fields, request-ID union, code/message/data
properties, titles, and description. This prevents a version label, permissive
schema match, socket file, or live process from becoming authorization by
itself.

The absolute executable is canonicalized and opened with `O_NOFOLLOW` before
the first subprocess. It must be a non-empty executable regular file no larger
than 512 MiB; group/other write bits and setuid/setgid bits are rejected. The
capability is bound to device, inode, length, mode, UID/GID, link count,
nanosecond mtime/ctime, and SHA-256. Before any subprocess starts, Calcifer
copies those verified bytes to a mode-`0500` executable inside a retained
mode-`0700` scratch directory and confirms equal length and digest. Every probe
phase executes only that staged copy, whose metadata is revalidated throughout,
so a legitimate updater cannot replace the installation path halfway through
and produce a mixed-build proof. Immediately before minting, Calcifer fully
rehashes both the staged copy and the original executable under the overall
deadline. Replacement of the original path therefore fails closed. The
capability remains bound to the original executable identity and does not expose
a raw executable-path accessor; arbitrary same-UID tampering remains outside
the threat guarantee.

Every subprocess runs below a new mode-`0700`, current-user-owned scratch root
with separate synthetic source home, target `CODEX_HOME`, workspace, and
environment home. Each command starts from `env_clear` and adds only a fixed
`PATH`, `LANG`, `LC_ALL`, `SHELL`, and `TERM`, plus synthetic `CODEX_HOME`,
`HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`,
`XDG_RUNTIME_DIR`, `TMPDIR`, `TMP`, and `TEMP`. This allowlist excludes ambient
provider credentials, endpoint and proxy overrides, `CALCIFER_HOME`, and test
hooks by construction. The probe invokes no login command, supplies no
credential or refresh token, creates no credential file, and rejects a bounded
scratch tree containing `auth.json` or `.credentials.json`. A private static
model catalog avoids online model discovery; the configured no-auth provider
points only to a loopback sentinel, and any connection to that sentinel rejects
the proof.

Each private source, target, workspace, environment, and schema directory is
kept open and bound to its visible device/inode, owner, and safe mode. Reads and
writes accept only normal relative path components. Every intermediate
component is opened relative to the retained descriptor with
`O_DIRECTORY | O_NOFOLLOW`, and the final regular file is opened with
`O_NOFOLLOW`; descriptor metadata is checked before and after bounded reads.
This prevents a provider-created intermediate or final symlink from redirecting
schema, config/catalog, source-rollout, or target-rollout readback.

The synthetic source rollout is bounded to 1 MiB and fingerprinted by device,
inode, length, mode, owner, link count, nanosecond mtime/ctime, and SHA-256
before the experimental `thread/fork.path` request. The response must name a
distinct UUID with the expected `forkedFromId`, CLI version, model provider,
cwd, preview, and turns. It must also return the requested model/provider/cwd,
`never` approval policy, and read-only/no-network sandbox plus the expected
`user` reviewer. Its target rollout must be canonically below the synthetic
target `sessions` root, contain the known history sentinel, and be a
current-user-owned, single-link regular file that is not writable by group or
other. Both source and target
directory descriptors and exact fingerprints are retained and revalidated
before remote attach, before the TUI launch, and after remote shutdown. These
checks prove the pinned provider's materialization behavior; they do not
validate or authorize a real handoff path.

The remote half starts a real private Unix App Server and the official
`codex resume --no-alt-screen --remote unix://... <target-thread-id>` TUI under
a PTY. Both sockets remain inside the retained, current-user-owned mode-`0700`
scratch root. The extracted readiness relay explicitly sets its own socket to
mode `0600`, reads back current UID/type/mode, records device/inode, and unlinks
only the matching socket. A collision or replacement is preserved and fails
closed. The App Server socket remains provider-created and is independently
validated by the compatibility runtime. An AF_UNIX descriptor inode is not the
filesystem pathname inode on Linux/macOS, so descriptor `fstat` cannot make
pathname cleanup atomic; same-UID namespace races remain outside the guarantee.

The proxy transparently forwards traffic while inspecting only enough of the
startup protocol to prove readiness. It first requires a successful
`thread/read` for the exact synthetic target, then a successful `thread/resume`
for that target whose model, provider, cwd, approval/reviewer, and
sandbox/network settings equal the fork proof. The official TUI must next issue
`thread/read` for the exact synthetic source-parent ID with `includeTurns`
absent. Because that source exists only in the isolated source home, the target
App Server's expected error response completes the round trip. Readiness is
signalled only after that error has been forwarded to the TUI; observing the
request proves the TUI parsed `forkedFromId` from the resumed thread rather than
merely opening a socket.

The two forwarding directions serialize each inspected forward/observe
operation so a request caused by a server response cannot overtake observation
of that response. An atomic three-state relay lifecycle records `RUNNING`,
unexpected `DISCONNECTED`, and intentional `STOPPING`. Before checked shutdown,
the final health probe actively polls the retained client and upstream streams
for error/hangup/invalid state and performs non-consuming non-blocking `PEEK`
reads to detect EOF. A disconnect cannot be relabelled as intentional shutdown;
it fails the proof even if readiness had already been emitted. Handshakes are
capped at 16 KiB, messages and captured TUI output at 1 MiB, target IDs at 256
bytes, and readiness events use a bounded channel and deadline. After readiness
the proxy stops parsing and becomes an opaque relay; message contents are not
logged.

Failure closes the gate and mints no capability. Every subprocess starts as its
own process-group leader. Calcifer uses non-reaping
`waitid(EXITED | NOHANG | WNOWAIT)` to observe a leader exit, sends `SIGKILL` to
that process group so descendants cannot keep stdout or PTY descriptors open,
and then waits for the direct child leader. Explicit shutdown propagates
process-group kill, direct wait/reap confirmation, stdout/stderr or PTY reader
join, and proxy pump/cleanup errors; an otherwise successful probe cannot mint a
capability after uncertain cleanup. macOS `EPERM` from process-group kill is
tolerated only after `WNOWAIT` already proved the group leader exited, covering
the zombie-only group behavior. Live-tree termination continues to treat
`EPERM` as failure. Calcifer does not claim to reap non-child descendants.
That compatibility-probe exception is deliberately separate from #54's
provider-release proof. `WNOWAIT` proves only the leader's terminal state, not
the absence of an unsignalable live group member, so the probe's process-group
kill is not production containment evidence. The pinned #54 App shutdown sends
the direct App child one `SIGTERM` and requires its code-zero exact wait; it
does not reuse group `ESRCH`/`EPERM` or the compatibility probe to claim that an
arbitrary detached descendant is absent.
The job-control fixture escalates an ignored `SIGTSTP` with process-group
`SIGSTOP` for a synthetic same-credential tree. The checksum-pinned #54
`official-tui-normal` scenario checks that the same production
suspend/resume implementation stops a stable, current-user official TUI process
group and resumes it through a fresh input gate. It passed twice consecutively
from the 2026-07-20 Issue #54 candidate source on Apple silicon. Neither test upgrades one observed
process-group boundary into general
detached-descendant containment evidence.
Cleanup unlinks a socket or recursively removes a scratch root only while its
recorded filesystem identity matches at the check. An identity mismatch is
preserved rather than risking deletion of an already-replaced node, subject to
the documented same-user `lstat`/`unlink` race. An interrupted or failed
best-effort scratch cleanup can therefore leave private synthetic files for
manual removal, but never rolls back by touching a user profile, credential,
rollout, or Calcifer registry.

Ubuntu 24.04 and macOS CI jobs are configured to download the official architecture-
specific `0.144.4` release archive, verify a pinned SHA-256 digest and its single
expected executable, and run three independently budgeted matrix scenarios
behind one aggregate gate. `contracts` runs the full ignored-by-default handoff
probe plus #54's live-turn one-`SIGTERM` App drain, official
`thread/shellCommand` `setsid(2)` descriptor/environment-isolation probe, and
typed-monitor rate-limit/reset-credit success plus redacted-provider-error
probe. `official-tui-normal` is designed to run the official remote TUI through
the production coordinator/guardian session, PTY, input gates, resize, and
group-wide stop/continue path under a test-owned outer terminal.
`official-tui-recovery` independently targets #55's retained-cleanup recovery
and four-proof deletion gate. Both official scenarios are designed to carry the
completion endpoint across real package-parent-to-coordinator and coordinator-
to-guardian `exec` boundaries; after consuming provider-release proof, the
guardian is designed to send the exact frame and close the endpoint, and the
package parent is configured to check that frame plus EOF. Their test-only role
dispatcher does not execute the production
`CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE` dispatcher/parser or persistent shell-
anchor role. Two consecutive local normal runs and one local retained-recovery
run passed on Apple silicon; the Ubuntu 24.04/macOS matrix remains pending. On
Linux, compilation and exact libtest discovery happen before a mandatory fresh
network namespace. The root stage enumerates the current namespace through
kernel interface APIs rather than an inherited sysfs mount. Only `lo` and the
exact nine upstream fallback-tunnel names are accepted; unknown interfaces fail
before mutation, while present fallbacks are forced down and proved to have no
address or route before only loopback is enabled. The root stage then drops to
the runner UID/GID with no supplementary groups or capabilities and with
`NoNewPrivs`; the user stage rechecks those facts, the exact environment, and
absence of inherited socket FDs before directly executing the prebuilt libtest.
There is no native-network fallback. macOS supplies native functional
evidence and does not claim a comparable egress boundary. The detached probe is
explicitly released before App shutdown, so it is FD/environment isolation
evidence, not detached-descendant absence evidence. The complete
handoff probe has a 180-second budget; the ignored
schema/fork-only diagnostic has 120 seconds. Windows and every unreviewed
release fail closed. These are compatibility tests for a trusted,
checksum-pinned official executable, not an OS sandbox. The Linux namespace is
direct IPv4/IPv6 egress confinement for the official scenarios; it does not
constrain AF_UNIX, an adversarial same-UID actor, or root, and metadata
revalidation is drift detection rather than a TOCTOU-free content seal. The #28 compatibility
loopback sentinel proves that its expected flow performs no configured model
request, but it
cannot constrain arbitrary egress from a malicious or compromised executable.

## Failover requirements

A profile pool is user-created, provider-specific, and bound to one trust domain. Automatic failover is opt-in. The only switching signal is fresh, authoritative, version-supported exhaustion state.

The selector must distinguish:

```text
available | exhausted | unknown
```

The observation records its provider, profile ID, source, observation time, optional reset time, detected provider version, adapter version, tested-version set, and compatibility state. On-demand Codex status accepts only the tested `0.144.4` initialize/home and typed usage contract. Every incompatible or unverified contract and every error that cannot be proven to mean exhaustion becomes `unknown` and stops selection.

The selector keeps an attempted-profile set, traverses a pool no more than once, and observes a cooldown. Cached state may prefilter candidates, but identity and fresh authoritative usage are revalidated after acquiring the profile lease. It never changes the credentials of a running process and never replays a started command.

A successful switch continues the same logical conversation. Credential profile identity remains immutable for each provider process, while the conversation advances to a new target-profile Codex thread generation. A serialized handoff retains the existing source-profile lease and reserves a freshly revalidated target profile. The source TUI and App Server must then be stopped and reaped while Calcifer retains source ownership. The source rollout is accepted only from Calcifer-owned metadata after canonical containment, owner, mode, regular-file, single-hard-link, and symlink validation. The target App Server imports that history through a version-gated provider API and must return the expected lineage plus a distinct rollout contained under the target profile before activation; Calcifer verifies that the source rollout content is unchanged and never copies credentials into a shared runtime home. The prepared transition is synced before the non-idempotent fork request, so crash recovery adopts only one uniquely matching target fork and otherwise fails closed. Source ownership is released only after the target generation is committed and attached.

The target-reservation and guardian lease-transfer primitive described above is
implemented, but no production command calls it yet. Issue #33 must integrate
it beneath the handoff coordinator and conversation-transition locks, own the
guardian lifecycle through ambiguous ACK outcomes, and preserve the global
lock order before automatic switching can be enabled.

The supervisor may subscribe to thread events for usage monitoring, but it never answers approvals or any other server-initiated request. Only the attached official TUI may respond, and no new turn is admitted while that TUI is absent. Source effective execution settings are fixed at fork time; target authentication and provider routing cannot be replaced by a remote-client override.

If the provider version, experimental schema, path provenance, target identity, or transition state is ambiguous, the handoff stops with the source rollout intact. A fresh thread may be offered as an explicit recovery choice, but it is not reported as a successful automatic resume.

The displayed remaining percentage is derived from a rounded provider value. `0% remaining` alone is not exhaustion. Current status requires a recognized structured `rateLimitReachedType` to report `exhausted`; all missing, malformed, stale, auth, network, and unsupported states are `unknown` for future switching logic.

Current on-demand status is intentionally limited to idle profiles. An active
profile retains an exclusive single-writer lease and reports busy/unknown
rather than starting another App Server that could refresh the same credential
file. The internal #54 supervisor owns a typed monitor beside its provider
session, but no public command consumes that observation yet. Public active
monitoring and automatic failover require the remaining selector, pool,
transition-journal, and cross-profile recovery transaction before they can be
enabled.

The typed monitor retains Codex thread and turn UUIDs only for bounded in-memory
target matching and one-shot routing. Those UUIDs are provider identifiers, so
transport, action, and session signal `Debug` surfaces use fixed payload-free
representations; the values never enter display text, error chains, lifecycle
evidence, logs, or persisted usage snapshots.

Immediately before launch, Calcifer reports the local profile alias, provider, trust domain, and selection reason. It does not display email or stable provider account, workspace, or organization identifiers, and repository-local configuration cannot suppress this notice.

## Security-sensitive review areas

Changes to authentication, storage, profile deletion, identity verification, environment sanitation, process spawning, output parsing, locking, usage classification, or failover require focused tests and explicit review of the invariants in [architecture.md](architecture.md).

Minimum security-sensitive test classes include. Implemented slices keep their
applicable classes in CI; future slices must add the remaining evidence before
public exposure:

1. Property tests proving non-exhaustion never switches, pools never loop, and trust domains never cross.
2. Multi-process tests for profile leases, mutation races, crashes, and lock release.
3. Filesystem adversarial tests for traversal, symlinks, ownership, Unix modes, Windows ACLs, and crash-injected atomic writes.
4. Identity tests for duplicate aliases, wrong-account drift, unbound legacy profiles, missing/replaced/unsafe keys, malformed or partial credentials, redaction, commit uncertainty, and concurrent registration/verification.
5. Redaction tests that seed synthetic token-shaped values and scan every output channel.
6. Adapter compatibility tests for versions, changed output, auth errors, timeouts, rate limits, and provider failures.
7. Process tests for exact argv, PATH resolution, arbitrary-command rejection, symlink swaps, signal forwarding, exit status, and authentication environment cleanup.
8. Deletion tests proving Calcifer never recursively removes a path outside its ownership-marked managed root.
9. Session tests proving lineage/profile separation, one writer per rollout generation, canonical path containment, hard-link rejection, serialized lease transfer, and no prompt replay across crash or handoff paths.
10. Transition-recovery tests for crashes before source stop, after source stop, after sending the non-idempotent target fork, before registry commit, and before remote TUI attach.
11. Subscription tests proving the monitor cannot answer approvals, a TUI must attach before input, and target authentication/provider routing cannot be overridden during rejoin.
12. Target-reservation race tests proving a single nonblocking winner across
    competing reservations, rename, status, run/resume, and identity
    verification, with no provider probe started by a losing reservation.
13. Lease-transfer adversarial tests for a wrong or replaced inode, an unlocked
    same-inode descriptor, malformed marker, missing or multiple descriptors,
    ancillary truncation, owner/type/mode/link violations, and close-on-exec
    readback before ACK.
14. Transfer recovery tests proving send failure returns A+B, ACK cannot commit
    early, invalid or lost ACK preserves ownership, coordinator-only and
    guardian-only crashes keep a second writer blocked, and no matching lease
    descriptor survives an actual provider-child `exec`. A deterministic
    pre-exec barrier additionally proves the parent remains close-on-exec and a
    concurrent unrelated child receives no matching device/inode.
15. Real-PTY terminal tests proving semantic snapshot-arm equality, no spawn or
    input before the respective ACKs, wrong-order/malformed/trailing/disconnected
    failure, early TUI exit, PTY EOF/EIO, bounded backpressure and worker
    failure, signal/job-control behavior including a `SIGTSTP`-ignoring
    descendant, foreground reclaim without stale restoration, restore and
    cleanup mismatch, selective coordinator/guardian death, exact disposition,
    and transcript absence on Linux and macOS.
