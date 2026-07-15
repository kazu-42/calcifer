# Security model

Calcifer will handle high-value local credentials. Its safest useful design is a small process wrapper with explicit trust boundaries, strict profile isolation, redacted diagnostics, and fail-closed provider adapters.

This document covers both implemented and intended guarantees. The current Unix Codex slice creates isolated file-backed credentials through the official login flow, may let the official CLI refresh them during run, resume, or status, and captures an exact same-profile thread key for crash-safe cold restore. Automatic failover and cross-profile conversation handoff are not implemented; [ADR 0001](adr/0001-cross-profile-conversation-handoff.md) defines their required boundary.

## Assets

- Codex and Claude access, refresh, ID, and setup tokens
- account, workspace, and organization identity
- profile selection and trust-domain policy
- source code, prompts, conversation context, and child process output
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
- mutable, redirected, oversized, partial, or digest-mismatched release metadata causing installation of the wrong target

## Threats outside the guarantee

Calcifer cannot protect credentials from:

- root, administrator, or malware running as the same OS user;
- a compromised official provider CLI, plugin, hook, or child tool;
- a malicious repository executed by the wrapped agent;
- provider compromise or provider-side account recovery;
- all exposure through OS swap, crash dumps, or debugging facilities.

Calcifer is not a sandbox and does not make an untrusted repository safe.

## Secret-handling requirements

- Managed profile roots and homes are private to the current user; secret files are private at creation time. Provider-owned nested rollout directories/files from older installations may retain non-writable `0755`/`0644` modes behind that private home boundary.
- Tokens and reset-credit IDs are never accepted as ordinary command-line flags because process listings and shell history can expose them.
- Raw arguments, child environments, credential files, account email, and stable provider IDs are not logged.
- Conversation metadata stores only Calcifer/profile/thread UUIDs, canonical cwd, tested adapter versions, bounded inventory timestamps, path-free file identity/size/mtime/ctime fingerprints, and lifecycle state. It excludes aliases, rollout paths, App Server previews, transcript bodies, prompts, responses, approvals, tool arguments, terminal streams, credentials, and provider identity.
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
- If the provider guardian is killed after reporting the exact provider PID, the coordinator retains its lease until that PID exits. If failure lands in the unobservable post-authorization/pre-report window, the coordinator deliberately remains alive and locked rather than guessing that no provider exists.
- The public wrapper, coordinator, and guardian catch `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT`; caught dispositions reset to child defaults on each `exec`, so terminal cancellation still reaches Codex while every wrapper remains attached if Codex handles the signal and continues.
- Bounded metadata-only App Servers for status and thread capture inherit only the provider-side lease. They issue no turn/tool methods and are started only while Calcifer owns the profile coordinator/provider order. This keeps a killed probe parent from admitting a second credential writer until stdio EOF terminates the probe.
- Automatic same-profile restore never guesses the newest thread. A private pending baseline is synced before provider spawn; only one new or uniquely changed root CLI thread can be adopted after direct metadata validation. Same-second changes use a path-free device/inode/length/nanosecond-mtime fingerprint in addition to provider timestamps. Zero candidates preserve the previous head only when every baseline ID remains present. Deleted, multiple, archived, wrong-profile/cwd, missing, corrupt, unsupported, capped, pre/post-mutated, or inconsistent results stop before automatic provider launch.
- Codex 0.144.4 hides its 10,000-file rollout scan cap from the v2 App Server response. Calcifer proves a conservative upper bound by snapshotting active and archived roots separately before and after listing, requiring each root to remain below the cap, and mapping every wire path to the stable snapshot. Nested nodes must remain owned, real, non-symlink, and non-writable by group/other; files must have one hard link. The enclosing managed home remains owner-private.
- Bare resume releases its initial conversation lock before waiting for a profile lease, then revalidates the unchanged UUID binding under that lease. Registry mutation order is coordinator lease, provider lease, then a short conversation lock; no conversation lock spans App Server or interactive provider I/O.
- A conversation document update uses create-only private same-directory temporary files, file fsync, rename, and directory fsync. Post-rename sync uncertainty is read back and reported without retrying a provider launch. Newer schemas and unsafe owner/type/mode/hard-link state are never rewritten.
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

## Failover requirements

A profile pool is user-created, provider-specific, and bound to one trust domain. Automatic failover is opt-in. The only switching signal is fresh, authoritative, version-supported exhaustion state.

The selector must distinguish:

```text
available | exhausted | unknown
```

The observation records its provider, profile ID, source, observation time, optional reset time, detected provider version, adapter version, tested-version set, and compatibility state. On-demand Codex status accepts only the tested `0.144.4` initialize/home and typed usage contract. Every incompatible or unverified contract and every error that cannot be proven to mean exhaustion becomes `unknown` and stops selection.

The selector keeps an attempted-profile set, traverses a pool no more than once, and observes a cooldown. Cached state may prefilter candidates, but identity and fresh authoritative usage are revalidated after acquiring the profile lease. It never changes the credentials of a running process and never replays a started command.

A successful switch continues the same logical conversation. Credential profile identity remains immutable for each provider process, while the conversation advances to a new target-profile Codex thread generation. A serialized handoff retains the existing source-profile lease and reserves a freshly revalidated target profile. The source TUI and App Server must then be stopped and reaped while Calcifer retains source ownership. The source rollout is accepted only from Calcifer-owned metadata after canonical containment, owner, mode, regular-file, single-hard-link, and symlink validation. The target App Server imports that history through a version-gated provider API and must return the expected lineage plus a distinct rollout contained under the target profile before activation; Calcifer verifies that the source rollout content is unchanged and never copies credentials into a shared runtime home. The prepared transition is synced before the non-idempotent fork request, so crash recovery adopts only one uniquely matching target fork and otherwise fails closed. Source ownership is released only after the target generation is committed and attached.

The supervisor may subscribe to thread events for usage monitoring, but it never answers approvals or any other server-initiated request. Only the attached official TUI may respond, and no new turn is admitted while that TUI is absent. Source effective execution settings are fixed at fork time; target authentication and provider routing cannot be replaced by a remote-client override.

If the provider version, experimental schema, path provenance, target identity, or transition state is ambiguous, the handoff stops with the source rollout intact. A fresh thread may be offered as an explicit recovery choice, but it is not reported as a successful automatic resume.

The displayed remaining percentage is derived from a rounded provider value. `0% remaining` alone is not exhaustion. Current status requires a recognized structured `rateLimitReachedType` to report `exhausted`; all missing, malformed, stale, auth, network, and unsupported states are `unknown` for future switching logic.

Current on-demand status is intentionally limited to idle profiles. An active profile retains an exclusive single-writer lease and reports busy/unknown rather than starting another app-server that could refresh the same credential file. A future long-lived supervisor must own both the provider session and its usage observations before active monitoring or automatic failover can be enabled.

Immediately before launch, Calcifer reports the local profile alias, provider, trust domain, and selection reason. It does not display email or stable provider account, workspace, or organization identifiers, and repository-local configuration cannot suppress this notice.

## Security-sensitive review areas

Changes to authentication, storage, profile deletion, identity verification, environment sanitation, process spawning, output parsing, locking, usage classification, or failover require focused tests and explicit review of the invariants in [architecture.md](architecture.md).

Minimum future test classes include:

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
