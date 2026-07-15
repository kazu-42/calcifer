# ADR 0002: Private provider-identity binding

- Status: accepted and implemented for the Unix Codex 0.144.4 adapter
- Date: 2026-07-15
- Related: [Issue 14](https://github.com/kazu-42/calcifer/issues/14), [ADR 0001](0001-cross-profile-conversation-handoff.md)

## Context

Calcifer profile aliases are local names. Without an additional binding, two
aliases can contain credentials for the same ChatGPT account/workspace and
therefore traverse the same provider quota. A profile can also be externally
re-authenticated to another account while keeping its old alias and future pool
membership. Either state makes automatic failover unsafe.

Codex 0.144.4 exposes no stable public identity read suitable for equality.
`account/read` returns email and plan type, while `codex login status` returns
only the authentication kind. Its persisted file-backed auth model does contain
an optional `tokens.account_id` used by the official CLI as its effective
ChatGPT routing scope. That file is a version-scoped compatibility surface, not
a documented cross-version identity API.

The raw routing scope is sensitive. Persisting or displaying it would create a
stable provider identifier and cross-install correlation surface. Email and
token-derived JWT claims are worse substitutes and must not become identity
keys.

## Decision

Calcifer binds each supported Codex profile to a provider-private equality
token before publishing a new registration.

1. Identity support is Unix-only until an equivalent Windows current-user-only
   ACL implementation is verified.
2. The provider module performs the existing App Server
   initialize/home/version gate and returns an unforgeable in-crate capability
   for the exact 0.144.4 identity adapter. Other production modules cannot
   construct this capability.
3. The identity adapter reads a bounded minimal projection containing only
   `auth_mode` and `tokens.account_id` from a private, owner-checked,
   single-link regular `auth.json`. Only managed `chatgpt` auth is supported.
4. One 256-bit installation key is generated from the OS CSPRNG. Its private
   key file records a random Calcifer-local key ID so key replacement can be
   distinguished from credential drift.
5. The equality token is HMAC-SHA-256 over a domain-separated,
   length-delimited tuple of provider, supported auth kind, adapter version,
   and effective account/workspace scope.
6. A profile-private `.calcifer-identity` marker records only schema version,
   local key ID, adapter ID, supported auth kind, and fingerprint. The public
   registry and command DTOs remain unchanged.
7. Registration compares every existing verified binding while holding the
   registry lock. An equal fingerprint returns `duplicate_provider_identity`,
   names only the two local aliases, and removes the unpublished staging
   directory. Different fingerprints mean only different routing scopes; they
   do not prove independent provider quota.

Raw account/workspace scope, email, access token, refresh token, ID token, API
key, reset-credit ID, fingerprint, and key ID are forbidden from registry
records, human/JSON output, errors, logs, telemetry, and snapshots.

## Legacy migration and revalidation

Profiles created by previous releases remain usable for explicit run, exact
same-profile resume, and read-only status. They are unverified and ineligible
for automatic selection.

`calcifer auth verify codex@<alias>` is an explicit, non-interactive migration.
It acquires the profile's split exclusive lease, lets only the version-probe
App Server inherit the provider side, checks the adapter, derives the current
identity, then acquires the registry lock for the final duplicate check and
marker publication. It never starts browser login, copies credentials, or
calls an OAuth refresh endpoint. Repeating it is idempotent when credentials
and marker still match.

The lease-retaining revalidation API rederives the identity after acquiring the
profile lock and returns a guard that keeps the lock alive for future launch
authorization. Missing binding, unsupported adapter/auth, malformed auth, key
loss/replacement, or fingerprint mismatch stops the selection attempt. It does
not silently skip a bad candidate or rewrite the marker. Multi-profile callers
must acquire immutable profile IDs in deterministic order before comparing the
opaque equality tokens.

## Persistence and recovery

Key and marker files use private same-directory temporary files, file fsync,
atomic rename, and parent-directory fsync. Readers accept only the exact final
name and ignore stale temporary files. Owner, mode, regular-file, symlink, and
hard-link checks run before use.

A parent-directory sync failure after a complete key or marker rename returns
`identity_commit_uncertain`. Registration reads back the complete private state
and retries only the idempotent parent sync; it never repeats provider login.
If that recovery sync also fails, the registry remains unpublished and the
complete staging credentials are preserved for explicit recovery. Any orphan
staging directory observed under the registration lock blocks all later
registration before provider login, so unresolved credentials cannot be
silently duplicated. Explicit verification can likewise be retried: it reads
and validates the complete marker before deciding whether any mutation remains.
Registry publication retains its existing recovery rule: uncertain registry
durability preserves visible credentials rather than deleting a possibly
referenced profile.

Missing, corrupt, replaced, unsafe, or unreadable installation keys all become
`identity_key_unavailable`. Calcifer never generates a replacement while any
binding exists. A future deliberate re-key command must verify and replace the
selected set atomically or leave all prior state untouched. Automatic key
rotation is rejected.

## Concurrency and lock order

New registration holds the registry lock while operating only on an
unpublished staging directory. Verification acquires the published profile
lease first and the registry lock second. Registration never waits for a
published profile lease, so these paths cannot form a cycle. Status, run, and
resume already take the profile lease and therefore exclude verification from
the same refreshable credential home.

Future re-authentication must stage replacement credentials and binding, follow
the published-profile lease-before-registry order, and require explicit user
confirmation for an identity change. Future pool validation and runtime
selection must repeat uniqueness and revalidation; configuration-time success
alone is not sufficient.

## Consequences

- Duplicate aliases and external identity drift are detectable without
  exposing a provider identifier.
- An installation-key loss disables identity-dependent automation until
  deliberate recovery; this availability cost is the intended fail-closed
  behavior.
- Provider identity remains coupled to an exact tested auth format. A new Codex
  release or auth mode requires a separately reviewed adapter and migration.
- HMAC limits accidental disclosure and cross-install correlation. It is not
  encryption and does not protect against root or malware running as the same
  OS user.
- API-key, agent-identity, header-auth, and future provider modes remain
  unsupported for deduplication.

## Rejected alternatives

- **Email or plan type:** not a routing identity, unnecessarily public, and may
  change independently of provider scope.
- **Raw account/workspace ID in the registry:** creates a stable disclosure and
  correlation surface.
- **Unkeyed hash:** permits cross-install correlation and dictionary testing.
- **JWT claim parsing:** broadens the credential parser and couples identity to
  token internals rather than the official persisted routing field.
- **Direct OAuth or backend identity call:** undocumented, mutating, or outside
  the supported local wrapper boundary.
- **Silently rebinding after external login:** preserves a misleading alias and
  can cross a configured trust domain.
- **Treating different scope as independent quota:** stronger than the provider
  contract supports.
