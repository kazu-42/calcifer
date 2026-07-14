# Security model

Calcifer will handle high-value local credentials. Its safest useful design is a small process wrapper with explicit trust boundaries, strict profile isolation, redacted diagnostics, and fail-closed provider adapters.

This document describes intended guarantees. The pre-alpha scaffold does not read, store, or mutate credentials.

## Assets

- Codex and Claude access, refresh, ID, and setup tokens
- account, workspace, and organization identity
- profile selection and trust-domain policy
- source code, prompts, conversation context, and child process output
- Calcifer registry integrity

## Threats in scope

- accidental credential disclosure through logs, errors, diagnostics, fixtures, or Git
- one profile receiving another profile's refreshed credentials
- malicious profile names escaping the managed root
- symlink, ownership, permission, and partial-write attacks on managed state
- concurrent refresh or mutation corrupting one profile
- PATH hijacking or shell injection when launching a provider CLI
- repository configuration forcing a more privileged or differently governed account
- automatic failover causing organization-boundary data disclosure
- incorrect quota classification causing failover loops
- automatic replay duplicating file, Git, deployment, billing, or messaging side effects

## Threats outside the guarantee

Calcifer cannot protect credentials from:

- root, administrator, or malware running as the same OS user;
- a compromised official provider CLI, plugin, hook, or child tool;
- a malicious repository executed by the wrapped agent;
- provider compromise or provider-side account recovery;
- all exposure through OS swap, crash dumps, or debugging facilities.

Calcifer is not a sandbox and does not make an untrusted repository safe.

## Secret-handling requirements

- Managed directories are private to the current user; secret files are private at creation time.
- Tokens are never accepted as ordinary command-line flags because process listings and shell history can expose them.
- Raw arguments, child environments, credential files, account email, and stable provider IDs are not logged.
- Diagnostics report capability and redacted status, not secret values or credential paths.
- Test credentials are synthetic and contain obvious non-production markers.
- Claude token storage fails closed when a supported OS credential store is unavailable. Plaintext fallback is a non-goal unless a later ADR and security review define it.
- Export, backup, telemetry, and crash-report features exclude credentials by design.
- Credential-bearing environments are passed only to a provider adapter's validated executable, never to an arbitrary command supplied after `--`.

## Failover requirements

A profile pool is user-created, provider-specific, and bound to one trust domain. Automatic failover is opt-in. The only switching signal is fresh, authoritative, version-supported exhaustion state.

The selector must distinguish:

```text
available | exhausted | unknown
```

The observation records its provider, profile ID, source, observation time, optional reset time, and adapter version. Every error that cannot be proven to mean exhaustion becomes `unknown` and stops selection.

The selector keeps an attempted-profile set, traverses a pool no more than once, and observes a cooldown. Cached state may prefilter candidates, but identity and fresh authoritative usage are revalidated after acquiring the profile lease. It never changes the credentials of a running process and never replays a started command.

Immediately before launch, Calcifer reports the local profile alias, provider, trust domain, and selection reason. It does not display email or stable provider account, workspace, or organization identifiers, and repository-local configuration cannot suppress this notice.

## Security-sensitive review areas

Changes to authentication, storage, profile deletion, identity verification, environment sanitation, process spawning, output parsing, locking, usage classification, or failover require focused tests and explicit review of the invariants in [architecture.md](architecture.md).

Minimum future test classes include:

1. Property tests proving non-exhaustion never switches, pools never loop, and trust domains never cross.
2. Multi-process tests for profile leases, mutation races, crashes, and lock release.
3. Filesystem adversarial tests for traversal, symlinks, ownership, Unix modes, Windows ACLs, and crash-injected atomic writes.
4. Identity tests for wrong-account, ambiguous, stale, rotated, corrupt, and partial credentials.
5. Redaction tests that seed synthetic token-shaped values and scan every output channel.
6. Adapter compatibility tests for versions, changed output, auth errors, timeouts, rate limits, and provider failures.
7. Process tests for exact argv, PATH resolution, arbitrary-command rejection, symlink swaps, signal forwarding, exit status, and authentication environment cleanup.
8. Deletion tests proving Calcifer never recursively removes a path outside its ownership-marked managed root.
