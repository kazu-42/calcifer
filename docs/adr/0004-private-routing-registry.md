# ADR 0004: Private default-disabled routing registry

- Status: accepted and implemented on Unix; selection remains unavailable
- Date: 2026-08-06
- Related: [Issue 31](https://github.com/kazu-42/calcifer/issues/31), [ADR 0001](0001-cross-profile-conversation-handoff.md), [ADR 0002](0002-private-provider-identity-binding.md)

## Context

Future automatic failover may send source code and conversation history to a
different provider account. The allowed set and its trust boundary are
therefore user security policy, not repository policy. A repository-controlled
file must not select an account or pool.

Profile aliases cannot be durable membership authority because users can rename
them and an old alias can later be reused. Configuration-time identity success
is also not durable: a managed credential can drift, a profile can disappear,
or the installation identity key can be lost after a definition is written.
The registry must remain useful for inspection and cleanup without implying
that a future launch is authorized.

## Decision

Calcifer stores an optional schema-v1 `routing.json` and `routing.lock` only in
its validated private user data root. The current working directory and
repository root are not constructor inputs.

The document contains a monotonic revision and two bounded collections:

1. A trust domain has an immutable canonical UUID, mutable local alias, one
   provider, and a canonical set of immutable profile UUIDs. One profile UUID
   can belong to at most one trust domain.
2. A pool has its own immutable canonical UUID, mutable local alias, one trust
   domain UUID, an ordered list of two or more distinct member UUIDs, and the
   only accepted activation value, `disabled`.
3. Pool members must be a subset of their trust domain. Definition IDs share
   one namespace. Provider-derived aliases are unique within their definition
   kind.
4. Document bytes, trust-domain and pool counts, per-definition members, and
   total membership edges have fixed upper bounds. Unknown fields, schema
   versions, activation values, and noncanonical IDs fail closed.

Aliases are accepted only to look up the current immutable UUID and to render
local output. A profile alias rename does not rewrite routing membership. Both
canonical definition UUIDs and `codex@alias` selectors are accepted by the
maintenance CLI.

## Identity validation transaction

Creating a non-empty trust domain, replacing trust-domain members, creating a
pool, or replacing pool members validates the complete affected membership.
Calcifer:

1. reads one routing snapshot and resolves requested profile aliases from one
   profile-registry snapshot;
2. constructs and validates the complete candidate definition in memory;
3. resolves every candidate member and rejects provider or trust-domain
   mismatch before probing credentials;
4. acquires profile leases in sorted immutable UUID order;
5. refetches each current profile row under its lease, checks that the alias
   lookup did not race a rename, version-gates the Codex identity adapter, and
   rederives the current private identity binding;
6. rejects missing or busy profiles, unverified legacy profiles, unsafe or
   missing identity state/key, credential drift, unsupported auth/adapters, and
   any equal effective provider identity; and
7. retains every opaque identity proof and lease while acquiring the routing
   lock and committing only against the original routing revision.

The routing lock is never held while starting a provider identity probe. A
concurrent routing writer can therefore win the revision race without being
blocked by a slow provider, while the losing operation fails with a revision
conflict rather than overwriting it. Profile mutation uses the profile lease
but not the routing lock, so it cannot race a validated member between proof
and commit. Multi-profile callers never acquire the profile-registry mutation
lock while retaining several profile leases.

Domain/pool rename and removal do not require a provider executable or current
identity. This is deliberate recovery behavior: invalid or missing membership
must not prevent metadata cleanup. Successful configuration validation is not
persisted as a boolean and never authorizes future use. A future selector must
repeat current identity and policy validation under the same leases.

## Persistence and failure semantics

The routing root, registry, lock, and temporary files reuse managed-profile
filesystem validation: private type/ownership/mode, no symlink following,
single-link registry and lock nodes, and empty supported macOS ACLs. Unverified
ACL platforms fail closed.

Writers serialize on `routing.lock`, write a bounded complete document to a
random owner-private same-directory temporary, fsync the file, revalidate the
temporary, atomically rename it over `routing.json`, and fsync the parent
directory. Failure before rename leaves the prior complete revision. Failure
after rename returns `routing_commit_uncertain`; callers must inspect the
visible revision before retrying. A no-op does not advance the revision or
replace the registry inode.

The filesystem protections defend against accidental exposure and unsafe
nodes; they are not a security boundary against root or arbitrary malware
already running as the same OS user.

## Public surface and redaction

The public commands can inspect, create, rename, replace membership, and remove
definitions. There is no enable, selector, supervisor, failover, or provider
launch path in this slice. Every pool remains disabled.

Human and JSON inspection DTOs can contain only schema/action metadata,
routing revision, definition UUIDs and aliases, provider, immutable member
UUIDs, current local profile references when present, and disabled activation.
They have no field for raw or fingerprinted provider identity, account,
workspace, organization, email, token, credential, usage, or reset-credit
data. Errors collapse storage and identity details to stable redacted codes.

Repository launch preflight explicitly owns `routing`, `routing_pools`, and
`trust_domains` keys and rejects them, while unknown future repository keys
already fail closed. Repository-local files named `routing.json` are ignored by
the user-level registry and cannot activate, select, or launch a profile.

## Rollback

All pools are optional and disabled. Removing pools and then their trust
domains through the maintenance commands returns operation to explicit profile
pinning without changing profiles, credentials, conversations, or provider
state. If an operator must recover from a commit-uncertain result, first run
`calcifer routing inspect`; do not blindly repeat a create with a new UUID.

## Rejected alternatives

- **Repository-local pools:** let untrusted project content choose the account
  that receives code and history.
- **Alias-backed membership:** rename and alias reuse can redirect authority.
- **Persisted `validated: true`:** identity and credentials can drift after the
  write.
- **Skip invalid candidates:** turns a malformed pool into implicit selection
  policy and can cross the intended boundary.
- **Hold the routing lock during provider probes:** serializes unrelated edits
  behind slow external processes and expands lock-order risk.
- **Validate only the changed member:** misses duplicate effective identities
  and whole-pool inconsistency.
- **Expose fingerprints for diagnostics:** creates a stable correlation and
  disclosure surface without improving safe operator action.
- **Ship a selector with the schema:** would make storage acceptance
  accidentally authorize provider launch before monitoring, handoff, recovery,
  and user-visible selection proofs exist.
