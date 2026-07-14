# Spec: Managed Codex repository configuration preflight

## Summary

Calcifer permits ordinary, reviewed repository settings without allowing a
repository-local Codex layer to own the selected account, provider route,
dynamic feature policy, project boundary, or managed state location. This is a
pre-spawn account-isolation boundary, not a repository sandbox.

## Compatibility baseline

The discovery and key policy are scoped to official Codex CLI `0.144.4`, tag
`rust-v0.144.4`, commit
`8c68d4c87dc54d38861f5114e920c3de2efa5876`. An unknown top-level key is
rejected until a compatibility review updates the allowlist. Known keys can
also change meaning, so executable-version verification remains a release gate
before automatic selection or failover.

## Discovery

For every interactive `run` and `resume`:

1. Resolve and validate the selected profile, then acquire its launch lease.
2. Canonicalize the current working directory; failure is fatal.
3. Walk toward the filesystem root and select the nearest `.git` marker.
   A real directory and a regular worktree marker file are accepted. A symlink
   or special node fails closed; Windows reparse points are also rejected.
4. If a marker exists, inspect each directory from that repository root through
   the canonical cwd in root-to-leaf order. Otherwise inspect only the cwd.
5. At each layer, `.codex` must be a real directory when present. An
   auto-discovered `.codex/agents` path must not exist as any filesystem node,
   regardless of whether `config.toml` exists, because each role file is a
   complete indirect configuration layer. `config.toml` must be a real regular
   file when present. Symlinks, dangling symlinks, special nodes, and filesystem
   errors fail closed.
6. Read at most 1 MiB plus one sentinel byte. Invalid UTF-8, invalid TOML, and
   oversized input fail closed.

The coordinator checks after acquiring its lease and before publishing the
private lifecycle socket. The provider guardian independently checks before it
announces readiness and again after launch authorization, immediately before
spawn. The final provider receives the verified canonical cwd explicitly.

## Account-only neutral boundary

Login and read-only account status do not consume repository context. Calcifer
runs those official CLI processes with the selected profile-specific
`CODEX_HOME`, but from a private runtime cwd containing its own real `.git`
directory. The runtime root, neutral cwd, and marker are real private
directories owned by the current OS user. They are independent of
user-selected `CALCIFER_HOME`, including when that state root is nested inside
a repository that has otherwise rejected local Codex configuration.

## Semantic policy

The accepted top-level keys form an explicit, sorted Codex 0.144.4 allowlist.
They cover reviewed presentation, model-name, reasoning, instructions,
sandbox/approval, documentation, tool, and web-search settings.

Calcifer rejects top-level settings in these managed categories:

- CLI and MCP OAuth credential stores;
- provider maps, backend selection, provider endpoints, and remote routing;
- forced login, workspace, profile, or account policy;
- alternate database, thread, log, catalog, or state locations;
- imported/indirect configuration and remote thread configuration;
- marketplace, plugin, and MCP server definitions that can replace the endpoint
  associated with managed MCP OAuth state;
- project-root discovery markers;
- dynamic feature maps until a version-specific safe feature allowlist exists.

Unknown top-level keys also fail closed. The official CLI remains responsible
for validating values and nested schemas of allowed settings.

## Child argument policy

Every public, coordinator, and guardian boundary rejects:

- config, profile, provider, OSS, and remote-routing overrides already owned by
  Calcifer;
- `-C`, joined `-C<path>`, `--cd`, and `--cd=<path>`;
- separated and joined `--enable` / `--disable` feature overrides;
- non-UTF-8 provider arguments that cannot be parsed safely.

A future user-facing cwd option must be owned by Calcifer so it can canonicalize
the path, perform this preflight, and persist the same cwd in conversation
lineage metadata.

## Failure behavior

- Failure occurs before the official provider process is spawned.
- The stable public code is `unsafe_project_configuration`.
- Public output never includes a path, rejected key, raw value, TOML contents,
  parser detail, or credential-shaped input.
- Calcifer does not repair or rewrite repository configuration.

## Residual risk and recovery

The double check and same-file metadata comparison reduce replacement races,
but mutation by any actor able to write the repository tree, including
same-user malware or another writer in a shared workspace, after the final
check and before Codex reads the file is outside Calcifer's guarantee. Complete
mediation requires an upstream-supported project-config disable switch or
effective-configuration API with provenance.

For a linked worktree, Codex 0.144.4 has an additional special case that reads
the primary checkout's `.codex/config.toml` and merges only its `hooks` field.
Calcifer currently stops discovery at the linked worktree's regular `.git`
marker file and does not resolve or inspect that external hook source. The
upstream merge cannot import account/provider/state settings, and repository
hooks are outside this preflight's sandbox guarantee, but this behavior must be
re-reviewed if Codex expands the merged field set.

Recovery is non-destructive: remove or revise the unsupported repository
setting and retry. Profile credentials and session files are not changed on a
preflight failure.

## Acceptance criteria

- [x] Repository root, nested layers, no-repository cwd, and worktree-file
      markers are covered by unit tests.
- [x] Invalid, oversized, unknown, managed, symlinked, and non-regular inputs
      fail closed with redacted output.
- [x] Every repository `.codex/agents` node type fails closed with or without a
      sibling config, and run/resume never spawn the provider or disclose role
      names and paths.
- [x] Exactly 1 MiB and representative benign configuration remain accepted.
- [x] Fresh run, exact resume, and latest resume fail before a synthetic provider
      starts when repository policy fails.
- [x] Safe configuration launches the synthetic provider in the canonical cwd.
- [x] Cwd, dynamic-feature, and non-UTF-8 argument forms are rejected.
- [x] Login and status remain neutral when `CALCIFER_HOME` is nested below a
      repository containing rejected configuration.
- [x] A deterministic mutation after launch authorization fails the guardian's
      final preflight, never starts the provider, sends `ABORT`, removes the
      lifecycle socket, releases both profile leases, and permits a safe retry.
