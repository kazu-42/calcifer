# Spec: Managed Codex configuration compatibility

## Summary

Calcifer validates each profile-local `config.toml` by semantic ownership rules,
not by byte identity. The official Codex CLI may persist supported user and
provider state, including the first-run project trust decision, without making
the profile unusable. Account selection, authentication storage, provider
routing, and managed state containment remain Calcifer-owned invariants.

## Compatibility baseline

The known top-level key set is version-scoped to Codex CLI `0.144.4`, tag
`rust-v0.144.4`, commit
`8c68d4c87dc54d38861f5114e920c3de2efa5876`, and its published
`codex-rs/core/config.schema.json`.

This policy validates Calcifer's ownership boundary. It is not a replacement
for Codex's complete value schema: values for known, non-owned user settings
remain the official CLI's responsibility. A top-level key absent from the
pinned schema is rejected until a compatibility review updates the adapter.

## Inputs

- A profile-local `config.toml` below a Calcifer-owned `CODEX_HOME`.
- The current filesystem metadata for that file.
- At most 1 MiB of TOML bytes.

## Filesystem invariants

- The file exists and is a regular file, not a symlink.
- On Unix, group and other users have no access bits.
- The containing home and profile directories retain their existing ownership,
  containment, and private-mode validation.
- `CODEX_HOME/agents` does not exist as any filesystem node. Directories,
  regular files, symlinks, and other node types all fail closed because Codex
  auto-discovers role configuration from that location.
- Validation reads at most 1 MiB plus one sentinel byte.
- Validation is read-only. Calcifer does not normalize, repair, or rewrite the
  official CLI's comments, formatting, or provider-owned settings.
- The same complete-home validation runs after official login and before a
  staging profile is published in the registry, then again under the profile
  lease before each status, run, or resume provider invocation.

## Semantic ownership rules

### Calcifer-owned settings

`cli_auth_credentials_store` is required and must be the string `"file"`.
`mcp_oauth_credentials_store` may be absent for compatibility with existing
profiles, but when present it must also be `"file"`. New profiles persist both
settings. Every provider invocation supplies runtime overrides for both stores,
so Codex account credentials and MCP/connector OAuth credentials remain inside
the selected `CODEX_HOME` instead of being implicitly shared through an OS
keyring.

The following supported Codex keys are rejected when present because they can
replace the selected account/provider or authentication route, import external
configuration, or move managed session state outside the profile:

- `agents`
- `apps_mcp_product_sku`
- `chatgpt_base_url`
- `debug`
- `experimental_realtime_webrtc_call_base_url`
- `experimental_realtime_ws_base_url`
- `experimental_thread_config_endpoint`
- `experimental_thread_store`
- `features`
- `forced_chatgpt_workspace_id`
- `forced_login_method`
- `log_dir`
- `marketplaces`
- `mcp_oauth_callback_port`
- `mcp_oauth_callback_url`
- `mcp_servers`
- `model_catalog_json`
- `model_provider`
- `model_providers`
- `openai_base_url`
- `oss_provider`
- `plugins`
- `profile`
- `profiles`
- `project_root_markers`
- `sqlite_home`

`project_root_markers` remains Calcifer-owned because managed launch preflight
uses the pinned Codex repository-root discovery rule. Allowing a profile to
change those markers would make Calcifer and Codex inspect different project
configuration layers.

The MCP OAuth callback URL replaces the redirect URI sent in an authorization
request, while the callback port controls the local listener paired with that
flow. Both remain Calcifer-owned endpoint settings so a managed profile cannot
redirect or destabilize connector authorization outside the reviewed route.

Codex role configuration is unsupported for managed profiles in this MVP.
Both a top-level `agents` table and the auto-discovered `CODEX_HOME/agents`
path can select additional role-specific configuration files. Those files are
complete configuration layers rather than a bounded role description, so
accepting them would bypass this policy's single validated configuration
boundary. Supporting roles requires a future provenance-aware design that
discovers and validates every referenced layer before provider launch.

The provider adapter independently forces both file-backed credential stores on
every invocation and rejects account/provider-routing child arguments.
Configuration validation is a second boundary, not the only boundary.

### Provider-owned project trust

`projects` is optional. If present, it must be a table whose:

- keys are non-empty absolute paths;
- values are tables containing exactly one field, `trust_level`;
- `trust_level` value is exactly `"trusted"` or `"untrusted"`.

Stale or nonexistent absolute paths remain valid. Deleting a repository must
not break an otherwise safe profile.

### Known user settings

Other top-level keys published in the pinned schema are allowed unless they are
listed above as Calcifer-owned. Comments, whitespace, key order, inline tables,
and explicit tables are not security invariants. The official CLI reports
invalid values for allowed user-owned settings when it loads them.

## Failure behavior

- Invalid UTF-8, invalid TOML, an oversized file, an unknown top-level key, an
  OAuth callback override, an `agents` filesystem node, or any ownership-rule
  violation returns `unsafe_profile_state` before Codex starts.
- Public errors never include TOML contents, project paths, or parser details.
- No automatic repair is attempted. Users retain the original file for
  inspection and recovery.

## Migration and rollback

- Existing two-line profiles require no migration; the runtime MCP OAuth store
  override still keeps their connector credentials profile-local.
- Profiles that already contain a valid Codex project-trust entry become usable
  immediately without changing `auth.json`, sessions, or registry data.
- Rolling back to the byte-exact validator will reject those valid profiles
  again. Operational recovery for an old binary is to back up `config.toml` and
  restore the original two-line file while no managed process is running.
- Forward-fixing the semantic policy is preferred because accepting the trust
  prompt under the old binary reproduces the failure.

## Acceptance criteria

- [x] A functional fake-Codex test persists the same project trust shape as
      Codex 0.144.4, then successfully performs status, run, and exact resume.
- [x] Comments, whitespace, key ordering, inline tables, and multiple project
      entries are accepted semantically.
- [x] Missing, non-string, `auto`, `keyring`, and `ephemeral` Codex account
      credential-store values are rejected.
- [x] MCP OAuth credential storage may be absent or `file`; `auto`, `keyring`,
      and non-string values are rejected, and every invocation forces `file`.
- [x] Invalid project tables, relative paths, unknown trust values, and extra
      project fields are rejected.
- [x] Every Calcifer-owned routing/state key and every unknown top-level key is
      rejected.
- [x] MCP OAuth callback URL and port overrides fail before provider spawn with
      generic output that omits their keys and values.
- [x] Top-level role definitions and every `CODEX_HOME/agents` filesystem node
      are rejected before provider spawn without disclosing role names or paths.
- [x] Registration revalidates the complete staging home before publication and
      rolls back role configuration or an auto-discovered agents node.
- [x] Symlink, unsafe Unix mode, missing file, invalid TOML, and oversized-file
      checks fail closed.
- [x] Rejection output does not disclose a project path.
