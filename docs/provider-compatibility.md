# Provider compatibility notes

This document records the upstream contracts behind Calcifer's resume and usage behavior. It is not a promise that an undocumented provider implementation will remain stable.

## Verification baseline

Verified on 2026-07-15 against:

- installed and released Codex CLI `0.144.4`, tag [`rust-v0.144.4`](https://github.com/openai/codex/releases/tag/rust-v0.144.4), commit [`8c68d4c87dc54d38861f5114e920c3de2efa5876`](https://github.com/openai/codex/commit/8c68d4c87dc54d38861f5114e920c3de2efa5876);
- OpenAI Codex `main` commit [`0396f99cf1a27fc87dd12d23403b25e840b6ecbd`](https://github.com/openai/codex/commit/0396f99cf1a27fc87dd12d23403b25e840b6ecbd), where the fields used here were unchanged;
- Orca `main` commit [`e0edc8ef76d341f7ab8083a006f785322bcaeb23`](https://github.com/stablyai/orca/commit/e0edc8ef76d341f7ab8083a006f785322bcaeb23).

The official Codex App Server command is still marked experimental as a whole. Calcifer negotiates its stable protocol subset with `experimentalApi: false` and fails closed when the method or response shape is unavailable.

## Codex resume

Codex persists sessions beneath the selected `CODEX_HOME`, normally as:

```text
sessions/YYYY/MM/DD/rollout-...-<thread-id>.jsonl
archived_sessions/
state_5.sqlite
```

The stable same-home operations are the CLI's `codex resume <thread-id>` and App Server's `thread/resume {threadId}`. The exact thread ID is preferred over `--last`; `--last` is affected by cwd filtering and can select an unintended conversation when several sessions exist.

Calcifer's current profile-specific `CODEX_HOME` preserves these files across wrapper restarts. Resume restores persisted conversation state, not the terminated process, live stream, or an in-flight tool call. Calcifer does not replay the previous prompt.

The current command is an explicit cold restore: `calcifer resume codex@<alias> [thread-id]`. Automatic previous-thread selection still requires Calcifer to persist the source profile, canonical cwd, exact thread ID, and interruption state.

Relevant upstream sources:

- [official App Server documentation](https://developers.openai.com/codex/app-server/);
- [thread resume types and experimental-field markers](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/app-server-protocol/src/protocol/v2/thread.rs#L310-L438);
- [session layout](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/rollout/src/list.rs#L418-L421).

### Cross-profile resume

A stable thread-ID lookup is scoped to the current `CODEX_HOME`. Codex 0.144.4 has an experimental `thread/resume.path` field that can read an absolute external rollout path. The upstream resolver canonicalizes the file but does not constrain it to the active home. Calcifer therefore does not enable this field today.

If cross-profile handoff is added, the path must come only from Calcifer-owned metadata, remain canonically contained in a registered source profile's sessions root, pass type/symlink/owner/mode checks, and have one writer. The source and target profiles must share an explicitly configured trust domain. The field must be version-gated and optional because upstream marks it unstable.

Relevant upstream sources:

- [external rollout resolver](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/thread-store/src/local/read_thread.rs#L150-L188);
- [upstream external-rollout resume test](https://github.com/openai/codex/blob/8c68d4c87dc54d38861f5114e920c3de2efa5876/codex-rs/thread-store/src/local/mod.rs#L1031-L1067).

## Codex rate limits and reset credits

Calcifer sends the following read-only request after the App Server initialization handshake:

```json
{
  "method": "account/rateLimits/read",
  "id": 1,
  "params": null
}
```

The normalized response can contain:

- legacy `rateLimits` and all `rateLimitsByLimitId` buckets;
- primary and secondary `usedPercent`, window duration, and Unix reset time;
- workspace credit availability, unlimited state, and balance;
- individual spend-control limit, used value, remaining percentage, and reset time;
- reset-credit authoritative `availableCount`;
- optional reset-credit status, grant time, and expiry.

Reset-credit detail arrays may be absent or shorter than `availableCount`; the count is authoritative. A missing summary means unavailable, not zero. Calcifer intentionally discards opaque reset-credit IDs and backend-provided title/description before constructing its public output.

Each read is attached to the local profile ID, canonical managed home, and exclusive lease—not to an email address. Calcifer does not yet verify a stable provider account identity, so two registered aliases may represent the same account and quota. A profile with an active `run` or `resume` child reports busy/unknown; Calcifer does not start a second app-server against the same refreshable `auth.json`.

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
