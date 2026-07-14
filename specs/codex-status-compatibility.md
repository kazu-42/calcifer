# Spec: Codex status compatibility gate

## Summary

Before Calcifer reads account usage, it verifies that the App Server is a
tested Codex release and that the server is operating on the selected managed
profile home. Successful status output includes the verified Codex version.

## Inputs

- Canonical, validated Codex executable path.
- Canonical, validated profile-specific `CODEX_HOME`.
- A bounded status timeout.
- App Server `initialize` and `account/rateLimits/read` responses.

## Outputs

- Success: normalized usage plus the verified Codex version, Calcifer adapter
  version, and a `compatible` status.
- Unsupported: a redacted `unsupported` status failure when a well-formed
  version or managed home is outside Calcifer's tested compatibility contract.
  The compatibility status is `incompatible`, and a detected version is
  returned only when it was parsed as a bounded numeric release.
- Protocol error: a redacted failure for malformed JSON-RPC, initialize schema,
  or usage data.
- Existing authentication, timeout, spawn, and busy outcomes remain unchanged.
  Their compatibility status is either `compatible` when the version gate was
  completed and the provider returned a recognized authentication outcome, or
  `unverified` when the contract could not be observed.

## Behavior

1. Start the already resolved and permission-checked Codex executable with the
   selected profile's `CODEX_HOME` and file-backed credential override.
2. Complete `initialize` with `experimentalApi: false`.
3. Require a structured initialize response containing a parseable server
   version and an absolute `codexHome`.
4. Canonicalize and compare the returned `codexHome` to the selected managed
   home. A mismatch fails closed before requesting account usage.
5. Admit only explicitly tested Codex versions. The first compatibility set is
   exactly `0.144.4`; adding another version requires fixture/schema and live
   smoke-test evidence.
6. Request `account/rateLimits/read` only after the gate succeeds. Accept only
   a JSON-RPC response containing exactly one of `result` or `error`; for Codex
   `0.144.4`, require a non-null root `rateLimits` object even when
   `rateLimitsByLimitId` is present.
7. Add the verified version, adapter version, protocol name, compatibility
   status, and tested version set to stable JSON and human output without
   exposing the managed home path or provider identity.

## Edge cases

- Missing or malformed initialize fields: protocol error, without a usage read.
- Newer or older untested version: unsupported, without a usage read.
- Returned home uses a platform alias such as `/private/var`: compare
  canonical paths rather than display strings.
- A returned home string that is relative, empty, or cannot be canonicalized is
  unsupported; an absent or wrongly typed home field is a protocol error.
- Notifications arrive before either response: continue to ignore them within
  the existing bounded deadline.
- A response containing both `result` and `error`, or neither, is a protocol
  error. Missing or null root `rateLimits` is also a protocol error for the
  `0.144.4` adapter, including when named limit buckets are otherwise valid.
- Unsupported method after a compatible initialize: retain the existing
  unsupported classification.
- EOF, broken pipe, channel disconnect, I/O failure, or an unrecognized valid
  provider error keeps the schema-v1 `protocol_error` code but reports
  compatibility as `unverified`; none proves contract drift.
- No raw user-agent, path, provider message, token, email, or account ID is
  copied into errors or diagnostics.
- `compatible` means the version, initialize, and managed-home gates passed. A
  successful observation also passed the typed usage-response checks; a
  recognized authentication error after the gate may be `compatible` without
  usage. `incompatible` and `unverified` are both `unknown` availability and
  can never authorize failover.
- Same-profile `calcifer resume` remains a direct delegation to the official
  CLI in the selected home; it does not parse App Server data. Experimental
  cross-profile resume/fork has a separate, still-disabled compatibility gate.

## Dependencies

- Existing permission-checked executable resolution.
- Existing managed-home validation and profile lease.
- Existing bounded JSONL App Server client.
- Codex App Server baseline `0.144.4`.

## Acceptance criteria

- [x] Codex `0.144.4` with the expected managed home reaches the usage read.
- [x] A different version fails as unsupported before the usage request.
- [x] A different or invalid `codexHome` fails before the usage request.
- [x] Successful human and JSON status output include `0.144.4`.
- [x] Complete, partial, malformed, authentication, timeout, unsupported-method,
      and unsupported-version synthetic tests pass without secret leakage.
- [x] Missing/null root `rateLimits` and ambiguous JSON-RPC envelopes fail as
      incompatible protocol errors while valid multi-bucket responses pass.
- [x] Existing schema-version-1 fields and meanings remain unchanged.
- [x] README, compatibility notes, roadmap, and changelog state the exact gate
      and its fail-closed upgrade behavior.
