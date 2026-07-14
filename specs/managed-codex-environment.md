# Spec: Managed Codex environment isolation

## Summary

Every credential-bearing Codex process receives one deterministic managed
authentication environment. Ambient provider secrets, endpoint and execution
backend overrides, test hooks, remote credentials, state-home overrides,
transcript/trace paths, and App Server config overrides must not supersede the
selected Calcifer profile.

## Inputs

- A permission-checked absolute Codex executable.
- A validated profile-specific `CODEX_HOME`.
- Provider arguments already checked by Calcifer policy.
- The caller's inherited operating-system environment.

## Outputs

- A direct `std::process::Command` for the official Codex executable.
- The selected `CODEX_HOME` and forced file credential-store setting.
- Ordinary non-provider environment such as terminal, locale, and proxy
  configuration remains available.
- Reviewed Codex authentication, routing, state, config, remote-auth, and test
  override variables are absent.

## Behavior

1. All login, run, resume, and App Server commands are created through one
   managed Codex command builder.
2. Unix run/resume also applies the same sanitizer before spawning Calcifer's
   internal coordinator and provider guardian. Ambient `CODEX_HOME` is removed
   from those helpers and reintroduced only on the final provider command.
3. The builder forces `cli_auth_credentials_store="file"` and the selected
   `CODEX_HOME`.
4. It removes the explicit environment variables currently known to override
   stored credentials, request headers, OAuth/provider endpoints, login
   routing, App Server config, Codex state location, remote execution, or
   transcript/trace capture.
5. It also removes any inherited `CODEX_TEST_*` variable and any inherited
   `CODEX_*_OVERRIDE` variable so newly added provider test/development hooks
   fail closed until reviewed.
6. Environment-variable matching is ASCII case-insensitive so the contract is
   consistent on Windows.
7. No environment values or full environment listing enter output, logs, test
   failure messages, or telemetry.

## Explicitly denied variables

- `OPENAI_API_KEY`
- `OPENAI_ORGANIZATION`
- `OPENAI_PROJECT`
- `CODEX_API_KEY`
- `CODEX_ACCESS_TOKEN`
- `CODEX_REFRESH_TOKEN_URL_OVERRIDE`
- `CODEX_REVOKE_TOKEN_URL_OVERRIDE`
- `CODEX_APP_SERVER_LOGIN_CLIENT_ID`
- `CODEX_AUTHAPI_BASE_URL`
- `CODEX_APP_SERVER_LOGIN_ISSUER`
- `CODEX_APP_SERVER_DEV_OPEN_APP_URL`
- `CODEX_APP_SERVER_MANAGED_CONFIG_PATH`
- `CODEX_APP_SERVER_DISABLE_MANAGED_CONFIG`
- `CODEX_APP_SERVER_TEST_USER_CONFIG_FILE`
- `CODEX_SQLITE_HOME`
- `CODEX_REMOTE_AUTH_TOKEN`
- `CODEX_CONNECTORS_TOKEN`
- `CODEX_CODE_MODE_HOST_PATH`
- `CODEX_STARTING_DIFF`
- `CODEX_TUI_RECORD_SESSION`
- `CODEX_TUI_SESSION_LOG_PATH`
- `CODEX_ROLLOUT_TRACE_ROOT`
- `CODEX_ANALYTICS_EVENTS_CAPTURE_FILE`

`CODEX_INTERNAL_ORIGINATOR_OVERRIDE` is covered by the suffix rule. Provider
test variables, including future unknown ones, are covered by the prefix rule.
The `CODEX_CLOUD_TASKS_*`, `CODEX_EXEC_SERVER_*`, and `CODEX_OSS_*` families are
also removed because they can replace an authenticated backend, remote
execution environment, or provider route.

## Edge cases

- A denied variable with an empty value is still removed.
- A mixed-case denied name is removed on every platform.
- An unrelated variable containing the word `CODEX` is preserved.
- `CODEX_HOME` is overwritten with the selected managed home, not removed.
- `PATH` remains inherited only for provider-started tools; the provider
  executable itself has already been resolved and permission checked.
- Proxy and CA environment variables remain inherited for legitimate
  enterprise networks. Calcifer does not claim to defend against a hostile
  same-user proxy or trust store; that residual boundary is documented.

## Dependencies

- Permission-checked executable resolution.
- Managed profile and file-backed credential invariants.
- Provider-argument routing rejection.
- Existing synthetic Unix process integration fixture.

## Acceptance criteria

- [x] Login succeeds with every denied variable seeded synthetically, and the
      fake official CLI observes none of their names.
- [x] Run, exact resume, latest resume, and status have the same guarantee.
- [x] A future-shaped `CODEX_TEST_*` and `CODEX_*_OVERRIDE` are removed.
- [x] `CODEX_HOME`, ordinary provider arguments, exit codes, and leases retain
      their existing behavior.
- [x] Unit tests cover exact, patterned, mixed-case, and unrelated names.
- [x] Internal run/resume helpers drop explicit provider secrets before spawn.
- [x] No fixture or failure output includes a secret-shaped environment value.
- [x] Security policy, security model, architecture, and changelog match the
      implemented credential behavior and residual proxy/CA boundary.
