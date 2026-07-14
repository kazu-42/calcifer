# Security policy

Calcifer is expected to handle authentication material. Please report vulnerabilities privately and never attach real credentials to a public issue.

## Supported versions

Calcifer has no stable release yet. Security fixes currently target the latest commit on `main` only.

| Version | Supported |
| --- | --- |
| `main` pre-alpha | Yes |
| older snapshots | No |

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/kazu-42/calcifer/security/advisories/new). If that form is temporarily unavailable, do not post the existence or details of a vulnerability in a public issue; retry later or use an already established private channel with the maintainer.

A useful report includes:

- Calcifer version or commit;
- operating system and architecture;
- official provider CLI name and version;
- minimal reproduction steps using synthetic profile names and fake tokens;
- expected impact and any known safe workaround.

Never include:

- `auth.json`, `.credentials.json`, setup tokens, or Keychain dumps;
- access, refresh, ID, API, or bearer tokens;
- a full environment dump or raw debug log;
- email addresses or stable account, workspace, or organization identifiers;
- private source code or conversation content.

Please allow maintainers a reasonable opportunity to investigate and coordinate a fix before public disclosure.

## If a credential was exposed

Use the provider's official logout, revoke, or re-authentication procedure immediately. Removing a file from a repository or rewriting Git history does not revoke a leaked token. Rotate the credential first, then remove the secret from every published location and history.

## Security guarantees and non-goals

The current Unix pre-alpha asks the official Codex CLI to create and refresh
file-backed credentials inside Calcifer-managed profile homes. Calcifer
validates the presence, type, permissions, and Calcifer-owned marker/path
boundary of those files but does not parse or log their token values. Stable
provider-account identity and explicit owner-UID verification remain release
gates. Implemented and planned
guarantees are documented in [docs/architecture.md](docs/architecture.md) and
[docs/security-model.md](docs/security-model.md).

Calcifer will not:

- protect secrets from root, administrators, or malware running as the same OS user;
- sandbox the wrapped official CLI, repository, hooks, plugins, or tools;
- bypass login, re-authentication, provider enforcement, quota, or organization policy;
- broker or share credentials between users;
- support undocumented provider OAuth endpoints as a compatibility contract;
- treat authentication, network, provider, or parser errors as quota exhaustion;
- automatically replay a started command under another account.

Security-sensitive pull requests must use synthetic credentials and include tests for redaction and the relevant failure boundaries.
