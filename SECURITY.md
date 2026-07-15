# Security policy

Calcifer is expected to handle authentication material. Please report vulnerabilities privately and never attach real credentials to a public issue.

## Supported versions

Calcifer has no stable release yet. During pre-alpha, security fixes target the
latest published prerelease and the current `main`. Each new prerelease
supersedes older prereleases; Calcifer does not backport fixes unless a security
advisory explicitly says otherwise.

| Version | Supported |
| --- | --- |
| latest published prerelease | Yes |
| current `main` pre-alpha | Yes |
| older prereleases and snapshots | No |

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

## Maintainer coordinated-disclosure process

For a vulnerability that is not already public and does not require immediate
user mitigation, maintainers use this order:

1. Immediately accept the private report into, or create, a draft GitHub
   repository security advisory. Keep technical details, reproduction material,
   and any temporary security fork private, and agree on reporter credit and a
   disclosure plan.
2. Reproduce and validate the impact, identify affected versions, implement the
   smallest complete fix, and test both the exploit boundary and regressions.
3. Add the intended patched version to the draft advisory and publish that
   patched release through the normal reviewed, tag-driven release workflow.
   Confirm its checksums, artifact attestations, immutable release attestation,
   and install smoke test.
4. Publish the advisory immediately after the patched release is verified so
   users receive the impact, affected range, fixed version, and mitigations
   together. Requesting a CVE can be coordinated in the advisory but must not
   create an unnecessary gap between a verified fix and user notification.

This follows GitHub's model of using a
[repository security advisory](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories)
to discuss and fix privately, then
[publishing it with a fix version](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/publish-repository-advisory)
once the patch is available.

Exceptions require an explicit incident-owner decision. If details are already
public, exploitation is active or credibly imminent, or users need an urgent
mitigation before a complete fix exists, notify users promptly with the safest
known mitigation and affected scope. An advisory may then be published before
a fixed version and updated as evidence and releases become available. Do not
delay credential revocation, release removal, feature disablement, or another
containment action merely to preserve the normal disclosure sequence.

The GitHub release workflow and the security-advisory workflow are deliberately
separate. Release automation builds and verifies public code; it does not
create, edit, publish, or choose the timing of an advisory. Publishing an
advisory is a manual security decision after release verification, except for
the emergency cases above. Release or tag removal follows the audited incident
procedure in [docs/releasing.md](docs/releasing.md), never an automatic
rollback path.

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
