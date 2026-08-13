# ADR 0005: Descriptor-backed provider execution

- Status: Accepted
- Date: 2026-08-13
- Scope: checksum-pinned Codex compatibility and supervised launch

## Context

Calcifer already captures the configured Codex executable with `O_NOFOLLOW`,
binds its complete metadata and SHA-256 identity, and copies the verified bytes
into a private executable scratch root. Revalidating that private pathname at
the final spawn boundary still leaves a pathname reopen between the last check
and the kernel's `exec`. It also leaves the staged inode writable in principle
by another process running as the same user. Metadata checks can detect many
races, but they cannot prove that the bytes opened by `exec` are the bytes that
were hashed.

The launch authority must therefore be a retained kernel object, not a path or
a later observation of a path. Numeric process identifiers, directory names,
and post-spawn inspection are not substitutes for that authority.

## Decision

### Linux

Linux is the supported production launch boundary for the pinned supervisor:

1. Calcifer performs the existing canonical-path capture, private scratch
   selection, durable staging copy, metadata checks, and SHA-256 checks.
2. Before any Codex probe starts, it reopens that exact staged identity, copies
   the verified native ELF image into a new anonymous `memfd`, and hashes the
   bytes during the copy.
3. The `memfd` is mode `0500`, close-on-exec, and created with sealing enabled.
   Calcifer applies `F_SEAL_SHRINK`, `F_SEAL_GROW`, `F_SEAL_WRITE`, the
   available executable seal, and finally `F_SEAL_SEAL`. It then rehashes the
   sealed object and revalidates its length, owner, mode, link state, and seal
   set.
4. Every version, schema, fork, App Server, and remote-TUI command executes
   through `/proc/self/fd/<retained-fd>`. That procfs entry resolves the
   already-owned descriptor in the child; it does not reopen the staged or
   installed pathname. Missing or unusable procfs makes spawn fail closed.
5. The parent launch descriptor always remains `FD_CLOEXEC`. App Server uses
   it at the one exec boundary. Remote TUI has a mandatory internal-launcher
   exec first, so the audited child-FD boundary creates a fresh child-only
   duplicate alongside the readiness descriptor. The launcher immediately
   restores `FD_CLOEXEC`, replaces the untrusted numeric path with its own
   inherited descriptor path, and retains that owner only through the final
   provider exec. App Server includes the authority in its ordinary negative
   forbidden-FD inventory. The held TUI launcher must still own this one
   descriptor, so its negative inventory excludes only that identity; reaching
   the readiness hold proves the audited launcher has already taken it and
   restored `FD_CLOEXEC`. The final real-exec test verifies that neither the
   provider nor its descendants receive it, without requiring post-exec procfs
   access from a provider that may set itself non-dumpable.
6. App Server and remote-TUI plans borrow the same move-only
   `LaunchExecutable`. A changed installed or staged path can make a later
   revalidation fail, but a race after the final gate can execute only the
   already sealed bytes.

`MFD_EXEC` is requested on kernels that support it. An `EINVAL` retry without
that newer flag supports older kernels where executable memfds predate the
flag; the resulting object must still pass the same content seals and actual
exec probe. This is not a pathname or unverified-byte fallback.

Scripts are not a production fallback. A shebang interpreter may need the
script descriptor after exec, which conflicts with the no-leak invariant.
Pinned Codex therefore must be a native ELF image. Tiny shell providers remain
available only through a sealed `cfg(test)` fixture path so unrelated state
machine tests do not claim production launch evidence.

### macOS

The current public macOS surface does not provide an equivalent primitive that
meets this contract. macOS has no public `fexecve`, and direct execution of an
already-open executable through `/dev/fd/<n>` returns `EACCES` on the supported
host. Process-table inspection, a last-moment `stat`, user immutable flags,
private sandbox APIs, and reverse-engineered launch services do not bind the
kernel exec to the previously hashed bytes.

Production compatibility capability creation therefore returns the existing
redacted `unsupported` result before any provider subprocess starts. There is
no direct-path fallback. macOS unit tests retain an explicitly compile-time,
test-only pathname fixture for state-machine coverage and separately assert
that the production descriptor boundary is unsupported.

### Other platforms

Windows needs a separate reviewed design using a platform-owned immutable
image/section or equivalent launch primitive. Until then it cannot mint the
pinned Unix supervisor capability.

## Security properties

- Verified bytes, not a metadata-equivalent pathname, are the exec authority.
- Rename, unlink/recreate, same-size substitution, and in-place writes cannot
  change a sealed Linux launch image.
- The installed path and private staged path remain useful integrity and
  cleanup evidence, but neither is reopened as execution authority.
- A launch descriptor, scratch directory descriptor, digest input, or other
  Calcifer control descriptor cannot survive into Codex or its descendants.
- Unsupported kernels, missing procfs, non-native executables, seal failures,
  and unsupported operating systems return failure; they never select a weaker
  execution route.

## Recovery and rollback

The feature is private to capability construction. A failure before capability
minting follows the existing retained scratch cleanup protocol. A failure after
provider startup remains owned by the existing exact-child/process-group
supervisor. Rolling back this implementation disables the pinned supervised
path; it must not restore final execution from the staged or configured
pathname.
