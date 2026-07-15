//! Audited descriptor boundary for the supervisor lifecycle channel.
//!
//! Lifecycle traffic and optional `SCM_RIGHTS` traffic deliberately use
//! different socket pairs. This module owns no ancillary-data API. It creates
//! one connected `AF_UNIX` stream pair, keeps every parent-side descriptor
//! close-on-exec, and moves exactly one endpoint into the guardian's stdin.

#![allow(dead_code)] // Wired to the default-off supervisor in issue #50.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rustix::io::{FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd};
use rustix::net::{AddressFamily, SendFlags, SocketType};

/// Path-free descriptor identity whose diagnostic representation is always
/// redacted. Callers must explicitly opt into the scanner representation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct DescriptorIdentity {
    scan_identity: calcifer_unix_child_fd::DescriptorIdentity,
}

impl DescriptorIdentity {
    fn read(descriptor: BorrowedFd<'_>) -> Result<Self, ChannelError> {
        let scan_identity = calcifer_unix_child_fd::descriptor_identity(descriptor)
            .map_err(|_| ChannelError::DescriptorIdentity)?;
        Ok(Self::from_scan_identity(scan_identity))
    }

    pub(super) const fn from_scan_identity(
        scan_identity: calcifer_unix_child_fd::DescriptorIdentity,
    ) -> Self {
        Self { scan_identity }
    }

    pub(super) const fn for_scan(self) -> calcifer_unix_child_fd::DescriptorIdentity {
        self.scan_identity
    }
}

impl fmt::Debug for DescriptorIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.scan_identity;
        formatter.write_str("DescriptorIdentity(<redacted>)")
    }
}

/// A newly-created lifecycle channel whose endpoint roles have not been split.
///
/// This type is intentionally not `Clone`: one coordinator and one guardian
/// own the only lifecycle read authorities.
#[must_use = "the lifecycle pair must be consumed by the guardian spawn boundary"]
pub(super) struct LifecyclePair {
    coordinator: LifecycleEndpoint,
    guardian: LifecycleEndpoint,
}

impl LifecyclePair {
    /// Creates a connected `AF_UNIX` stream pair with close-on-exec endpoints.
    pub(super) fn new() -> Result<Self, ChannelError> {
        let (coordinator, guardian) = create_socket_pair()?;

        #[cfg(target_os = "linux")]
        {
            // Linux created both descriptors atomically with `SOCK_CLOEXEC`.
            verify_close_on_exec(&coordinator)?;
            verify_close_on_exec(&guardian)?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Darwin has no `SOCK_CLOEXEC`. This runs immediately after pair
            // creation, before this module permits any worker or spawn.
            set_and_verify_close_on_exec(&coordinator)?;
            set_and_verify_close_on_exec(&guardian)?;
        }

        let coordinator = LifecycleEndpoint::adopt(coordinator)?;
        let guardian = LifecycleEndpoint::adopt(guardian)?;
        Ok(Self {
            coordinator,
            guardian,
        })
    }

    pub(super) fn coordinator_identity(&self) -> Result<DescriptorIdentity, ChannelError> {
        self.coordinator.descriptor_identity()
    }

    pub(super) fn guardian_identity(&self) -> Result<DescriptorIdentity, ChannelError> {
        self.guardian.descriptor_identity()
    }
}

impl fmt::Debug for LifecyclePair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.coordinator, &self.guardian);
        formatter.write_str("LifecyclePair(<redacted>)")
    }
}

/// One non-cloneable endpoint of the dedicated lifecycle socket pair.
#[must_use = "dropping a lifecycle endpoint changes supervisor liveness"]
pub(super) struct LifecycleEndpoint {
    stream: UnixStream,
}

impl LifecycleEndpoint {
    fn adopt(stream: UnixStream) -> Result<Self, ChannelError> {
        verify_endpoint(&stream)?;
        configure_sigpipe_safety(&stream)?;
        Ok(Self { stream })
    }

    fn verify_invariants(&self) -> Result<(), ChannelError> {
        verify_close_on_exec(&self.stream)?;
        verify_endpoint(&self.stream)
    }

    pub(super) fn descriptor_identity(&self) -> Result<DescriptorIdentity, ChannelError> {
        DescriptorIdentity::read(self.stream.as_fd())
    }

    pub(super) fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), ChannelError> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(|_| ChannelError::TimeoutConfiguration)
    }

    pub(super) fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), ChannelError> {
        self.stream
            .set_write_timeout(timeout)
            .map_err(|_| ChannelError::TimeoutConfiguration)
    }
}

impl fmt::Debug for LifecycleEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.stream;
        formatter.write_str("LifecycleEndpoint(<redacted>)")
    }
}

impl Read for LifecycleEndpoint {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        read_endpoint(&self.stream, buffer)
    }
}

impl Write for LifecycleEndpoint {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        write_endpoint(self, buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for &LifecycleEndpoint {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        read_endpoint(&self.stream, buffer)
    }
}

impl Write for &LifecycleEndpoint {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        write_endpoint(self, buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_endpoint(stream: &UnixStream, buffer: &mut [u8]) -> io::Result<usize> {
    let mut stream = stream;
    stream.read(buffer)
}

fn write_endpoint(endpoint: &LifecycleEndpoint, buffer: &[u8]) -> io::Result<usize> {
    let flags = sigpipe_safe_send_flags(endpoint)
        .map_err(|_| io::Error::other("the lifecycle channel could not send safely"))?;
    rustix::net::send(&endpoint.stream, buffer, flags).map_err(io::Error::from)
}

/// A successfully-spawned guardian and the coordinator's only channel end.
#[must_use = "the guardian child and coordinator endpoint must remain owned"]
pub(super) struct SpawnedGuardian {
    child: Child,
    coordinator: LifecycleEndpoint,
}

impl SpawnedGuardian {
    pub(super) fn into_parts(self) -> (Child, LifecycleEndpoint) {
        (self.child, self.coordinator)
    }
}

/// Preserves all process/channel ownership available after a failed spawn
/// boundary. A post-spawn invariant failure retains the direct child handle so
/// the coordinator can perform an exact bounded shutdown and wait.
#[must_use = "a failed guardian spawn can still own a child and channel endpoint"]
pub(super) struct GuardianSpawnFailure {
    coordinator: LifecycleEndpoint,
    child: Option<Child>,
    error: ChannelError,
}

impl GuardianSpawnFailure {
    pub(super) const fn error(&self) -> ChannelError {
        self.error
    }

    pub(super) fn into_parts(self) -> (LifecycleEndpoint, Option<Child>, ChannelError) {
        (self.coordinator, self.child, self.error)
    }
}

impl fmt::Debug for GuardianSpawnFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardianSpawnFailure")
            .field("error", &self.error)
            .field("child_started", &self.child.is_some())
            .finish_non_exhaustive()
    }
}

/// Moves only the guardian endpoint into stdin and spawns the command once.
///
/// The caller configures stdout, stderr, the environment, and process-group
/// containment before passing the command here. The command is consumed so
/// its installed stdin cannot be reused with a second child. The coordinator
/// endpoint is checked both before and after spawn and is returned on every
/// path. Profile authority remains outside this function and is never dropped.
pub(super) fn spawn_guardian_with_lifecycle_stdin(
    mut command: Command,
    pair: LifecyclePair,
) -> Result<SpawnedGuardian, GuardianSpawnFailure> {
    let LifecyclePair {
        coordinator,
        guardian,
    } = pair;

    if let Err(error) = coordinator.verify_invariants() {
        return Err(GuardianSpawnFailure {
            coordinator,
            child: None,
            error,
        });
    }
    if let Err(error) = guardian.verify_invariants() {
        return Err(GuardianSpawnFailure {
            coordinator,
            child: None,
            error,
        });
    }

    let LifecycleEndpoint { stream } = guardian;
    let guardian_descriptor = OwnedFd::from(stream);
    command.stdin(Stdio::from(guardian_descriptor));

    let child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return Err(GuardianSpawnFailure {
                coordinator,
                child: None,
                error: ChannelError::Spawn,
            });
        }
    };

    if let Err(error) = coordinator.verify_invariants() {
        return Err(GuardianSpawnFailure {
            coordinator,
            child: Some(child),
            error,
        });
    }

    Ok(SpawnedGuardian { child, coordinator })
}

/// Adopts the guardian's inherited stdin without ever taking ownership of fd 0.
///
/// The inherited descriptor is duplicated atomically with close-on-exec. The
/// borrowed stdin descriptor is then restored to close-on-exec before any
/// guardian worker or child may start. Only the duplicate is converted into an
/// owned `UnixStream`, avoiding a second owner for fd 0.
pub(super) fn bootstrap_guardian_from_stdin() -> Result<LifecycleEndpoint, ChannelError> {
    let stdin = io::stdin();
    bootstrap_guardian_from_descriptor(stdin.as_fd())
}

fn bootstrap_guardian_from_descriptor(
    inherited: BorrowedFd<'_>,
) -> Result<LifecycleEndpoint, ChannelError> {
    let duplicate = fcntl_dupfd_cloexec(inherited, 3).map_err(|_| ChannelError::Duplicate)?;
    set_and_verify_close_on_exec(inherited)?;
    verify_close_on_exec(&duplicate)?;

    let stream = UnixStream::from(duplicate);
    LifecycleEndpoint::adopt(stream)
}

/// Returns the per-send flags/configuration that prevents lifecycle writes
/// from terminating the process when the peer has exited.
pub(super) fn sigpipe_safe_send_flags(
    endpoint: &LifecycleEndpoint,
) -> Result<SendFlags, ChannelError> {
    sigpipe_safe_send_flags_for_descriptor(&endpoint.stream)
}

#[cfg(target_os = "linux")]
fn create_socket_pair() -> Result<(UnixStream, UnixStream), ChannelError> {
    let (coordinator, guardian) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| ChannelError::Create)?;
    Ok((UnixStream::from(coordinator), UnixStream::from(guardian)))
}

#[cfg(not(target_os = "linux"))]
fn create_socket_pair() -> Result<(UnixStream, UnixStream), ChannelError> {
    UnixStream::pair().map_err(|_| ChannelError::Create)
}

fn set_and_verify_close_on_exec<Fd: AsFd>(descriptor: Fd) -> Result<(), ChannelError> {
    let flags = fcntl_getfd(&descriptor).map_err(|_| ChannelError::DescriptorFlags)?;
    fcntl_setfd(&descriptor, flags | FdFlags::CLOEXEC)
        .map_err(|_| ChannelError::DescriptorFlags)?;
    verify_close_on_exec(descriptor)
}

fn verify_close_on_exec<Fd: AsFd>(descriptor: Fd) -> Result<(), ChannelError> {
    let flags = fcntl_getfd(descriptor).map_err(|_| ChannelError::DescriptorFlags)?;
    if flags.contains(FdFlags::CLOEXEC) {
        Ok(())
    } else {
        Err(ChannelError::DescriptorInheritable)
    }
}

fn verify_endpoint<Fd: AsFd>(descriptor: Fd) -> Result<(), ChannelError> {
    let socket_type =
        rustix::net::sockopt::socket_type(&descriptor).map_err(|_| ChannelError::InvalidSocket)?;
    if socket_type != SocketType::STREAM {
        return Err(ChannelError::InvalidSocketType);
    }

    let local = rustix::net::getsockname(&descriptor).map_err(|_| ChannelError::InvalidSocket)?;
    if local.address_family() != AddressFamily::UNIX {
        return Err(ChannelError::InvalidSocketDomain);
    }

    let peer = rustix::net::getpeername(descriptor).map_err(|_| ChannelError::MissingPeer)?;
    match peer {
        Some(peer) if peer.address_family() == AddressFamily::UNIX => Ok(()),
        Some(_) => Err(ChannelError::InvalidPeerDomain),
        // Darwin reports an unnamed, connected socketpair peer with a zero
        // address length. `getpeername` still succeeds; an unconnected stream
        // fails the syscall instead and is mapped to `MissingPeer` above.
        None => Ok(()),
    }
}

fn configure_sigpipe_safety<Fd: AsFd>(descriptor: Fd) -> Result<(), ChannelError> {
    let _ = sigpipe_safe_send_flags_for_descriptor(descriptor)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn sigpipe_safe_send_flags_for_descriptor<Fd: AsFd>(
    descriptor: Fd,
) -> Result<SendFlags, ChannelError> {
    let _ = descriptor;
    Ok(SendFlags::NOSIGNAL)
}

#[cfg(target_os = "macos")]
fn sigpipe_safe_send_flags_for_descriptor<Fd: AsFd>(
    descriptor: Fd,
) -> Result<SendFlags, ChannelError> {
    rustix::net::sockopt::set_socket_nosigpipe(&descriptor, true)
        .map_err(|_| ChannelError::SignalSafety)?;
    if !rustix::net::sockopt::socket_nosigpipe(descriptor)
        .map_err(|_| ChannelError::SignalSafety)?
    {
        return Err(ChannelError::SignalSafety);
    }
    Ok(SendFlags::empty())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn sigpipe_safe_send_flags_for_descriptor<Fd: AsFd>(
    descriptor: Fd,
) -> Result<SendFlags, ChannelError> {
    let _ = descriptor;
    Err(ChannelError::UnsupportedPlatform)
}

/// A bounded, redacted channel-boundary failure.
///
/// No variant stores an OS error, path, descriptor number, socket inode,
/// process ID, profile, or account-derived value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ChannelError {
    Create,
    DescriptorFlags,
    DescriptorIdentity,
    DescriptorInheritable,
    Duplicate,
    InvalidSocket,
    InvalidSocketType,
    InvalidSocketDomain,
    InvalidPeerDomain,
    MissingPeer,
    SignalSafety,
    TimeoutConfiguration,
    Spawn,
    UnsupportedPlatform,
}

impl ChannelError {
    const fn code(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::DescriptorFlags => "descriptor_flags",
            Self::DescriptorIdentity => "descriptor_identity",
            Self::DescriptorInheritable => "descriptor_inheritable",
            Self::Duplicate => "duplicate",
            Self::InvalidSocket => "invalid_socket",
            Self::InvalidSocketType => "invalid_socket_type",
            Self::InvalidSocketDomain => "invalid_socket_domain",
            Self::InvalidPeerDomain => "invalid_peer_domain",
            Self::MissingPeer => "missing_peer",
            Self::SignalSafety => "signal_safety",
            Self::TimeoutConfiguration => "timeout_configuration",
            Self::Spawn => "spawn",
            Self::UnsupportedPlatform => "unsupported_platform",
        }
    }
}

impl fmt::Debug for ChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ChannelError")
            .field(&self.code())
            .finish()
    }
}

impl fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Create => "the lifecycle channel could not be created",
            Self::DescriptorFlags => "the lifecycle descriptor flags could not be verified",
            Self::DescriptorIdentity => "the lifecycle descriptor identity could not be read",
            Self::DescriptorInheritable => "a lifecycle descriptor was inheritable",
            Self::Duplicate => "the inherited lifecycle descriptor could not be duplicated",
            Self::InvalidSocket => "the lifecycle descriptor was not a valid socket",
            Self::InvalidSocketType => "the lifecycle socket type was invalid",
            Self::InvalidSocketDomain => "the lifecycle socket domain was invalid",
            Self::InvalidPeerDomain => "the lifecycle peer domain was invalid",
            Self::MissingPeer => "the lifecycle socket had no connected peer",
            Self::SignalSafety => "the lifecycle channel could not suppress SIGPIPE",
            Self::TimeoutConfiguration => "the lifecycle channel timeout could not be configured",
            Self::Spawn => "the guardian process could not be spawned",
            Self::UnsupportedPlatform => "the lifecycle channel is unsupported on this platform",
        })
    }
}

impl std::error::Error for ChannelError {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;

    #[test]
    fn pair_is_cloexec_connected_and_duplex() -> Result<(), Box<dyn Error>> {
        let LifecyclePair {
            mut coordinator,
            mut guardian,
        } = LifecyclePair::new()?;
        coordinator.set_read_timeout(Some(Duration::from_secs(2)))?;
        guardian.set_read_timeout(Some(Duration::from_secs(2)))?;

        verify_close_on_exec(&coordinator.stream)?;
        verify_close_on_exec(&guardian.stream)?;
        verify_endpoint(&coordinator.stream)?;
        verify_endpoint(&guardian.stream)?;

        coordinator.write_all(b"coordinator")?;
        let mut from_coordinator = [0_u8; 11];
        guardian.read_exact(&mut from_coordinator)?;
        assert_eq!(&from_coordinator, b"coordinator");

        guardian.write_all(b"guardian")?;
        let mut from_guardian = [0_u8; 8];
        coordinator.read_exact(&mut from_guardian)?;
        assert_eq!(&from_guardian, b"guardian");
        Ok(())
    }

    #[test]
    fn shared_endpoint_references_support_duplex_io_without_cloning() -> Result<(), Box<dyn Error>>
    {
        let LifecyclePair {
            coordinator,
            guardian,
        } = LifecyclePair::new()?;
        coordinator.set_read_timeout(Some(Duration::from_secs(2)))?;
        guardian.set_read_timeout(Some(Duration::from_secs(2)))?;

        let mut coordinator_writer = &coordinator;
        let mut coordinator_reader = &coordinator;
        let mut guardian_writer = &guardian;
        let mut guardian_reader = &guardian;

        coordinator_writer.write_all(b"c")?;
        let mut from_coordinator = [0_u8; 1];
        guardian_reader.read_exact(&mut from_coordinator)?;
        assert_eq!(from_coordinator, *b"c");

        guardian_writer.write_all(b"g")?;
        let mut from_guardian = [0_u8; 1];
        coordinator_reader.read_exact(&mut from_guardian)?;
        assert_eq!(from_guardian, *b"g");
        Ok(())
    }

    #[test]
    fn endpoint_and_pair_identities_are_stable_and_redacted() -> Result<(), Box<dyn Error>> {
        let pair = LifecyclePair::new()?;
        let coordinator = pair.coordinator_identity()?;
        let guardian = pair.guardian_identity()?;

        assert_eq!(coordinator, pair.coordinator.descriptor_identity()?);
        assert_eq!(guardian, pair.guardian.descriptor_identity()?);
        assert_ne!(coordinator.for_scan().inode, 0);
        assert_ne!(guardian.for_scan().inode, 0);
        assert_eq!(format!("{coordinator:?}"), "DescriptorIdentity(<redacted>)");
        assert_eq!(format!("{guardian:?}"), "DescriptorIdentity(<redacted>)");
        Ok(())
    }

    #[test]
    fn bootstrap_duplicates_the_inherited_endpoint_and_restores_cloexec()
    -> Result<(), Box<dyn Error>> {
        let LifecyclePair {
            mut coordinator,
            guardian,
        } = LifecyclePair::new()?;
        let inherited_flags = fcntl_getfd(&guardian.stream)?;
        fcntl_setfd(&guardian.stream, inherited_flags & !FdFlags::CLOEXEC)?;
        assert!(!fcntl_getfd(&guardian.stream)?.contains(FdFlags::CLOEXEC));

        let mut adopted = bootstrap_guardian_from_descriptor(guardian.stream.as_fd())?;
        assert!(fcntl_getfd(&guardian.stream)?.contains(FdFlags::CLOEXEC));
        verify_close_on_exec(&adopted.stream)?;
        drop(guardian);

        adopted.set_read_timeout(Some(Duration::from_secs(2)))?;
        coordinator.set_read_timeout(Some(Duration::from_secs(2)))?;
        coordinator.write_all(b"a")?;
        let mut from_coordinator = [0_u8; 1];
        adopted.read_exact(&mut from_coordinator)?;
        assert_eq!(from_coordinator, *b"a");
        adopted.write_all(b"b")?;
        let mut from_guardian = [0_u8; 1];
        coordinator.read_exact(&mut from_guardian)?;
        assert_eq!(from_guardian, *b"b");
        Ok(())
    }

    #[test]
    fn failed_spawn_returns_a_live_parent_endpoint_without_unredacted_details()
    -> Result<(), Box<dyn Error>> {
        let pair = LifecyclePair::new()?;
        let secret = "calcifer-guardian-path-must-not-render";
        let command = Command::new(format!("/nonexistent/{secret}"));
        let failure = spawn_guardian_with_lifecycle_stdin(command, pair)
            .err()
            .ok_or("the synthetic guardian spawn must fail")?;

        assert_eq!(failure.error(), ChannelError::Spawn);
        let rendered = format!("{failure:?}");
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("nonexistent"));

        let (mut coordinator, child, error) = failure.into_parts();
        assert!(child.is_none());
        assert_eq!(error, ChannelError::Spawn);
        verify_close_on_exec(&coordinator.stream)?;
        // The retained descriptor remains valid and close-on-exec, while a
        // bounded HUP/EOF observation proves that the failed command dropped
        // only the guardian peer.
        let mut poll_descriptors = [rustix::event::PollFd::new(
            &coordinator.stream,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        assert_eq!(
            rustix::event::poll(&mut poll_descriptors, Some(&timeout))?,
            1
        );
        assert!(
            poll_descriptors[0]
                .revents()
                .intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP)
        );
        let mut byte = [0_u8; 1];
        assert_eq!(coordinator.read(&mut byte)?, 0);
        verify_close_on_exec(&coordinator.stream)?;
        Ok(())
    }

    #[test]
    fn spawn_moves_only_the_guardian_endpoint_into_stdin() -> Result<(), Box<dyn Error>> {
        let pair = LifecyclePair::new()?;
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "IFS= read -r marker; [ \"$marker\" = ping ] || exit 2; printf pong >&0",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let spawned = spawn_guardian_with_lifecycle_stdin(command, pair)
            .map_err(|failure| failure.error())?;
        let (mut child, mut coordinator) = spawned.into_parts();
        coordinator.set_read_timeout(Some(Duration::from_secs(2)))?;
        coordinator.set_write_timeout(Some(Duration::from_secs(2)))?;
        coordinator.write_all(b"ping\n")?;
        let mut reply = [0_u8; 4];
        coordinator.read_exact(&mut reply)?;
        assert_eq!(&reply, b"pong");
        assert!(child.wait()?.success());
        verify_close_on_exec(&coordinator.stream)?;
        Ok(())
    }

    #[test]
    fn channel_debug_identity_is_fully_redacted() -> Result<(), Box<dyn Error>> {
        let pair = LifecyclePair::new()?;
        assert_eq!(format!("{pair:?}"), "LifecyclePair(<redacted>)");
        assert_eq!(
            format!("{:?}", pair.coordinator),
            "LifecycleEndpoint(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", ChannelError::InvalidSocket),
            "ChannelError(\"invalid_socket\")"
        );
        Ok(())
    }
}
