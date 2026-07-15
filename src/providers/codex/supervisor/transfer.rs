//! Dedicated, default-unused channel for a future one-shot lease transfer.
//!
//! This is deliberately a different type and socket pair from the lifecycle
//! channel. It exposes descriptor identities for real-exec leak assertions and
//! typed sender/receiver operations, but no raw stream accessor, `Read`
//! implementation, or local `recvmsg` surface. Those operations delegate to
//! the already-tested single ancillary receiver and one-shot send/ACK state
//! machine in `profiles.rs` from issue #32. This issue proves that a future
//! supervisor reserves a distinct channel and never gives lifecycle code
//! access to that receiver.

#![cfg(any(target_os = "linux", target_os = "macos"))]
#![allow(dead_code)] // The first integration is intentionally deferred past issue #50.

use std::fmt;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::{AddressFamily, SocketType};

use super::channel::DescriptorIdentity;
use crate::profiles::{
    AwaitingProviderLeaseAck, Profile, ProfileError, ProviderLeaseTransferSendError, Registry,
    UnacknowledgedTargetGuardianLease, VerifiedTargetReservation,
};

/// The only endpoint allowed to send the one-shot provider lease.
#[must_use = "dropping the transfer sender changes lease-transfer liveness"]
pub(super) struct TransferSender {
    stream: UnixStream,
}

impl TransferSender {
    pub(super) fn send_provider_lease(
        &self,
        reservation: VerifiedTargetReservation,
    ) -> Result<AwaitingProviderLeaseAck<'_>, Box<ProviderLeaseTransferSendError>> {
        reservation.send_provider_lease(&self.stream)
    }
}

/// The only endpoint allowed to receive the one-shot provider lease.
#[must_use = "dropping the transfer receiver changes lease-transfer liveness"]
pub(super) struct TransferReceiver {
    stream: UnixStream,
}

impl TransferReceiver {
    pub(super) fn receive_provider_lease<'channel>(
        &'channel self,
        registry: &Registry,
        profile: &Profile,
    ) -> Result<UnacknowledgedTargetGuardianLease<'channel>, ProfileError> {
        registry.receive_profile_provider_lease(profile, &self.stream)
    }
}

/// A separate sender/receiver pair reserved for optional `SCM_RIGHTS` work.
///
/// The pair is intentionally not `Clone`. Its endpoints have disjoint typed
/// operations, so lifecycle code cannot accidentally become a second
/// ancillary-data reader. Keeping it live in this slice also supplies the
/// child-exec descriptor leak assertions.
#[must_use = "the transfer channel pair must remain owned or be deliberately dropped"]
pub(super) struct TransferChannelPair {
    sender: TransferSender,
    receiver: TransferReceiver,
}

impl TransferChannelPair {
    pub(super) fn new() -> Result<Self, TransferChannelError> {
        let (sender, receiver) = create_socket_pair()?;

        #[cfg(target_os = "linux")]
        {
            // Linux created both descriptors atomically with `SOCK_CLOEXEC`.
            verify_close_on_exec(&sender)?;
            verify_close_on_exec(&receiver)?;
        }
        #[cfg(target_os = "macos")]
        {
            // Darwin lacks `SOCK_CLOEXEC`; no worker or spawn is permitted
            // between pair creation and these immediate flag readbacks.
            set_and_verify_close_on_exec(&sender)?;
            set_and_verify_close_on_exec(&receiver)?;
        }

        verify_connected_unix_stream(&sender)?;
        verify_connected_unix_stream(&receiver)?;
        Ok(Self {
            sender: TransferSender { stream: sender },
            receiver: TransferReceiver { stream: receiver },
        })
    }

    pub(super) fn sender_identity(&self) -> Result<DescriptorIdentity, TransferChannelError> {
        read_identity(&self.sender.stream)
    }

    pub(super) fn receiver_identity(&self) -> Result<DescriptorIdentity, TransferChannelError> {
        read_identity(&self.receiver.stream)
    }
}

impl fmt::Debug for TransferChannelPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.sender, &self.receiver);
        formatter.write_str("TransferChannelPair(<redacted>)")
    }
}

#[cfg(target_os = "linux")]
fn create_socket_pair() -> Result<(UnixStream, UnixStream), TransferChannelError> {
    let (sender, receiver) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| TransferChannelError::Create)?;
    Ok((UnixStream::from(sender), UnixStream::from(receiver)))
}

#[cfg(target_os = "macos")]
fn create_socket_pair() -> Result<(UnixStream, UnixStream), TransferChannelError> {
    UnixStream::pair().map_err(|_| TransferChannelError::Create)
}

fn set_and_verify_close_on_exec<Fd: AsFd>(descriptor: Fd) -> Result<(), TransferChannelError> {
    let flags = fcntl_getfd(&descriptor).map_err(|_| TransferChannelError::DescriptorFlags)?;
    fcntl_setfd(&descriptor, flags | FdFlags::CLOEXEC)
        .map_err(|_| TransferChannelError::DescriptorFlags)?;
    verify_close_on_exec(descriptor)
}

fn verify_close_on_exec<Fd: AsFd>(descriptor: Fd) -> Result<(), TransferChannelError> {
    let flags = fcntl_getfd(descriptor).map_err(|_| TransferChannelError::DescriptorFlags)?;
    if flags.contains(FdFlags::CLOEXEC) {
        Ok(())
    } else {
        Err(TransferChannelError::DescriptorInheritable)
    }
}

fn verify_connected_unix_stream<Fd: AsFd>(descriptor: Fd) -> Result<(), TransferChannelError> {
    let socket_type = rustix::net::sockopt::socket_type(&descriptor)
        .map_err(|_| TransferChannelError::InvalidSocket)?;
    if socket_type != SocketType::STREAM {
        return Err(TransferChannelError::InvalidSocketType);
    }

    let local =
        rustix::net::getsockname(&descriptor).map_err(|_| TransferChannelError::InvalidSocket)?;
    if local.address_family() != AddressFamily::UNIX {
        return Err(TransferChannelError::InvalidSocketDomain);
    }

    let peer =
        rustix::net::getpeername(descriptor).map_err(|_| TransferChannelError::MissingPeer)?;
    match peer {
        Some(peer) if peer.address_family() == AddressFamily::UNIX => Ok(()),
        Some(_) => Err(TransferChannelError::InvalidPeerDomain),
        // Darwin represents an unnamed connected socketpair peer with a zero
        // address length. The successful syscall is the connectedness proof.
        None => Ok(()),
    }
}

fn read_identity<Fd: AsFd>(descriptor: Fd) -> Result<DescriptorIdentity, TransferChannelError> {
    let identity = calcifer_unix_child_fd::descriptor_identity(descriptor.as_fd())
        .map_err(|_| TransferChannelError::DescriptorIdentity)?;
    Ok(DescriptorIdentity::from_scan_identity(identity))
}

/// A fixed transfer-channel failure with no retained OS error or identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TransferChannelError {
    Create,
    DescriptorFlags,
    DescriptorInheritable,
    DescriptorIdentity,
    InvalidSocket,
    InvalidSocketType,
    InvalidSocketDomain,
    InvalidPeerDomain,
    MissingPeer,
}

impl TransferChannelError {
    const fn code(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::DescriptorFlags => "descriptor_flags",
            Self::DescriptorInheritable => "descriptor_inheritable",
            Self::DescriptorIdentity => "descriptor_identity",
            Self::InvalidSocket => "invalid_socket",
            Self::InvalidSocketType => "invalid_socket_type",
            Self::InvalidSocketDomain => "invalid_socket_domain",
            Self::InvalidPeerDomain => "invalid_peer_domain",
            Self::MissingPeer => "missing_peer",
        }
    }
}

impl fmt::Debug for TransferChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TransferChannelError")
            .field(&self.code())
            .finish()
    }
}

impl fmt::Display for TransferChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Create => "the transfer channel could not be created",
            Self::DescriptorFlags => "the transfer descriptor flags could not be verified",
            Self::DescriptorInheritable => "a transfer descriptor was inheritable",
            Self::DescriptorIdentity => "the transfer descriptor identity could not be read",
            Self::InvalidSocket => "the transfer descriptor was not a valid socket",
            Self::InvalidSocketType => "the transfer socket type was invalid",
            Self::InvalidSocketDomain => "the transfer socket domain was invalid",
            Self::InvalidPeerDomain => "the transfer peer domain was invalid",
            Self::MissingPeer => "the transfer socket had no connected peer",
        })
    }
}

impl std::error::Error for TransferChannelError {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;
    use std::io::{Read, Write};

    #[test]
    fn pair_is_cloexec_connected_and_duplex() -> Result<(), Box<dyn Error>> {
        let mut pair = TransferChannelPair::new()?;

        verify_close_on_exec(&pair.sender.stream)?;
        verify_close_on_exec(&pair.receiver.stream)?;
        verify_connected_unix_stream(&pair.sender.stream)?;
        verify_connected_unix_stream(&pair.receiver.stream)?;

        pair.sender.stream.write_all(b"transfer")?;
        let mut payload = [0_u8; 8];
        pair.receiver.stream.read_exact(&mut payload)?;
        assert_eq!(&payload, b"transfer");
        Ok(())
    }

    #[test]
    fn sender_and_receiver_identities_are_stable_and_redacted() -> Result<(), Box<dyn Error>> {
        let pair = TransferChannelPair::new()?;
        let sender = pair.sender_identity()?;
        let receiver = pair.receiver_identity()?;

        assert_eq!(sender, pair.sender_identity()?);
        assert_eq!(receiver, pair.receiver_identity()?);
        assert_ne!(sender.for_scan().inode, 0);
        assert_ne!(receiver.for_scan().inode, 0);
        assert_eq!(format!("{sender:?}"), "DescriptorIdentity(<redacted>)");
        assert_eq!(format!("{receiver:?}"), "DescriptorIdentity(<redacted>)");
        assert_eq!(format!("{pair:?}"), "TransferChannelPair(<redacted>)");
        Ok(())
    }

    #[test]
    fn errors_are_bounded_and_redacted() {
        let errors = [
            TransferChannelError::Create,
            TransferChannelError::DescriptorFlags,
            TransferChannelError::DescriptorInheritable,
            TransferChannelError::DescriptorIdentity,
            TransferChannelError::InvalidSocket,
            TransferChannelError::InvalidSocketType,
            TransferChannelError::InvalidSocketDomain,
            TransferChannelError::InvalidPeerDomain,
            TransferChannelError::MissingPeer,
        ];

        for error in errors {
            let rendered = format!("{error:?}");
            assert!(rendered.starts_with("TransferChannelError(\""));
            assert!(!rendered.contains('/'));
            assert!(!rendered.contains('@'));
            assert!(!rendered.contains("codex"));
        }
    }
}
