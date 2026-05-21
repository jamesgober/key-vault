//! Layer 9 — Audit logging.
//!
//! Where Layer 8 ([`crate::monitor`]) reports **anomalies and
//! failures**, Layer 9 records **every operation** the vault performs.
//! Every successful access — register, read, rotate, unregister,
//! master-unlock attempt — produces an [`AuditEvent`] that the
//! configured [`AuditSink`] receives.
//!
//! The audit trail is the forensic complement to the monitor:
//! monitors tell you when something went wrong; audit logs tell you
//! what happened across the lifetime of the vault, in order.
//!
//! # Storage discipline
//!
//! Audit events are designed to be safe to ship to remote sinks
//! (centralized log aggregators, SIEM systems, compliance archives).
//! Every field is sanitized by trait contract:
//!
//! - **No key bytes** — the vault never passes raw key material to a
//!   sink. Only the key's name appears.
//! - **No caller-supplied secrets** — the `note` field is
//!   `Cow<'static, str>`; caller responsibility to keep it free of
//!   key-equivalent values.
//!
//! # Default
//!
//! The default sink is [`NoAudit`] — events are constructed and
//! discarded. Zero allocations on the happy path (the event struct is
//! built on the stack and dropped immediately).
//!
//! Enable a real sink with [`KeyVaultBuilder::with_audit_sink`](crate::KeyVaultBuilder::with_audit_sink).

use alloc::borrow::Cow;
use alloc::string::String;
use core::fmt;
use core::time::Duration;
use std::thread::ThreadId;

mod no_audit;

pub use self::no_audit::NoAudit;

#[cfg(feature = "monitor-tracing")]
mod log_audit;
#[cfg(feature = "monitor-tracing")]
pub use self::log_audit::LogAudit;

/// Discriminant of the operation an [`AuditEvent`] describes.
///
/// `#[non_exhaustive]` — new variants are additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessKind {
    /// A new named key was registered via
    /// [`KeyVault::register`](crate::KeyVault::register).
    Register,
    /// A registered key was removed via
    /// [`KeyVault::unregister`](crate::KeyVault::unregister).
    Unregister,
    /// The key was accessed in a scoped callback via
    /// [`KeyVault::with_key`](crate::KeyVault::with_key).
    Read,
    /// The key was rotated to fresh material via
    /// [`KeyVault::rotate`](crate::KeyVault::rotate).
    Rotate,
    /// A one-shot [`KeyVault::fragment`](crate::KeyVault::fragment)
    /// call (no registry entry).
    OneShotFragment,
    /// A one-shot [`KeyVault::defragment`](crate::KeyVault::defragment)
    /// call.
    OneShotDefragment,
    /// A master-key emergency-unlock attempt. The boolean reports
    /// whether the supplied bytes matched the stored digest.
    MasterUnlockAttempt {
        /// `true` if the supplied bytes matched the registered master
        /// digest in constant-time comparison.
        matched: bool,
    },
}

impl fmt::Display for AccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register => f.write_str("register"),
            Self::Unregister => f.write_str("unregister"),
            Self::Read => f.write_str("read"),
            Self::Rotate => f.write_str("rotate"),
            Self::OneShotFragment => f.write_str("one-shot-fragment"),
            Self::OneShotDefragment => f.write_str("one-shot-defragment"),
            Self::MasterUnlockAttempt { matched: true } => f.write_str("master-unlock-ok"),
            Self::MasterUnlockAttempt { matched: false } => f.write_str("master-unlock-fail"),
        }
    }
}

/// Single record in the vault's audit trail.
///
/// Constructed by the vault on every operation; passed to the
/// configured [`AuditSink`]. All fields are non-secret and safe to ship
/// to log aggregators / SIEM systems.
///
/// `#[non_exhaustive]` — additional fields (caller identity, request
/// id correlation, etc.) may be added in minor releases.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuditEvent {
    /// Time the event was emitted, expressed as a `Duration` since the
    /// Unix epoch. Same encoding used by [`KeyMetadata`](crate::KeyMetadata)
    /// for portability to future `no_std` builds.
    pub timestamp: Duration,
    /// Logical name of the key. For one-shot fragment/defragment
    /// operations (no registry entry) the value is the empty string.
    /// For master-unlock attempts the reserved name `"<master>"` is
    /// used.
    pub key_name: String,
    /// Operation discriminant.
    pub kind: AccessKind,
    /// Thread that produced the event.
    pub thread_id: ThreadId,
    /// Caller-supplied free-text label. Never includes key material.
    pub note: Cow<'static, str>,
}

/// Outbound channel for the vault's audit trail.
///
/// # Implementor contract
///
/// - **Non-blocking.** Sink calls must return promptly. Network / disk
///   work belongs on a background worker.
/// - **No panics.** A panicking sink implementation is a bug in the
///   implementation, not the vault.
/// - **No back-pressure into the vault.** If the sink is overloaded,
///   shed events internally — never block the caller.
/// - **`Send + Sync`.** Sinks are shared across threads.
pub trait AuditSink: Send + Sync {
    /// Receive one audit event. The sink may inspect any field but
    /// must not mutate the event (it is passed by reference).
    fn on_event(&self, event: &AuditEvent);
}

// Blanket forwarding impl so callers can pass a pre-wrapped
// `Arc<dyn AuditSink>` to APIs that accept `impl AuditSink`.
impl AuditSink for alloc::sync::Arc<dyn AuditSink> {
    fn on_event(&self, event: &AuditEvent) {
        (**self).on_event(event);
    }
}
