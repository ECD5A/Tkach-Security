/*
 * Tkach Security
 *
 * Copyright 2026 ECD5A
 * Licensed under the Apache License, Version 2.0.
 *
 * Repository: https://github.com/ECD5A/Tkach-Security
 *
 * See LICENSE and SECURITY.md.
 */

//! Bounded authenticated runtime transport and lifecycle admission.
//!
//! This module is a transport-independent frame boundary. A deployment may
//! carry the frame over an authenticated local IPC or loopback server, but the
//! frame parser and lifecycle semantics remain inside Tkach. It deliberately
//! does not expose a listener, raw socket, executor, or broker over the wire.

use crate::gateway::{Gateway, GatewayError, GatewayErrorKind};
use crate::input::ExternalRequest;
use crate::provider::{Provider, ProviderError};
use crate::tools::{EffectOutcome, EffectReceipt};
use serde::de::{Deserializer, Error as DeError, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use thiserror::Error;
use tkach_core::domain::{Destination, Operation, ResourceKind};

/// Maximum encoded request frame accepted by the runtime transport.
pub const MAX_RUNTIME_FRAME_BYTES: usize = 64 * 1024;
/// Maximum encoded response frame emitted by the runtime transport.
pub const MAX_RUNTIME_RESPONSE_BYTES: usize = 128 * 1024;
/// Maximum authentication proof length accepted from the wire.
pub const MAX_RUNTIME_AUTH_BYTES: usize = 256;
/// Maximum request/lifecycle identifier length.
pub const MAX_RUNTIME_ID_BYTES: usize = 128;
/// Maximum remembered request/lifecycle identities in one runtime instance.
pub const MAX_RUNTIME_REPLAY_ENTRIES: usize = 1_024;
/// The runtime default is deliberately serialized: no unbounded worker queue.
pub const DEFAULT_MAX_ACTIVE_REQUESTS: usize = 1;
const RUNTIME_TRANSPORT_TIMEOUT: Duration = Duration::from_millis(500);

/// Errors in trusted runtime configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RuntimeConfigError {
    /// The configured authentication proof is empty or oversized.
    #[error("runtime authentication configuration is invalid")]
    InvalidAuthentication,
    /// A runtime limit is zero or exceeds the fixed transport ceiling.
    #[error("runtime limit is invalid")]
    InvalidLimit,
}

/// A bounded opaque request identity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(String);

impl RequestId {
    /// Construct an identifier accepted by the runtime ledger.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeConfigError::InvalidLimit`] for empty, oversized, or
    /// non-token values.
    pub fn new(value: impl Into<String>) -> Result<Self, RuntimeConfigError> {
        let value = value.into();
        if !is_runtime_token(value.as_bytes()) {
            return Err(RuntimeConfigError::InvalidLimit);
        }
        Ok(Self(value))
    }

    /// Return the bounded identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for RequestId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("RequestId").field(&self.0).finish()
    }
}

impl Serialize for RequestId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// A bounded opaque lifecycle identity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LifecycleId(String);

impl LifecycleId {
    /// Construct a lifecycle identifier accepted by the runtime ledger.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeConfigError::InvalidLimit`] for invalid token syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, RuntimeConfigError> {
        let value = value.into();
        if !is_runtime_token(value.as_bytes()) {
            return Err(RuntimeConfigError::InvalidLimit);
        }
        Ok(Self(value))
    }

    /// Return the bounded identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for LifecycleId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("LifecycleId").field(&self.0).finish()
    }
}

impl Serialize for LifecycleId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// Trusted runtime authentication configuration.
pub struct RuntimeAuthenticator {
    expected: Vec<u8>,
}

impl Debug for RuntimeAuthenticator {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RuntimeAuthenticator(REDACTED)")
    }
}

impl RuntimeAuthenticator {
    /// Construct an authenticator from trusted deployment configuration.
    ///
    /// The proof is kept private and is never serialized, displayed, or put
    /// into a runtime error. This API makes no zeroization claim.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeConfigError::InvalidAuthentication`] for an empty or
    /// oversized proof.
    pub fn new(proof: impl Into<Vec<u8>>) -> Result<Self, RuntimeConfigError> {
        let expected = proof.into();
        if expected.is_empty() || expected.len() > MAX_RUNTIME_AUTH_BYTES {
            return Err(RuntimeConfigError::InvalidAuthentication);
        }
        Ok(Self { expected })
    }

    fn authenticates(&self, supplied: &str) -> bool {
        constant_time_equal(supplied.as_bytes(), &self.expected)
    }
}

/// Explicit runtime outcome. `OutcomeUnknown` is terminal and is never a
/// success/failure claim or a retry instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOutcome {
    /// The Gateway completed and any reported effect was verified.
    Success,
    /// Authentication or core authorization denied the request.
    Denied,
    /// The request failed before a protected effect was attempted.
    FailedBeforeEffect,
    /// An effect may have occurred but its final state cannot be proven.
    OutcomeUnknown,
}

/// Safe runtime failure category. It contains no caller/model payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFailure {
    /// The encoded frame was oversized or malformed.
    InvalidFrame,
    /// The authentication proof was absent or invalid.
    AuthenticationFailed,
    /// The request or lifecycle identity was already consumed.
    Replay,
    /// The bounded replay ledger cannot admit another identity.
    ReplayCapacityExceeded,
    /// The runtime stopped accepting new lifecycles.
    ShuttingDown,
    /// The bounded active-request budget was reached.
    ConcurrencyLimit,
    /// The external request failed strict Gateway validation.
    InvalidRequest,
    /// Cancellation was observed before a pending boundary.
    Cancelled,
    /// Provider behavior failed or was malformed.
    ProviderFailure,
    /// Strong Core or egress authorization denied an operation.
    AuthorizationDenied,
    /// A protected executor rejected/failed before an effect.
    EffectFailedBeforeEffect,
    /// The effect outcome cannot be determined.
    EffectOutcomeUnknown,
    /// The safe response itself exceeded its transport bound.
    ResponseTooLarge,
}

/// Static transport errors. OS/socket details are intentionally not returned
/// to the untrusted caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RuntimeTransportError {
    /// The listener address is not loopback-only.
    #[error("runtime transport must bind to a loopback address")]
    NonLoopbackBind,
    /// A listener or stream operation failed.
    #[error("runtime transport I/O failed")]
    Io,
    /// A response could not be represented within the response frame bound.
    #[error("runtime transport response is too large")]
    ResponseTooLarge,
}

/// A payload-free summary of one executor effect for transport evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeEffect {
    operation: Operation,
    resource_kind: ResourceKind,
    destination: Destination,
    execution_id: u64,
    outcome: RuntimeEffectOutcome,
}

impl RuntimeEffect {
    /// Return the effect operation.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Return the resource category without a resource identifier.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    /// Return the destination category.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Return the bounded executor sequence number.
    #[must_use]
    pub const fn execution_id(&self) -> u64 {
        self.execution_id
    }

    /// Return the verified effect outcome.
    #[must_use]
    pub const fn outcome(&self) -> RuntimeEffectOutcome {
        self.outcome
    }
}

/// Outcome of an effect represented inside a successful receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEffectOutcome {
    /// The executor verified the local commit/response contract.
    Committed,
}

/// Bounded payload-free lifecycle receipt. It is evidence, never a `Propusk`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeReceipt {
    request_id: RequestId,
    lifecycle_id: LifecycleId,
    outcome: RuntimeOutcome,
    uncertain: bool,
    effects: Vec<RuntimeEffect>,
}

impl RuntimeReceipt {
    /// Return the request identity.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Return the lifecycle identity.
    #[must_use]
    pub const fn lifecycle_id(&self) -> &LifecycleId {
        &self.lifecycle_id
    }

    /// Return the lifecycle outcome.
    #[must_use]
    pub const fn outcome(&self) -> RuntimeOutcome {
        self.outcome
    }

    /// Return whether the effect result is uncertain.
    #[must_use]
    pub const fn uncertain(&self) -> bool {
        self.uncertain
    }

    /// Return bounded effect summaries.
    #[must_use]
    pub fn effects(&self) -> &[RuntimeEffect] {
        &self.effects
    }
}

/// Safe response returned by the frame boundary.
#[derive(Clone, Serialize)]
pub enum RuntimeResponse {
    /// A successful, fully gated Gateway result.
    Success {
        /// Payload-free receipt for the lifecycle.
        receipt: RuntimeReceipt,
        /// Output released by the Gateway's final egress checks.
        output: Option<String>,
    },
    /// A terminal failure with no protected output.
    Failure {
        /// Parsed request identity, when it was safe to retain.
        request_id: Option<RequestId>,
        /// Parsed lifecycle identity, when it was safe to retain.
        lifecycle_id: Option<LifecycleId>,
        /// Static failure category.
        failure: RuntimeFailure,
        /// Payload-free terminal receipt.
        receipt: Option<RuntimeReceipt>,
    },
}

impl Debug for RuntimeResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success { receipt, output } => formatter
                .debug_struct("RuntimeResponse::Success")
                .field("receipt", receipt)
                .field("has_output", &output.is_some())
                .finish(),
            Self::Failure {
                request_id,
                lifecycle_id,
                failure,
                receipt,
            } => formatter
                .debug_struct("RuntimeResponse::Failure")
                .field("request_id", request_id)
                .field("lifecycle_id", lifecycle_id)
                .field("failure", failure)
                .field("receipt", receipt)
                .finish(),
        }
    }
}

impl RuntimeResponse {
    /// Encode a bounded response frame without exposing authentication data.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeFailure::ResponseTooLarge`] if the encoded response
    /// exceeds the fixed response budget.
    pub fn to_json(&self) -> Result<Vec<u8>, RuntimeFailure> {
        let bytes = serde_json::to_vec(self).map_err(|_| RuntimeFailure::ResponseTooLarge)?;
        if bytes.len() > MAX_RUNTIME_RESPONSE_BYTES {
            return Err(RuntimeFailure::ResponseTooLarge);
        }
        Ok(bytes)
    }

    fn transport_fallback(&self) -> Self {
        match self {
            Self::Success { receipt, .. } => Self::Failure {
                request_id: Some(receipt.request_id.clone()),
                lifecycle_id: Some(receipt.lifecycle_id.clone()),
                failure: RuntimeFailure::ResponseTooLarge,
                receipt: Some(receipt.clone()),
            },
            Self::Failure {
                request_id,
                lifecycle_id,
                receipt,
                ..
            } => Self::Failure {
                request_id: request_id.clone(),
                lifecycle_id: lifecycle_id.clone(),
                failure: RuntimeFailure::ResponseTooLarge,
                receipt: receipt.clone(),
            },
        }
    }
}

/// Cancellation state owned by the caller of one runtime lifecycle.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Construct a non-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the lifecycle cancelled. Cancellation is sticky.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Return whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Bounded runtime admission configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeLimits {
    max_frame_bytes: usize,
    max_active_requests: usize,
}

impl RuntimeLimits {
    /// Construct limits below the fixed protocol ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeConfigError::InvalidLimit`] for zero or oversized
    /// values.
    pub fn new(
        max_frame_bytes: usize,
        max_active_requests: usize,
    ) -> Result<Self, RuntimeConfigError> {
        if max_frame_bytes == 0
            || max_frame_bytes > MAX_RUNTIME_FRAME_BYTES
            || max_active_requests == 0
        {
            return Err(RuntimeConfigError::InvalidLimit);
        }
        Ok(Self {
            max_frame_bytes,
            max_active_requests,
        })
    }

    /// Return the configured request frame ceiling.
    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }

    /// Return the configured active-request ceiling.
    #[must_use]
    pub const fn max_active_requests(self) -> usize {
        self.max_active_requests
    }
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: MAX_RUNTIME_FRAME_BYTES,
            max_active_requests: DEFAULT_MAX_ACTIVE_REQUESTS,
        }
    }
}

struct RuntimeLedger {
    accepting: bool,
    active_requests: usize,
    request_ids: BTreeSet<RequestId>,
    lifecycle_ids: BTreeSet<LifecycleId>,
}

impl RuntimeLedger {
    fn new() -> Self {
        Self {
            accepting: true,
            active_requests: 0,
            request_ids: BTreeSet::new(),
            lifecycle_ids: BTreeSet::new(),
        }
    }

    fn begin(
        &mut self,
        request_id: RequestId,
        lifecycle_id: LifecycleId,
        limits: RuntimeLimits,
    ) -> Result<(), RuntimeFailure> {
        if !self.accepting {
            return Err(RuntimeFailure::ShuttingDown);
        }
        if self.active_requests >= limits.max_active_requests {
            return Err(RuntimeFailure::ConcurrencyLimit);
        }
        if self.request_ids.contains(&request_id) || self.lifecycle_ids.contains(&lifecycle_id) {
            return Err(RuntimeFailure::Replay);
        }
        if self.request_ids.len() >= MAX_RUNTIME_REPLAY_ENTRIES
            || self.lifecycle_ids.len() >= MAX_RUNTIME_REPLAY_ENTRIES
        {
            return Err(RuntimeFailure::ReplayCapacityExceeded);
        }
        self.request_ids.insert(request_id);
        self.lifecycle_ids.insert(lifecycle_id);
        self.active_requests += 1;
        Ok(())
    }

    fn finish(&mut self) {
        self.active_requests = self.active_requests.saturating_sub(1);
    }
}

/// Provider-independent authenticated runtime service.
pub struct RuntimeService<P> {
    gateway: Gateway,
    provider: P,
    authenticator: RuntimeAuthenticator,
    limits: RuntimeLimits,
    ledger: RuntimeLedger,
}

impl<P> Debug for RuntimeService<P> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeService")
            .field("authenticator", &self.authenticator)
            .field("limits", &self.limits)
            .field("accepting", &self.ledger.accepting)
            .field("active_requests", &self.ledger.active_requests)
            .field("remembered_requests", &self.ledger.request_ids.len())
            .finish_non_exhaustive()
    }
}

impl<P: Provider> RuntimeService<P> {
    /// Construct a service with a trusted Gateway, provider, authenticator,
    /// and bounded admission policy.
    #[must_use]
    pub fn new(
        gateway: Gateway,
        provider: P,
        authenticator: RuntimeAuthenticator,
        limits: RuntimeLimits,
    ) -> Self {
        Self {
            gateway,
            provider,
            authenticator,
            limits,
            ledger: RuntimeLedger::new(),
        }
    }

    /// Stop accepting new lifecycles. Existing synchronous work is not
    /// forcefully interrupted; its eventual result remains explicit.
    pub fn shutdown(&mut self) {
        self.ledger.accepting = false;
    }

    /// Return whether new frames are accepted.
    #[must_use]
    pub const fn is_accepting(&self) -> bool {
        self.ledger.accepting
    }

    /// Return the configured runtime limits.
    #[must_use]
    pub const fn limits(&self) -> RuntimeLimits {
        self.limits
    }

    /// Handle one bounded authenticated frame.
    ///
    /// Authentication is checked before nested Gateway request decoding and
    /// before lifecycle admission. The request and lifecycle identities are
    /// consumed for the lifetime of this service even when Gateway denies or
    /// fails; retrying an unknown outcome therefore requires an explicit new
    /// lifecycle and is never automatic.
    #[must_use]
    pub fn handle_frame(
        &mut self,
        frame: &[u8],
        cancellation: &CancellationToken,
    ) -> RuntimeResponse {
        if frame.len() > self.limits.max_frame_bytes {
            return failure_response(None, None, RuntimeFailure::InvalidFrame, None);
        }
        let wire: RuntimeWireRequest = match serde_json::from_slice(frame) {
            Ok(wire) => wire,
            Err(_) => return failure_response(None, None, RuntimeFailure::InvalidFrame, None),
        };
        let Ok(request_id) = RequestId::new(wire.request_id) else {
            return failure_response(None, None, RuntimeFailure::InvalidFrame, None);
        };
        let Ok(lifecycle_id) = LifecycleId::new(wire.lifecycle_id) else {
            return failure_response(Some(request_id), None, RuntimeFailure::InvalidFrame, None);
        };
        if !self.authenticator.authenticates(&wire.auth) {
            return failure_response(
                Some(request_id),
                Some(lifecycle_id),
                RuntimeFailure::AuthenticationFailed,
                None,
            );
        }
        if cancellation.is_cancelled() {
            return failure_response(
                Some(request_id),
                Some(lifecycle_id),
                RuntimeFailure::Cancelled,
                None,
            );
        }
        if let Err(failure) =
            self.ledger
                .begin(request_id.clone(), lifecycle_id.clone(), self.limits)
        {
            return failure_response(Some(request_id), Some(lifecycle_id), failure, None);
        }

        let request_bytes = wire.request.get().as_bytes();
        if request_bytes.len() > crate::MAX_REQUEST_BODY_BYTES {
            self.ledger.finish();
            return failure_response(
                Some(request_id),
                Some(lifecycle_id),
                RuntimeFailure::InvalidRequest,
                None,
            );
        }
        let Ok(request) = ExternalRequest::from_json(request_bytes) else {
            self.ledger.finish();
            return failure_response(
                Some(request_id),
                Some(lifecycle_id),
                RuntimeFailure::InvalidRequest,
                None,
            );
        };

        let result = self
            .gateway
            .run_with_cancellation(&mut self.provider, &request, || cancellation.is_cancelled());
        self.ledger.finish();
        match result {
            Ok(result) => RuntimeResponse::Success {
                receipt: success_receipt(&request_id, &lifecycle_id, result.effects()),
                output: result.output().map(str::to_owned),
            },
            Err(error) => failure_from_gateway(&request_id, &lifecycle_id, &error),
        }
    }
}

/// A sequential loopback transport adapter for [`RuntimeService`].
///
/// The wire format is a four-byte big-endian length followed by one strict
/// JSON runtime frame. It has no compression, redirects, proxy semantics, or
/// internet binding. The adapter intentionally serves one connection at a
/// time; this gives a concrete concurrency ceiling while keeping provider and
/// executor ownership in the Tkach process. A future process split can keep
/// this frame contract and replace the carrier with reviewed authenticated
/// IPC/TLS termination.
pub struct RuntimeListener<P> {
    listener: TcpListener,
    service: RuntimeService<P>,
}

impl<P> Debug for RuntimeListener<P> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeListener")
            .field("local_addr", &self.listener.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl<P: Provider> RuntimeListener<P> {
    /// Bind a runtime service to a loopback address.
    ///
    /// Port zero is accepted for tests and asks the OS to allocate an
    /// ephemeral loopback port. No DNS name or non-loopback address is
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns a static error without exposing the requested address.
    pub fn bind(
        address: SocketAddr,
        service: RuntimeService<P>,
    ) -> Result<Self, RuntimeTransportError> {
        if !address.ip().is_loopback() {
            return Err(RuntimeTransportError::NonLoopbackBind);
        }
        let listener = TcpListener::bind(address).map_err(|_| RuntimeTransportError::Io)?;
        listener
            .set_nonblocking(false)
            .map_err(|_| RuntimeTransportError::Io)?;
        Ok(Self { listener, service })
    }

    /// Return the concrete loopback address selected by the OS.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeTransportError::Io`] if the listener address cannot be
    /// read.
    pub fn local_addr(&self) -> Result<SocketAddr, RuntimeTransportError> {
        self.listener
            .local_addr()
            .map_err(|_| RuntimeTransportError::Io)
    }

    /// Return mutable access to lifecycle controls without exposing the
    /// Gateway, provider, executor, or authenticator internals.
    pub fn service_mut(&mut self) -> &mut RuntimeService<P> {
        &mut self.service
    }

    /// Accept, authenticate, handle, and reply to one framed loopback request.
    ///
    /// The listener reads at most the configured frame bound. A claimed length
    /// above that bound receives a safe invalid-frame response without body
    /// allocation. There is no implicit retry after a stream reset, timeout,
    /// malformed response, or `OutcomeUnknown` result.
    ///
    /// # Errors
    ///
    /// Returns a static transport error when the carrier cannot accept/read/
    /// write the connection. A successfully read application frame always
    /// returns a [`RuntimeResponse`], including authentication and Gateway
    /// denials.
    pub fn serve_one(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<RuntimeResponse, RuntimeTransportError> {
        let (mut stream, _) = self
            .listener
            .accept()
            .map_err(|_| RuntimeTransportError::Io)?;
        stream
            .set_read_timeout(Some(RUNTIME_TRANSPORT_TIMEOUT))
            .map_err(|_| RuntimeTransportError::Io)?;
        stream
            .set_write_timeout(Some(RUNTIME_TRANSPORT_TIMEOUT))
            .map_err(|_| RuntimeTransportError::Io)?;

        let mut header = [0_u8; 4];
        stream
            .read_exact(&mut header)
            .map_err(|_| RuntimeTransportError::Io)?;
        let frame_len = u32::from_be_bytes(header) as usize;
        let response = if frame_len > self.service.limits.max_frame_bytes {
            failure_response(None, None, RuntimeFailure::InvalidFrame, None)
        } else {
            let mut frame = vec![0_u8; frame_len];
            stream
                .read_exact(&mut frame)
                .map_err(|_| RuntimeTransportError::Io)?;
            self.service.handle_frame(&frame, cancellation)
        };
        write_response_frame(&mut stream, &response)?;
        Ok(response)
    }
}

fn write_response_frame(
    stream: &mut TcpStream,
    response: &RuntimeResponse,
) -> Result<(), RuntimeTransportError> {
    let bytes = response
        .to_json()
        .or_else(|_| response.transport_fallback().to_json())
        .map_err(|_| RuntimeTransportError::ResponseTooLarge)?;
    let length = u32::try_from(bytes.len()).map_err(|_| RuntimeTransportError::ResponseTooLarge)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(&bytes))
        .and_then(|()| stream.flush())
        .map_err(|_| RuntimeTransportError::Io)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeWireRequest {
    #[serde(deserialize_with = "deserialize_bounded_id")]
    request_id: String,
    #[serde(deserialize_with = "deserialize_bounded_id")]
    lifecycle_id: String,
    #[serde(deserialize_with = "deserialize_bounded_auth")]
    auth: String,
    request: Box<serde_json::value::RawValue>,
}

fn deserialize_bounded_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_RUNTIME_ID_BYTES>(deserializer)
}

fn deserialize_bounded_auth<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_RUNTIME_AUTH_BYTES>(deserializer)
}

fn deserialize_bounded_string<'de, D, const MAX: usize>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedStringVisitor<const MAX: usize>;

    impl<const MAX: usize> Visitor<'_> for BoundedStringVisitor<MAX> {
        type Value = String;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a string with at most {MAX} bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if value.len() > MAX {
                return Err(E::custom("runtime string exceeds bound"));
            }
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if value.len() > MAX {
                return Err(E::custom("runtime string exceeds bound"));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_string(BoundedStringVisitor::<MAX>)
}

fn is_runtime_token(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RUNTIME_ID_BYTES
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let max = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn success_receipt(
    request_id: &RequestId,
    lifecycle_id: &LifecycleId,
    effects: &[EffectReceipt],
) -> RuntimeReceipt {
    RuntimeReceipt {
        request_id: request_id.clone(),
        lifecycle_id: lifecycle_id.clone(),
        outcome: RuntimeOutcome::Success,
        uncertain: false,
        effects: effects.iter().map(runtime_effect).collect(),
    }
}

fn runtime_effect(effect: &EffectReceipt) -> RuntimeEffect {
    RuntimeEffect {
        operation: effect.operation().clone(),
        resource_kind: effect.resource_kind(),
        destination: effect.destination().clone(),
        execution_id: effect.execution_id(),
        outcome: match effect.outcome() {
            EffectOutcome::Committed => RuntimeEffectOutcome::Committed,
        },
    }
}

fn failure_from_gateway(
    request_id: &RequestId,
    lifecycle_id: &LifecycleId,
    error: &GatewayError,
) -> RuntimeResponse {
    let (failure, outcome, uncertain) = match error.kind() {
        GatewayErrorKind::IngressDenied(_)
        | GatewayErrorKind::ActionDenied(_)
        | GatewayErrorKind::EgressDenied(_)
        | GatewayErrorKind::EgressContentDenied(_) => (
            RuntimeFailure::AuthorizationDenied,
            RuntimeOutcome::Denied,
            false,
        ),
        GatewayErrorKind::InvalidRequest => (
            RuntimeFailure::InvalidRequest,
            RuntimeOutcome::FailedBeforeEffect,
            false,
        ),
        GatewayErrorKind::Provider(provider_error) => {
            if matches!(provider_error, ProviderError::Cancelled) {
                (
                    RuntimeFailure::Cancelled,
                    RuntimeOutcome::FailedBeforeEffect,
                    false,
                )
            } else {
                (
                    RuntimeFailure::ProviderFailure,
                    RuntimeOutcome::FailedBeforeEffect,
                    false,
                )
            }
        }
        GatewayErrorKind::Cancelled => (
            RuntimeFailure::Cancelled,
            RuntimeOutcome::FailedBeforeEffect,
            false,
        ),
        GatewayErrorKind::EffectOutcomeUnknown => (
            RuntimeFailure::EffectOutcomeUnknown,
            RuntimeOutcome::OutcomeUnknown,
            true,
        ),
        GatewayErrorKind::ExecutorFailedBeforeEffect | GatewayErrorKind::ToolRejected => (
            RuntimeFailure::EffectFailedBeforeEffect,
            RuntimeOutcome::FailedBeforeEffect,
            false,
        ),
        GatewayErrorKind::InvalidLifecycle
        | GatewayErrorKind::TraceCapacityExceeded
        | GatewayErrorKind::TurnLimitExceeded => (
            RuntimeFailure::ProviderFailure,
            RuntimeOutcome::FailedBeforeEffect,
            false,
        ),
    };
    let receipt = RuntimeReceipt {
        request_id: request_id.clone(),
        lifecycle_id: lifecycle_id.clone(),
        outcome,
        uncertain,
        effects: Vec::new(),
    };
    failure_response(
        Some(request_id.clone()),
        Some(lifecycle_id.clone()),
        failure,
        Some(receipt),
    )
}

fn failure_response(
    request_id: Option<RequestId>,
    lifecycle_id: Option<LifecycleId>,
    failure: RuntimeFailure,
    receipt: Option<RuntimeReceipt>,
) -> RuntimeResponse {
    RuntimeResponse::Failure {
        request_id,
        lifecycle_id,
        failure,
        receipt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Gateway;
    use crate::provider::{DeterministicProvider, ProviderStep, ScriptedStep};
    use crate::tools::{
        FakeToolBroker, REAL_FILE_WRITE_CONTENT, RealEffectExecutor, protected_write_request,
    };
    use serde_json::json;
    use std::fs;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tkach_core::domain::{ActionRequest, Destination, Identity, PolicyId, Principal, RuleId};
    use tkach_core::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};
    use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
    use tkach_core::zaslon::Zaslon;

    fn service(provider: DeterministicProvider) -> RuntimeService<DeterministicProvider> {
        let gateway = Gateway::new(
            Krosna::with_ruslo(
                Policy::new(PolicyId::new("runtime-test").unwrap(), vec![]).unwrap(),
                Ruslo::new(vec![FlowRule::allow(
                    RuleId::new("allow-runtime-release").unwrap(),
                    FlowMatcher::any()
                        .principal(Principal::Model)
                        .source(FlowSource::Model)
                        .destination(Destination::Internal(Identity::new("client").unwrap()))
                        .operation(FlowOperation::Export),
                )])
                .unwrap(),
            ),
            Zaslon::empty(),
            Zaslon::empty(),
            Destination::Internal(Identity::new("client").unwrap()),
            FakeToolBroker::new(),
        );
        RuntimeService::new(
            gateway,
            provider,
            RuntimeAuthenticator::new(b"runtime-secret".to_vec()).unwrap(),
            RuntimeLimits::default(),
        )
    }

    fn release_only_kernel() -> Krosna {
        Krosna::with_ruslo(
            Policy::new(PolicyId::new("runtime-release-only").unwrap(), vec![]).unwrap(),
            Ruslo::new(vec![FlowRule::allow(
                RuleId::new("allow-runtime-release").unwrap(),
                FlowMatcher::any()
                    .principal(Principal::Model)
                    .source(FlowSource::Model)
                    .destination(Destination::Internal(Identity::new("client").unwrap()))
                    .operation(FlowOperation::Export),
            )])
            .unwrap(),
        )
    }

    fn exact_write_kernel(action: &ActionRequest) -> Krosna {
        let policy = Policy::new(
            PolicyId::new("runtime-real-write").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-exact-runtime-write").unwrap(),
                RuleMatcher::any()
                    .principal(Principal::Model)
                    .operation(action.operation().clone())
                    .capability(action.capability().clone())
                    .resource(tkach_core::domain::ResourceScope::exact(action.resource()))
                    .destination(action.destination().clone())
                    .classification(tkach_core::domain::Classification::Unknown),
            )],
        )
        .unwrap();
        let storage = Destination::Internal(Identity::new("storage").unwrap());
        let client = Destination::Internal(Identity::new("client").unwrap());
        let ruslo = Ruslo::new(vec![
            FlowRule::allow(
                RuleId::new("allow-runtime-storage-transfer").unwrap(),
                FlowMatcher::any()
                    .principal(Principal::Model)
                    .source(FlowSource::Model)
                    .destination(storage)
                    .operation(FlowOperation::Transfer),
            ),
            FlowRule::allow(
                RuleId::new("allow-runtime-client-export").unwrap(),
                FlowMatcher::any()
                    .principal(Principal::Model)
                    .source(FlowSource::Model)
                    .destination(client)
                    .operation(FlowOperation::Export),
            ),
        ])
        .unwrap();
        Krosna::with_ruslo(policy, ruslo)
    }

    fn real_service(
        root: &Path,
        kernel: Krosna,
        provider: DeterministicProvider,
    ) -> RuntimeService<DeterministicProvider> {
        let gateway = Gateway::new(
            kernel,
            Zaslon::empty(),
            Zaslon::empty(),
            Destination::Internal(Identity::new("client").unwrap()),
            RealEffectExecutor::new(root, SocketAddr::from(([127, 0, 0, 1], 1))).unwrap(),
        );
        RuntimeService::new(
            gateway,
            provider,
            RuntimeAuthenticator::new(b"runtime-secret".to_vec()).unwrap(),
            RuntimeLimits::default(),
        )
    }

    fn unique_runtime_root(label: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tkach-runtime-{label}-{suffix}"));
        fs::create_dir_all(root.join("workspace")).unwrap();
        root
    }

    fn frame(request_id: &str, lifecycle_id: &str, auth: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "request_id": request_id,
            "lifecycle_id": lifecycle_id,
            "auth": auth,
            "request": {"messages": [{"role": "user", "content": "hello"}]}
        }))
        .unwrap()
    }

    fn complete_provider() -> DeterministicProvider {
        DeterministicProvider::new(vec![ScriptedStep {
            chunks: vec!["safe response".to_owned()],
            actions: Vec::new(),
            continuation: ProviderStep::Complete,
        }])
    }

    fn unauthorized_action_provider() -> DeterministicProvider {
        DeterministicProvider::new(vec![ScriptedStep {
            chunks: Vec::new(),
            actions: vec![protected_write_request()],
            continuation: ProviderStep::Complete,
        }])
    }

    #[test]
    fn authenticated_bounded_frame_reaches_only_final_gateway_release() {
        let mut service = service(complete_provider());
        let response = service.handle_frame(
            &frame("request-1", "lifecycle-1", "runtime-secret"),
            &CancellationToken::new(),
        );
        match response {
            RuntimeResponse::Success { receipt, output } => {
                assert_eq!(output.as_deref(), Some("safe response"));
                assert_eq!(receipt.outcome(), RuntimeOutcome::Success);
                assert!(!receipt.uncertain());
                assert!(receipt.effects().is_empty());
            }
            RuntimeResponse::Failure { .. } => panic!("authenticated request must succeed"),
        }
    }

    #[test]
    fn invalid_auth_is_terminal_before_provider_and_effect() {
        let mut service = service(complete_provider());
        let response = service.handle_frame(
            &frame("request-1", "lifecycle-1", "wrong"),
            &CancellationToken::new(),
        );
        assert!(matches!(
            response,
            RuntimeResponse::Failure {
                failure: RuntimeFailure::AuthenticationFailed,
                receipt: None,
                ..
            }
        ));
    }

    #[test]
    fn valid_authentication_does_not_authorize_an_unauthorized_effect() {
        let mut service = service(unauthorized_action_provider());
        let response = service.handle_frame(
            &frame("request-1", "lifecycle-1", "runtime-secret"),
            &CancellationToken::new(),
        );
        assert!(matches!(
            response,
            RuntimeResponse::Failure {
                failure: RuntimeFailure::AuthorizationDenied,
                receipt: Some(RuntimeReceipt {
                    outcome: RuntimeOutcome::Denied,
                    uncertain: false,
                    ..
                }),
                ..
            }
        ));
    }

    #[test]
    fn request_and_lifecycle_replay_are_rejected_without_provider_retry() {
        let mut service = service(complete_provider());
        let token = CancellationToken::new();
        assert!(matches!(
            service.handle_frame(&frame("request-1", "lifecycle-1", "runtime-secret"), &token),
            RuntimeResponse::Success { .. }
        ));
        assert!(matches!(
            service.handle_frame(&frame("request-1", "lifecycle-2", "runtime-secret"), &token),
            RuntimeResponse::Failure {
                failure: RuntimeFailure::Replay,
                ..
            }
        ));
        assert!(matches!(
            service.handle_frame(&frame("request-2", "lifecycle-1", "runtime-secret"), &token),
            RuntimeResponse::Failure {
                failure: RuntimeFailure::Replay,
                ..
            }
        ));
    }

    #[test]
    fn cancellation_and_shutdown_are_terminal_admission_states() {
        let mut service = service(complete_provider());
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            service.handle_frame(
                &frame("request-1", "lifecycle-1", "runtime-secret"),
                &cancelled
            ),
            RuntimeResponse::Failure {
                failure: RuntimeFailure::Cancelled,
                ..
            }
        ));
        service.shutdown();
        assert!(!service.is_accepting());
        assert!(matches!(
            service.handle_frame(
                &frame("request-2", "lifecycle-2", "runtime-secret"),
                &CancellationToken::new()
            ),
            RuntimeResponse::Failure {
                failure: RuntimeFailure::ShuttingDown,
                ..
            }
        ));
    }

    #[test]
    fn frame_and_response_budgets_and_debug_surfaces_are_bounded() {
        let mut service = service(complete_provider());
        let oversized = vec![b'x'; MAX_RUNTIME_FRAME_BYTES + 1];
        assert!(matches!(
            service.handle_frame(&oversized, &CancellationToken::new()),
            RuntimeResponse::Failure {
                failure: RuntimeFailure::InvalidFrame,
                ..
            }
        ));
        let response = service.handle_frame(
            &frame("request-1", "lifecycle-1", "runtime-secret"),
            &CancellationToken::new(),
        );
        let debug = format!("{response:?}");
        assert!(!debug.contains("runtime-secret"));
        assert!(!debug.contains("safe response"));
        assert!(response.to_json().unwrap().len() <= MAX_RUNTIME_RESPONSE_BYTES);
    }

    #[test]
    fn oversized_transport_output_preserves_the_effect_receipt_without_retry() {
        let receipt = RuntimeReceipt {
            request_id: RequestId::new("request-transport").unwrap(),
            lifecycle_id: LifecycleId::new("lifecycle-transport").unwrap(),
            outcome: RuntimeOutcome::Success,
            uncertain: false,
            effects: Vec::new(),
        };
        let response = RuntimeResponse::Success {
            receipt,
            output: Some("\0".repeat(32 * 1024)),
        };
        assert_eq!(response.to_json(), Err(RuntimeFailure::ResponseTooLarge));
        let fallback = response.transport_fallback();
        match &fallback {
            RuntimeResponse::Failure {
                failure: RuntimeFailure::ResponseTooLarge,
                receipt: Some(receipt),
                ..
            } => {
                assert_eq!(receipt.outcome(), RuntimeOutcome::Success);
                assert!(!receipt.uncertain());
            }
            RuntimeResponse::Success { .. } | RuntimeResponse::Failure { .. } => {
                panic!("transport fallback must preserve a terminal receipt")
            }
        }
        assert!(fallback.to_json().is_ok());
    }

    #[test]
    fn malformed_nested_request_fails_after_auth_without_gateway_invocation() {
        let mut service = service(complete_provider());
        let body = serde_json::to_vec(&json!({
            "request_id": "request-1",
            "lifecycle_id": "lifecycle-1",
            "auth": "runtime-secret",
            "request": {"messages": []}
        }))
        .unwrap();
        assert!(matches!(
            service.handle_frame(&body, &CancellationToken::new()),
            RuntimeResponse::Failure {
                failure: RuntimeFailure::InvalidRequest,
                receipt: None,
                ..
            }
        ));
    }

    #[test]
    fn constant_time_comparison_does_not_accept_prefix_or_empty_proofs() {
        assert!(constant_time_equal(b"secret", b"secret"));
        assert!(!constant_time_equal(b"secret", b"secret2"));
        assert!(!constant_time_equal(b"", b"secret"));
    }

    #[test]
    fn runtime_limits_reject_zero_and_oversized_values() {
        assert!(RuntimeLimits::new(0, 1).is_err());
        assert!(RuntimeLimits::new(MAX_RUNTIME_FRAME_BYTES + 1, 1).is_err());
        assert!(RuntimeLimits::new(MAX_RUNTIME_FRAME_BYTES, 0).is_err());
        assert!(RuntimeAuthenticator::new(Vec::new()).is_err());
        assert!(RequestId::new("../escape").is_err());
        assert!(LifecycleId::new(" ").is_err());
    }

    #[test]
    fn admission_ledger_enforces_a_bounded_active_request_count() {
        let limits = RuntimeLimits::new(MAX_RUNTIME_FRAME_BYTES, 1).unwrap();
        let mut ledger = RuntimeLedger::new();
        ledger
            .begin(
                RequestId::new("request-1").unwrap(),
                LifecycleId::new("lifecycle-1").unwrap(),
                limits,
            )
            .unwrap();
        assert_eq!(
            ledger.begin(
                RequestId::new("request-2").unwrap(),
                LifecycleId::new("lifecycle-2").unwrap(),
                limits,
            ),
            Err(RuntimeFailure::ConcurrencyLimit)
        );
        ledger.finish();
    }

    #[test]
    fn replay_ledger_rejects_new_identities_at_the_fixed_capacity() {
        let limits = RuntimeLimits::default();
        let mut ledger = RuntimeLedger::new();
        for index in 0..MAX_RUNTIME_REPLAY_ENTRIES {
            ledger
                .begin(
                    RequestId::new(format!("request-{index}")).unwrap(),
                    LifecycleId::new(format!("lifecycle-{index}")).unwrap(),
                    limits,
                )
                .unwrap();
            ledger.finish();
        }
        assert_eq!(
            ledger.begin(
                RequestId::new("request-over-capacity").unwrap(),
                LifecycleId::new("lifecycle-over-capacity").unwrap(),
                limits,
            ),
            Err(RuntimeFailure::ReplayCapacityExceeded)
        );
    }

    #[test]
    fn outcome_unknown_is_a_terminal_uncertain_receipt_not_a_retry_instruction() {
        let error = GatewayError::new(GatewayErrorKind::EffectOutcomeUnknown);
        let request_id = RequestId::new("request-unknown").unwrap();
        let lifecycle_id = LifecycleId::new("lifecycle-unknown").unwrap();
        let response = failure_from_gateway(&request_id, &lifecycle_id, &error);
        match response {
            RuntimeResponse::Failure {
                failure: RuntimeFailure::EffectOutcomeUnknown,
                receipt: Some(receipt),
                ..
            } => {
                assert_eq!(receipt.outcome(), RuntimeOutcome::OutcomeUnknown);
                assert!(receipt.uncertain());
                assert!(receipt.effects().is_empty());
            }
            RuntimeResponse::Success { .. } | RuntimeResponse::Failure { .. } => {
                panic!("unknown outcome must be represented explicitly")
            }
        }
    }

    #[test]
    fn authenticated_runtime_commits_exact_real_write_once_and_replay_is_terminal() {
        let root = unique_runtime_root("write");
        let action = protected_write_request();
        let provider = DeterministicProvider::new(vec![ScriptedStep {
            chunks: vec!["runtime write".to_owned()],
            actions: vec![action.clone()],
            continuation: ProviderStep::Complete,
        }]);
        let mut service = real_service(&root, exact_write_kernel(&action), provider);
        let token = CancellationToken::new();
        let request = frame(
            "request-real-write",
            "lifecycle-real-write",
            "runtime-secret",
        );

        let response = service.handle_frame(&request, &token);
        match response {
            RuntimeResponse::Success { receipt, output } => {
                assert_eq!(output.as_deref(), Some("runtime write"));
                assert_eq!(receipt.outcome(), RuntimeOutcome::Success);
                assert_eq!(receipt.effects().len(), 1);
                assert_eq!(
                    receipt.effects()[0].outcome(),
                    RuntimeEffectOutcome::Committed
                );
            }
            RuntimeResponse::Failure { .. } => panic!("authorized runtime write must succeed"),
        }
        assert_eq!(
            fs::read(root.join("workspace/output.txt")).unwrap(),
            REAL_FILE_WRITE_CONTENT
        );
        assert!(matches!(
            service.handle_frame(&request, &token),
            RuntimeResponse::Failure {
                failure: RuntimeFailure::Replay,
                ..
            }
        ));
        assert_eq!(
            fs::read(root.join("workspace/output.txt")).unwrap(),
            REAL_FILE_WRITE_CONTENT
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authenticated_runtime_cannot_turn_a_valid_identity_into_real_authority() {
        let root = unique_runtime_root("denied-write");
        let mut service =
            real_service(&root, release_only_kernel(), unauthorized_action_provider());
        let response = service.handle_frame(
            &frame(
                "request-denied-write",
                "lifecycle-denied-write",
                "runtime-secret",
            ),
            &CancellationToken::new(),
        );
        assert!(matches!(
            response,
            RuntimeResponse::Failure {
                failure: RuntimeFailure::AuthorizationDenied,
                receipt: Some(RuntimeReceipt {
                    outcome: RuntimeOutcome::Denied,
                    uncertain: false,
                    ..
                }),
                ..
            }
        ));
        assert!(!root.join("workspace/output.txt").exists());
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loopback_listener_uses_authenticated_bounded_framing() {
        let service = service(complete_provider());
        let mut listener = RuntimeListener::bind("127.0.0.1:0".parse().unwrap(), service).unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let frame = frame("request-1", "lifecycle-1", "runtime-secret");
        client
            .write_all(&(u32::try_from(frame.len()).unwrap()).to_be_bytes())
            .unwrap();
        client.write_all(&frame).unwrap();
        client.flush().unwrap();
        let response = listener.serve_one(&CancellationToken::new()).unwrap();
        assert!(matches!(response, RuntimeResponse::Success { .. }));
        let mut header = [0_u8; 4];
        client.read_exact(&mut header).unwrap();
        let response_len = u32::from_be_bytes(header) as usize;
        assert!(response_len <= MAX_RUNTIME_RESPONSE_BYTES);
        let mut response_body = vec![0_u8; response_len];
        client.read_exact(&mut response_body).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&response_body).unwrap();
        assert_eq!(json["Success"]["output"], "safe response");
        assert!(String::from_utf8_lossy(&response_body).contains("request-1"));
        assert!(!String::from_utf8_lossy(&response_body).contains("runtime-secret"));
    }

    #[test]
    fn loopback_listener_rejects_non_loopback_and_oversized_lengths() {
        let service_for_non_loopback = service(complete_provider());
        assert!(matches!(
            RuntimeListener::bind("192.0.2.1:1234".parse().unwrap(), service_for_non_loopback),
            Err(RuntimeTransportError::NonLoopbackBind)
        ));

        let mut listener =
            RuntimeListener::bind("127.0.0.1:0".parse().unwrap(), service(complete_provider()))
                .unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let too_large = (u32::try_from(MAX_RUNTIME_FRAME_BYTES).unwrap() + 1).to_be_bytes();
        client.write_all(&too_large).unwrap();
        let response = listener.serve_one(&CancellationToken::new()).unwrap();
        assert!(matches!(
            response,
            RuntimeResponse::Failure {
                failure: RuntimeFailure::InvalidFrame,
                ..
            }
        ));
    }
}
