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

//! A small, bounded Rust client for the Tkach loopback HTTP contract.
//!
//! This crate is an adapter only. It validates input with the public Gateway
//! parser, carries a bearer token in the HTTP header, and returns the bounded
//! HTTP response. It does not retry, interpret policy, mint authority, or
//! expose a public-network transport.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::Serialize;
use serde_json::{Value, value::RawValue};
use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use thiserror::Error;
use tkach_gateway::{
    ExternalRequest, LifecycleId, MAX_REQUEST_BODY_BYTES, MAX_RUNTIME_AUTH_BYTES,
    MAX_RUNTIME_RESPONSE_BYTES, RequestId,
};
use tkach_http::{MAX_HTTP_BODY_BYTES, MAX_HTTP_HEADER_BYTES};
use zeroize::Zeroizing;

/// Default total transport budget for one local request/response exchange.
///
/// This leaves bounded headroom above the provider adapter's 30-second
/// default without making a local client wait indefinitely. Requests are
/// still sent once and are never retried.
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(35);

/// Static client-side failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ClientError {
    /// The client would connect to a non-loopback address.
    #[error("Tkach client requires a loopback address")]
    NonLoopbackAddress,
    /// The bearer token is empty, too long, or contains an unsafe byte.
    #[error("bearer authentication is invalid")]
    InvalidAuthentication,
    /// The request is malformed or exceeds a published protocol budget.
    #[error("request is invalid or exceeds the Tkach protocol budget")]
    InvalidRequest,
    /// The connection or socket operation failed.
    #[error("Tkach HTTP connection failed")]
    Io,
    /// The peer returned a malformed or unsupported HTTP response.
    #[error("Tkach HTTP response is invalid")]
    InvalidResponse,
    /// The peer declared a response larger than the published response budget.
    #[error("Tkach HTTP response exceeds the published budget")]
    ResponseTooLarge,
    /// The health endpoint did not return its exact liveness response.
    #[error("Tkach health response was unexpected")]
    UnexpectedHealthResponse,
    /// The readiness endpoint did not report an admitting runtime.
    #[error("Tkach readiness response was unexpected")]
    UnexpectedReadinessResponse,
}

/// A validated request payload for the POST /v1/run endpoint.
pub struct RunRequest {
    request_id: RequestId,
    lifecycle_id: LifecycleId,
    request_json: Vec<u8>,
}

impl Debug for RunRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunRequest")
            .field("request_id", &self.request_id)
            .field("lifecycle_id", &self.lifecycle_id)
            .field("request_bytes", &self.request_json.len())
            .finish()
    }
}

impl RunRequest {
    /// Validate and construct a request from the Gateway JSON object.
    ///
    /// The request bytes are checked before deserialization and are retained
    /// without being logged or echoed. The HTTP envelope is checked again by
    /// the run method because its identifiers add bounded overhead.
    ///
    /// # Errors
    ///
    /// Returns the invalid-request client error when an identifier or the
    /// external request JSON is invalid or exceeds a published budget.
    pub fn new(
        request_id: impl Into<String>,
        lifecycle_id: impl Into<String>,
        request_json: impl Into<Vec<u8>>,
    ) -> Result<Self, ClientError> {
        let request_json = request_json.into();
        if request_json.len() > MAX_REQUEST_BODY_BYTES {
            return Err(ClientError::InvalidRequest);
        }
        let request_id = RequestId::new(request_id).map_err(|_| ClientError::InvalidRequest)?;
        let lifecycle_id =
            LifecycleId::new(lifecycle_id).map_err(|_| ClientError::InvalidRequest)?;
        ExternalRequest::from_json(&request_json).map_err(|_| ClientError::InvalidRequest)?;
        Ok(Self {
            request_id,
            lifecycle_id,
            request_json,
        })
    }

    /// Return the validated request identifier.
    #[must_use]
    pub fn request_id(&self) -> &str {
        self.request_id.as_str()
    }

    /// Return the validated lifecycle identifier.
    #[must_use]
    pub fn lifecycle_id(&self) -> &str {
        self.lifecycle_id.as_str()
    }

    /// Return the original validated Gateway request JSON.
    #[must_use]
    pub fn request_json(&self) -> &[u8] {
        &self.request_json
    }
}

/// A bounded response returned by the Tkach HTTP adapter.
pub struct ClientResponse {
    status_code: u16,
    body: Vec<u8>,
}

/// Stable classification of a bounded runtime response.
///
/// This is an observation of the HTTP/runtime contract, not a policy decision
/// and never a retry instruction. In particular, [`Self::OutcomeUnknown`]
/// means that the client must not guess whether an effect happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseKind {
    /// The runtime completed the request and returned a success receipt.
    Success,
    /// Authentication or Strong Core authorization refused the request.
    Refused,
    /// The provider failed before a protected effect was attempted.
    ProviderFailure,
    /// The effect may have happened but its final state is not provable.
    OutcomeUnknown,
    /// The request/lifecycle was replayed or cancelled at a terminal boundary.
    ReplayOrCancelled,
    /// The runtime cannot currently admit the request.
    Unavailable,
    /// The request or its protocol envelope was rejected.
    InvalidRequest,
    /// A protected effect failed before it could be committed.
    EffectFailed,
    /// The status is outside the stable classifications above.
    Other,
}

impl ResponseKind {
    /// Return the stable wire-safe label for this classification.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Refused => "refused",
            Self::ProviderFailure => "provider_failure",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::ReplayOrCancelled => "replay_or_cancelled",
            Self::Unavailable => "unavailable",
            Self::InvalidRequest => "invalid_request",
            Self::EffectFailed => "effect_failed",
            Self::Other => "other",
        }
    }
}

impl Debug for ClientResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientResponse")
            .field("status_code", &self.status_code)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl ClientResponse {
    /// Return the HTTP status code without interpreting its policy meaning.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Return the bounded JSON response bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Return whether the peer returned a 2xx status.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }

    /// Classify the runtime result without interpreting model/provider data.
    ///
    /// The classification is intentionally terminal. Callers must not retry a
    /// `ReplayOrCancelled`, `EffectFailed`, or `OutcomeUnknown` response.
    #[must_use]
    pub fn kind(&self) -> ResponseKind {
        match self.status_code {
            200..=299 => ResponseKind::Success,
            401 | 403 => ResponseKind::Refused,
            400 | 413 | 415 => ResponseKind::InvalidRequest,
            409 => ResponseKind::ReplayOrCancelled,
            424 => ResponseKind::EffectFailed,
            502 => ResponseKind::ProviderFailure,
            503 if response_failure_is(self.body(), "effect_outcome_unknown") => {
                ResponseKind::OutcomeUnknown
            }
            503 => ResponseKind::Unavailable,
            _ => ResponseKind::Other,
        }
    }
}

fn response_failure_is(body: &[u8], expected: &str) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("Failure").cloned())
        .and_then(|value| value.get("failure").cloned())
        .and_then(|value| value.as_str().map(str::to_owned))
        .is_some_and(|value| value == expected)
}

/// A loopback-only client for the published Tkach HTTP adapter.
pub struct TkachClient {
    address: SocketAddr,
    bearer_token: Zeroizing<String>,
}

impl Debug for TkachClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TkachClient")
            .field("address", &self.address)
            .field("has_bearer_token", &true)
            .finish_non_exhaustive()
    }
}

impl TkachClient {
    /// Create a client for a loopback listener and a validated bearer token.
    ///
    /// No DNS lookup or public-network address is accepted. The token is
    /// zeroized when the client is dropped and is never included in Debug.
    ///
    /// # Errors
    ///
    /// Returns a non-loopback or invalid-authentication client error for
    /// invalid configuration.
    pub fn new(address: SocketAddr, bearer_token: impl Into<String>) -> Result<Self, ClientError> {
        if !address.ip().is_loopback() {
            return Err(ClientError::NonLoopbackAddress);
        }
        let bearer_token = bearer_token.into();
        if bearer_token.is_empty()
            || bearer_token.len() > MAX_RUNTIME_AUTH_BYTES
            || !bearer_token.bytes().all(is_bearer_token_byte)
        {
            return Err(ClientError::InvalidAuthentication);
        }
        Ok(Self {
            address,
            bearer_token: Zeroizing::new(bearer_token),
        })
    }

    /// Return the configured loopback address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Perform the unauthenticated static health check.
    ///
    /// The exact {"status":"ok"} response is required. No retry or fallback
    /// behavior is performed.
    ///
    /// # Errors
    ///
    /// Returns a transport/response error or
    /// an unexpected-health-response client error if liveness is not exact.
    pub fn health(&self) -> Result<(), ClientError> {
        let mut request = Zeroizing::new(Vec::with_capacity(128));
        append_request_prefix(&mut request, "GET", "/healthz", self.address);
        request.extend_from_slice(b"Content-Length: 0\r\nConnection: close\r\n\r\n");
        let response = self.exchange(&request, &[])?;
        if response.status_code == 200 && response.body == br#"{"status":"ok"}"# {
            Ok(())
        } else {
            Err(ClientError::UnexpectedHealthResponse)
        }
    }

    /// Require the exact unauthenticated runtime admission response.
    ///
    /// Readiness means that the runtime is accepting new lifecycles and still
    /// has replay-ledger capacity. It does not probe provider connectivity.
    /// No retry or fallback behavior is performed.
    ///
    /// # Errors
    ///
    /// Returns a transport/response error or an unexpected-readiness-response
    /// client error when the runtime is not ready.
    pub fn ready(&self) -> Result<(), ClientError> {
        let mut request = Zeroizing::new(Vec::with_capacity(128));
        append_request_prefix(&mut request, "GET", "/readyz", self.address);
        request.extend_from_slice(b"Content-Length: 0\r\nConnection: close\r\n\r\n");
        let response = self.exchange(&request, &[])?;
        if response.status_code == 200 && response.body == br#"{"status":"ready"}"# {
            Ok(())
        } else {
            Err(ClientError::UnexpectedReadinessResponse)
        }
    }

    /// Send one validated request to the POST /v1/run endpoint.
    ///
    /// The response status is returned verbatim as a bounded value. In
    /// particular, authentication and authorization statuses are not retried
    /// or converted into client-side authority.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request client error if the HTTP envelope would
    /// exceed its budget, or a transport/response error otherwise.
    pub fn run(&self, request: &RunRequest) -> Result<ClientResponse, ClientError> {
        let raw_request: Box<RawValue> = serde_json::from_slice(&request.request_json)
            .map_err(|_| ClientError::InvalidRequest)?;
        let envelope = HttpRunRequest {
            request_id: request.request_id.as_str(),
            lifecycle_id: request.lifecycle_id.as_str(),
            request: raw_request.as_ref(),
        };
        let body = serde_json::to_vec(&envelope).map_err(|_| ClientError::InvalidRequest)?;
        if body.len() > MAX_HTTP_BODY_BYTES {
            return Err(ClientError::InvalidRequest);
        }
        let mut header = Zeroizing::new(Vec::with_capacity(256));
        append_request_prefix(&mut header, "POST", "/v1/run", self.address);
        header.extend_from_slice(b"Authorization: Bearer ");
        header.extend_from_slice(self.bearer_token.as_bytes());
        header.extend_from_slice(b"\r\nContent-Type: application/json\r\nContent-Length: ");
        header.extend_from_slice(body.len().to_string().as_bytes());
        header.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
        self.exchange(&header, &body)
    }

    fn exchange(&self, header: &[u8], body: &[u8]) -> Result<ClientResponse, ClientError> {
        if header.len() > MAX_HTTP_HEADER_BYTES || body.len() > MAX_HTTP_BODY_BYTES {
            return Err(ClientError::InvalidRequest);
        }
        let mut stream = TcpStream::connect_timeout(&self.address, CLIENT_IO_TIMEOUT)
            .map_err(|_| ClientError::Io)?;
        stream
            .set_read_timeout(Some(CLIENT_IO_TIMEOUT))
            .map_err(|_| ClientError::Io)?;
        stream
            .set_write_timeout(Some(CLIENT_IO_TIMEOUT))
            .map_err(|_| ClientError::Io)?;
        let deadline = Instant::now() + CLIENT_IO_TIMEOUT;
        write_until(&mut stream, header, deadline)?;
        write_until(&mut stream, body, deadline)?;
        read_response(&mut stream, deadline)
    }
}

fn append_request_prefix(
    request: &mut Zeroizing<Vec<u8>>,
    method: &str,
    target: &str,
    address: SocketAddr,
) {
    request.extend_from_slice(method.as_bytes());
    request.extend_from_slice(b" ");
    request.extend_from_slice(target.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(address.to_string().as_bytes());
    request.extend_from_slice(b"\r\n");
}

#[derive(Serialize)]
struct HttpRunRequest<'a> {
    request_id: &'a str,
    lifecycle_id: &'a str,
    request: &'a RawValue,
}

fn is_bearer_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
}

fn write_until(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> Result<(), ClientError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ClientError::Io);
        }
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| ClientError::Io)?;
        let written = stream
            .write(&bytes[offset..])
            .map_err(|_| ClientError::Io)?;
        if written == 0 {
            return Err(ClientError::Io);
        }
        offset += written;
    }
    Ok(())
}

fn read_response(stream: &mut TcpStream, deadline: Instant) -> Result<ClientResponse, ClientError> {
    let mut raw = Vec::with_capacity(MAX_HTTP_HEADER_BYTES.min(1024));
    loop {
        if raw.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(ClientError::ResponseTooLarge);
        }
        let mut byte = [0_u8; 1];
        read_until(stream, &mut byte, deadline)?;
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let (status_code, content_length) = parse_response_head(&raw)?;
    let mut body = vec![0_u8; content_length];
    read_until(stream, &mut body, deadline)?;
    Ok(ClientResponse { status_code, body })
}

fn read_until(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), ClientError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ClientError::Io);
        }
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| ClientError::Io)?;
        let read = stream
            .read(&mut buffer[offset..])
            .map_err(|_| ClientError::Io)?;
        if read == 0 {
            return Err(ClientError::InvalidResponse);
        }
        offset += read;
    }
    Ok(())
}

fn parse_response_head(raw: &[u8]) -> Result<(u16, usize), ClientError> {
    let text = std::str::from_utf8(raw).map_err(|_| ClientError::InvalidResponse)?;
    let without_terminator = text
        .strip_suffix("\r\n\r\n")
        .ok_or(ClientError::InvalidResponse)?;
    let mut lines = without_terminator.split("\r\n");
    let status_line = lines.next().ok_or(ClientError::InvalidResponse)?;
    let mut status_parts = status_line.splitn(3, ' ');
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(ClientError::InvalidResponse);
    }
    let status_code = status_parts
        .next()
        .filter(|code| code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(ClientError::InvalidResponse)?
        .parse::<u16>()
        .map_err(|_| ClientError::InvalidResponse)?;
    if status_parts.next().is_none() {
        return Err(ClientError::InvalidResponse);
    }

    let mut content_type_seen = false;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ClientError::InvalidResponse)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~".contains(&byte))
            || value
                .bytes()
                .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(ClientError::InvalidResponse);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("Content-Type") {
            if content_type_seen || value != "application/json" {
                return Err(ClientError::InvalidResponse);
            }
            content_type_seen = true;
        } else if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(ClientError::InvalidResponse);
            }
            let length = value
                .parse::<usize>()
                .map_err(|_| ClientError::ResponseTooLarge)?;
            if length > MAX_RUNTIME_RESPONSE_BYTES {
                return Err(ClientError::ResponseTooLarge);
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(ClientError::InvalidResponse);
        }
    }
    if !content_type_seen {
        return Err(ClientError::InvalidResponse);
    }
    Ok((
        status_code,
        content_length.ok_or(ClientError::InvalidResponse)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use tkach_core::domain::{Destination, Identity, PolicyId, Principal, RuleId};
    use tkach_core::krosna::{Krosna, Policy};
    use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
    use tkach_core::zaslon::Zaslon;
    use tkach_gateway::{
        DeterministicProvider, FakeToolBroker, ProviderStep, RuntimeAuthenticator, RuntimeLimits,
        RuntimeService, ScriptedStep,
    };
    use tkach_http::HttpListener;

    fn service() -> RuntimeService<DeterministicProvider> {
        let client = Destination::Internal(Identity::new("client").unwrap());
        let flow = FlowRule::allow(
            RuleId::new("allow-client-export").unwrap(),
            FlowMatcher::any()
                .principal(Principal::Model)
                .source(FlowSource::Model)
                .destination(client.clone())
                .operation(FlowOperation::Export),
        );
        let kernel = Krosna::with_zaslon_and_ruslo(
            Policy::new(PolicyId::new("client-test-policy").unwrap(), Vec::new()).unwrap(),
            Zaslon::empty(),
            Ruslo::new(vec![flow]).unwrap(),
        );
        let gateway = tkach_gateway::Gateway::new(
            kernel,
            Zaslon::empty(),
            Zaslon::empty(),
            client,
            FakeToolBroker::new(),
        );
        RuntimeService::new(
            gateway,
            DeterministicProvider::new(vec![ScriptedStep {
                chunks: vec!["safe client response".to_owned()],
                actions: Vec::new(),
                continuation: ProviderStep::Complete,
            }]),
            RuntimeAuthenticator::new(b"runtime-secret".to_vec()).unwrap(),
            RuntimeLimits::default(),
        )
    }

    fn request() -> RunRequest {
        RunRequest::new(
            "request-client-1",
            "lifecycle-client-1",
            br#"{"messages":[{"role":"user","content":"hello"}]}"#.to_vec(),
        )
        .unwrap()
    }

    fn client_with_listener() -> (HttpListener<DeterministicProvider>, TkachClient) {
        let listener = HttpListener::bind("127.0.0.1:0".parse().unwrap(), service()).unwrap();
        let address = listener.local_addr().unwrap();
        let client = TkachClient::new(address, "runtime-secret").unwrap();
        (listener, client)
    }

    #[test]
    fn configuration_and_request_bounds_fail_closed() {
        assert_eq!(
            TkachClient::new("192.0.2.1:80".parse().unwrap(), "secret").unwrap_err(),
            ClientError::NonLoopbackAddress
        );
        assert_eq!(
            TkachClient::new("127.0.0.1:80".parse().unwrap(), "bad token").unwrap_err(),
            ClientError::InvalidAuthentication
        );
        assert_eq!(
            TkachClient::new("127.0.0.1:80".parse().unwrap(), "bad\r\nX-Leak: yes").unwrap_err(),
            ClientError::InvalidAuthentication
        );
        assert_eq!(
            TkachClient::new(
                "127.0.0.1:80".parse().unwrap(),
                "x".repeat(MAX_RUNTIME_AUTH_BYTES + 1)
            )
            .unwrap_err(),
            ClientError::InvalidAuthentication
        );
        assert_eq!(
            RunRequest::new(
                "request",
                "lifecycle",
                vec![b'x'; MAX_REQUEST_BODY_BYTES + 1]
            )
            .unwrap_err(),
            ClientError::InvalidRequest
        );
        assert!(RunRequest::new("request", "lifecycle", b"not-json".to_vec()).is_err());
    }

    #[test]
    fn debug_output_redacts_bearer_and_request_body() {
        let client = TkachClient::new("127.0.0.1:80".parse().unwrap(), "secret-token").unwrap();
        let request = RunRequest::new(
            "request",
            "lifecycle",
            br#"{"messages":[{"role":"user","content":"private"}]}"#.to_vec(),
        )
        .unwrap();
        assert!(!format!("{client:?}").contains("secret-token"));
        assert!(!format!("{request:?}").contains("private"));
    }

    #[test]
    fn health_uses_the_exact_static_endpoint() {
        let (mut listener, client) = client_with_listener();
        let peer = thread::spawn(move || client.health());
        listener.serve_one().unwrap();
        assert!(peer.join().unwrap().is_ok());
    }

    #[test]
    fn readiness_uses_the_exact_static_endpoint() {
        let (mut listener, client) = client_with_listener();
        let peer = thread::spawn(move || client.ready());
        listener.serve_one().unwrap();
        assert!(peer.join().unwrap().is_ok());
    }

    #[test]
    fn run_returns_bounded_safe_response_without_auth_header_echo() {
        let (mut listener, client) = client_with_listener();
        let request = request();
        let peer = thread::spawn(move || client.run(&request));
        listener.serve_one().unwrap();
        let response = peer.join().unwrap().unwrap();
        assert_eq!(response.status_code(), 200);
        assert!(response.is_success());
        assert!(
            response
                .body()
                .windows(b"safe client response".len())
                .any(|window| window == b"safe client response")
        );
        assert!(
            !response
                .body()
                .windows(b"runtime-secret".len())
                .any(|window| window == b"runtime-secret")
        );
    }

    #[test]
    fn run_accepts_a_bounded_slow_response_without_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let header_end = request.len();
            let content_length = request
                .windows(b"Content-Length: ".len())
                .position(|window| window == b"Content-Length: ")
                .and_then(|start| {
                    let value = &request[start + b"Content-Length: ".len()..header_end];
                    let end = value.windows(2).position(|pair| pair == b"\r\n")?;
                    std::str::from_utf8(&value[..end])
                        .ok()?
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
                .unwrap();
            while request.len() < header_end + content_length {
                let read = stream.read(&mut byte).unwrap();
                assert_ne!(read, 0, "client closed before request body was received");
                request.push(byte[0]);
            }
            let body = br#"{"Success":{"output":"slow but bounded"}}"#;
            thread::sleep(Duration::from_millis(800));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let client = TkachClient::new(address, "runtime-secret").unwrap();
        let response = client.run(&request()).unwrap();
        peer.join().unwrap();
        assert_eq!(response.status_code(), 200);
        assert_eq!(
            response.body(),
            br#"{"Success":{"output":"slow but bounded"}}"#
        );
    }

    #[test]
    fn authentication_failure_is_returned_without_retry_or_token_echo() {
        let (mut listener, _) = client_with_listener();
        let client = TkachClient::new(listener.local_addr().unwrap(), "wrong-token").unwrap();
        let request = request();
        let peer = thread::spawn(move || client.run(&request));
        listener.serve_one().unwrap();
        let response = peer.join().unwrap().unwrap();
        assert_eq!(response.status_code(), 401);
        assert!(
            !response
                .body()
                .windows(b"wrong-token".len())
                .any(|window| window == b"wrong-token")
        );
    }

    #[test]
    fn response_parser_rejects_chunked_and_oversized_responses() {
        let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            parse_response_head(chunked).unwrap_err(),
            ClientError::InvalidResponse
        );
        let oversized = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_RUNTIME_RESPONSE_BYTES + 1
        );
        assert_eq!(
            parse_response_head(oversized.as_bytes()).unwrap_err(),
            ClientError::ResponseTooLarge
        );
    }

    #[test]
    fn response_kind_distinguishes_terminal_runtime_outcomes_without_retry() {
        let cases: &[(u16, &[u8], ResponseKind)] = &[
            (200, br#"{"Success":{}}"#, ResponseKind::Success),
            (
                401,
                br#"{"Failure":{"failure":"authentication_failed"}}"#,
                ResponseKind::Refused,
            ),
            (
                403,
                br#"{"Failure":{"failure":"authorization_denied"}}"#,
                ResponseKind::Refused,
            ),
            (
                409,
                br#"{"Failure":{"failure":"replay"}}"#,
                ResponseKind::ReplayOrCancelled,
            ),
            (
                424,
                br#"{"Failure":{"failure":"effect_failed_before_effect"}}"#,
                ResponseKind::EffectFailed,
            ),
            (
                502,
                br#"{"Failure":{"failure":"provider_failure"}}"#,
                ResponseKind::ProviderFailure,
            ),
            (
                503,
                br#"{"Failure":{"failure":"effect_outcome_unknown"}}"#,
                ResponseKind::OutcomeUnknown,
            ),
            (
                503,
                br#"{"Failure":{"failure":"replay_capacity_exceeded"}}"#,
                ResponseKind::Unavailable,
            ),
            (
                400,
                br#"{"Failure":{"failure":"invalid_request"}}"#,
                ResponseKind::InvalidRequest,
            ),
        ];
        for (status_code, body, expected) in cases {
            let response = ClientResponse {
                status_code: *status_code,
                body: body.to_vec(),
            };
            assert_eq!(response.kind(), *expected);
        }
    }
}
