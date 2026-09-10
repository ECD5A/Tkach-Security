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

//! Small loopback-only HTTP/1.1 adapter around the authenticated Tkach runtime.
//!
//! This crate is a carrier, not a second policy engine. It translates one
//! strict HTTP request into the existing [`tkach_gateway::RuntimeService`]
//! frame contract and returns its bounded response. It deliberately provides
//! no public-internet binding, TLS termination, proxy behavior, streaming
//! endpoint, generic executor, or provider implementation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::de::{Deserializer, Error as DeError, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};
use thiserror::Error;
use tkach_gateway::{
    CancellationToken, LifecycleId, MAX_RUNTIME_AUTH_BYTES, MAX_RUNTIME_FRAME_BYTES,
    MAX_RUNTIME_RESPONSE_BYTES, Provider, RequestId, RuntimeFailure, RuntimeResponse,
    RuntimeService,
};

/// Maximum bytes read before the HTTP header terminator is required.
pub const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
/// Maximum HTTP request body accepted by this adapter.
pub const MAX_HTTP_BODY_BYTES: usize = MAX_RUNTIME_FRAME_BYTES - MAX_RUNTIME_AUTH_BYTES - 256;

const HTTP_IO_TIMEOUT: Duration = Duration::from_millis(500);
const HEALTH_BODY: &[u8] = br#"{"status":"ok"}"#;
const INVALID_HTTP_BODY: &[u8] = br#"{"error":"invalid_http_request"}"#;
const HEADERS_TOO_LARGE_BODY: &[u8] = br#"{"error":"request_headers_too_large"}"#;
const UNAUTHORIZED_BODY: &[u8] = br#"{"error":"authentication_required"}"#;
const UNSUPPORTED_MEDIA_BODY: &[u8] = br#"{"error":"unsupported_media_type"}"#;
const PAYLOAD_TOO_LARGE_BODY: &[u8] = br#"{"error":"payload_too_large"}"#;
const INTERNAL_ERROR_BODY: &[u8] = br#"{"error":"internal_server_error"}"#;

/// Static errors from accepting or writing an HTTP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum HttpTransportError {
    /// The listener address is not loopback-only.
    #[error("HTTP transport must bind to a loopback address")]
    NonLoopbackBind,
    /// A connection or socket operation failed.
    #[error("HTTP transport I/O failed")]
    Io,
    /// The bounded response could not be represented safely.
    #[error("HTTP response is too large")]
    ResponseTooLarge,
}

/// Sequential loopback HTTP adapter for an authenticated runtime service.
///
/// The listener accepts one HTTP/1.1 connection at a time. `GET /healthz` is
/// an unauthenticated liveness response. `POST /v1/run` requires an exact
/// `Authorization: Bearer <token>` header and a strict bounded JSON body; the
/// token is translated into the existing runtime authentication field and is
/// never returned in the response. The listener closes each connection after
/// one response.
pub struct HttpListener<P> {
    listener: TcpListener,
    service: RuntimeService<P>,
}

impl<P> Debug for HttpListener<P> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpListener")
            .field("local_addr", &self.listener.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl<P: Provider> HttpListener<P> {
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
    ) -> Result<Self, HttpTransportError> {
        if !address.ip().is_loopback() {
            return Err(HttpTransportError::NonLoopbackBind);
        }
        let listener = TcpListener::bind(address).map_err(|_| HttpTransportError::Io)?;
        listener
            .set_nonblocking(false)
            .map_err(|_| HttpTransportError::Io)?;
        Ok(Self { listener, service })
    }

    /// Return the concrete loopback address selected by the OS.
    ///
    /// # Errors
    ///
    /// Returns [`HttpTransportError::Io`] if the listener address cannot be
    /// read.
    pub fn local_addr(&self) -> Result<SocketAddr, HttpTransportError> {
        self.listener
            .local_addr()
            .map_err(|_| HttpTransportError::Io)
    }

    /// Return mutable access to lifecycle controls without exposing the
    /// Gateway, provider, executor, or authenticator internals.
    pub fn service_mut(&mut self) -> &mut RuntimeService<P> {
        &mut self.service
    }

    /// Accept and serve one bounded HTTP connection.
    ///
    /// Malformed or unauthorized application requests receive a safe HTTP
    /// response and return `Ok(())`. Socket failures return a static transport
    /// error. There is no keep-alive, redirect, compression, retry, or
    /// cancellation-on-disconnect behavior.
    ///
    /// # Errors
    ///
    /// Returns [`HttpTransportError::Io`] when the connection cannot be
    /// accepted, read, or written, and [`HttpTransportError::ResponseTooLarge`]
    /// if a bounded runtime response cannot be represented as HTTP.
    pub fn serve_one(&mut self) -> Result<(), HttpTransportError> {
        let (mut stream, _) = self.listener.accept().map_err(|_| HttpTransportError::Io)?;
        stream
            .set_read_timeout(Some(HTTP_IO_TIMEOUT))
            .map_err(|_| HttpTransportError::Io)?;
        stream
            .set_write_timeout(Some(HTTP_IO_TIMEOUT))
            .map_err(|_| HttpTransportError::Io)?;
        serve_connection(&mut stream, &mut self.service)
    }
}

#[derive(Debug)]
struct RequestHead {
    method: String,
    target: String,
    authorization: Option<String>,
    content_length: Option<usize>,
    content_type_json: bool,
    transfer_encoding: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpProblem {
    BadRequest,
    Unauthorized,
    HeadersTooLarge,
    NotFound,
    MethodNotAllowed,
    UnsupportedMediaType,
    PayloadTooLarge,
}

impl HttpProblem {
    const fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::HeadersTooLarge => 431,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::UnsupportedMediaType => 415,
            Self::PayloadTooLarge => 413,
        }
    }

    const fn body(self) -> &'static [u8] {
        match self {
            Self::BadRequest | Self::NotFound | Self::MethodNotAllowed => INVALID_HTTP_BODY,
            Self::Unauthorized => UNAUTHORIZED_BODY,
            Self::HeadersTooLarge => HEADERS_TOO_LARGE_BODY,
            Self::UnsupportedMediaType => UNSUPPORTED_MEDIA_BODY,
            Self::PayloadTooLarge => PAYLOAD_TOO_LARGE_BODY,
        }
    }

    const fn challenge(self) -> bool {
        matches!(self, Self::Unauthorized)
    }
}

enum HeadReadError {
    Io,
    Problem(HttpProblem),
}

fn serve_connection<P: Provider>(
    stream: &mut TcpStream,
    service: &mut RuntimeService<P>,
) -> Result<(), HttpTransportError> {
    let deadline = Instant::now() + HTTP_IO_TIMEOUT;
    let head = match read_head(stream, deadline) {
        Ok(head) => head,
        Err(HeadReadError::Io) => return Err(HttpTransportError::Io),
        Err(HeadReadError::Problem(problem)) => {
            return write_response(
                stream,
                problem.status(),
                problem.body(),
                problem.challenge(),
            );
        }
    };

    if head.method == "GET" && head.target == "/healthz" {
        if head.transfer_encoding || head.content_length.unwrap_or_default() != 0 {
            return write_problem_after_body(stream, &head, HttpProblem::BadRequest, deadline);
        }
        return write_response(stream, 200, HEALTH_BODY, false);
    }

    if head.target != "/v1/run" {
        return write_problem_after_body(stream, &head, HttpProblem::NotFound, deadline);
    }
    if head.method != "POST" {
        return write_problem_after_body(stream, &head, HttpProblem::MethodNotAllowed, deadline);
    }
    if head.transfer_encoding {
        return write_problem(stream, HttpProblem::BadRequest);
    }
    if !head.content_type_json {
        return write_problem_after_body(
            stream,
            &head,
            HttpProblem::UnsupportedMediaType,
            deadline,
        );
    }
    let auth = match bearer_token(head.authorization.as_deref()) {
        Ok(auth) => auth,
        Err(problem) => return write_problem_after_body(stream, &head, problem, deadline),
    };
    let Some(content_length) = head.content_length else {
        return write_problem_after_body(stream, &head, HttpProblem::BadRequest, deadline);
    };
    let mut body = vec![0_u8; content_length];
    read_exact_until(stream, &mut body, deadline)?;
    let request: HttpRunRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return write_problem(stream, HttpProblem::BadRequest),
    };
    let Ok(request_id) = RequestId::new(request.request_id) else {
        return write_problem(stream, HttpProblem::BadRequest);
    };
    let Ok(lifecycle_id) = LifecycleId::new(request.lifecycle_id) else {
        return write_problem(stream, HttpProblem::BadRequest);
    };
    let frame = RuntimeFrame {
        request_id: request_id.as_str(),
        lifecycle_id: lifecycle_id.as_str(),
        auth: &auth,
        request: request.request.as_ref(),
    };
    let frame = match serde_json::to_vec(&frame) {
        Ok(frame) if frame.len() <= MAX_RUNTIME_FRAME_BYTES => frame,
        Ok(_) | Err(_) => return write_problem(stream, HttpProblem::PayloadTooLarge),
    };
    let response = service.handle_frame(&frame, &CancellationToken::new());
    let challenge = matches!(
        response,
        RuntimeResponse::Failure {
            failure: RuntimeFailure::AuthenticationFailed,
            ..
        }
    );
    let (status, body) = match response.to_json() {
        Ok(body) => (runtime_status(&response), body),
        Err(_) => (500, INTERNAL_ERROR_BODY.to_vec()),
    };
    write_response(stream, status, &body, challenge)
}

fn write_problem(stream: &mut TcpStream, problem: HttpProblem) -> Result<(), HttpTransportError> {
    write_response(
        stream,
        problem.status(),
        problem.body(),
        problem.challenge(),
    )
}

fn write_problem_after_body(
    stream: &mut TcpStream,
    head: &RequestHead,
    problem: HttpProblem,
    deadline: Instant,
) -> Result<(), HttpTransportError> {
    if !head.transfer_encoding {
        discard_declared_body(stream, head.content_length.unwrap_or_default(), deadline)?;
    }
    write_problem(stream, problem)
}

fn discard_declared_body(
    stream: &mut TcpStream,
    mut remaining: usize,
    deadline: Instant,
) -> Result<(), HttpTransportError> {
    let mut buffer = [0_u8; 4096];
    while remaining != 0 {
        let read_len = remaining.min(buffer.len());
        let read = read_with_deadline(stream, &mut buffer[..read_len], deadline)?;
        if read == 0 {
            return Err(HttpTransportError::Io);
        }
        remaining -= read;
    }
    Ok(())
}

fn read_exact_until(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), HttpTransportError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let read = read_with_deadline(stream, &mut buffer[offset..], deadline)?;
        if read == 0 {
            return Err(HttpTransportError::Io);
        }
        offset += read;
    }
    Ok(())
}

fn read_with_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, HttpTransportError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HttpTransportError::Io);
    }
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| HttpTransportError::Io)?;
    stream.read(buffer).map_err(|_| HttpTransportError::Io)
}

fn read_head(stream: &mut TcpStream, deadline: Instant) -> Result<RequestHead, HeadReadError> {
    let mut raw = Vec::with_capacity(MAX_HTTP_HEADER_BYTES.min(1024));
    loop {
        let mut byte = [0_u8; 1];
        read_with_deadline(stream, &mut byte, deadline).map_err(|_| HeadReadError::Io)?;
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
        if raw.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(HeadReadError::Problem(HttpProblem::HeadersTooLarge));
        }
    }
    parse_head(&raw).map_err(HeadReadError::Problem)
}

fn parse_head(raw: &[u8]) -> Result<RequestHead, HttpProblem> {
    let text = std::str::from_utf8(raw).map_err(|_| HttpProblem::BadRequest)?;
    let without_terminator = text
        .strip_suffix("\r\n\r\n")
        .ok_or(HttpProblem::BadRequest)?;
    let mut lines = without_terminator.split("\r\n");
    let request_line = lines.next().ok_or(HttpProblem::BadRequest)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(HttpProblem::BadRequest)?;
    let target = parts.next().ok_or(HttpProblem::BadRequest)?;
    let version = parts.next().ok_or(HttpProblem::BadRequest)?;
    if parts.next().is_some() || version != "HTTP/1.1" || method.is_empty() || target.is_empty() {
        return Err(HttpProblem::BadRequest);
    }

    let mut host_count = 0_u8;
    let mut authorization = None;
    let mut content_length = None;
    let mut content_type_seen = false;
    let mut content_type_json = false;
    let mut transfer_encoding = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(HttpProblem::BadRequest)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || value
                .bytes()
                .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(HttpProblem::BadRequest);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("Host") {
            host_count = host_count.saturating_add(1);
            if value.is_empty() {
                return Err(HttpProblem::BadRequest);
            }
        } else if name.eq_ignore_ascii_case("Authorization") {
            if authorization.replace(value.to_owned()).is_some() {
                return Err(HttpProblem::BadRequest);
            }
        } else if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(HttpProblem::BadRequest);
            }
            let length = value.parse().map_err(|_| HttpProblem::PayloadTooLarge)?;
            if length > MAX_HTTP_BODY_BYTES {
                return Err(HttpProblem::PayloadTooLarge);
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("Content-Type") {
            if content_type_seen {
                return Err(HttpProblem::BadRequest);
            }
            content_type_seen = true;
            content_type_json = value == "application/json";
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            transfer_encoding = true;
        }
    }
    if host_count != 1 {
        return Err(HttpProblem::BadRequest);
    }
    Ok(RequestHead {
        method: method.to_owned(),
        target: target.to_owned(),
        authorization,
        content_length,
        content_type_json,
        transfer_encoding,
    })
}

fn bearer_token(value: Option<&str>) -> Result<String, HttpProblem> {
    let Some(value) = value else {
        return Err(HttpProblem::Unauthorized);
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err(HttpProblem::Unauthorized);
    };
    if token.is_empty()
        || token.len() > MAX_RUNTIME_AUTH_BYTES
        || !token.bytes().all(is_bearer_token_byte)
    {
        return Err(HttpProblem::Unauthorized);
    }
    Ok(token.to_owned())
}

fn is_bearer_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
}

fn runtime_status(response: &RuntimeResponse) -> u16 {
    match response {
        RuntimeResponse::Success { .. } => 200,
        RuntimeResponse::Failure { failure, .. } => match failure {
            RuntimeFailure::AuthenticationFailed => 401,
            RuntimeFailure::AuthorizationDenied => 403,
            RuntimeFailure::Replay | RuntimeFailure::Cancelled => 409,
            RuntimeFailure::InvalidFrame | RuntimeFailure::InvalidRequest => 400,
            RuntimeFailure::ShuttingDown
            | RuntimeFailure::ReplayCapacityExceeded
            | RuntimeFailure::ConcurrencyLimit
            | RuntimeFailure::EffectOutcomeUnknown => 503,
            RuntimeFailure::ProviderFailure => 502,
            RuntimeFailure::EffectFailedBeforeEffect => 424,
            RuntimeFailure::ResponseTooLarge => 500,
        },
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &[u8],
    challenge: bool,
) -> Result<(), HttpTransportError> {
    if body.len() > MAX_RUNTIME_RESPONSE_BYTES {
        return Err(HttpTransportError::ResponseTooLarge);
    }
    let reason = reason_phrase(status);
    let challenge_header = if challenge {
        "WWW-Authenticate: Bearer\r\n"
    } else {
        ""
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{challenge_header}\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|_| HttpTransportError::Io)
}

const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        424 => "Failed Dependency",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpRunRequest {
    #[serde(deserialize_with = "deserialize_bounded_id")]
    request_id: String,
    #[serde(deserialize_with = "deserialize_bounded_id")]
    lifecycle_id: String,
    request: Box<serde_json::value::RawValue>,
}

#[derive(Serialize)]
struct RuntimeFrame<'a> {
    request_id: &'a str,
    lifecycle_id: &'a str,
    auth: &'a str,
    request: &'a serde_json::value::RawValue,
}

fn deserialize_bounded_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedIdVisitor;

    impl Visitor<'_> for BoundedIdVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded request or lifecycle identifier")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if value.len() > tkach_gateway::MAX_RUNTIME_ID_BYTES {
                return Err(E::custom("runtime identifier exceeds bound"));
            }
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if value.len() > tkach_gateway::MAX_RUNTIME_ID_BYTES {
                return Err(E::custom("runtime identifier exceeds bound"));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_string(BoundedIdVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpStream;
    use std::thread;
    use tkach_core::domain::{Destination, Identity, PolicyId, Principal, RuleId};
    use tkach_core::krosna::{Krosna, Policy};
    use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
    use tkach_core::zaslon::Zaslon;
    use tkach_gateway::{
        DeterministicProvider, FakeToolBroker, ProviderStep, RuntimeAuthenticator, RuntimeLimits,
        ScriptedStep,
    };

    fn service(provider: DeterministicProvider) -> RuntimeService<DeterministicProvider> {
        let client = Destination::Internal(Identity::new("client").unwrap());
        let flow = FlowRule::allow(
            RuleId::new("allow-http-test-release").unwrap(),
            FlowMatcher::any()
                .principal(Principal::Model)
                .source(FlowSource::Model)
                .destination(client.clone())
                .operation(FlowOperation::Export),
        );
        let kernel = Krosna::with_zaslon_and_ruslo(
            Policy::new(PolicyId::new("http-test-policy").unwrap(), Vec::new()).unwrap(),
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
            provider,
            RuntimeAuthenticator::new(b"runtime-secret".to_vec()).unwrap(),
            RuntimeLimits::default(),
        )
    }

    fn provider() -> DeterministicProvider {
        DeterministicProvider::new(vec![ScriptedStep {
            chunks: vec!["safe response".to_owned()],
            actions: Vec::new(),
            continuation: ProviderStep::Complete,
        }])
    }

    fn request_json() -> String {
        serde_json::json!({
            "request_id": "request-1",
            "lifecycle_id": "lifecycle-1",
            "request": {
                "messages": [{"role": "user", "content": "hello"}]
            }
        })
        .to_string()
    }

    fn exchange(request: String) -> String {
        let mut listener =
            HttpListener::bind("127.0.0.1:0".parse().unwrap(), service(provider())).unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut client = TcpStream::connect(address).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client.write_all(request.as_bytes()).unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            response
        });
        listener.serve_one().unwrap();
        client.join().unwrap()
    }

    fn run_request(auth: &str, body: &str) -> String {
        format!(
            "POST /v1/run HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {auth}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn listener_rejects_non_loopback_bind() {
        assert_eq!(
            HttpListener::bind("192.0.2.1:1234".parse().unwrap(), service(provider())).unwrap_err(),
            HttpTransportError::NonLoopbackBind
        );
    }

    #[test]
    fn health_endpoint_is_static_and_unauthenticated() {
        let response = exchange(
            "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_owned(),
        );
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("{\"status\":\"ok\"}"));
    }

    #[test]
    fn authenticated_run_reuses_runtime_authority_and_hides_header() {
        let response = exchange(run_request("runtime-secret", &request_json()));
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("safe response"));
        assert!(!response.contains("runtime-secret"));
    }

    #[test]
    fn invalid_auth_is_401_without_echoing_the_supplied_token() {
        let response = exchange(run_request("wrong-token", &request_json()));
        assert!(response.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(response.contains("WWW-Authenticate: Bearer\r\n"));
        assert!(!response.contains("wrong-token"));
    }

    #[test]
    fn strict_http_shape_rejects_unknown_fields_and_chunked_transfer() {
        let body = serde_json::json!({
            "request_id": "request-1",
            "lifecycle_id": "lifecycle-1",
            "request": {"messages": []},
            "extra": true
        })
        .to_string();
        let response = exchange(run_request("runtime-secret", &body));
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));

        let request = "POST /v1/run HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer runtime-secret\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".to_owned();
        let response = exchange(request);
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    }

    #[test]
    fn ambiguous_headers_and_header_ceiling_fail_closed() {
        let duplicate_length = "POST /v1/run HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer runtime-secret\r\nContent-Type: application/json\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".to_owned();
        let response = exchange(duplicate_length);
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));

        let oversized = String::from_utf8(vec![b'X'; MAX_HTTP_HEADER_BYTES]).unwrap();
        let response = exchange(oversized);
        assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));
    }

    #[test]
    fn body_bound_is_rejected_before_allocation_or_runtime_admission() {
        let request = format!(
            "POST /v1/run HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer runtime-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_HTTP_BODY_BYTES + 1
        );
        let response = exchange(request);
        assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    }

    #[test]
    fn route_and_media_type_are_explicit() {
        let response = exchange(
            "GET /v1/run HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_owned(),
        );
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));

        let body = request_json();
        let request = format!(
            "POST /v1/run HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer runtime-secret\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = exchange(request);
        assert!(response.starts_with("HTTP/1.1 415 Unsupported Media Type\r\n"));
    }

    #[test]
    fn runtime_response_failure_maps_to_safe_http_status() {
        let response = exchange(run_request("runtime-secret", "not-json"));
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(!response.contains("not-json"));
    }

    #[test]
    fn published_http_budgets_remain_inside_runtime_ceilings() {
        const {
            assert!(MAX_HTTP_HEADER_BYTES < MAX_HTTP_BODY_BYTES);
            assert!(MAX_HTTP_BODY_BYTES < MAX_RUNTIME_FRAME_BYTES);
        }
    }
}
