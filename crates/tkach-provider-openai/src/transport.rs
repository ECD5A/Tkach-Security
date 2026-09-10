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

//! Bounded HTTPS transport for the `OpenAI` adapter.

use crate::{MAX_RESPONSE_BODY_BYTES, config::OpenAiConfig};
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use std::io::Read;
use thiserror::Error;

/// Payload-free transport failures mapped to the Gateway provider contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum TransportError {
    /// The request exceeded its configured deadline.
    #[error("OpenAI request timed out")]
    Timeout,
    /// The endpoint returned a non-success status.
    #[error("OpenAI endpoint returned an error status")]
    HttpStatus,
    /// The response could not be read safely.
    #[error("OpenAI response could not be read")]
    Read,
    /// The bounded response body was too large.
    #[error("OpenAI response exceeded the adapter limit")]
    ResponseTooLarge,
    /// The trusted HTTP client could not be constructed.
    #[error("OpenAI HTTPS client is unavailable")]
    ClientUnavailable,
}

pub(crate) trait Transport: Send + Sync {
    fn post(&self, config: &OpenAiConfig, body: &[u8]) -> Result<Vec<u8>, TransportError>;
}

pub(crate) struct ReqwestTransport {
    client: Client,
}

impl ReqwestTransport {
    pub(crate) fn new(config: &OpenAiConfig) -> Result<Self, TransportError> {
        Client::builder()
            // A model-controlled response must never redirect a credential-
            // bearing request to an arbitrary endpoint.
            .redirect(Policy::none())
            .timeout(config.timeout())
            .build()
            .map(|client| Self { client })
            .map_err(|_| TransportError::ClientUnavailable)
    }
}

impl Transport for ReqwestTransport {
    fn post(&self, config: &OpenAiConfig, body: &[u8]) -> Result<Vec<u8>, TransportError> {
        let endpoint = config
            .endpoint()
            .join("responses")
            .map_err(|_| TransportError::Read)?;
        let response = self
            .client
            .post(endpoint)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", config.api_key()),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    TransportError::Timeout
                } else {
                    TransportError::Read
                }
            })?;
        let success = response.status().is_success();
        let body = read_bounded_body(response)?;
        if success {
            Ok(body)
        } else {
            // Do not return or log an error body. OpenAI error payloads are
            // provider data and can contain attacker-controlled text.
            Err(TransportError::HttpStatus)
        }
    }
}

fn read_bounded_body(mut response: Response) -> Result<Vec<u8>, TransportError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BODY_BYTES as u64)
    {
        return Err(TransportError::ResponseTooLarge);
    }
    let mut body = Vec::with_capacity(MAX_RESPONSE_BODY_BYTES);
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|_| TransportError::Read)?;
        if read == 0 {
            break;
        }
        let next_len = body
            .len()
            .checked_add(read)
            .ok_or(TransportError::ResponseTooLarge)?;
        if next_len > MAX_RESPONSE_BODY_BYTES {
            return Err(TransportError::ResponseTooLarge);
        }
        body.extend_from_slice(&buffer[..read]);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::thread;

    fn read_local_response(
        body: Vec<u8>,
        content_length: Option<usize>,
    ) -> Result<Vec<u8>, TransportError> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let header = match content_length {
                Some(length) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                ),
                None => "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_owned(),
            };
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        });
        let client = Client::builder().build().unwrap();
        let response = client.get(format!("http://{address}/")).send().unwrap();
        read_bounded_body(response)
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_rejects_length_header_over_limit() {
        let exact = read_local_response(
            vec![b'x'; MAX_RESPONSE_BODY_BYTES],
            Some(MAX_RESPONSE_BODY_BYTES),
        )
        .unwrap();
        assert_eq!(exact.len(), MAX_RESPONSE_BODY_BYTES);
        assert_eq!(
            read_local_response(Vec::new(), Some(MAX_RESPONSE_BODY_BYTES + 1)),
            Err(TransportError::ResponseTooLarge)
        );
    }

    #[test]
    fn bounded_reader_rejects_chunked_or_close_delimited_body_over_limit() {
        assert_eq!(
            read_local_response(vec![b'x'; MAX_RESPONSE_BODY_BYTES + 1], None),
            Err(TransportError::ResponseTooLarge)
        );
    }

    #[test]
    fn post_does_not_synthesize_success_when_tls_connection_fails() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = stream.shutdown(Shutdown::Both);
        });
        let config = OpenAiConfig::with_endpoint_and_timeout(
            "sk-test-only",
            "gpt-4.1-mini",
            &format!("https://{address}/v1/"),
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        let transport = ReqwestTransport::new(&config).unwrap();
        assert!(transport.post(&config, b"{}").is_err());
    }
}
