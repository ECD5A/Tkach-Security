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
