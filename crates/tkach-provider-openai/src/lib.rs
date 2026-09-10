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

//! `OpenAI` Responses API boundary for Tkach Security.
//!
//! This crate deliberately starts with trusted adapter configuration and
//! credential handling. Provider wire data will be parsed into untrusted
//! Gateway proposals in later, separately reviewed milestones. It does not
//! implement policy, Propusk issuance, protected execution, or Pechat.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod provider;
mod transport;
mod wire;

pub use config::{ConfigError, OpenAiConfig};
pub use provider::OpenAiProvider;

/// Parse one untrusted Responses payload for the dedicated fuzz harness.
///
/// This is available only with the non-default `fuzzing` feature and returns
/// no provider data. It exists to exercise the same bounded parser used by the
/// adapter without creating a network-capable fuzz target.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_response(input: &[u8]) {
    let _ = wire::parse_response(input);
}

/// Maximum bytes read from one successful or error HTTP response body.
pub const MAX_RESPONSE_BODY_BYTES: usize = 128 * 1024;
/// Maximum output items accepted from one non-streaming response.
pub const MAX_RESPONSE_ITEMS: usize = 32;
/// Maximum output content items accepted inside one assistant message.
pub const MAX_RESPONSE_CONTENT_ITEMS: usize = 32;
/// Maximum bytes in one provider function-call argument string.
pub const MAX_FUNCTION_ARGUMENT_BYTES: usize = 8 * 1024;
/// Maximum bytes in one provider response or function-call identifier.
pub const MAX_PROVIDER_ID_BYTES: usize = 128;
/// Maximum number of conversation items retained for stateless follow-up.
pub const MAX_CONVERSATION_ITEMS: usize = 128;
/// Maximum serialized request body sent by the adapter.
pub const MAX_REQUEST_BODY_BYTES: usize = 512 * 1024;
