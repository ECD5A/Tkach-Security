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

//! Trusted `OpenAI` adapter configuration and credential boundary.

use std::fmt::{Debug, Formatter};
use std::time::Duration;
use thiserror::Error;
use url::Url;

const DEFAULT_ENDPOINT: &str = "https://api.openai.com/v1/";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_API_KEY_BYTES: usize = 4096;
const MAX_MODEL_BYTES: usize = 128;
const MAX_TIMEOUT: Duration = Duration::from_secs(120);

/// Configuration errors that never include the rejected credential or URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// No non-empty `OPENAI_API_KEY` was available.
    #[error("OpenAI API key is missing")]
    MissingApiKey,
    /// The configured credential contains invalid control data or is too large.
    #[error("OpenAI API key is invalid")]
    InvalidApiKey,
    /// The configured model label is empty, oversized, or not a safe token.
    #[error("OpenAI model is invalid")]
    InvalidModel,
    /// The endpoint is not a trusted HTTPS base URL.
    #[error("OpenAI endpoint is invalid")]
    InvalidEndpoint,
    /// The request timeout is outside the adapter's bounded range.
    #[error("OpenAI timeout is invalid")]
    InvalidTimeout,
    /// The mature HTTPS client could not be initialized.
    #[error("OpenAI HTTPS client is unavailable")]
    HttpClientUnavailable,
}

/// Trusted, immutable configuration for the `OpenAI` adapter.
///
/// The API key is an infrastructure secret. It has no public accessor,
/// serialization, `Display`, or revealing `Debug` implementation. The
/// endpoint and model are trusted host configuration; no provider or model
/// field can replace them.
pub struct OpenAiConfig {
    api_key: ApiKey,
    model: String,
    endpoint: Url,
    timeout: Duration,
}

impl Debug for OpenAiConfig {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenAiConfig")
            .field("api_key", &"REDACTED")
            .field("model", &self.model)
            .field("endpoint", &self.endpoint)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OpenAiConfig {
    /// Create configuration for the default `OpenAI` Responses endpoint.
    ///
    /// # Errors
    ///
    /// Returns a static error when the key or model violates the credential
    /// boundary. The rejected values are never included in the error.
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self, ConfigError> {
        Self::with_endpoint_and_timeout(api_key, model, DEFAULT_ENDPOINT, DEFAULT_TIMEOUT)
    }

    /// Load the API key from `OPENAI_API_KEY` using the default endpoint.
    ///
    /// The environment variable is read only at trusted adapter construction;
    /// it is never copied into a model request, provider response, Sled, or
    /// public diagnostic.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MissingApiKey`] when the variable is absent or
    /// empty, or another static configuration error for invalid input.
    pub fn from_env(model: impl Into<String>) -> Result<Self, ConfigError> {
        let api_key = std::env::var("OPENAI_API_KEY").map_err(|_| ConfigError::MissingApiKey)?;
        if api_key.is_empty() {
            return Err(ConfigError::MissingApiKey);
        }
        Self::new(api_key, model)
    }

    /// Create configuration with a trusted custom HTTPS endpoint.
    ///
    /// Custom endpoints are intended for trusted OpenAI-compatible deployment
    /// configuration and offline transport tests. The value cannot come from
    /// a client request or model output. Redirects are disabled by the HTTP
    /// transport milestone that consumes this configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidEndpoint`] unless the endpoint is an
    /// HTTPS URL with no embedded credentials, query, or fragment and a path
    /// ending in `/`.
    pub fn with_endpoint_and_timeout(
        api_key: impl Into<String>,
        model: impl Into<String>,
        endpoint: &str,
        timeout: Duration,
    ) -> Result<Self, ConfigError> {
        let api_key = ApiKey::new(api_key.into())?;
        let model = validate_model(model.into())?;
        let endpoint = Url::parse(endpoint).map_err(|_| ConfigError::InvalidEndpoint)?;
        validate_endpoint(&endpoint)?;
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(ConfigError::InvalidTimeout);
        }
        Ok(Self {
            api_key,
            model,
            endpoint,
            timeout,
        })
    }

    pub(crate) fn api_key(&self) -> &str {
        self.api_key.as_str()
    }

    pub(crate) fn model(&self) -> &str {
        &self.model
    }

    pub(crate) fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub(crate) const fn timeout(&self) -> Duration {
        self.timeout
    }
}

struct ApiKey(String);

impl ApiKey {
    fn new(value: String) -> Result<Self, ConfigError> {
        if value.is_empty()
            || value.len() > MAX_API_KEY_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ConfigError::InvalidApiKey);
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_model(value: String) -> Result<String, ConfigError> {
    if value.is_empty()
        || value.len() > MAX_MODEL_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ConfigError::InvalidModel);
    }
    Ok(value)
}

fn validate_endpoint(endpoint: &Url) -> Result<(), ConfigError> {
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.path().ends_with('/')
    {
        return Err(ConfigError::InvalidEndpoint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_redacts_fake_credentials_everywhere_public() {
        let config = OpenAiConfig::new("sk-test-only-not-real", "gpt-4.1-mini").unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("sk-test-only-not-real"));
        assert!(debug.contains("REDACTED"));
        assert_eq!(config.model(), "gpt-4.1-mini");
    }

    #[test]
    fn endpoint_rejects_non_https_and_ambiguous_authority() {
        for endpoint in [
            "http://localhost/v1/",
            "https://user:password@example.test/v1/",
            "https://example.test/v1/?redirect=elsewhere",
            "https://example.test/v1/#fragment",
            "https://example.test/v1",
        ] {
            assert_eq!(
                OpenAiConfig::with_endpoint_and_timeout(
                    "sk-test-only",
                    "gpt-4.1-mini",
                    endpoint,
                    DEFAULT_TIMEOUT,
                )
                .unwrap_err(),
                ConfigError::InvalidEndpoint
            );
        }
    }

    #[test]
    fn credential_model_and_timeout_bounds_fail_closed() {
        assert_eq!(
            OpenAiConfig::new("", "gpt-4.1-mini").unwrap_err(),
            ConfigError::InvalidApiKey
        );
        assert_eq!(
            OpenAiConfig::new("sk-test-only", "model with spaces").unwrap_err(),
            ConfigError::InvalidModel
        );
        assert_eq!(
            OpenAiConfig::with_endpoint_and_timeout(
                "sk-test-only",
                "gpt-4.1-mini",
                DEFAULT_ENDPOINT,
                Duration::ZERO,
            )
            .unwrap_err(),
            ConfigError::InvalidTimeout
        );
    }
}
