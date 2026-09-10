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

//! Pechat, the opaque-secret broker boundary.
//!
//! Pechat protects the model-context boundary under the documented assumption
//! that the host process and operating system are not fully compromised. The
//! model receives a [`SecretHandle`], while the fake broker keeps the raw value
//! in a non-serializable, redacted type and never returns it.

use crate::domain::{Destination, Operation, Resource, ResourceId, ResourceKind};
use crate::propusk::Propusk;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use thiserror::Error;

/// Errors from the opaque-secret boundary.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum PechatError {
    /// The handle is empty, malformed, or not present in the broker.
    #[error("invalid or unknown secret handle")]
    InvalidHandle,
    /// Revealing raw secret material is never an allowed broker operation.
    #[error("raw secret disclosure is denied")]
    UnauthorizedReveal,
    /// The supplied Propusk is not an exact authorized secret-use action.
    #[error("secret use requires a matching Propusk")]
    InvalidPropusk,
    /// A fake broker registration would replace an existing handle.
    #[error("secret handle already registered")]
    DuplicateHandle,
}

/// An opaque identifier safe to place in model-visible context.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretHandle(ResourceId);

impl SecretHandle {
    /// Construct a validated opaque handle; this does not retrieve a secret.
    ///
    /// # Errors
    ///
    /// Returns [`PechatError::InvalidHandle`] for invalid identifier syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, PechatError> {
        Ok(Self(
            ResourceId::new(value).map_err(|_| PechatError::InvalidHandle)?,
        ))
    }

    /// Return the non-secret handle identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Return the typed secret resource represented by this handle.
    #[must_use]
    pub fn resource(&self) -> Resource {
        Resource::new(ResourceKind::Secret, self.0.clone())
    }
}

impl Debug for SecretHandle {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("SecretHandle")
            .field(&self.as_str())
            .finish()
    }
}

/// Raw broker-held material. It intentionally has no public value accessor,
/// serialization, display implementation, or revealing debug output.
struct SecretValue(Vec<u8>);

impl Debug for SecretValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretValue(REDACTED)")
    }
}

/// A payload-free receipt proving that an authorized mock operation ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerReceipt {
    /// The handle used, never the corresponding raw value.
    pub handle: SecretHandle,
    /// The operation performed inside the broker.
    pub operation: Operation,
}

/// Provider-independent secret broker contract.
pub trait SecretBroker {
    /// Use broker-held material for an already-authorized operation.
    ///
    /// # Errors
    ///
    /// Returns [`PechatError::InvalidPropusk`] if the token is not bound to the
    /// exact secret handle/use operation.
    fn use_authorized(
        &self,
        handle: &SecretHandle,
        action: Propusk,
    ) -> Result<BrokerReceipt, PechatError>;

    /// Refuse to return raw material, regardless of handle possession.
    ///
    /// # Errors
    ///
    /// Always returns [`PechatError::UnauthorizedReveal`].
    fn reveal(&self, handle: &SecretHandle) -> Result<(), PechatError>;
}

/// In-memory fake broker used only for provider-independent security tests.
pub struct FakeBroker {
    secrets: HashMap<SecretHandle, SecretValue>,
}

impl Debug for FakeBroker {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeBroker")
            .field("secret_count", &self.secrets.len())
            .finish()
    }
}

impl FakeBroker {
    /// Create an empty fake broker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    /// Register a fake raw secret on the trusted broker side.
    ///
    /// The value is accepted only for test setup and is not returned or logged
    /// by any Pechat API.
    ///
    /// # Errors
    ///
    /// Returns [`PechatError::DuplicateHandle`] if the handle exists.
    pub fn register(&mut self, handle: SecretHandle, value: Vec<u8>) -> Result<(), PechatError> {
        if self.secrets.contains_key(&handle) {
            return Err(PechatError::DuplicateHandle);
        }
        self.secrets.insert(handle, SecretValue(value));
        Ok(())
    }

    /// Return the number of broker-held entries without exposing their values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Return whether the broker has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

impl Default for FakeBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBroker for FakeBroker {
    fn use_authorized(
        &self,
        handle: &SecretHandle,
        action: Propusk,
    ) -> Result<BrokerReceipt, PechatError> {
        let request = action.request();
        if request.operation() != &Operation::Execute
            || request.capability().as_str() != "secret.use"
            || request.resource() != &handle.resource()
            || request.destination() != &Destination::SecretBroker
        {
            return Err(PechatError::InvalidPropusk);
        }
        let Some(secret) = self.secrets.get(handle) else {
            return Err(PechatError::InvalidHandle);
        };
        // The fake operation intentionally consumes only an internal property.
        // No reference to the raw bytes escapes this method.
        let _secret_length = secret.0.len();
        Ok(BrokerReceipt {
            handle: handle.clone(),
            operation: Operation::Execute,
        })
    }

    fn reveal(&self, _handle: &SecretHandle) -> Result<(), PechatError> {
        Err(PechatError::UnauthorizedReveal)
    }
}

/// Branded Pechat facade for documentation and future broker implementations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pechat;

impl Pechat {
    /// Construct a stateless Pechat facade.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Classification, Identity, Principal, Provenance, ProvenanceSource, ResourceScope,
    };
    use crate::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};

    fn handle() -> SecretHandle {
        SecretHandle::new("github-prod").unwrap()
    }

    fn authorized_action() -> Propusk {
        let resource = handle().resource();
        let matcher = RuleMatcher::any()
            .principal(Principal::Model)
            .operation(Operation::Execute)
            .capability(crate::domain::CapabilityName::new("secret.use").unwrap())
            .resource(ResourceScope::exact(&resource))
            .destination(Destination::SecretBroker)
            .classification(Classification::Public);
        let policy = Policy::new(
            crate::domain::PolicyId::new("secret-use").unwrap(),
            vec![PolicyRule::allow(
                crate::domain::RuleId::new("allow-secret-use").unwrap(),
                matcher,
            )],
        )
        .unwrap();
        let context = crate::domain::SecurityContext::untrusted_data(
            Principal::Model,
            Provenance::from_source(ProvenanceSource::Web(
                Identity::new("broker-caller").unwrap(),
            ))
            .unwrap(),
            Classification::Public,
        );
        let request = crate::domain::ActionRequest::new(
            Principal::Model,
            Operation::Execute,
            resource,
            Destination::SecretBroker,
            crate::domain::CapabilityName::new("secret.use").unwrap(),
        );
        Krosna::new(policy).authorize(&context, &request).unwrap()
    }

    #[test]
    fn model_sees_only_opaque_handle_and_broker_debug_is_redacted() {
        let handle = handle();
        let mut broker = FakeBroker::new();
        broker
            .register(handle.clone(), b"actual-secret-value".to_vec())
            .unwrap();
        let serialized = serde_json::to_string(&handle).unwrap();
        assert!(serialized.contains("github-prod"));
        assert!(!serialized.contains("actual-secret-value"));
        assert!(!format!("{broker:?}").contains("actual-secret-value"));
        assert_eq!(broker.len(), 1);
    }

    #[test]
    fn reveal_is_denied_even_when_handle_exists_and_error_has_no_secret() {
        let handle = handle();
        let mut broker = FakeBroker::new();
        broker
            .register(handle.clone(), b"actual-secret-value".to_vec())
            .unwrap();
        let error = broker.reveal(&handle).unwrap_err();
        assert_eq!(error, PechatError::UnauthorizedReveal);
        assert!(!error.to_string().contains("actual-secret-value"));
        assert!(!format!("{error:?}").contains("actual-secret-value"));
    }

    #[test]
    fn authorized_use_succeeds_without_returning_secret() {
        let handle = handle();
        let mut broker = FakeBroker::new();
        broker
            .register(handle.clone(), b"actual-secret-value".to_vec())
            .unwrap();
        let receipt = broker.use_authorized(&handle, authorized_action()).unwrap();
        assert_eq!(receipt.handle, handle);
        assert_eq!(receipt.operation, Operation::Execute);
        let serialized = serde_json::to_string(&receipt).unwrap();
        assert!(!serialized.contains("actual-secret-value"));
    }

    #[test]
    fn unauthorized_action_cannot_use_secret() {
        let handle = handle();
        let mut broker = FakeBroker::new();
        broker
            .register(handle.clone(), b"actual-secret-value".to_vec())
            .unwrap();
        let mut action = authorized_action();
        // The token is private and cannot be edited; passing a different handle
        // must fail before the broker touches the stored value.
        let other = SecretHandle::new("other-secret").unwrap();
        let error = broker.use_authorized(&other, action).unwrap_err();
        assert_eq!(error, PechatError::InvalidPropusk);
        action = authorized_action();
        let receipt = broker.use_authorized(&handle, action).unwrap();
        assert_eq!(receipt.operation, Operation::Execute);
    }

    #[test]
    fn invalid_handle_and_duplicate_registration_are_safe() {
        assert_eq!(
            SecretHandle::new("").unwrap_err(),
            PechatError::InvalidHandle
        );
        let handle = handle();
        let mut broker = FakeBroker::new();
        broker.register(handle.clone(), Vec::new()).unwrap();
        assert_eq!(
            broker.register(handle, b"second".to_vec()).unwrap_err(),
            PechatError::DuplicateHandle
        );
    }

    #[test]
    fn pechat_facade_is_provider_independent() {
        assert_eq!(Pechat::new(), Pechat);
    }
}
