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

//! Klyuchnik, the opaque-secret broker boundary.
//!
//! Klyuchnik protects the model-context boundary under the documented assumption
//! that the host process and operating system are not fully compromised. The
//! model receives a [`crate::klyuchnik::SecretHandle`], while the fake broker
//! keeps the raw value in a non-serializable, redacted type and never returns it.

use crate::domain::{Destination, Operation, Resource, ResourceId, ResourceKind};
use crate::propusk::Propusk;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use thiserror::Error;

const MAX_REGISTERED_SECRETS: usize = 1_024;
const MAX_SECRET_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_SECRET_BYTES: usize = 16 * 1024 * 1024;

/// Errors from the opaque-secret boundary.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum KlyuchnikError {
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
    /// The fake broker reached its bounded registration capacity.
    #[error("secret broker capacity exceeded")]
    CapacityExceeded,
    /// A fake broker value exceeds the bounded test setup limit.
    #[error("secret value is too large")]
    SecretTooLarge,
    /// The aggregate fake-broker memory budget was exceeded.
    #[error("secret broker byte budget exceeded")]
    TotalSecretBytesExceeded,
}

/// An opaque identifier safe to place in model-visible context.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretHandle(ResourceId);

impl SecretHandle {
    /// Construct a validated opaque handle; this does not retrieve a secret.
    ///
    /// # Errors
    ///
    /// Returns [`KlyuchnikError::InvalidHandle`] for invalid identifier syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, KlyuchnikError> {
        Ok(Self(
            ResourceId::new(value).map_err(|_| KlyuchnikError::InvalidHandle)?,
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
#[derive(Clone, PartialEq, Eq)]
pub struct BrokerReceipt {
    /// The handle used, never the corresponding raw value.
    handle: SecretHandle,
    /// The operation performed inside the broker.
    operation: Operation,
}

impl Debug for BrokerReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BrokerReceipt(REDACTED)")
    }
}

impl BrokerReceipt {
    /// Return the opaque handle used by the broker.
    #[must_use]
    pub const fn handle(&self) -> &SecretHandle {
        &self.handle
    }

    /// Return the operation performed inside the broker.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }
}

/// Provider-independent secret broker contract.
pub trait SecretBroker {
    /// Use broker-held material for an already-authorized operation.
    ///
    /// # Errors
    ///
    /// Returns [`KlyuchnikError::InvalidPropusk`] if the token is not bound to the
    /// exact secret handle/use operation.
    fn use_authorized(
        &self,
        handle: &SecretHandle,
        action: Propusk,
    ) -> Result<BrokerReceipt, KlyuchnikError>;

    /// Refuse to return raw material, regardless of handle possession.
    ///
    /// # Errors
    ///
    /// Always returns [`KlyuchnikError::UnauthorizedReveal`].
    fn reveal(&self, handle: &SecretHandle) -> Result<(), KlyuchnikError>;
}

/// In-memory fake broker used only for provider-independent security tests.
pub struct FakeBroker {
    secrets: HashMap<SecretHandle, SecretValue>,
    total_secret_bytes: usize,
}

impl Debug for FakeBroker {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeBroker")
            .field("secret_count", &self.secrets.len())
            .finish_non_exhaustive()
    }
}

impl FakeBroker {
    /// Create an empty fake broker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            total_secret_bytes: 0,
        }
    }

    /// Register a fake raw secret on the trusted broker side.
    ///
    /// The value is accepted only for test setup and is not returned or logged
    /// by any Klyuchnik API.
    ///
    /// # Errors
    ///
    /// Returns an error when the handle exists, the value exceeds its per-value
    /// limit, or the aggregate broker memory budget would be exceeded.
    pub fn register(&mut self, handle: SecretHandle, value: Vec<u8>) -> Result<(), KlyuchnikError> {
        if self.secrets.contains_key(&handle) {
            return Err(KlyuchnikError::DuplicateHandle);
        }
        if self.secrets.len() >= MAX_REGISTERED_SECRETS {
            return Err(KlyuchnikError::CapacityExceeded);
        }
        if value.len() > MAX_SECRET_BYTES {
            return Err(KlyuchnikError::SecretTooLarge);
        }
        let new_total = self
            .total_secret_bytes
            .checked_add(value.len())
            .ok_or(KlyuchnikError::TotalSecretBytesExceeded)?;
        if new_total > MAX_TOTAL_SECRET_BYTES {
            return Err(KlyuchnikError::TotalSecretBytesExceeded);
        }
        self.total_secret_bytes = new_total;
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
    ) -> Result<BrokerReceipt, KlyuchnikError> {
        let request = action.request();
        if request.operation() != &Operation::Execute
            || request.capability().as_str() != "secret.use"
            || request.resource() != &handle.resource()
            || request.destination() != &Destination::SecretBroker
        {
            return Err(KlyuchnikError::InvalidPropusk);
        }
        let Some(secret) = self.secrets.get(handle) else {
            return Err(KlyuchnikError::InvalidHandle);
        };
        // The fake operation intentionally consumes only an internal property.
        // No reference to the raw bytes escapes this method.
        let _secret_length = secret.0.len();
        Ok(BrokerReceipt {
            handle: handle.clone(),
            operation: Operation::Execute,
        })
    }

    fn reveal(&self, _handle: &SecretHandle) -> Result<(), KlyuchnikError> {
        Err(KlyuchnikError::UnauthorizedReveal)
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
        let context = crate::domain::SecurityContext::untrusted_with_metadata(
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
        assert_eq!(
            format!("{:?}", SecretValue(b"actual-secret-value".to_vec())),
            "SecretValue(REDACTED)"
        );
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
        assert_eq!(error, KlyuchnikError::UnauthorizedReveal);
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
        assert_eq!(receipt.handle(), &handle);
        assert_eq!(receipt.operation(), &Operation::Execute);
        assert_eq!(format!("{receipt:?}"), "BrokerReceipt(REDACTED)");
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
        assert_eq!(error, KlyuchnikError::InvalidPropusk);
        action = authorized_action();
        let receipt = broker.use_authorized(&handle, action).unwrap();
        assert_eq!(receipt.operation(), &Operation::Execute);
    }

    #[test]
    fn invalid_handle_and_duplicate_registration_are_safe() {
        assert_eq!(
            SecretHandle::new("").unwrap_err(),
            KlyuchnikError::InvalidHandle
        );
        let handle = handle();
        let mut broker = FakeBroker::new();
        broker.register(handle.clone(), Vec::new()).unwrap();
        assert_eq!(
            broker.register(handle, b"second".to_vec()).unwrap_err(),
            KlyuchnikError::DuplicateHandle
        );
    }

    #[test]
    fn broker_registration_is_bounded() {
        let oversized = SecretHandle::new("oversized").unwrap();
        let mut broker = FakeBroker::new();
        assert_eq!(
            broker.register(oversized, vec![0; MAX_SECRET_BYTES + 1]),
            Err(KlyuchnikError::SecretTooLarge)
        );
        for index in 0..MAX_REGISTERED_SECRETS {
            let handle = SecretHandle::new(format!("secret-{index}")).unwrap();
            broker.register(handle, vec![0]).unwrap();
        }
        assert_eq!(
            broker.register(SecretHandle::new("overflow").unwrap(), vec![0]),
            Err(KlyuchnikError::CapacityExceeded)
        );
    }

    #[test]
    fn broker_aggregate_secret_memory_is_bounded() {
        let mut broker = FakeBroker::new();
        for index in 0..(MAX_TOTAL_SECRET_BYTES / MAX_SECRET_BYTES) {
            broker
                .register(
                    SecretHandle::new(format!("aggregate-{index}")).unwrap(),
                    vec![0; MAX_SECRET_BYTES],
                )
                .unwrap();
        }
        assert_eq!(
            broker.register(SecretHandle::new("aggregate-overflow").unwrap(), vec![0],),
            Err(KlyuchnikError::TotalSecretBytesExceeded)
        );
    }
}
