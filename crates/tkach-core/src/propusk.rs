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

//! Propusk, the scoped capability and execution-authority boundary.
//!
//! The only production constructor for [`crate::propusk::AuthorizedAction`] is
//! crate-private.
//! Krosna issues it only after an explicit deterministic allow and binds it to
//! the exact principal, operation, capability, and resource being authorized.

use crate::domain::{ActionRequest, Operation, Principal, ResourceScope};
use thiserror::Error;

/// A capability grant issued by trusted kernel code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityGrant {
    principal: Principal,
    capability: crate::domain::CapabilityName,
    operation: Operation,
    scope: ResourceScope,
}

impl CapabilityGrant {
    pub(crate) fn issue(
        principal: Principal,
        capability: crate::domain::CapabilityName,
        operation: Operation,
        scope: ResourceScope,
    ) -> Self {
        Self {
            principal,
            capability,
            operation,
            scope,
        }
    }

    /// Return the principal bound to this grant.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Return the capability name bound to this grant.
    #[must_use]
    pub const fn capability(&self) -> &crate::domain::CapabilityName {
        &self.capability
    }

    /// Return the operation bound to this grant.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Return the non-widenable resource scope bound to this grant.
    #[must_use]
    pub const fn scope(&self) -> &ResourceScope {
        &self.scope
    }

    fn matches(&self, request: &ActionRequest) -> bool {
        self.principal == *request.principal()
            && self.capability == *request.capability()
            && self.operation == *request.operation()
            && self.scope.contains(request.resource())
    }
}

/// A kernel-issued execution authority. It is intentionally not deserializable
/// and has no public constructor.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedAction {
    request: ActionRequest,
    grant: CapabilityGrant,
}

impl AuthorizedAction {
    pub(crate) fn issue(
        request: ActionRequest,
        grant: CapabilityGrant,
    ) -> Result<Self, AuthorizationError> {
        if !grant.matches(&request) {
            return Err(AuthorizationError::InvalidGrant);
        }
        Ok(Self { request, grant })
    }

    /// Return the exact request authorized by this token.
    #[must_use]
    pub const fn request(&self) -> &ActionRequest {
        &self.request
    }

    /// Return the capability grant bound to this token.
    #[must_use]
    pub const fn grant(&self) -> &CapabilityGrant {
        &self.grant
    }
}

/// Public name for the kernel-issued execution permit.
pub type Propusk = AuthorizedAction;

/// Errors returned when a request cannot become execution authority.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum AuthorizationError {
    /// Krosna did not produce an allow decision.
    #[error("action was not authorized")]
    Denied(Box<crate::domain::Decision>),
    /// An internal grant/request mismatch was detected; no token was issued.
    #[error("invalid capability grant")]
    InvalidGrant,
}

/// An executor boundary that cannot accept a raw [`ActionRequest`].
pub trait ProtectedExecutor {
    /// The effect result produced by the protected executor.
    type Output;

    /// Execute only a kernel-issued [`Propusk`].
    ///
    /// # Errors
    ///
    /// The executor may reject an already-authorized operation for its own
    /// non-policy reasons.
    fn execute(&mut self, action: Propusk) -> Result<Self::Output, ExecutionError>;
}

/// Non-policy execution failures. They carry no protected payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ExecutionError {
    /// The protected executor rejected the authorized effect.
    #[error("protected executor rejected action")]
    Rejected,
    /// Validation failed before the real effect was attempted.
    #[error("protected effect failed before execution")]
    FailedBeforeEffect,
    /// The executor cannot determine whether the real effect committed.
    #[error("protected effect outcome is unknown")]
    OutcomeUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{CapabilityName, Resource, ResourceId, ResourceKind};

    fn request() -> ActionRequest {
        ActionRequest::new(
            Principal::Model,
            Operation::Read,
            Resource::new(
                ResourceKind::File,
                ResourceId::new("workspace/a.txt").unwrap(),
            ),
            crate::domain::Destination::Model,
            CapabilityName::new("file.read").unwrap(),
        )
    }

    #[test]
    fn incoherent_internal_grant_never_becomes_token() {
        let request = request();
        let grant = CapabilityGrant::issue(
            Principal::System,
            CapabilityName::new("file.read").unwrap(),
            Operation::Read,
            ResourceScope::exact(request.resource()),
        );
        assert_eq!(
            AuthorizedAction::issue(request, grant).unwrap_err(),
            AuthorizationError::InvalidGrant
        );
    }

    #[test]
    fn exact_scope_is_bound_into_grant() {
        let request = request();
        let grant = CapabilityGrant::issue(
            Principal::Model,
            CapabilityName::new("file.read").unwrap(),
            Operation::Read,
            ResourceScope::exact(request.resource()),
        );
        let token = AuthorizedAction::issue(request, grant).unwrap();
        assert_eq!(token.grant().principal(), &Principal::Model);
        assert_eq!(token.grant().capability().as_str(), "file.read");
        assert!(token.grant().scope().contains(token.request().resource()));
    }

    struct RecordingExecutor;

    impl ProtectedExecutor for RecordingExecutor {
        type Output = Operation;

        fn execute(&mut self, action: Propusk) -> Result<Self::Output, ExecutionError> {
            Ok(action.request().operation().clone())
        }
    }

    #[test]
    fn protected_executor_accepts_propusk_type_not_raw_request() {
        let request = request();
        let grant = CapabilityGrant::issue(
            Principal::Model,
            CapabilityName::new("file.read").unwrap(),
            Operation::Read,
            ResourceScope::exact(request.resource()),
        );
        let token = AuthorizedAction::issue(request, grant).unwrap();
        let mut executor = RecordingExecutor;
        assert_eq!(executor.execute(token).unwrap(), Operation::Read);
    }
}
