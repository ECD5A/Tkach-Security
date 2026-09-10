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

//! Fake protected tools for Gateway Phase 1.

use std::fmt::{Debug, Formatter};
use tkach_core::domain::{
    ActionRequest, CapabilityName, Destination, Identity, Operation, ProvenanceSource, Resource,
    ResourceId, ResourceKind,
};
use tkach_core::niti_metka::TaggedData;
use tkach_core::pechat::{FakeBroker, SecretBroker, SecretHandle};
use tkach_core::propusk::{ExecutionError, Propusk, ProtectedExecutor};

const MAX_FAKE_EFFECTS: usize = 1_024;

/// A payload-free summary of one authorized fake effect.
#[derive(Clone, PartialEq, Eq)]
pub struct EffectReceipt {
    operation: Operation,
    resource_kind: ResourceKind,
    destination: Destination,
}

impl Debug for EffectReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EffectReceipt(REDACTED)")
    }
}

impl EffectReceipt {
    /// Return the operation category of the authorized effect.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Return the resource category without an attacker-controlled identifier.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    /// Return the typed destination used by the effect.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }
}

/// Result returned by a protected tool. Data results retain Niti and Metka;
/// effect receipts carry no protected payload.
#[derive(Clone, PartialEq, Eq)]
pub enum ToolResult {
    /// A protected or public result intentionally made visible to the model.
    Data(TaggedData<String>),
    /// A completed effect with a payload-free receipt.
    Effect(EffectReceipt),
}

impl Debug for ToolResult {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data(value) => formatter.debug_tuple("Data").field(value).finish(),
            Self::Effect(value) => formatter.debug_tuple("Effect").field(value).finish(),
        }
    }
}

/// In-memory tool boundary used only for provider-independent gateway tests.
///
/// The provider never receives this value or a reference to it. Its executor
/// implementation accepts only Strong Core `Propusk` values.
pub struct FakeToolBroker {
    broker: FakeBroker,
    secret_handle: SecretHandle,
    effects: Vec<EffectReceipt>,
    read_count: usize,
    external_send_count: usize,
}

impl Debug for FakeToolBroker {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeToolBroker")
            .field("effect_count", &self.effects.len())
            .field("read_count", &self.read_count)
            .field("external_send_count", &self.external_send_count)
            .finish_non_exhaustive()
    }
}

impl FakeToolBroker {
    /// Construct a fake broker with one opaque handle and one fake raw secret.
    ///
    /// # Panics
    ///
    /// Only fixed, source-controlled setup values are used; a panic indicates
    /// an invariant-preserving test fixture was changed incorrectly, not an
    /// attacker-controlled input.
    #[must_use]
    pub fn new() -> Self {
        let secret_handle = SecretHandle::new("github-prod").expect("static test handle is valid");
        let mut broker = FakeBroker::new();
        broker
            .register(
                secret_handle.clone(),
                b"fake-github-production-secret".to_vec(),
            )
            .expect("static fake broker setup is within bounds");
        Self {
            broker,
            secret_handle,
            effects: Vec::new(),
            read_count: 0,
            external_send_count: 0,
        }
    }

    /// Return the opaque handle advertised to a model-facing tool catalog.
    #[must_use]
    pub const fn secret_handle(&self) -> &SecretHandle {
        &self.secret_handle
    }

    /// Return the number of effects accepted by the protected executor.
    #[must_use]
    pub fn effect_count(&self) -> usize {
        self.effects.len()
    }

    /// Return the number of protected read results produced.
    #[must_use]
    pub const fn read_count(&self) -> usize {
        self.read_count
    }

    /// Return the number of external sends that actually reached the tool.
    #[must_use]
    pub const fn external_send_count(&self) -> usize {
        self.external_send_count
    }

    /// Return safe effect receipts for inspection.
    #[must_use]
    pub fn effects(&self) -> &[EffectReceipt] {
        &self.effects
    }

    fn receipt(action: &Propusk) -> EffectReceipt {
        EffectReceipt {
            operation: action.request().operation().clone(),
            resource_kind: action.request().resource().kind(),
            destination: action.request().destination().clone(),
        }
    }

    fn record_effect(&mut self, receipt: EffectReceipt) -> Result<(), ExecutionError> {
        if self.effects.len() >= MAX_FAKE_EFFECTS {
            return Err(ExecutionError::Rejected);
        }
        self.effects.push(receipt);
        Ok(())
    }

    fn protected_read(&mut self, action: &Propusk) -> Result<ToolResult, ExecutionError> {
        let request = action.request();
        if request.operation() != &Operation::Read
            || request.capability().as_str() != "database.read"
            || request.resource().kind() != ResourceKind::Database
            || request.resource().id().as_str() != "customer-db"
            || request.destination() != &Destination::Model
        {
            return Err(ExecutionError::Rejected);
        }
        if self.effects.len() >= MAX_FAKE_EFFECTS {
            return Err(ExecutionError::Rejected);
        }
        self.read_count += 1;
        let tagged = TaggedData::from_trusted_ingress(
            "customer=alice; balance=protected".to_owned(),
            ProvenanceSource::Database(
                ResourceId::new("customer-db").map_err(|_| ExecutionError::Rejected)?,
            ),
            tkach_core::domain::Classification::Secret,
        )
        .map_err(|_| ExecutionError::Rejected)?;
        Ok(ToolResult::Data(tagged))
    }

    fn harmless_read(&mut self, action: &Propusk) -> Result<ToolResult, ExecutionError> {
        let request = action.request();
        if request.operation() != &Operation::Read
            || request.capability().as_str() != "database.read"
            || request.resource().kind() != ResourceKind::Database
            || request.resource().id().as_str() != "status"
            || request.destination() != &Destination::Model
        {
            return Err(ExecutionError::Rejected);
        }
        if self.effects.len() >= MAX_FAKE_EFFECTS {
            return Err(ExecutionError::Rejected);
        }
        self.read_count += 1;
        let tagged = TaggedData::from_trusted_ingress(
            "status=ok".to_owned(),
            ProvenanceSource::Tool(
                Identity::new("status-tool").map_err(|_| ExecutionError::Rejected)?,
            ),
            tkach_core::domain::Classification::Public,
        )
        .map_err(|_| ExecutionError::Rejected)?;
        Ok(ToolResult::Data(tagged))
    }
}

impl Default for FakeToolBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtectedExecutor for FakeToolBroker {
    type Output = ToolResult;

    fn execute(&mut self, action: Propusk) -> Result<Self::Output, ExecutionError> {
        let request = action.request();
        if request.operation() == &Operation::Read
            && request.capability().as_str() == "database.read"
            && request.resource().id().as_str() == "customer-db"
        {
            let result = self.protected_read(&action)?;
            self.record_effect(Self::receipt(&action))?;
            return Ok(result);
        }
        if request.operation() == &Operation::Read
            && request.capability().as_str() == "database.read"
        {
            let result = self.harmless_read(&action)?;
            self.record_effect(Self::receipt(&action))?;
            return Ok(result);
        }
        if request.operation() == &Operation::Write
            && request.capability().as_str() == "file.write"
            && request.resource().kind() == ResourceKind::File
            && is_storage_destination(request.destination())
        {
            let receipt = Self::receipt(&action);
            self.record_effect(receipt.clone())?;
            return Ok(ToolResult::Effect(receipt));
        }
        if request.operation() == &Operation::NetworkSend
            && request.capability().as_str() == "network.send"
            && request.resource().kind() == ResourceKind::Network
            && request.destination() == &Destination::PublicExternal
        {
            if self.effects.len() >= MAX_FAKE_EFFECTS {
                return Err(ExecutionError::Rejected);
            }
            self.external_send_count += 1;
            let receipt = Self::receipt(&action);
            self.record_effect(receipt.clone())?;
            return Ok(ToolResult::Effect(receipt));
        }
        if request.operation() == &Operation::Execute
            && request.capability().as_str() == "secret.use"
            && request.resource().kind() == ResourceKind::Secret
            && request.destination() == &Destination::SecretBroker
        {
            if self.effects.len() >= MAX_FAKE_EFFECTS {
                return Err(ExecutionError::Rejected);
            }
            self.broker
                .use_authorized(&self.secret_handle, action)
                .map_err(|_| ExecutionError::Rejected)?;
            let receipt = EffectReceipt {
                operation: Operation::Execute,
                resource_kind: ResourceKind::Secret,
                destination: Destination::SecretBroker,
            };
            self.record_effect(receipt.clone())?;
            return Ok(ToolResult::Effect(receipt));
        }
        Err(ExecutionError::Rejected)
    }
}

fn is_storage_destination(destination: &Destination) -> bool {
    matches!(destination, Destination::Internal(identity) if identity.as_str() == "storage")
}

/// Build a protected database-read proposal.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn protected_read_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Read,
        Resource::new(
            ResourceKind::Database,
            ResourceId::new("customer-db").expect("static resource id is valid"),
        ),
        Destination::Model,
        CapabilityName::new("database.read").expect("static capability is valid"),
    )
}

/// Build a public external-send proposal.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn external_send_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::NetworkSend,
        Resource::new(
            ResourceKind::Network,
            ResourceId::new("public-api").expect("static resource id is valid"),
        ),
        Destination::PublicExternal,
        CapabilityName::new("network.send").expect("static capability is valid"),
    )
}

/// Build a secret-reveal proposal for hostile-provider tests.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn secret_reveal_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::RevealSecret,
        Resource::new(
            ResourceKind::Secret,
            ResourceId::new("github-prod").expect("static resource id is valid"),
        ),
        Destination::SecretBroker,
        CapabilityName::new("secret.reveal").expect("static capability is valid"),
    )
}

/// Build a protected write proposal for lifecycle tests.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn protected_write_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Write,
        Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/output.txt").expect("static resource id is valid"),
        ),
        Destination::Internal(Identity::new("storage").expect("static identity is valid")),
        CapabilityName::new("file.write").expect("static capability is valid"),
    )
}

/// Build a harmless read-only tool proposal.
///
/// # Panics
///
/// Panics only if a fixed source-controlled test identifier becomes invalid.
#[must_use]
pub fn harmless_read_request() -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Read,
        Resource::new(
            ResourceKind::Database,
            ResourceId::new("status").expect("static resource id is valid"),
        ),
        Destination::Model,
        CapabilityName::new("database.read").expect("static capability is valid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tkach_core::domain::ResourceScope;
    use tkach_core::domain::{Classification, PolicyId, Principal, RuleId, SecurityContext};
    use tkach_core::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};

    fn permit(action: &ActionRequest) -> Propusk {
        let policy = Policy::new(
            PolicyId::new("tool-boundary-test").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-exact-test-action").unwrap(),
                RuleMatcher::any()
                    .principal(Principal::Model)
                    .operation(action.operation().clone())
                    .capability(action.capability().clone())
                    .resource(ResourceScope::exact(action.resource()))
                    .destination(action.destination().clone())
                    .classification(Classification::Unknown),
            )],
        )
        .unwrap();
        Krosna::new(policy)
            .authorize(&SecurityContext::untrusted_data(), action)
            .unwrap()
    }

    #[test]
    fn read_helpers_reject_wrong_identifier_and_destination() {
        let mut broker = FakeToolBroker::new();

        let mut wrong_customer_destination = protected_read_request();
        wrong_customer_destination = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            wrong_customer_destination.resource().clone(),
            Destination::Internal(Identity::new("storage").unwrap()),
            wrong_customer_destination.capability().clone(),
        );
        assert!(
            broker
                .protected_read(&permit(&wrong_customer_destination))
                .is_err()
        );

        let wrong_customer_id = harmless_read_request();
        assert!(broker.protected_read(&permit(&wrong_customer_id)).is_err());

        let mut wrong_status_destination = harmless_read_request();
        wrong_status_destination = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            wrong_status_destination.resource().clone(),
            Destination::Internal(Identity::new("storage").unwrap()),
            wrong_status_destination.capability().clone(),
        );
        assert!(
            broker
                .harmless_read(&permit(&wrong_status_destination))
                .is_err()
        );

        let wrong_status_id = protected_read_request();
        assert!(broker.harmless_read(&permit(&wrong_status_id)).is_err());
    }

    #[test]
    fn executor_routes_only_the_exact_write_destination() {
        let mut broker = FakeToolBroker::new();
        let wrong_destination = ActionRequest::new(
            Principal::Model,
            Operation::Write,
            protected_write_request().resource().clone(),
            Destination::Internal(Identity::new("other").unwrap()),
            protected_write_request().capability().clone(),
        );
        assert!(broker.execute(permit(&wrong_destination)).is_err());
        assert_eq!(broker.effect_count(), 0);

        let result = broker.execute(permit(&protected_write_request())).unwrap();
        assert!(matches!(result, ToolResult::Effect(_)));
        assert_eq!(broker.effect_count(), 1);
    }

    #[test]
    fn executor_rejects_network_send_to_a_non_public_destination() {
        let mut broker = FakeToolBroker::new();
        let wrong_destination = ActionRequest::new(
            Principal::Model,
            Operation::NetworkSend,
            Resource::new(
                ResourceKind::Network,
                ResourceId::new("public-api").unwrap(),
            ),
            Destination::Internal(Identity::new("storage").unwrap()),
            CapabilityName::new("network.send").unwrap(),
        );
        assert!(broker.execute(permit(&wrong_destination)).is_err());
        assert_eq!(broker.external_send_count(), 0);
    }

    #[test]
    fn kernel_cannot_mint_permits_for_coupled_unknown_read_shapes() {
        for action in [
            ActionRequest::new(
                Principal::Model,
                Operation::Write,
                protected_read_request().resource().clone(),
                Destination::Model,
                CapabilityName::new("database.read").unwrap(),
            ),
            ActionRequest::new(
                Principal::Model,
                Operation::Read,
                Resource::new(ResourceKind::File, ResourceId::new("customer-db").unwrap()),
                Destination::Model,
                CapabilityName::new("database.read").unwrap(),
            ),
        ] {
            let policy = Policy::new(
                PolicyId::new("coupled-shape-test").unwrap(),
                vec![PolicyRule::allow(
                    RuleId::new("allow-coupled-shape").unwrap(),
                    RuleMatcher::any()
                        .principal(Principal::Model)
                        .operation(action.operation().clone())
                        .capability(action.capability().clone())
                        .resource(ResourceScope::exact(action.resource()))
                        .destination(action.destination().clone())
                        .classification(Classification::Unknown),
                )],
            )
            .unwrap();
            assert!(
                Krosna::new(policy)
                    .authorize(&SecurityContext::untrusted_data(), &action)
                    .is_err()
            );
        }
    }
}
