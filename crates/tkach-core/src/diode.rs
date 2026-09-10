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

//! Diode, first-class directional information-flow control.
//!
//! A Diode rule describes one directed edge. No reverse or onward edge is
//! inferred. Classification and provenance travel with the flow request and
//! are evaluated independently from action authorization.

use crate::domain::{
    Classification, Decision, DecisionKind, Destination, FlowDirection, Identity, Operation,
    Principal, Provenance, ProvenanceSource, Resource, RuleId, SledEvidence, SledReason,
};
use thiserror::Error;

const MAX_RULES: usize = 1_024;

/// Errors while constructing a directional policy.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum DiodeError {
    /// Two flow rules reused the same identity.
    #[error("duplicate Diode rule id")]
    DuplicateRuleId,
    /// The directional policy would exceed its deterministic rule budget.
    #[error("Diode rule capacity exceeded")]
    TooManyRules,
}

/// A directional source endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FlowSource {
    /// A typed protected resource.
    Resource(Resource),
    /// Model or agent output/context.
    Model,
    /// An approved internal endpoint.
    Internal(Identity),
    /// An unrecognized endpoint, handled conservatively.
    Unknown(Identity),
}

/// The flow operation, kept distinct from action authorization operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowOperation {
    /// Read information into the destination context.
    Read,
    /// Export information out to a destination.
    Export,
    /// Transfer information between internal endpoints.
    Transfer,
    /// Unknown flow operation, never allowed by default.
    Unknown,
}

/// One directional information-flow request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRequest {
    principal: Principal,
    source: FlowSource,
    destination: Destination,
    operation: FlowOperation,
    provenance: Provenance,
    classification: Classification,
}

impl FlowRequest {
    /// Construct a directional flow request from a validated security context.
    ///
    /// This is the public boundary mapper for context-backed flows: provenance
    /// and classification are copied from the context and cannot be supplied as
    /// independent caller claims.
    #[must_use]
    pub(crate) fn from_context(
        context: &crate::domain::SecurityContext,
        source: FlowSource,
        destination: Destination,
        operation: FlowOperation,
    ) -> Self {
        Self::new(
            context.principal().clone(),
            source,
            destination,
            operation,
            context.provenance().clone(),
            context.classification(),
        )
    }

    /// Construct a flow from tagged data so Niti/Metka metadata is carried
    /// rather than recreated by a model-facing caller.
    #[must_use]
    pub fn from_tagged<T>(
        destination: Destination,
        operation: FlowOperation,
        data: &crate::niti_metka::TaggedData<T>,
    ) -> Self {
        Self::new(
            Principal::Model,
            FlowSource::Model,
            destination,
            operation,
            data.niti().provenance().clone(),
            data.metka().classification(),
        )
    }

    /// Internal constructor used only by kernel boundary mappers and tests.
    pub(crate) fn new(
        principal: Principal,
        source: FlowSource,
        destination: Destination,
        operation: FlowOperation,
        provenance: Provenance,
        classification: Classification,
    ) -> Self {
        Self {
            principal,
            source,
            destination,
            operation,
            provenance,
            classification,
        }
    }

    /// Return the principal responsible for the flow.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Return the directed source endpoint.
    #[must_use]
    pub const fn source(&self) -> &FlowSource {
        &self.source
    }

    /// Return the directed destination endpoint.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Return the flow operation.
    #[must_use]
    pub const fn operation(&self) -> FlowOperation {
        self.operation
    }

    /// Return retained provenance.
    #[must_use]
    pub const fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Return conservative classification.
    #[must_use]
    pub const fn classification(&self) -> Classification {
        self.classification
    }
}

/// Explicit effect of a directional rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowEffect {
    /// Hard denial that no allow rule can override.
    HardDeny,
    /// Normal explicit denial.
    Deny,
    /// A separate approval is required.
    RequireApproval,
    /// Explicit directional allow.
    Allow,
}

impl FlowEffect {
    const fn precedence(self) -> u8 {
        match self {
            Self::HardDeny => 4,
            Self::Deny => 3,
            Self::RequireApproval => 2,
            Self::Allow => 1,
        }
    }

    const fn decision_kind(self) -> DecisionKind {
        match self {
            Self::HardDeny | Self::Deny => DecisionKind::Deny,
            Self::RequireApproval => DecisionKind::RequireApproval,
            Self::Allow => DecisionKind::Allow,
        }
    }
}

/// Predicates for a directional flow rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlowMatcher {
    principal: Option<Principal>,
    source: Option<FlowSource>,
    destination: Option<Destination>,
    operation: Option<FlowOperation>,
    provenance: Option<ProvenanceSource>,
    classification: Option<Classification>,
}

impl FlowMatcher {
    /// Construct an unrestricted matcher. Explicit policy is still required.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            principal: None,
            source: None,
            destination: None,
            operation: None,
            provenance: None,
            classification: None,
        }
    }

    /// Restrict to one principal.
    #[must_use]
    pub fn principal(mut self, principal: Principal) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Restrict to one source endpoint.
    #[must_use]
    pub fn source(mut self, source: FlowSource) -> Self {
        self.source = Some(source);
        self
    }

    /// Restrict to one destination.
    #[must_use]
    pub fn destination(mut self, destination: Destination) -> Self {
        self.destination = Some(destination);
        self
    }

    /// Restrict to one flow operation.
    #[must_use]
    pub fn operation(mut self, operation: FlowOperation) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Restrict to one immediate provenance source.
    #[must_use]
    pub fn provenance(mut self, provenance: ProvenanceSource) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Restrict to one exact classification.
    #[must_use]
    pub fn classification(mut self, classification: Classification) -> Self {
        self.classification = Some(classification);
        self
    }

    fn matches(&self, request: &FlowRequest) -> bool {
        self.principal
            .as_ref()
            .is_none_or(|principal| principal == request.principal())
            && self
                .source
                .as_ref()
                .is_none_or(|source| source == request.source())
            && self
                .destination
                .as_ref()
                .is_none_or(|destination| destination == request.destination())
            && self
                .operation
                .is_none_or(|operation| operation == request.operation)
            && self
                .provenance
                .as_ref()
                .is_none_or(|provenance| provenance == request.provenance().source())
            && self
                .classification
                .is_none_or(|classification| classification == request.classification)
    }
}

/// One named directional rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRule {
    id: RuleId,
    matcher: FlowMatcher,
    effect: FlowEffect,
}

impl FlowRule {
    /// Construct an explicit directional allow.
    #[must_use]
    pub const fn allow(id: RuleId, matcher: FlowMatcher) -> Self {
        Self {
            id,
            matcher,
            effect: FlowEffect::Allow,
        }
    }

    /// Construct a normal directional deny.
    #[must_use]
    pub const fn deny(id: RuleId, matcher: FlowMatcher) -> Self {
        Self {
            id,
            matcher,
            effect: FlowEffect::Deny,
        }
    }

    /// Construct a hard directional deny.
    #[must_use]
    pub const fn hard_deny(id: RuleId, matcher: FlowMatcher) -> Self {
        Self {
            id,
            matcher,
            effect: FlowEffect::HardDeny,
        }
    }

    /// Construct a directional approval requirement.
    #[must_use]
    pub const fn require_approval(id: RuleId, matcher: FlowMatcher) -> Self {
        Self {
            id,
            matcher,
            effect: FlowEffect::RequireApproval,
        }
    }
}

/// A deterministic directional policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diode {
    rules: Vec<FlowRule>,
}

impl Diode {
    /// Validate and construct a directional policy.
    ///
    /// # Errors
    ///
    /// Returns [`DiodeError::DuplicateRuleId`] for repeated rule identities.
    pub fn new(mut rules: Vec<FlowRule>) -> Result<Self, DiodeError> {
        if rules.len() > MAX_RULES {
            return Err(DiodeError::TooManyRules);
        }
        let mut ids = std::collections::HashSet::new();
        for rule in &rules {
            if !ids.insert(rule.id.clone()) {
                return Err(DiodeError::DuplicateRuleId);
            }
        }
        rules.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(Self { rules })
    }

    /// Evaluate one directed flow with default denial.
    #[must_use]
    pub fn evaluate(&self, request: &FlowRequest) -> Decision {
        if matches!(request.operation, FlowOperation::Unknown)
            || matches!(request.destination, Destination::Unknown(_))
            || matches!(request.source, FlowSource::Unknown(_))
        {
            return deny(request, None, SledReason::UnknownDenied);
        }

        if request.classification.is_protected() && request.destination.is_public_external() {
            return deny(request, None, SledReason::FlowDenied);
        }

        let selected = self
            .rules
            .iter()
            .filter(|rule| rule.matcher.matches(request))
            .min_by(|left, right| {
                right
                    .effect
                    .precedence()
                    .cmp(&left.effect.precedence())
                    .then_with(|| left.id.as_str().cmp(right.id.as_str()))
            });
        match selected {
            Some(rule) => {
                let reason = match rule.effect {
                    FlowEffect::HardDeny => SledReason::HardDeny,
                    FlowEffect::Deny => SledReason::PolicyDeny,
                    FlowEffect::RequireApproval => SledReason::ApprovalRequired,
                    FlowEffect::Allow => SledReason::ExplicitAllow,
                };
                Decision::new(
                    rule.effect.decision_kind(),
                    evidence(request, Some(rule.id.clone()), reason),
                )
            }
            None => deny(request, None, SledReason::NoAuthorization),
        }
    }
}

fn deny(request: &FlowRequest, rule_id: Option<RuleId>, reason: SledReason) -> Decision {
    Decision::new(DecisionKind::Deny, evidence(request, rule_id, reason))
}

fn evidence(request: &FlowRequest, rule_id: Option<RuleId>, reason: SledReason) -> SledEvidence {
    let capability =
        crate::domain::CapabilityName::new("diode.flow").expect("static capability is valid");
    let operation = match request.operation {
        FlowOperation::Read => Operation::Read,
        FlowOperation::Export => Operation::NetworkSend,
        FlowOperation::Transfer => Operation::Write,
        FlowOperation::Unknown => Operation::Unknown(capability.clone()),
    };
    SledEvidence {
        rule_id,
        principal: request.principal.clone(),
        operation,
        capability,
        provenance: request.provenance.source().clone(),
        classification: request.classification,
        destination: request.destination.clone(),
        direction: Some(match request.operation {
            FlowOperation::Read => FlowDirection::Ingress,
            FlowOperation::Export | FlowOperation::Transfer | FlowOperation::Unknown => {
                FlowDirection::Egress
            }
        }),
        reason,
    }
}

/// Convert an action request and its context into a directional flow request.
#[must_use]
pub(crate) fn flow_from_action(
    context: &crate::domain::SecurityContext,
    request: &crate::domain::ActionRequest,
) -> FlowRequest {
    let operation = match request.operation() {
        Operation::Read if request.destination() == &Destination::PublicExternal => {
            FlowOperation::Export
        }
        Operation::Read => FlowOperation::Read,
        Operation::NetworkSend => FlowOperation::Export,
        Operation::Unknown(_) => FlowOperation::Unknown,
        Operation::Write
        | Operation::Execute
        | Operation::RevealSecret
        | Operation::Declassify
        | Operation::MutatePolicy => FlowOperation::Transfer,
    };
    FlowRequest::from_context(
        context,
        match request.operation() {
            Operation::NetworkSend => FlowSource::Model,
            _ => FlowSource::Resource(request.resource().clone()),
        },
        request.destination().clone(),
        operation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{CapabilityName, Identity, ResourceId, ResourceKind};
    use proptest::prelude::*;

    fn secret_database() -> Resource {
        Resource::new(
            ResourceKind::Database,
            ResourceId::new("customer.db").unwrap(),
        )
    }

    fn secret_provenance() -> Provenance {
        Provenance::from_source(ProvenanceSource::Database(
            ResourceId::new("customer.db").unwrap(),
        ))
        .unwrap()
    }

    fn read_flow() -> FlowRequest {
        FlowRequest::new(
            Principal::Model,
            FlowSource::Resource(secret_database()),
            Destination::Model,
            FlowOperation::Read,
            secret_provenance(),
            Classification::Secret,
        )
    }

    fn export_flow(destination: Destination, classification: Classification) -> FlowRequest {
        FlowRequest::new(
            Principal::Model,
            FlowSource::Model,
            destination,
            FlowOperation::Export,
            secret_provenance(),
            classification,
        )
    }

    #[test]
    fn read_is_not_export_and_reverse_is_not_inferred() {
        let read = FlowMatcher::any()
            .source(FlowSource::Resource(secret_database()))
            .destination(Destination::Model)
            .operation(FlowOperation::Read)
            .classification(Classification::Secret);
        let diode = Diode::new(vec![FlowRule::allow(
            RuleId::new("db-to-model-read").unwrap(),
            read,
        )])
        .unwrap();
        assert_eq!(diode.evaluate(&read_flow()).kind, DecisionKind::Allow);
        let reverse = FlowRequest::new(
            Principal::Model,
            FlowSource::Model,
            Destination::Internal(Identity::new("database").unwrap()),
            FlowOperation::Export,
            secret_provenance(),
            Classification::Secret,
        );
        assert_eq!(diode.evaluate(&reverse).kind, DecisionKind::Deny);
    }

    #[test]
    fn protected_external_export_is_denied_even_by_allow() {
        let diode = Diode::new(vec![FlowRule::allow(
            RuleId::new("allow-any").unwrap(),
            FlowMatcher::any(),
        )])
        .unwrap();
        let decision = diode.evaluate(&export_flow(
            Destination::PublicExternal,
            Classification::Secret,
        ));
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::FlowDenied);
    }

    #[test]
    fn protected_public_destination_is_denied_for_every_flow_operation() {
        let diode = Diode::new(vec![FlowRule::allow(
            RuleId::new("allow-any").unwrap(),
            FlowMatcher::any(),
        )])
        .unwrap();
        for operation in [
            FlowOperation::Read,
            FlowOperation::Export,
            FlowOperation::Transfer,
        ] {
            let request = FlowRequest::new(
                Principal::Model,
                FlowSource::Model,
                Destination::PublicExternal,
                operation,
                secret_provenance(),
                Classification::Unknown,
            );
            let decision = diode.evaluate(&request);
            assert_eq!(decision.kind, DecisionKind::Deny);
            assert_eq!(decision.evidence.reason, SledReason::FlowDenied);
        }
    }

    #[test]
    fn tagged_secret_metadata_cannot_be_replaced_by_public_model_claim() {
        let secret = crate::niti_metka::TaggedData::from_source(
            "raw secret".to_owned(),
            secret_provenance().source().clone(),
            Classification::Secret,
        )
        .unwrap();
        let diode = Diode::new(vec![FlowRule::allow(
            RuleId::new("allow-public").unwrap(),
            FlowMatcher::any()
                .destination(Destination::PublicExternal)
                .operation(FlowOperation::Export)
                .classification(Classification::Public),
        )])
        .unwrap();
        let flow =
            FlowRequest::from_tagged(Destination::PublicExternal, FlowOperation::Export, &secret);
        let decision = diode.evaluate(&flow);
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::FlowDenied);
    }

    #[test]
    fn public_tagged_flow_cannot_supply_source_or_sensitivity_metadata() {
        let tagged = crate::niti_metka::TaggedData::from_untrusted("model output".to_owned());
        let flow = FlowRequest::from_tagged(
            Destination::PublicExternal,
            FlowOperation::Transfer,
            &tagged,
        );
        assert_eq!(flow.source(), &FlowSource::Model);
        assert_eq!(flow.classification(), Classification::Unknown);
        assert_eq!(flow.provenance().source(), &ProvenanceSource::Unknown);

        let diode = Diode::new(vec![FlowRule::allow(
            RuleId::new("allow-any").unwrap(),
            FlowMatcher::any(),
        )])
        .unwrap();
        let decision = diode.evaluate(&flow);
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::FlowDenied);
    }

    #[test]
    fn unknown_destination_fails_closed() {
        let diode = Diode::new(vec![FlowRule::allow(
            RuleId::new("allow-any").unwrap(),
            FlowMatcher::any(),
        )])
        .unwrap();
        let decision = diode.evaluate(&export_flow(
            Destination::Unknown(Identity::new("future").unwrap()),
            Classification::Public,
        ));
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::UnknownDenied);
    }

    #[test]
    fn mixed_provenance_cannot_be_laundered_by_model_endpoint() {
        let diode = Diode::new(vec![FlowRule::allow(
            RuleId::new("allow-public-export").unwrap(),
            FlowMatcher::any()
                .source(FlowSource::Model)
                .destination(Destination::PublicExternal)
                .operation(FlowOperation::Export)
                .classification(Classification::Public),
        )])
        .unwrap();
        let decision = diode.evaluate(&export_flow(
            Destination::PublicExternal,
            Classification::Secret,
        ));
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::FlowDenied);
    }

    #[test]
    fn conflicting_rules_are_order_independent_and_evidence_stable() {
        let allow = FlowRule::allow(RuleId::new("z-allow").unwrap(), FlowMatcher::any());
        let deny = FlowRule::deny(RuleId::new("a-deny").unwrap(), FlowMatcher::any());
        let first = Diode::new(vec![allow.clone(), deny.clone()]).unwrap();
        let second = Diode::new(vec![deny, allow]).unwrap();
        let one = first.evaluate(&read_flow());
        let two = second.evaluate(&read_flow());
        assert_eq!(one, two);
        assert_eq!(one.kind, DecisionKind::Deny);
        assert_eq!(one.evidence.reason, SledReason::PolicyDeny);
    }

    #[test]
    fn rule_budget_is_enforced_before_rule_indexing() {
        let rules = (0..=MAX_RULES)
            .map(|index| {
                FlowRule::allow(
                    RuleId::new(format!("flow-{index}")).unwrap(),
                    FlowMatcher::any(),
                )
            })
            .collect();
        assert_eq!(Diode::new(rules).unwrap_err(), DiodeError::TooManyRules);
    }

    #[test]
    fn sled_evidence_contains_no_flow_payload() {
        let diode = Diode::new(Vec::new()).unwrap();
        let decision = diode.evaluate(&export_flow(
            Destination::PublicExternal,
            Classification::Secret,
        ));
        let encoded = serde_json::to_string(&decision).unwrap();
        assert!(encoded.contains("customer.db"));
        assert!(!encoded.contains("actual-secret-value"));
        assert!(encoded.contains("Database"));
    }

    proptest! {
        #[test]
        fn explicit_public_export_rule_cannot_allow_more_sensitive_data(
            classification in prop::sample::select(vec![
                Classification::Public,
                Classification::Internal,
                Classification::Confidential,
                Classification::Sensitive,
                Classification::Secret,
                Classification::Unknown,
            ])
        ) {
            let diode = Diode::new(vec![FlowRule::allow(
                RuleId::new("public-only").unwrap(),
                FlowMatcher::any()
                    .destination(Destination::PublicExternal)
                    .operation(FlowOperation::Export)
                    .classification(Classification::Public),
            )]).unwrap();
            let decision = diode.evaluate(&export_flow(Destination::PublicExternal, classification));
            if classification != Classification::Public {
                prop_assert_ne!(decision.kind, DecisionKind::Allow);
            }
        }

        #[test]
        fn unknown_flow_operation_never_allows(_seed in any::<u64>()) {
            let diode = Diode::new(vec![FlowRule::allow(
                RuleId::new("allow-any").unwrap(),
                FlowMatcher::any(),
            )]).unwrap();
            let mut flow = read_flow();
            flow.operation = FlowOperation::Unknown;
            prop_assert_ne!(diode.evaluate(&flow).kind, DecisionKind::Allow);
        }
    }

    #[test]
    fn capability_name_for_flow_evidence_is_validated() {
        assert_eq!(
            CapabilityName::new("diode.flow").unwrap().as_str(),
            "diode.flow"
        );
    }
}
