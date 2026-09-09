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

//! Krosna, the synchronous deterministic policy kernel.
//!
//! Krosna answers authorization questions from validated structured state. It
//! never asks a model to authorize itself. Every result is a [`Decision`] with
//! payload-free [`SledEvidence`].

use crate::domain::{
    ActionRequest, Authority, Classification, Decision, DecisionKind, Destination, Operation,
    PolicyId, Principal, ResourceScope, RuleId, SecurityContext, SledEvidence, SledReason,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Errors found while loading a typed policy.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// Two rules attempted to occupy the same identity.
    #[error("duplicate policy rule id: {rule_id}")]
    DuplicateRuleId {
        /// The duplicated non-secret rule identity.
        rule_id: RuleId,
    },
}

/// A rule's deterministic effect class. Higher-ranked effects take precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleKind {
    /// An unconditional hard deny at the policy boundary.
    HardDeny,
    /// A normal explicit deny.
    Deny,
    /// A restricted result requiring a separate approval step.
    RequireApproval,
    /// An explicit allow.
    Allow,
}

impl RuleKind {
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

/// An explicit set of predicates for a policy rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatcher {
    principal: Option<Principal>,
    operation: Option<Operation>,
    capability: Option<crate::domain::CapabilityName>,
    resource: Option<ResourceScope>,
    destination: Option<Destination>,
    classification: Option<Classification>,
}

impl RuleMatcher {
    /// Construct a matcher with no wildcard restrictions.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            principal: None,
            operation: None,
            capability: None,
            resource: None,
            destination: None,
            classification: None,
        }
    }

    /// Restrict the rule to one principal.
    #[must_use]
    pub fn principal(mut self, principal: Principal) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Restrict the rule to one operation.
    #[must_use]
    pub fn operation(mut self, operation: Operation) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Restrict the rule to one capability name.
    #[must_use]
    pub fn capability(mut self, capability: crate::domain::CapabilityName) -> Self {
        self.capability = Some(capability);
        self
    }

    /// Restrict the rule to one exact resource scope.
    #[must_use]
    pub fn resource(mut self, resource: ResourceScope) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Restrict the rule to one destination.
    #[must_use]
    pub fn destination(mut self, destination: Destination) -> Self {
        self.destination = Some(destination);
        self
    }

    /// Restrict the rule to one exact classification.
    #[must_use]
    pub fn classification(mut self, classification: Classification) -> Self {
        self.classification = Some(classification);
        self
    }

    fn matches(&self, context: &SecurityContext, request: &ActionRequest) -> bool {
        self.principal
            .as_ref()
            .is_none_or(|principal| principal == request.principal())
            && self
                .operation
                .as_ref()
                .is_none_or(|operation| operation == request.operation())
            && self
                .capability
                .as_ref()
                .is_none_or(|capability| capability == request.capability())
            && self
                .resource
                .as_ref()
                .is_none_or(|scope| scope.contains(request.resource()))
            && self
                .destination
                .as_ref()
                .is_none_or(|destination| destination == request.destination())
            && self
                .classification
                .is_none_or(|classification| classification == context.classification())
    }
}

/// One named typed policy rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    id: RuleId,
    matcher: RuleMatcher,
    kind: RuleKind,
}

impl PolicyRule {
    /// Construct an explicit allow rule.
    #[must_use]
    pub const fn allow(id: RuleId, matcher: RuleMatcher) -> Self {
        Self {
            id,
            matcher,
            kind: RuleKind::Allow,
        }
    }

    /// Construct an explicit normal deny rule.
    #[must_use]
    pub const fn deny(id: RuleId, matcher: RuleMatcher) -> Self {
        Self {
            id,
            matcher,
            kind: RuleKind::Deny,
        }
    }

    /// Construct an explicit hard-deny rule.
    #[must_use]
    pub const fn hard_deny(id: RuleId, matcher: RuleMatcher) -> Self {
        Self {
            id,
            matcher,
            kind: RuleKind::HardDeny,
        }
    }

    /// Construct a rule requiring an external approval.
    #[must_use]
    pub const fn require_approval(id: RuleId, matcher: RuleMatcher) -> Self {
        Self {
            id,
            matcher,
            kind: RuleKind::RequireApproval,
        }
    }

    /// Return the stable rule identity.
    #[must_use]
    pub const fn id(&self) -> &RuleId {
        &self.id
    }

    /// Return the rule's effect class.
    #[must_use]
    pub const fn kind(&self) -> RuleKind {
        self.kind
    }
}

/// A validated policy set. Rule order does not define authorization precedence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Policy {
    id: PolicyId,
    rules: Vec<PolicyRule>,
}

impl Policy {
    /// Validate and construct a policy. An empty policy is valid and denies by
    /// default.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::DuplicateRuleId`] when a rule identity repeats.
    pub fn new(id: PolicyId, rules: Vec<PolicyRule>) -> Result<Self, PolicyError> {
        let mut seen = HashSet::with_capacity(rules.len());
        for rule in &rules {
            if !seen.insert(rule.id.clone()) {
                return Err(PolicyError::DuplicateRuleId {
                    rule_id: rule.id.clone(),
                });
            }
        }
        Ok(Self { id, rules })
    }

    /// Return the policy identity.
    #[must_use]
    pub const fn id(&self) -> &PolicyId {
        &self.id
    }

    /// Return the configured rules in their stored order.
    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }
}

#[derive(Deserialize)]
struct PolicyWire {
    id: PolicyId,
    rules: Vec<PolicyRule>,
}

impl<'de> Deserialize<'de> for Policy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = PolicyWire::deserialize(deserializer)?;
        Self::new(wire.id, wire.rules).map_err(serde::de::Error::custom)
    }
}

enum PolicyState {
    Ready(Policy),
    Failed,
}

/// The deterministic Krosna policy evaluator.
pub struct Krosna {
    policy: PolicyState,
}

impl Krosna {
    /// Create a kernel from a validated policy.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: PolicyState::Ready(policy),
        }
    }

    /// Create a fail-closed kernel from a policy load result.
    #[must_use]
    pub fn from_policy_result(result: Result<Policy, PolicyError>) -> Self {
        match result {
            Ok(policy) => Self::new(policy),
            Err(_) => Self {
                policy: PolicyState::Failed,
            },
        }
    }

    /// Evaluate one request synchronously and deterministically.
    ///
    /// The returned decision is always safe to inspect: policy-load failure,
    /// malformed boundary state, unknown privileged operations, and hard flow
    /// invariants produce denial rather than an authorization error that a
    /// caller might accidentally reinterpret as allow.
    #[must_use]
    pub fn evaluate(&self, context: &SecurityContext, request: &ActionRequest) -> Decision {
        if context.principal() != request.principal() {
            return Self::deny(context, request, None, SledReason::InvalidRequest);
        }

        if is_unknown_request(request) {
            return Self::deny(context, request, None, SledReason::UnknownDenied);
        }

        if requires_trusted_control(request.operation())
            && context.authority() != Authority::TrustedControl
        {
            return Self::deny(context, request, None, SledReason::HardDeny);
        }

        if context.classification().is_protected()
            && request.operation() == &Operation::NetworkSend
            && request.destination().is_public_external()
        {
            return Self::deny(context, request, None, SledReason::FlowDenied);
        }

        let selected = match &self.policy {
            PolicyState::Ready(policy) => select_rule(policy, context, request),
            PolicyState::Failed => {
                return Self::deny(context, request, None, SledReason::InvalidRequest);
            }
        };

        match selected {
            Some(rule) => {
                let reason = match rule.kind {
                    RuleKind::HardDeny => SledReason::HardDeny,
                    RuleKind::Deny => SledReason::PolicyDeny,
                    RuleKind::RequireApproval => SledReason::ApprovalRequired,
                    RuleKind::Allow => SledReason::ExplicitAllow,
                };
                Decision::new(
                    rule.kind.decision_kind(),
                    Self::evidence(context, request, Some(rule.id.clone()), reason),
                )
            }
            None => Self::deny(context, request, None, SledReason::NoAuthorization),
        }
    }

    fn deny(
        context: &SecurityContext,
        request: &ActionRequest,
        rule_id: Option<RuleId>,
        reason: SledReason,
    ) -> Decision {
        Decision::new(
            DecisionKind::Deny,
            Self::evidence(context, request, rule_id, reason),
        )
    }

    fn evidence(
        context: &SecurityContext,
        request: &ActionRequest,
        rule_id: Option<RuleId>,
        reason: SledReason,
    ) -> SledEvidence {
        SledEvidence {
            rule_id,
            principal: request.principal().clone(),
            operation: request.operation().clone(),
            capability: request.capability().clone(),
            provenance: context.provenance().source().clone(),
            classification: context.classification(),
            destination: request.destination().clone(),
            reason,
        }
    }
}

fn select_rule<'a>(
    policy: &'a Policy,
    context: &SecurityContext,
    request: &ActionRequest,
) -> Option<&'a PolicyRule> {
    policy
        .rules
        .iter()
        .filter(|rule| rule.matcher.matches(context, request))
        .min_by(|left, right| {
            right
                .kind
                .precedence()
                .cmp(&left.kind.precedence())
                .then_with(|| left.id.as_str().cmp(right.id.as_str()))
        })
}

fn is_unknown_request(request: &ActionRequest) -> bool {
    matches!(request.operation(), Operation::Unknown(_))
        || matches!(request.destination(), Destination::Unknown(_))
}

fn requires_trusted_control(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::MutatePolicy | Operation::Declassify | Operation::RevealSecret
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Classification, Identity, Provenance, ProvenanceSource, Resource, ResourceId, ResourceKind,
    };
    use proptest::prelude::*;

    fn fixture_ids() -> (PolicyId, RuleId, crate::domain::CapabilityName) {
        (
            PolicyId::new("test-policy").unwrap(),
            RuleId::new("allow-read").unwrap(),
            crate::domain::CapabilityName::new("file.read").unwrap(),
        )
    }

    fn fixture_resource() -> Resource {
        Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/data.txt").unwrap(),
        )
    }

    fn fixture_context(classification: Classification) -> SecurityContext {
        SecurityContext::untrusted_data(
            Principal::Model,
            Provenance::from_source(ProvenanceSource::Web(
                Identity::new("example.test").unwrap(),
            ))
            .unwrap(),
            classification,
        )
    }

    fn fixture_request(operation: Operation, destination: Destination) -> ActionRequest {
        let resource = fixture_resource();
        ActionRequest::new(
            Principal::Model,
            operation,
            resource,
            destination,
            crate::domain::CapabilityName::new("file.read").unwrap(),
        )
    }

    fn read_matcher() -> RuleMatcher {
        let resource = fixture_resource();
        RuleMatcher::any()
            .principal(Principal::Model)
            .operation(Operation::Read)
            .capability(crate::domain::CapabilityName::new("file.read").unwrap())
            .resource(ResourceScope::exact(&resource))
            .destination(Destination::Model)
            .classification(Classification::Public)
    }

    #[test]
    fn explicit_allow_is_structured_and_deterministic() {
        let (policy_id, rule_id, _) = fixture_ids();
        let policy =
            Policy::new(policy_id, vec![PolicyRule::allow(rule_id, read_matcher())]).unwrap();
        let kernel = Krosna::new(policy);
        let request = fixture_request(Operation::Read, Destination::Model);
        let context = fixture_context(Classification::Public);
        let first = kernel.evaluate(&context, &request);
        assert_eq!(first.kind, DecisionKind::Allow);
        assert_eq!(first.evidence.reason, SledReason::ExplicitAllow);
        assert_eq!(
            first.evidence.rule_id.as_ref().unwrap().as_str(),
            "allow-read"
        );
        assert_eq!(first, kernel.evaluate(&context, &request));
    }

    #[test]
    fn deny_beats_allow_and_rule_order_is_not_authority() {
        let policy_id = PolicyId::new("conflict-policy").unwrap();
        let allow = PolicyRule::allow(RuleId::new("z-allow").unwrap(), read_matcher());
        let deny = PolicyRule::deny(RuleId::new("a-deny").unwrap(), read_matcher());
        let first =
            Krosna::new(Policy::new(policy_id.clone(), vec![allow.clone(), deny.clone()]).unwrap());
        let second = Krosna::new(Policy::new(policy_id, vec![deny, allow]).unwrap());
        let decision_one = first.evaluate(
            &fixture_context(Classification::Public),
            &fixture_request(Operation::Read, Destination::Model),
        );
        let decision_two = second.evaluate(
            &fixture_context(Classification::Public),
            &fixture_request(Operation::Read, Destination::Model),
        );
        assert_eq!(decision_one.kind, DecisionKind::Deny);
        assert_eq!(decision_one.evidence.reason, SledReason::PolicyDeny);
        assert_eq!(decision_one, decision_two);
    }

    #[test]
    fn hard_deny_beats_everything() {
        let policy = Policy::new(
            PolicyId::new("hard-policy").unwrap(),
            vec![
                PolicyRule::allow(RuleId::new("allow").unwrap(), read_matcher()),
                PolicyRule::hard_deny(RuleId::new("hard").unwrap(), read_matcher()),
            ],
        )
        .unwrap();
        let decision = Krosna::new(policy).evaluate(
            &fixture_context(Classification::Public),
            &fixture_request(Operation::Read, Destination::Model),
        );
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::HardDeny);
    }

    #[test]
    fn unknown_privileged_requests_fail_closed() {
        let policy = Policy::new(
            PolicyId::new("wildcard").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-any").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let kernel = Krosna::new(policy);
        let context = fixture_context(Classification::Public);
        let unknown_operation = fixture_request(
            Operation::Unknown(crate::domain::CapabilityName::new("future.op").unwrap()),
            Destination::Model,
        );
        let unknown_destination = fixture_request(
            Operation::Read,
            Destination::Unknown(Identity::new("future-destination").unwrap()),
        );
        assert_eq!(
            kernel.evaluate(&context, &unknown_operation).kind,
            DecisionKind::Deny
        );
        assert_eq!(
            kernel
                .evaluate(&context, &unknown_operation)
                .evidence
                .reason,
            SledReason::UnknownDenied
        );
        assert_eq!(
            kernel.evaluate(&context, &unknown_destination).kind,
            DecisionKind::Deny
        );
    }

    #[test]
    fn policy_failure_is_not_authorization() {
        let duplicate = RuleId::new("same").unwrap();
        let invalid = Policy::new(
            PolicyId::new("invalid").unwrap(),
            vec![
                PolicyRule::allow(duplicate.clone(), RuleMatcher::any()),
                PolicyRule::allow(duplicate, RuleMatcher::any()),
            ],
        );
        let decision = Krosna::from_policy_result(invalid).evaluate(
            &fixture_context(Classification::Public),
            &fixture_request(Operation::Read, Destination::Model),
        );
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::InvalidRequest);
    }

    #[test]
    fn protected_public_export_is_hard_gated_even_by_allow_rule() {
        let policy = Policy::new(
            PolicyId::new("export").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-export").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let request = fixture_request(Operation::NetworkSend, Destination::PublicExternal);
        let decision =
            Krosna::new(policy).evaluate(&fixture_context(Classification::Secret), &request);
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::FlowDenied);
    }

    #[test]
    fn model_cannot_use_policy_rule_to_declassify_or_mutate_policy() {
        let policy = Policy::new(
            PolicyId::new("control").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-any").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let kernel = Krosna::new(policy);
        let context = fixture_context(Classification::Secret);
        for operation in [
            Operation::Declassify,
            Operation::MutatePolicy,
            Operation::RevealSecret,
        ] {
            let decision =
                kernel.evaluate(&context, &fixture_request(operation, Destination::Model));
            assert_eq!(decision.kind, DecisionKind::Deny);
            assert_eq!(decision.evidence.reason, SledReason::HardDeny);
        }
    }

    #[test]
    fn mismatched_request_principal_is_rejected() {
        let policy = Policy::new(
            PolicyId::new("identity").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-any").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let context = fixture_context(Classification::Public);
        let resource = fixture_resource();
        let request = ActionRequest::new(
            Principal::System,
            Operation::Read,
            resource,
            Destination::Model,
            crate::domain::CapabilityName::new("file.read").unwrap(),
        );
        let decision = Krosna::new(policy).evaluate(&context, &request);
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::InvalidRequest);
    }

    #[test]
    fn serialized_policy_rechecks_duplicate_rule_invariant() {
        let json = serde_json::json!({
            "id": "policy",
            "rules": [
                {"id": "same", "matcher": {}, "kind": "Allow"},
                {"id": "same", "matcher": {}, "kind": "Deny"}
            ]
        });
        assert!(serde_json::from_value::<Policy>(json).is_err());
    }

    proptest! {
        #[test]
        fn rule_order_cannot_change_conflict_result(swap in any::<bool>()) {
            let policy_id = PolicyId::new("prop-policy").unwrap();
            let allow = PolicyRule::allow(RuleId::new("z-allow").unwrap(), read_matcher());
            let deny = PolicyRule::deny(RuleId::new("a-deny").unwrap(), read_matcher());
            let rules = if swap { vec![deny, allow] } else { vec![allow, deny] };
            let kernel = Krosna::new(Policy::new(policy_id, rules).unwrap());
            let decision = kernel.evaluate(
                &fixture_context(Classification::Public),
                &fixture_request(Operation::Read, Destination::Model),
            );
            prop_assert_eq!(decision.kind, DecisionKind::Deny);
            prop_assert_eq!(decision.evidence.reason, SledReason::PolicyDeny);
        }

        #[test]
        fn policy_failure_never_allows(_seed in any::<u64>()) {
            let rule_id = RuleId::new("same").unwrap();
            let invalid = Policy::new(
                PolicyId::new("invalid-prop").unwrap(),
                vec![
                    PolicyRule::allow(rule_id.clone(), RuleMatcher::any()),
                    PolicyRule::allow(rule_id, RuleMatcher::any()),
                ],
            );
            let decision = Krosna::from_policy_result(invalid).evaluate(
                &fixture_context(Classification::Public),
                &fixture_request(Operation::Read, Destination::Model),
            );
            prop_assert_ne!(decision.kind, DecisionKind::Allow);
        }
    }
}
