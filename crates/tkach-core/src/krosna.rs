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
    PolicyId, Principal, ResourceKind, ResourceScope, RuleId, SecurityContext, SledEvidence,
    SledReason, Trust,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

const MAX_POLICY_RULES: usize = 1_024;

/// Errors found while loading a typed policy.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// Two rules attempted to occupy the same identity.
    #[error("duplicate policy rule id: {rule_id}")]
    DuplicateRuleId {
        /// The duplicated non-secret rule identity.
        rule_id: RuleId,
    },
    /// The policy would exceed the deterministic in-memory rule budget.
    #[error("policy rule capacity exceeded")]
    TooManyRules,
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

    pub(crate) fn matches(&self, context: &SecurityContext, request: &ActionRequest) -> bool {
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
        if rules.len() > MAX_POLICY_RULES {
            return Err(PolicyError::TooManyRules);
        }
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
    #[serde(deserialize_with = "deserialize_policy_rules")]
    rules: Vec<PolicyRule>,
}

fn deserialize_policy_rules<'de, D>(deserializer: D) -> Result<Vec<PolicyRule>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    crate::domain::deserialize_bounded_vec::<D, PolicyRule, MAX_POLICY_RULES>(deserializer)
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
    zaslon: Option<crate::zaslon::Zaslon>,
    diode: Option<crate::diode::Diode>,
}

impl Krosna {
    /// Create a kernel from a validated policy.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: PolicyState::Ready(policy),
            zaslon: None,
            diode: None,
        }
    }

    /// Create a fail-closed kernel from a policy load result.
    #[must_use]
    pub fn from_policy_result(result: Result<Policy, PolicyError>) -> Self {
        match result {
            Ok(policy) => Self::new(policy),
            Err(_) => Self {
                policy: PolicyState::Failed,
                zaslon: None,
                diode: None,
            },
        }
    }

    /// Create a kernel with a deterministic Zaslon hard-deny plane.
    #[must_use]
    pub fn with_zaslon(policy: Policy, zaslon: crate::zaslon::Zaslon) -> Self {
        Self {
            policy: PolicyState::Ready(policy),
            zaslon: Some(zaslon),
            diode: None,
        }
    }

    /// Create a kernel with a deterministic Diode flow plane.
    #[must_use]
    pub fn with_diode(policy: Policy, diode: crate::diode::Diode) -> Self {
        Self {
            policy: PolicyState::Ready(policy),
            zaslon: None,
            diode: Some(diode),
        }
    }

    /// Create a kernel with both hard-deny and directional-flow planes.
    #[must_use]
    pub fn with_zaslon_and_diode(
        policy: Policy,
        zaslon: crate::zaslon::Zaslon,
        diode: crate::diode::Diode,
    ) -> Self {
        Self {
            policy: PolicyState::Ready(policy),
            zaslon: Some(zaslon),
            diode: Some(diode),
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

        // The public context constructor is intentionally untrusted. It must
        // not be usable to relabel a model proposal as System/User/Service and
        // match a policy intended for that trusted principal.
        if context.trust() == Trust::Untrusted && context.principal() != &Principal::Model {
            return Self::deny(context, request, None, SledReason::InvalidRequest);
        }

        if is_unknown_request(request) {
            return Self::deny(context, request, None, SledReason::UnknownDenied);
        }

        // SecretBroker is a dedicated Pechat route, not a general executor
        // destination. Enforce this at the authority minting boundary so a
        // custom ProtectedExecutor cannot accidentally process a non-secret
        // Propusk addressed at the broker.
        if request.destination() == &Destination::SecretBroker
            && !is_valid_secret_broker_request(request)
        {
            return Self::deny(context, request, None, SledReason::HardDeny);
        }

        if let Some(zaslon) = &self.zaslon {
            if let Some(decision) = zaslon.action_decision(context, request) {
                return decision;
            }
        }

        if requires_trusted_control(request.operation())
            && context.authority() != Authority::TrustedControl
        {
            return Self::deny(context, request, None, SledReason::HardDeny);
        }

        if !is_known_capability(request) {
            return Self::deny(context, request, None, SledReason::UnknownDenied);
        }

        if let Some(diode) = &self.diode {
            let flow = crate::diode::flow_from_action(context, request);
            let decision = diode.evaluate(&flow);
            if !decision.is_allowed() {
                return decision;
            }
        }

        if context.classification().is_protected() && request.destination().is_public_external() {
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

    /// Authorize a request and mint a scoped Propusk only for an explicit allow.
    ///
    /// # Errors
    ///
    /// Returns [`crate::propusk::AuthorizationError::Denied`] for every deny or
    /// approval result. No execution token is created in those cases.
    pub fn authorize(
        &self,
        context: &SecurityContext,
        request: &ActionRequest,
    ) -> Result<crate::propusk::AuthorizedAction, crate::propusk::AuthorizationError> {
        let decision = self.evaluate(context, request);
        if !decision.is_allowed() {
            return Err(crate::propusk::AuthorizationError::Denied(Box::new(
                decision,
            )));
        }
        let grant = crate::propusk::CapabilityGrant::issue(
            request.principal().clone(),
            request.capability().clone(),
            request.operation().clone(),
            ResourceScope::exact(request.resource()),
        );
        crate::propusk::AuthorizedAction::issue(request.clone(), grant)
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
            principal: request.principal().into(),
            operation: request.operation().into(),
            capability: request.capability().into(),
            provenance: context.provenance().source().into(),
            classification: context.classification(),
            destination: request.destination().into(),
            direction: None,
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

fn is_valid_secret_broker_request(request: &ActionRequest) -> bool {
    request.operation() == &Operation::Execute
        && request.resource().kind() == ResourceKind::Secret
        && request.capability().as_str() == "secret.use"
}

fn is_known_capability(request: &ActionRequest) -> bool {
    let capability = request.capability().as_str();
    match request.operation() {
        Operation::Read => matches!(
            (request.resource().kind(), capability),
            (ResourceKind::File, "file.read") | (ResourceKind::Database, "database.read")
        ),
        Operation::Write => matches!(
            (request.resource().kind(), capability),
            (ResourceKind::File, "file.write") | (ResourceKind::Database, "database.write")
        ),
        Operation::Execute => match (request.resource().kind(), capability) {
            (ResourceKind::Tool, "tool.execute") => true,
            (ResourceKind::Secret, "secret.use") => {
                request.destination() == &Destination::SecretBroker
            }
            _ => false,
        },
        Operation::NetworkSend => {
            request.resource().kind() == ResourceKind::Network && capability == "network.send"
        }
        Operation::RevealSecret => {
            request.resource().kind() == ResourceKind::Secret && capability == "secret.reveal"
        }
        Operation::Declassify => {
            request.resource().kind() != ResourceKind::Unknown && capability == "data.declassify"
        }
        Operation::MutatePolicy => {
            request.resource().kind() == ResourceKind::Policy && capability == "policy.mutate"
        }
        Operation::Unknown(_) => false,
    }
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
    use crate::diode::{Diode, FlowMatcher, FlowOperation, FlowRule, FlowSource};
    use crate::domain::{
        CapabilityName, Classification, Identity, Provenance, ProvenanceSource, Resource,
        ResourceId, ResourceKind,
    };
    use crate::zaslon::{ActionRule, Zaslon};
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
        SecurityContext::untrusted_with_metadata(
            Principal::Model,
            Provenance::from_source(ProvenanceSource::Web(
                Identity::new("example.test").unwrap(),
            ))
            .unwrap(),
            classification,
        )
    }

    fn fixture_request(operation: Operation, destination: Destination) -> ActionRequest {
        let (kind, capability) = match &operation {
            Operation::Read => (ResourceKind::File, "file.read"),
            Operation::Write => (ResourceKind::File, "file.write"),
            Operation::Execute => (ResourceKind::Tool, "tool.execute"),
            Operation::NetworkSend => (ResourceKind::Network, "network.send"),
            Operation::RevealSecret => (ResourceKind::Secret, "secret.reveal"),
            Operation::Declassify => (ResourceKind::Policy, "data.declassify"),
            Operation::MutatePolicy => (ResourceKind::Policy, "policy.mutate"),
            Operation::Unknown(_) => (ResourceKind::Unknown, "unknown.capability"),
        };
        ActionRequest::new(
            Principal::Model,
            operation,
            Resource::new(kind, ResourceId::new("workspace/data.txt").unwrap()),
            destination,
            crate::domain::CapabilityName::new(capability).unwrap(),
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
    fn authorize_mints_only_a_bound_exact_scope_token() {
        let policy = Policy::new(
            PolicyId::new("authorize").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-read").unwrap(),
                read_matcher(),
            )],
        )
        .unwrap();
        let kernel = Krosna::new(policy);
        let request = fixture_request(Operation::Read, Destination::Model);
        let token = kernel
            .authorize(&fixture_context(Classification::Public), &request)
            .unwrap();
        assert_eq!(token.request(), &request);
        assert_eq!(token.grant().principal(), &Principal::Model);
        assert_eq!(token.grant().operation(), &Operation::Read);
        assert!(token.grant().scope().contains(request.resource()));
    }

    #[test]
    fn unknown_capability_denies_even_with_wildcard_policy() {
        let policy = Policy::new(
            PolicyId::new("unknown-capability").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-any").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let resource = fixture_resource();
        let request = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            resource,
            Destination::Model,
            crate::domain::CapabilityName::new("future.read").unwrap(),
        );
        let decision =
            Krosna::new(policy).evaluate(&fixture_context(Classification::Public), &request);
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::UnknownDenied);
    }

    #[test]
    fn prefix_policy_scope_allows_child_but_not_lookalike_path() {
        let prefix = ResourceScope::file_prefix("workspace/src").unwrap();
        let policy = Policy::new(
            PolicyId::new("prefix").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-src").unwrap(),
                RuleMatcher::any()
                    .principal(Principal::Model)
                    .operation(Operation::Read)
                    .capability(crate::domain::CapabilityName::new("file.read").unwrap())
                    .resource(prefix)
                    .destination(Destination::Model)
                    .classification(Classification::Public),
            )],
        )
        .unwrap();
        let kernel = Krosna::new(policy);
        let context = fixture_context(Classification::Public);
        let child = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            Resource::new(
                ResourceKind::File,
                ResourceId::new("workspace/src/lib.rs").unwrap(),
            ),
            Destination::Model,
            crate::domain::CapabilityName::new("file.read").unwrap(),
        );
        let lookalike = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            Resource::new(
                ResourceKind::File,
                ResourceId::new("workspace/src-private/lib.rs").unwrap(),
            ),
            Destination::Model,
            crate::domain::CapabilityName::new("file.read").unwrap(),
        );
        assert!(kernel.authorize(&context, &child).is_ok());
        assert!(matches!(
            kernel.authorize(&context, &lookalike),
            Err(crate::propusk::AuthorizationError::Denied(_))
        ));
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
    fn every_protected_external_action_is_denied_not_only_network_send() {
        let policy = Policy::new(
            PolicyId::new("all-actions").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-any").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let context = fixture_context(Classification::Secret);
        let cases = [
            (
                Operation::Read,
                ResourceKind::Database,
                "customer.db",
                "database.read",
            ),
            (
                Operation::Write,
                ResourceKind::Database,
                "customer.db",
                "database.write",
            ),
            (
                Operation::Execute,
                ResourceKind::Tool,
                "shell",
                "tool.execute",
            ),
        ];
        for (operation, kind, id, capability) in cases {
            let request = ActionRequest::new(
                Principal::Model,
                operation,
                Resource::new(kind, ResourceId::new(id).unwrap()),
                Destination::PublicExternal,
                crate::domain::CapabilityName::new(capability).unwrap(),
            );
            let decision = Krosna::new(policy.clone()).evaluate(&context, &request);
            assert_eq!(decision.kind, DecisionKind::Deny);
            assert_eq!(decision.evidence.reason, SledReason::FlowDenied);
        }
    }

    #[test]
    fn secret_use_cannot_be_authorized_outside_pechat() {
        let policy = Policy::new(
            PolicyId::new("secret-route").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-any").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let request = ActionRequest::new(
            Principal::Model,
            Operation::Execute,
            Resource::new(
                ResourceKind::Secret,
                ResourceId::new("github-prod").unwrap(),
            ),
            Destination::Model,
            crate::domain::CapabilityName::new("secret.use").unwrap(),
        );
        let decision =
            Krosna::new(policy).evaluate(&fixture_context(Classification::Public), &request);
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::UnknownDenied);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn known_capability_table_is_exact_for_each_operation() {
        let cases = [
            (
                Operation::Read,
                ResourceKind::File,
                "file.read",
                Destination::Model,
                true,
            ),
            (
                Operation::Read,
                ResourceKind::Database,
                "database.read",
                Destination::Model,
                true,
            ),
            (
                Operation::Read,
                ResourceKind::File,
                "database.read",
                Destination::Model,
                false,
            ),
            (
                Operation::Write,
                ResourceKind::File,
                "file.write",
                Destination::Model,
                true,
            ),
            (
                Operation::Write,
                ResourceKind::Database,
                "database.write",
                Destination::Model,
                true,
            ),
            (
                Operation::Write,
                ResourceKind::File,
                "database.write",
                Destination::Model,
                false,
            ),
            (
                Operation::Execute,
                ResourceKind::Tool,
                "tool.execute",
                Destination::Model,
                true,
            ),
            (
                Operation::Execute,
                ResourceKind::Secret,
                "secret.use",
                Destination::SecretBroker,
                true,
            ),
            (
                Operation::Execute,
                ResourceKind::Secret,
                "secret.use",
                Destination::Model,
                false,
            ),
            (
                Operation::Execute,
                ResourceKind::Tool,
                "secret.use",
                Destination::SecretBroker,
                false,
            ),
            (
                Operation::NetworkSend,
                ResourceKind::Network,
                "network.send",
                Destination::PublicExternal,
                true,
            ),
            (
                Operation::NetworkSend,
                ResourceKind::File,
                "network.send",
                Destination::PublicExternal,
                false,
            ),
            (
                Operation::RevealSecret,
                ResourceKind::Secret,
                "secret.reveal",
                Destination::Model,
                true,
            ),
            (
                Operation::RevealSecret,
                ResourceKind::Secret,
                "secret.use",
                Destination::Model,
                false,
            ),
            (
                Operation::Declassify,
                ResourceKind::File,
                "data.declassify",
                Destination::Model,
                true,
            ),
            (
                Operation::Declassify,
                ResourceKind::File,
                "file.read",
                Destination::Model,
                false,
            ),
            (
                Operation::Declassify,
                ResourceKind::Unknown,
                "data.declassify",
                Destination::Model,
                false,
            ),
            (
                Operation::MutatePolicy,
                ResourceKind::Policy,
                "policy.mutate",
                Destination::Internal(Identity::new("control").unwrap()),
                true,
            ),
            (
                Operation::MutatePolicy,
                ResourceKind::File,
                "policy.mutate",
                Destination::Internal(Identity::new("control").unwrap()),
                false,
            ),
            (
                Operation::Unknown(CapabilityName::new("future.op").unwrap()),
                ResourceKind::Unknown,
                "future.op",
                Destination::Model,
                false,
            ),
        ];
        for (operation, kind, capability, destination, expected) in cases {
            let request = ActionRequest::new(
                Principal::Model,
                operation,
                Resource::new(kind, ResourceId::new("oracle-resource").unwrap()),
                destination,
                CapabilityName::new(capability).unwrap(),
            );
            assert_eq!(is_known_capability(&request), expected, "{request:?}");
        }
    }

    #[test]
    fn secret_broker_destination_requires_exact_pechat_route() {
        let policy = Policy::new(
            PolicyId::new("broker-route-boundary").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-any").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let request = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            Resource::new(
                ResourceKind::File,
                ResourceId::new("ordinary-file").unwrap(),
            ),
            Destination::SecretBroker,
            CapabilityName::new("file.read").unwrap(),
        );
        let kernel = Krosna::new(policy);
        let decision = kernel.evaluate(&SecurityContext::untrusted_data(), &request);
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::HardDeny);
        assert!(
            kernel
                .authorize(&SecurityContext::untrusted_data(), &request)
                .is_err()
        );
    }

    #[test]
    fn secret_broker_route_predicate_requires_all_three_dimensions() {
        let secret = Resource::new(ResourceKind::Secret, ResourceId::new("secret").unwrap());
        let tool = Resource::new(ResourceKind::Tool, ResourceId::new("tool").unwrap());
        let cases = [
            (Operation::Execute, secret.clone(), "secret.use", true),
            (Operation::Read, secret.clone(), "secret.use", false),
            (Operation::Execute, tool, "secret.use", false),
            (Operation::Execute, secret, "other.use", false),
        ];
        for (operation, resource, capability, expected) in cases {
            let request = ActionRequest::new(
                Principal::Model,
                operation,
                resource,
                Destination::SecretBroker,
                CapabilityName::new(capability).unwrap(),
            );
            assert_eq!(is_valid_secret_broker_request(&request), expected);
        }
    }

    #[test]
    fn network_send_is_mapped_to_model_source_for_diode() {
        let policy = Policy::new(
            PolicyId::new("network").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-network").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let diode = Diode::new(vec![
            FlowRule::hard_deny(
                RuleId::new("deny-model-egress").unwrap(),
                FlowMatcher::any()
                    .source(FlowSource::Model)
                    .destination(Destination::PublicExternal)
                    .operation(FlowOperation::Export),
            ),
            FlowRule::allow(RuleId::new("allow-any-flow").unwrap(), FlowMatcher::any()),
        ])
        .unwrap();
        let decision = Krosna::with_diode(policy, diode).evaluate(
            &fixture_context(Classification::Public),
            &fixture_request(Operation::NetworkSend, Destination::PublicExternal),
        );
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::HardDeny);
        assert_eq!(
            decision.evidence.rule_id.unwrap().as_str(),
            "deny-model-egress"
        );
    }

    #[test]
    fn configured_diode_allows_read_but_denies_protected_export() {
        let database = Resource::new(
            ResourceKind::Database,
            ResourceId::new("customer.db").unwrap(),
        );
        let read_request = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            database.clone(),
            Destination::Model,
            crate::domain::CapabilityName::new("database.read").unwrap(),
        );
        let read_policy = RuleMatcher::any()
            .principal(Principal::Model)
            .operation(Operation::Read)
            .capability(crate::domain::CapabilityName::new("database.read").unwrap())
            .resource(ResourceScope::exact(&database))
            .destination(Destination::Model)
            .classification(Classification::Secret);
        let read_flow = FlowMatcher::any()
            .source(FlowSource::Resource(database))
            .destination(Destination::Model)
            .operation(FlowOperation::Read)
            .classification(Classification::Secret);
        let policy = Policy::new(
            PolicyId::new("diode-composition").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-db-read").unwrap(),
                read_policy,
            )],
        )
        .unwrap();
        let diode = Diode::new(vec![
            FlowRule::allow(RuleId::new("allow-db-to-model").unwrap(), read_flow),
            FlowRule::allow(RuleId::new("allow-any-flow").unwrap(), FlowMatcher::any()),
        ])
        .unwrap();
        let kernel = Krosna::with_diode(policy, diode);
        let context = fixture_context(Classification::Secret);
        assert!(kernel.authorize(&context, &read_request).is_ok());

        let export_request = fixture_request(Operation::NetworkSend, Destination::PublicExternal);
        let decision = kernel.evaluate(&context, &export_request);
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
    fn configured_zaslon_cannot_be_overridden_by_policy_allow() {
        let policy = Policy::new(
            PolicyId::new("with-zaslon").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-exec").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap();
        let zaslon = Zaslon::new(
            vec![ActionRule::deny(
                RuleId::new("zaslon-exec").unwrap(),
                RuleMatcher::any().operation(Operation::Execute),
            )],
            Vec::new(),
        )
        .unwrap();
        let decision = Krosna::with_zaslon(policy, zaslon).evaluate(
            &fixture_context(Classification::Public),
            &fixture_request(Operation::Execute, Destination::Model),
        );
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::HardDeny);
        assert_eq!(
            decision.evidence.rule_id.as_ref().unwrap().as_str(),
            "zaslon-exec"
        );
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
    fn untrusted_context_cannot_spoof_trusted_principal() {
        let policy = Policy::new(
            PolicyId::new("principal-spoofing").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-system-read").unwrap(),
                RuleMatcher::any()
                    .principal(Principal::System)
                    .operation(Operation::Read),
            )],
        )
        .unwrap();
        let context = SecurityContext::untrusted_with_metadata(
            Principal::System,
            Provenance::from_source(ProvenanceSource::Web(
                Identity::new("attacker.example").unwrap(),
            ))
            .unwrap(),
            Classification::Public,
        );
        let request = ActionRequest::new(
            Principal::System,
            Operation::Read,
            fixture_resource(),
            Destination::Model,
            crate::domain::CapabilityName::new("file.read").unwrap(),
        );
        let decision = Krosna::new(policy).evaluate(&context, &request);
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.evidence.reason, SledReason::InvalidRequest);
    }

    #[test]
    fn public_untrusted_boundary_cannot_mint_system_provenance() {
        assert!(Provenance::from_source(ProvenanceSource::System).is_err());
        let forged = serde_json::json!({
            "source": "System",
            "lineage": ["System"]
        });
        assert!(serde_json::from_value::<Provenance>(forged).is_err());
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

    #[test]
    fn policy_rule_budget_is_enforced_at_constructor_and_wire_boundary() {
        let rules = (0..=MAX_POLICY_RULES)
            .map(|index| {
                PolicyRule::allow(
                    RuleId::new(format!("rule-{index}")).unwrap(),
                    RuleMatcher::any(),
                )
            })
            .collect();
        assert_eq!(
            Policy::new(PolicyId::new("bounded-policy").unwrap(), rules).unwrap_err(),
            PolicyError::TooManyRules
        );

        let wire = serde_json::json!({
            "id": "bounded-policy",
            "rules": (0..=MAX_POLICY_RULES)
                .map(|index| serde_json::json!({
                    "id": format!("rule-{index}"),
                    "matcher": {},
                    "kind": "Allow"
                }))
                .collect::<Vec<_>>()
        });
        assert!(serde_json::from_value::<Policy>(wire).is_err());
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
