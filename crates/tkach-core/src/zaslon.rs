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

//! Zaslon, the deterministic hard-deny boundary.
//!
//! Zaslon intentionally recognizes only formal rules represented by the
//! caller. Its canonicalizer rejects ambiguous encodings instead of claiming
//! to understand every Unicode or semantic paraphrase.

use crate::domain::{
    ActionRequest, CapabilityName, Decision, DecisionKind, Destination, FlowDirection, Operation,
    RuleId, SecurityContext, SledEvidence, SledReason,
};
use crate::krosna::RuleMatcher;
use thiserror::Error;

const MAX_CONTENT_BYTES: usize = 16 * 1024;

/// Errors from formal Zaslon rule or content handling.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ZaslonError {
    /// A rule or content could not be represented in the canonical alphabet.
    #[error("invalid canonical content")]
    InvalidCanonicalContent,
    /// A hard-deny rule identity was repeated.
    #[error("duplicate Zaslon rule id")]
    DuplicateRuleId,
}

/// Strict canonical form used by formal content rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalText(String);

impl CanonicalText {
    /// Canonicalize formal text using ASCII lowercase and ASCII-space folding.
    ///
    /// Non-ASCII characters, controls, and backslash escape syntax are rejected
    /// because silently decoding them would create representation-dependent
    /// security semantics. Empty canonical content is also rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ZaslonError::InvalidCanonicalContent`] for an ambiguous,
    /// oversized, empty, or otherwise unsupported representation.
    pub fn new(raw: &str) -> Result<Self, ZaslonError> {
        if raw.is_empty() || raw.len() > MAX_CONTENT_BYTES {
            return Err(ZaslonError::InvalidCanonicalContent);
        }
        let mut canonical = String::with_capacity(raw.len());
        let mut previous_space = false;
        for character in raw.chars() {
            if !character.is_ascii() || character.is_control() || character == '\\' {
                return Err(ZaslonError::InvalidCanonicalContent);
            }
            if character == ' ' {
                if !canonical.is_empty() {
                    previous_space = true;
                }
                continue;
            }
            if previous_space {
                canonical.push(' ');
                previous_space = false;
            }
            canonical.push(character.to_ascii_lowercase());
        }
        if canonical.is_empty() {
            return Err(ZaslonError::InvalidCanonicalContent);
        }
        Ok(Self(canonical))
    }

    /// Return the canonical text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One formal content sequence that Zaslon must block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentRule {
    id: RuleId,
    direction: FlowDirection,
    pattern: CanonicalText,
}

impl ContentRule {
    /// Construct a content rule after canonicalizing its pattern.
    ///
    /// # Errors
    ///
    /// Returns [`ZaslonError::InvalidCanonicalContent`] when the pattern is
    /// ambiguous or unsupported.
    pub fn new(id: RuleId, direction: FlowDirection, pattern: &str) -> Result<Self, ZaslonError> {
        Ok(Self {
            id,
            direction,
            pattern: CanonicalText::new(pattern)?,
        })
    }

    /// Return the rule identity.
    #[must_use]
    pub const fn id(&self) -> &RuleId {
        &self.id
    }
}

/// A formal action rule that is always a denial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRule {
    id: RuleId,
    matcher: RuleMatcher,
}

impl ActionRule {
    /// Construct a hard action-deny rule.
    #[must_use]
    pub const fn deny(id: RuleId, matcher: RuleMatcher) -> Self {
        Self { id, matcher }
    }
}

/// A deterministic hard-deny plane for action and formal content boundaries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Zaslon {
    action_rules: Vec<ActionRule>,
    content_rules: Vec<ContentRule>,
}

impl Zaslon {
    /// Validate and construct a hard-deny plane.
    ///
    /// Rule identities are unique across action and content rules. Rules are
    /// sorted by identity so equal inputs produce equal inspection behavior
    /// regardless of configuration order.
    ///
    /// # Errors
    ///
    /// Returns [`ZaslonError::DuplicateRuleId`] for repeated identities.
    pub fn new(
        mut action_rules: Vec<ActionRule>,
        mut content_rules: Vec<ContentRule>,
    ) -> Result<Self, ZaslonError> {
        let mut ids = std::collections::HashSet::new();
        for rule in &action_rules {
            if !ids.insert(rule.id.clone()) {
                return Err(ZaslonError::DuplicateRuleId);
            }
        }
        for rule in &content_rules {
            if !ids.insert(rule.id.clone()) {
                return Err(ZaslonError::DuplicateRuleId);
            }
        }
        action_rules.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        content_rules.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        Ok(Self {
            action_rules,
            content_rules,
        })
    }

    /// Return an empty hard-deny plane.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Inspect an action and return a denial when a hard action rule matches.
    #[must_use]
    pub fn action_decision(
        &self,
        context: &SecurityContext,
        request: &ActionRequest,
    ) -> Option<Decision> {
        self.action_rules
            .iter()
            .find(|rule| rule.matcher.matches(context, request))
            .map(|rule| {
                Decision::new(
                    DecisionKind::Deny,
                    action_evidence(
                        context,
                        request,
                        Some(rule.id.clone()),
                        if request.operation() == &Operation::NetworkSend {
                            Some(FlowDirection::Egress)
                        } else {
                            None
                        },
                        SledReason::HardDeny,
                    ),
                )
            })
    }

    /// Start a stateful formal content scan for one direction.
    #[must_use]
    pub fn stream(&self, direction: FlowDirection) -> ZaslonStream {
        let matchers = self
            .content_rules
            .iter()
            .filter(|rule| rule.direction == direction)
            .map(ContentMatcher::from_rule)
            .collect();
        ZaslonStream {
            direction,
            matchers,
            blocked: None,
        }
    }

    /// Inspect one complete content value and return a typed content result.
    #[must_use]
    pub fn inspect_content(
        &self,
        direction: FlowDirection,
        context: &SecurityContext,
        raw: &str,
    ) -> ContentDecision {
        let mut stream = self.stream(direction);
        match stream.push_chunk(raw) {
            ContentVerdict::Clear => ContentDecision::Clear,
            ContentVerdict::Blocked { rule_id, reason } => ContentDecision::Blocked {
                decision: Decision::new(
                    DecisionKind::Deny,
                    content_evidence(context, direction, rule_id, reason),
                ),
            },
        }
    }
}

/// Result of a complete Zaslon content inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentDecision {
    /// No configured formal sequence matched.
    Clear,
    /// Content must be blocked; the decision contains safe Sled evidence.
    Blocked {
        /// Payload-free denial decision.
        decision: Decision,
    },
}

/// Result of incrementally scanning content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentVerdict {
    /// No sequence has matched yet.
    Clear,
    /// The stream is blocked permanently for this scan.
    Blocked {
        /// Matching rule, if the block was caused by malformed input.
        rule_id: Option<RuleId>,
        /// Safe reason for the block.
        reason: SledReason,
    },
}

/// Stateful streaming matcher that preserves cross-chunk boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZaslonStream {
    direction: FlowDirection,
    matchers: Vec<ContentMatcher>,
    blocked: Option<ContentVerdict>,
}

impl ZaslonStream {
    /// Scan one chunk. A malformed chunk blocks the stream instead of passing.
    #[must_use]
    pub fn push_chunk(&mut self, chunk: &str) -> ContentVerdict {
        if let Some(verdict) = &self.blocked {
            return verdict.clone();
        }
        if chunk.is_empty() {
            return ContentVerdict::Clear;
        }
        let Ok(canonical) = CanonicalText::new(chunk) else {
            let verdict = ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            };
            self.blocked = Some(verdict.clone());
            return verdict;
        };
        for matcher in &mut self.matchers {
            if matcher.push(&canonical) {
                let verdict = ContentVerdict::Blocked {
                    rule_id: Some(matcher.id.clone()),
                    reason: SledReason::HardDeny,
                };
                self.blocked = Some(verdict.clone());
                return verdict;
            }
        }
        ContentVerdict::Clear
    }

    /// Return the boundary direction represented by this stream.
    #[must_use]
    pub const fn direction(&self) -> FlowDirection {
        self.direction
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ContentMatcher {
    id: RuleId,
    pattern: String,
    tail: String,
}

impl ContentMatcher {
    fn from_rule(rule: &ContentRule) -> Self {
        Self {
            id: rule.id.clone(),
            pattern: rule.pattern.as_str().to_owned(),
            tail: String::new(),
        }
    }

    fn push(&mut self, chunk: &CanonicalText) -> bool {
        let mut candidate = self.tail.clone();
        candidate.push_str(chunk.as_str());
        if candidate.contains(&self.pattern) {
            return true;
        }

        // CanonicalText is ASCII-only, so byte slicing is on a character
        // boundary. Keep enough suffix to detect a sequence split next time.
        let keep = self.pattern.len().saturating_sub(1);
        let start = candidate.len().saturating_sub(keep);
        candidate[start..].clone_into(&mut self.tail);
        false
    }
}

fn content_evidence(
    context: &SecurityContext,
    direction: FlowDirection,
    rule_id: Option<RuleId>,
    reason: SledReason,
) -> SledEvidence {
    let destination = match direction {
        FlowDirection::Ingress => Destination::Model,
        FlowDirection::Egress => Destination::PublicExternal,
    };
    let capability = CapabilityName::new("zaslon.content").expect("static capability is valid");
    SledEvidence {
        rule_id,
        principal: context.principal().clone(),
        operation: Operation::Execute,
        capability,
        provenance: context.provenance().source().clone(),
        classification: context.classification(),
        destination,
        direction: Some(direction),
        reason,
    }
}

fn action_evidence(
    context: &SecurityContext,
    request: &ActionRequest,
    rule_id: Option<RuleId>,
    direction: Option<FlowDirection>,
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
        direction,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Classification, Identity, Principal, Provenance, ProvenanceSource, Resource, ResourceId,
        ResourceKind,
    };

    fn context() -> SecurityContext {
        SecurityContext::untrusted_data(
            Principal::Model,
            Provenance::from_source(ProvenanceSource::Web(
                Identity::new("example.test").unwrap(),
            ))
            .unwrap(),
            Classification::Public,
        )
    }

    fn request(operation: Operation) -> ActionRequest {
        ActionRequest::new(
            Principal::Model,
            operation,
            Resource::new(ResourceKind::File, ResourceId::new("input.txt").unwrap()),
            Destination::Model,
            CapabilityName::new("file.read").unwrap(),
        )
    }

    #[test]
    fn canonicalizer_is_strict_and_deterministic() {
        assert_eq!(
            CanonicalText::new("  SECRET_  TOKEN ").unwrap().as_str(),
            "secret_ token"
        );
        assert!(CanonicalText::new("\tsecret").is_err());
        assert!(CanonicalText::new("zero\u{200b}width").is_err());
        assert!(CanonicalText::new("bidi\u{202e}value").is_err());
        assert!(CanonicalText::new("\\u0053ECRET").is_err());
        assert!(CanonicalText::new(" \t ").is_err());
        assert!(CanonicalText::new(&"a".repeat(MAX_CONTENT_BYTES + 1)).is_err());
    }

    #[test]
    fn direction_is_explicit() {
        let rule = ContentRule::new(
            RuleId::new("egress-secret").unwrap(),
            FlowDirection::Egress,
            "secret_token",
        )
        .unwrap();
        let zaslon = Zaslon::new(Vec::new(), vec![rule]).unwrap();
        assert!(matches!(
            zaslon.inspect_content(FlowDirection::Ingress, &context(), "secret_token"),
            ContentDecision::Clear
        ));
        assert!(matches!(
            zaslon.inspect_content(FlowDirection::Egress, &context(), "secret_token"),
            ContentDecision::Blocked { .. }
        ));
    }

    #[test]
    fn sequence_cannot_cross_chunk_boundary() {
        let rule = ContentRule::new(
            RuleId::new("secret-sequence").unwrap(),
            FlowDirection::Egress,
            "SECRET_TOKEN",
        )
        .unwrap();
        let zaslon = Zaslon::new(Vec::new(), vec![rule]).unwrap();
        let mut stream = zaslon.stream(FlowDirection::Egress);
        assert_eq!(stream.push_chunk("SECRET_"), ContentVerdict::Clear);
        let verdict = stream.push_chunk("TOKEN");
        assert_eq!(
            verdict,
            ContentVerdict::Blocked {
                rule_id: Some(RuleId::new("secret-sequence").unwrap()),
                reason: SledReason::HardDeny,
            }
        );
        assert_eq!(stream.push_chunk("anything"), verdict);
    }

    #[test]
    fn malformed_stream_input_fails_closed_without_payload() {
        let zaslon = Zaslon::new(Vec::new(), Vec::new()).unwrap();
        let mut stream = zaslon.stream(FlowDirection::Egress);
        assert_eq!(
            stream.push_chunk("unsafe\u{202e}text"),
            ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            }
        );
        let decision = zaslon.inspect_content(FlowDirection::Egress, &context(), "secret\u{200b}");
        let ContentDecision::Blocked { decision } = decision else {
            panic!("malformed content must block");
        };
        let serialized = serde_json::to_string(&decision).unwrap();
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn hard_action_rule_produces_sled_deny() {
        let rule = ActionRule::deny(
            RuleId::new("block-exec").unwrap(),
            RuleMatcher::any()
                .principal(Principal::Model)
                .operation(Operation::Execute),
        );
        let zaslon = Zaslon::new(vec![rule], Vec::new()).unwrap();
        let decision = zaslon.action_decision(&context(), &request(Operation::Execute));
        assert_eq!(decision.as_ref().unwrap().kind, DecisionKind::Deny);
        assert_eq!(
            decision.as_ref().unwrap().evidence.reason,
            SledReason::HardDeny
        );
        assert_eq!(
            decision
                .as_ref()
                .unwrap()
                .evidence
                .rule_id
                .as_ref()
                .unwrap()
                .as_str(),
            "block-exec"
        );
    }

    #[test]
    fn duplicate_rule_identity_is_rejected() {
        let id = RuleId::new("same").unwrap();
        let action = ActionRule::deny(id.clone(), RuleMatcher::any());
        let content = ContentRule::new(id, FlowDirection::Ingress, "blocked").unwrap();
        assert_eq!(
            Zaslon::new(vec![action], vec![content]).unwrap_err(),
            ZaslonError::DuplicateRuleId
        );
    }
}
