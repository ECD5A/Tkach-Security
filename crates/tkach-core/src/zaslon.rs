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
use std::fmt::{Debug, Formatter};
use thiserror::Error;

const MAX_CONTENT_BYTES: usize = 16 * 1024;
const MAX_RULES: usize = 1_024;
const MAX_PATTERN_BYTES: usize = 256 * 1024;

/// Errors from formal Zaslon rule or content handling.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ZaslonError {
    /// A rule or content could not be represented in the canonical alphabet.
    #[error("invalid canonical content")]
    InvalidCanonicalContent,
    /// A hard-deny rule identity was repeated.
    #[error("duplicate Zaslon rule id")]
    DuplicateRuleId,
    /// The hard-deny plane would exceed its deterministic rule budget.
    #[error("Zaslon rule capacity exceeded")]
    TooManyRules,
    /// The aggregate pattern memory budget would be exceeded.
    #[error("Zaslon pattern byte budget exceeded")]
    PatternCapacityExceeded,
}

/// Strict canonical form used by formal content rules.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalText(String);

impl Debug for CanonicalText {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CanonicalText(REDACTED)")
    }
}

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
#[derive(Clone, PartialEq, Eq)]
pub struct ContentRule {
    id: RuleId,
    direction: FlowDirection,
    pattern: CanonicalText,
}

impl Debug for ContentRule {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContentRule")
            .field("id", &self.id)
            .field("direction", &self.direction)
            .field("pattern", &"REDACTED")
            .finish()
    }
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
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Zaslon {
    action_rules: Vec<ActionRule>,
    content_rules: Vec<ContentRule>,
}

impl Debug for Zaslon {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Zaslon")
            .field("action_rule_count", &self.action_rules.len())
            .field("content_rule_count", &self.content_rules.len())
            .finish()
    }
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
        if action_rules.len().saturating_add(content_rules.len()) > MAX_RULES {
            return Err(ZaslonError::TooManyRules);
        }
        let pattern_bytes = content_rules.iter().fold(0usize, |total, rule| {
            total.saturating_add(rule.pattern.as_str().len())
        });
        if pattern_bytes > MAX_PATTERN_BYTES {
            return Err(ZaslonError::PatternCapacityExceeded);
        }
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
            finished: false,
            has_content: false,
            pending_space: false,
            input_bytes: 0,
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
        let verdict = match stream.push_chunk(raw) {
            ContentVerdict::NeedMoreData | ContentVerdict::Clear => stream.finish(),
            blocked @ ContentVerdict::Blocked { .. } => blocked,
        };
        match verdict {
            ContentVerdict::Clear => ContentDecision::Clear,
            ContentVerdict::NeedMoreData => ContentDecision::Blocked {
                decision: Decision::new(
                    DecisionKind::Deny,
                    content_evidence(context, direction, None, SledReason::InvalidRequest),
                ),
            },
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
    /// No sequence has matched, but the stream is not final or releasable.
    NeedMoreData,
    /// The explicitly finished stream contains no configured sequence.
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
#[derive(Clone, PartialEq, Eq)]
pub struct ZaslonStream {
    direction: FlowDirection,
    matchers: Vec<ContentMatcher>,
    blocked: Option<ContentVerdict>,
    finished: bool,
    has_content: bool,
    pending_space: bool,
    input_bytes: usize,
}

impl Debug for ZaslonStream {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ZaslonStream")
            .field("direction", &self.direction)
            .field("matcher_count", &self.matchers.len())
            .field("blocked", &self.blocked)
            .finish_non_exhaustive()
    }
}

impl ZaslonStream {
    /// Scan one chunk. A malformed chunk blocks the stream instead of passing.
    #[must_use]
    pub fn push_chunk(&mut self, chunk: &str) -> ContentVerdict {
        if let Some(verdict) = &self.blocked {
            return verdict.clone();
        }
        if self.finished {
            let verdict = ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            };
            self.blocked = Some(verdict.clone());
            return verdict;
        }
        if chunk.is_empty() {
            return ContentVerdict::NeedMoreData;
        }
        if chunk.len() > MAX_CONTENT_BYTES
            || self.input_bytes.saturating_add(chunk.len()) > MAX_CONTENT_BYTES
        {
            let verdict = ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            };
            self.blocked = Some(verdict.clone());
            return verdict;
        }
        self.input_bytes += chunk.len();
        let mut canonical = String::with_capacity(chunk.len());
        for character in chunk.chars() {
            if !character.is_ascii() || character.is_control() || character == '\\' {
                let verdict = ContentVerdict::Blocked {
                    rule_id: None,
                    reason: SledReason::InvalidRequest,
                };
                self.blocked = Some(verdict.clone());
                return verdict;
            }
            if character == ' ' {
                if self.has_content {
                    self.pending_space = true;
                }
                continue;
            }
            if self.pending_space && self.has_content {
                canonical.push(' ');
            }
            canonical.push(character.to_ascii_lowercase());
            self.has_content = true;
            self.pending_space = false;
        }
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
        ContentVerdict::NeedMoreData
    }

    /// Finish a stream and reject empty or whitespace-only content.
    #[must_use]
    pub fn finish(&mut self) -> ContentVerdict {
        if let Some(verdict) = &self.blocked {
            return verdict.clone();
        }
        if !self.has_content {
            let verdict = ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            };
            self.blocked = Some(verdict.clone());
            return verdict;
        }
        self.finished = true;
        ContentVerdict::Clear
    }

    /// Return the boundary direction represented by this stream.
    #[must_use]
    pub const fn direction(&self) -> FlowDirection {
        self.direction
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ContentMatcher {
    id: RuleId,
    pattern: String,
    prefix: Vec<usize>,
    matched: usize,
}

impl Debug for ContentMatcher {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContentMatcher")
            .field("id", &self.id)
            .field("pattern", &"REDACTED")
            .field("matched_prefix_length", &self.matched)
            .finish_non_exhaustive()
    }
}

impl ContentMatcher {
    fn from_rule(rule: &ContentRule) -> Self {
        Self {
            id: rule.id.clone(),
            pattern: rule.pattern.as_str().to_owned(),
            prefix: prefix_table(rule.pattern.as_str().as_bytes()),
            matched: 0,
        }
    }

    fn push(&mut self, chunk: &str) -> bool {
        let pattern = self.pattern.as_bytes();
        if pattern.is_empty() {
            return false;
        }
        for byte in chunk.bytes() {
            while self.matched > 0 && pattern.get(self.matched).copied() != Some(byte) {
                self.matched = self
                    .prefix
                    .get(self.matched.saturating_sub(1))
                    .copied()
                    .unwrap_or(0);
            }
            if pattern.get(self.matched).copied() == Some(byte) {
                self.matched += 1;
                if self.matched == pattern.len() {
                    return true;
                }
            }
        }
        false
    }
}

fn prefix_table(pattern: &[u8]) -> Vec<usize> {
    let mut prefix = vec![0; pattern.len()];
    let mut matched = 0;
    for index in 1..pattern.len() {
        while matched > 0 && pattern.get(index) != pattern.get(matched) {
            matched = prefix.get(matched.saturating_sub(1)).copied().unwrap_or(0);
        }
        if pattern.get(index) == pattern.get(matched) {
            matched += 1;
        }
        if let Some(slot) = prefix.get_mut(index) {
            *slot = matched;
        }
    }
    prefix
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
        principal: context.principal().into(),
        operation: (&Operation::Execute).into(),
        capability: (&capability).into(),
        provenance: context.provenance().source().into(),
        classification: context.classification(),
        destination: (&destination).into(),
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
        principal: request.principal().into(),
        operation: request.operation().into(),
        capability: request.capability().into(),
        provenance: context.provenance().source().into(),
        classification: context.classification(),
        destination: request.destination().into(),
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
        SecurityContext::untrusted_with_metadata(
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
        let canonical = CanonicalText::new("  SECRET_  TOKEN ").unwrap();
        assert_eq!(CanonicalText::new(canonical.as_str()).unwrap(), canonical);
        assert!(CanonicalText::new("\tsecret").is_err());
        assert!(CanonicalText::new("zero\u{200b}width").is_err());
        assert!(CanonicalText::new("bidi\u{202e}value").is_err());
        assert!(CanonicalText::new("\\u0053ECRET").is_err());
        assert!(CanonicalText::new(" \t ").is_err());
        assert!(CanonicalText::new(&"a".repeat(MAX_CONTENT_BYTES + 1)).is_err());
    }

    #[test]
    fn debug_surfaces_do_not_echo_patterns_or_stream_tails() {
        let sensitive_marker = "top-secret-token";
        let rule = ContentRule::new(
            RuleId::new("debug-redaction").unwrap(),
            FlowDirection::Egress,
            &format!("forbidden {sensitive_marker}"),
        )
        .unwrap();
        let zaslon = Zaslon::new(Vec::new(), vec![rule.clone()]).unwrap();
        let mut stream = zaslon.stream(FlowDirection::Egress);
        assert_eq!(
            stream.push_chunk(&format!("prefix {sensitive_marker}")),
            ContentVerdict::NeedMoreData
        );
        assert!(!format!("{zaslon:?}").contains(sensitive_marker));
        assert!(!format!("{stream:?}").contains(sensitive_marker));
        assert!(
            !format!("{:?}", CanonicalText::new(sensitive_marker).unwrap())
                .contains(sensitive_marker)
        );
        let matcher = ContentMatcher::from_rule(&rule);
        let matcher_debug = format!("{matcher:?}");
        assert!(matcher_debug.contains("ContentMatcher"));
        assert!(matcher_debug.contains("REDACTED"));
        assert!(!matcher_debug.contains(sensitive_marker));
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
        assert_eq!(stream.push_chunk("SECRET_"), ContentVerdict::NeedMoreData);
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
    fn canonical_space_cannot_be_removed_at_chunk_boundary() {
        let rule = ContentRule::new(
            RuleId::new("space-sequence").unwrap(),
            FlowDirection::Ingress,
            "DROP SECRET",
        )
        .unwrap();
        let zaslon = Zaslon::new(Vec::new(), vec![rule]).unwrap();
        let mut stream = zaslon.stream(FlowDirection::Ingress);
        assert_eq!(stream.push_chunk("DROP "), ContentVerdict::NeedMoreData);
        assert_eq!(
            stream.push_chunk("SECRET"),
            ContentVerdict::Blocked {
                rule_id: Some(RuleId::new("space-sequence").unwrap()),
                reason: SledReason::HardDeny,
            }
        );
    }

    #[test]
    fn leading_space_at_chunk_boundary_has_whole_input_semantics() {
        let rule = ContentRule::new(
            RuleId::new("leading-space-sequence").unwrap(),
            FlowDirection::Ingress,
            "DROP SECRET",
        )
        .unwrap();
        let zaslon = Zaslon::new(Vec::new(), vec![rule]).unwrap();
        let mut stream = zaslon.stream(FlowDirection::Ingress);
        assert_eq!(stream.push_chunk("DROP"), ContentVerdict::NeedMoreData);
        assert_eq!(
            stream.push_chunk(" SECRET"),
            ContentVerdict::Blocked {
                rule_id: Some(RuleId::new("leading-space-sequence").unwrap()),
                reason: SledReason::HardDeny,
            }
        );
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
    fn stream_finish_rejects_empty_whitespace_and_oversized_input() {
        let zaslon = Zaslon::empty();
        let mut empty = zaslon.stream(FlowDirection::Ingress);
        assert_eq!(
            empty.finish(),
            ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            }
        );
        assert_eq!(
            empty.finish(),
            ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            }
        );

        let mut whitespace = zaslon.stream(FlowDirection::Ingress);
        assert_eq!(whitespace.push_chunk("   "), ContentVerdict::NeedMoreData);
        assert_eq!(
            whitespace.finish(),
            ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            }
        );
        assert!(matches!(
            zaslon.inspect_content(FlowDirection::Ingress, &context(), "   "),
            ContentDecision::Blocked { .. }
        ));

        let mut oversized = zaslon.stream(FlowDirection::Ingress);
        assert_eq!(
            oversized.push_chunk(&"a".repeat(MAX_CONTENT_BYTES + 1)),
            ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            }
        );
    }

    #[test]
    fn stream_cumulative_input_budget_cannot_be_reset_by_chunking() {
        let zaslon = Zaslon::empty();
        let mut stream = zaslon.stream(FlowDirection::Ingress);
        assert_eq!(
            stream.push_chunk(&"a".repeat(MAX_CONTENT_BYTES)),
            ContentVerdict::NeedMoreData
        );
        assert_eq!(
            stream.push_chunk("b"),
            ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest,
            }
        );
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

    #[test]
    fn rule_budget_is_enforced_before_rule_indexing() {
        let rules = (0..=MAX_RULES)
            .map(|index| {
                ActionRule::deny(
                    RuleId::new(format!("action-{index}")).unwrap(),
                    RuleMatcher::any(),
                )
            })
            .collect();
        assert_eq!(
            Zaslon::new(rules, Vec::new()).unwrap_err(),
            ZaslonError::TooManyRules
        );
    }

    #[test]
    fn aggregate_pattern_budget_is_enforced() {
        let pattern = "a".repeat(MAX_CONTENT_BYTES);
        let make_rules = |count| {
            (0..count)
                .map(|index| {
                    ContentRule::new(
                        RuleId::new(format!("pattern-{index}")).unwrap(),
                        FlowDirection::Ingress,
                        &pattern,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        assert!(Zaslon::new(Vec::new(), make_rules(16)).is_ok());
        let rules = make_rules(17);
        assert_eq!(
            Zaslon::new(Vec::new(), rules).unwrap_err(),
            ZaslonError::PatternCapacityExceeded
        );
    }

    #[test]
    fn incremental_matcher_preserves_prefix_and_chunk_semantics() {
        assert_eq!(prefix_table(b"abab"), vec![0, 0, 1, 2]);
        assert_eq!(prefix_table(b"aab"), vec![0, 1, 0]);
        let rule = ContentRule::new(
            RuleId::new("overlap").unwrap(),
            FlowDirection::Ingress,
            "abab",
        )
        .unwrap();
        let mut matcher = ContentMatcher::from_rule(&rule);
        assert!(!matcher.push("aba"));
        assert!(!matcher.push("ab"));
        let mut matcher = ContentMatcher::from_rule(&rule);
        assert!(!matcher.push("ab"));
        assert!(matcher.push("ab"));
    }
}
