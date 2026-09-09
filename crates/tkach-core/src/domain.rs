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

//! Strongly typed security facts used by the Tkach kernel.
//!
//! The types in this module deliberately keep authority, trust, provenance,
//! classification, capability, identity, and destination separate. A raw
//! [`ActionRequest`] is data describing a proposed operation; it is never an
//! execution permit.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;

const MAX_ID_BYTES: usize = 128;

/// Errors returned when structured security state cannot be represented safely.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreError {
    /// An identifier was empty, too long, or contained an unsafe character.
    #[error("invalid {kind} identifier")]
    InvalidIdentifier {
        /// The non-sensitive type name that failed validation.
        kind: &'static str,
    },
    /// A security-context combination violates a hard domain invariant.
    #[error("invalid security context: {reason}")]
    InvalidContext {
        /// The violated invariant, intentionally limited to a static reason.
        reason: &'static str,
    },
    /// A resource scope cannot be used for the requested resource.
    #[error("invalid resource scope")]
    InvalidResourceScope,
    /// A serialized value cannot be decoded into a valid domain type.
    #[error("invalid serialized {kind}")]
    InvalidSerialization {
        /// The non-sensitive type name that failed decoding.
        kind: &'static str,
    },
}

fn validate_identifier(value: String, kind: &'static str) -> Result<String, CoreError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
        && !value
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."));
    valid
        .then_some(value)
        .ok_or(CoreError::InvalidIdentifier { kind })
}

macro_rules! validated_identifier {
    ($name:ident, $kind:literal) => {
        #[doc = concat!("Validated ", $kind, " identifier.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!(
                "Construct a validated ",
                $kind,
                " identifier.\n\n# Errors\n\nReturns [`CoreError::InvalidIdentifier`] when the value is empty, too long, or contains a character outside the identifier alphabet."
            )]
            pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
                Ok(Self(validate_identifier(value.into(), $kind)?))
            }

            /// Return the validated identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = CoreError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

validated_identifier!(Identity, "identity");
validated_identifier!(ResourceId, "resource");
validated_identifier!(CapabilityName, "capability");
validated_identifier!(PolicyId, "policy");
validated_identifier!(RuleId, "rule");

/// The actor making a request. Model identity is intentionally not authority.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Principal {
    /// A probabilistic model or agent, assumed potentially compromised.
    Model,
    /// The user identity represented by the validated identifier.
    User(Identity),
    /// Trusted system control code.
    System,
    /// A named trusted service boundary.
    Service(Identity),
}

/// The authority carried by a value, separate from who produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Authority {
    /// No security authority.
    None,
    /// Data authority only; it cannot mutate policy or mint capabilities.
    Data,
    /// Trusted control authority, available only through trusted construction.
    TrustedControl,
}

/// Whether the source is trusted for security control decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Trust {
    /// The source is attacker-influenced or otherwise untrusted.
    Untrusted,
    /// The source is trusted for the specific control operation represented.
    Trusted,
}

/// The lane through which a value travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Lane {
    /// Natural-language or other untrusted content lane.
    Data,
    /// Structured trusted control lane.
    Control,
}

/// Direction of a security-relevant information or content boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowDirection {
    /// Content entering the protected model/system boundary.
    Ingress,
    /// Content or information leaving the protected model/system boundary.
    Egress,
}

/// Formal origins used by Niti.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProvenanceSource {
    /// User-provided content.
    User,
    /// Trusted system content.
    System,
    /// A named file.
    File(ResourceId),
    /// A named database or record class.
    Database(ResourceId),
    /// Web content.
    Web(Identity),
    /// Retrieval-augmented content.
    Rag(Identity),
    /// API content.
    Api(Identity),
    /// MCP content, represented without depending on MCP types.
    Mcp(Identity),
    /// Tool output.
    Tool(Identity),
    /// Model-generated content.
    Model,
    /// A controlled derivation from prior lineage.
    Derived,
    /// An origin that is not recognized by the current policy.
    Unknown,
}

/// A provenance thread. Lineage is explicit and cannot be absent accidentally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Provenance {
    source: ProvenanceSource,
    lineage: Vec<ProvenanceSource>,
}

impl Provenance {
    /// Create a root provenance thread.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidContext`] when called with the derived
    /// marker, which is valid only when parent lineage is supplied.
    pub fn from_source(source: ProvenanceSource) -> Result<Self, CoreError> {
        if source == ProvenanceSource::Derived {
            return Err(CoreError::InvalidContext {
                reason: "derived provenance requires parent lineage",
            });
        }
        Ok(Self {
            lineage: vec![source.clone()],
            source,
        })
    }

    /// Create derived provenance while retaining every known parent source.
    #[must_use]
    pub fn derived_from(parents: &[Self]) -> Self {
        let mut lineage = Vec::new();
        for parent in parents {
            for source in &parent.lineage {
                if !lineage.contains(source) {
                    lineage.push(source.clone());
                }
            }
        }
        if lineage.is_empty() {
            lineage.push(ProvenanceSource::Unknown);
        }
        lineage.push(ProvenanceSource::Derived);
        Self {
            source: ProvenanceSource::Derived,
            lineage,
        }
    }

    /// The immediate source label.
    #[must_use]
    pub const fn source(&self) -> &ProvenanceSource {
        &self.source
    }

    /// The retained lineage, in deterministic insertion order.
    #[must_use]
    pub fn lineage(&self) -> &[ProvenanceSource] {
        &self.lineage
    }
}

#[derive(Deserialize)]
struct ProvenanceWire {
    source: ProvenanceSource,
    lineage: Vec<ProvenanceSource>,
}

impl<'de> Deserialize<'de> for Provenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ProvenanceWire::deserialize(deserializer)?;
        if wire.lineage.is_empty() {
            return Err(serde::de::Error::custom(CoreError::InvalidSerialization {
                kind: "provenance",
            }));
        }
        let valid = match wire.source {
            ProvenanceSource::Derived => {
                wire.lineage.len() > 1 && wire.lineage.last() == Some(&ProvenanceSource::Derived)
            }
            ref source => wire.lineage.first() == Some(source),
        };
        if !valid {
            return Err(serde::de::Error::custom(CoreError::InvalidSerialization {
                kind: "provenance",
            }));
        }
        Ok(Self {
            source: wire.source,
            lineage: wire.lineage,
        })
    }
}

/// Conservative security classification. Higher rank is more restrictive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Classification {
    /// Safe for public release under the current model.
    Public,
    /// Non-public but not treated as a secret.
    Internal,
    /// Protected business information.
    Confidential,
    /// More strongly protected information.
    Sensitive,
    /// Highest known protected classification.
    Secret,
    /// Unknown classification, handled conservatively.
    Unknown,
}

impl Classification {
    /// Return the conservative ordering rank.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Public => 0,
            Self::Internal => 1,
            Self::Confidential => 2,
            Self::Sensitive => 3,
            Self::Secret => 4,
            Self::Unknown => 5,
        }
    }

    /// Return the more restrictive of two classifications.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    /// Whether this class requires protected-flow treatment.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        !matches!(self, Self::Public | Self::Internal)
    }
}

/// Broad resource category used to prevent cross-resource capability confusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceKind {
    /// Filesystem or document resources.
    File,
    /// Database or record resources.
    Database,
    /// Broker-held secret resources.
    Secret,
    /// Network destinations.
    Network,
    /// External or internal tool resources.
    Tool,
    /// Policy/configuration resources.
    Policy,
    /// An unrecognized resource class.
    Unknown,
}

/// A typed resource reference.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Resource {
    kind: ResourceKind,
    id: ResourceId,
}

impl Resource {
    /// Construct a resource reference from an explicit kind and id.
    #[must_use]
    pub const fn new(kind: ResourceKind, id: ResourceId) -> Self {
        Self { kind, id }
    }

    /// Return the resource class.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    /// Return the validated resource id.
    #[must_use]
    pub const fn id(&self) -> &ResourceId {
        &self.id
    }
}

/// A deliberately narrow initial scope. Broader forms require explicit
/// canonicalization in the Propusk mandate and are not implicit here.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceScope {
    kind: ResourceKind,
    resource: ResourceId,
}

impl ResourceScope {
    /// Grant an exact scope for one typed resource.
    #[must_use]
    pub fn exact(resource: &Resource) -> Self {
        Self {
            kind: resource.kind,
            resource: resource.id.clone(),
        }
    }

    /// Return whether this exact scope contains the resource.
    #[must_use]
    pub fn contains(&self, resource: &Resource) -> bool {
        self.kind == resource.kind && self.resource == resource.id
    }
}

/// A destination is directional; it is not interchangeable with a resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Destination {
    /// The model context.
    Model,
    /// An approved internal destination.
    Internal(Identity),
    /// A public external destination.
    PublicExternal,
    /// The opaque-secret broker boundary.
    SecretBroker,
    /// Unknown destination, handled conservatively.
    Unknown(Identity),
}

impl Destination {
    /// Return whether the destination is public and external.
    #[must_use]
    pub const fn is_public_external(&self) -> bool {
        matches!(self, Self::PublicExternal)
    }
}

/// Operations that can be requested. Unknown operations are never privileged
/// by default.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    /// Read a resource.
    Read,
    /// Write a resource.
    Write,
    /// Execute a resource/tool operation.
    Execute,
    /// Send information to a destination.
    NetworkSend,
    /// Ask the secret broker to reveal raw material.
    RevealSecret,
    /// Request a trusted declassification transformation.
    Declassify,
    /// Request policy mutation.
    MutatePolicy,
    /// Operation not known to this core version.
    Unknown(CapabilityName),
}

/// A named capability with an exact initial resource scope.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Capability {
    name: CapabilityName,
    operation: Operation,
    scope: ResourceScope,
}

impl Capability {
    /// Construct a capability declaration.
    #[must_use]
    pub const fn new(name: CapabilityName, operation: Operation, scope: ResourceScope) -> Self {
        Self {
            name,
            operation,
            scope,
        }
    }

    /// Return the capability identity.
    #[must_use]
    pub const fn name(&self) -> &CapabilityName {
        &self.name
    }

    /// Return the operation covered by this capability.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Return the resource scope.
    #[must_use]
    pub const fn scope(&self) -> &ResourceScope {
        &self.scope
    }
}

/// A request proposed by a principal. This type carries no authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequest {
    principal: Principal,
    operation: Operation,
    resource: Resource,
    destination: Destination,
    capability: CapabilityName,
}

impl ActionRequest {
    /// Construct a request; policy evaluation is required before execution.
    #[must_use]
    pub const fn new(
        principal: Principal,
        operation: Operation,
        resource: Resource,
        destination: Destination,
        capability: CapabilityName,
    ) -> Self {
        Self {
            principal,
            operation,
            resource,
            destination,
            capability,
        }
    }

    /// Return the requesting principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Return the requested operation.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Return the requested resource.
    #[must_use]
    pub const fn resource(&self) -> &Resource {
        &self.resource
    }

    /// Return the destination of the proposed flow.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Return the requested capability name.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityName {
        &self.capability
    }
}

/// Validated context surrounding a request or data value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SecurityContext {
    principal: Principal,
    authority: Authority,
    trust: Trust,
    lane: Lane,
    provenance: Provenance,
    classification: Classification,
}

#[derive(Deserialize)]
struct SecurityContextWire {
    principal: Principal,
    authority: Authority,
    trust: Trust,
    lane: Lane,
    provenance: Provenance,
    classification: Classification,
}

impl<'de> Deserialize<'de> for SecurityContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SecurityContextWire::deserialize(deserializer)?;
        Self::try_new(
            wire.principal,
            wire.authority,
            wire.trust,
            wire.lane,
            wire.provenance,
            wire.classification,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl SecurityContext {
    /// Construct and validate a complete security context.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidContext`] when trusted control is paired
    /// with an untrusted source, data lane, or model principal.
    pub fn try_new(
        principal: Principal,
        authority: Authority,
        trust: Trust,
        lane: Lane,
        provenance: Provenance,
        classification: Classification,
    ) -> Result<Self, CoreError> {
        if lane == Lane::Control && authority != Authority::TrustedControl {
            return Err(CoreError::InvalidContext {
                reason: "control lane requires trusted control authority",
            });
        }
        if authority == Authority::TrustedControl
            && (trust != Trust::Trusted || lane != Lane::Control)
        {
            return Err(CoreError::InvalidContext {
                reason: "trusted control requires trusted control lane",
            });
        }
        if authority == Authority::TrustedControl && principal == Principal::Model {
            return Err(CoreError::InvalidContext {
                reason: "model cannot be trusted control authority",
            });
        }
        if lane == Lane::Data && authority == Authority::TrustedControl {
            return Err(CoreError::InvalidContext {
                reason: "data lane cannot carry trusted control",
            });
        }
        if trust == Trust::Untrusted && authority == Authority::TrustedControl {
            return Err(CoreError::InvalidContext {
                reason: "untrusted source cannot carry trusted control",
            });
        }
        Ok(Self {
            principal,
            authority,
            trust,
            lane,
            provenance,
            classification,
        })
    }

    /// Construct the canonical untrusted data context used by Gnezdo.
    #[must_use]
    pub fn untrusted_data(
        principal: Principal,
        provenance: Provenance,
        classification: Classification,
    ) -> Self {
        Self {
            principal,
            authority: Authority::None,
            trust: Trust::Untrusted,
            lane: Lane::Data,
            provenance,
            classification,
        }
    }

    /// Return the principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Return the authority class.
    #[must_use]
    pub const fn authority(&self) -> Authority {
        self.authority
    }

    /// Return the trust class.
    #[must_use]
    pub const fn trust(&self) -> Trust {
        self.trust
    }

    /// Return the lane.
    #[must_use]
    pub const fn lane(&self) -> Lane {
        self.lane
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

/// A safe reason code for decision evidence; it cannot contain a payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SledReason {
    /// An explicit hard deny matched.
    HardDeny,
    /// No matching authorization exists.
    NoAuthorization,
    /// A normal policy deny matched.
    PolicyDeny,
    /// An information-flow rule denied the edge.
    FlowDenied,
    /// A malformed or invariant-violating request was rejected.
    InvalidRequest,
    /// An operation was allowed by an explicit policy rule.
    ExplicitAllow,
    /// The policy requires a separate approval step.
    ApprovalRequired,
    /// A privileged unknown was denied by default.
    UnknownDenied,
}

/// Structured, payload-free evidence attached to an important decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SledEvidence {
    /// The matched rule, if one exists.
    pub rule_id: Option<RuleId>,
    /// Principal involved in the decision.
    pub principal: Principal,
    /// Requested operation.
    pub operation: Operation,
    /// Requested capability name.
    pub capability: CapabilityName,
    /// Provenance source, without content.
    pub provenance: ProvenanceSource,
    /// Conservative classification.
    pub classification: Classification,
    /// Destination involved in the decision.
    pub destination: Destination,
    /// Direction of the boundary, when the decision concerns one.
    pub direction: Option<FlowDirection>,
    /// Controlled reason code.
    pub reason: SledReason,
}

/// Deterministic result class of a policy decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecisionKind {
    /// The requested operation may proceed subject to execution checks.
    Allow,
    /// The requested operation must not proceed.
    Deny,
    /// The operation is not authorized yet and requires an external approval.
    RequireApproval,
}

/// A decision always carries evidence rather than a bare boolean.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// The deterministic result class.
    pub kind: DecisionKind,
    /// Safe structured explanation for the result.
    pub evidence: SledEvidence,
}

impl Decision {
    /// Construct a decision with its structured evidence.
    #[must_use]
    pub const fn new(kind: DecisionKind, evidence: SledEvidence) -> Self {
        Self { kind, evidence }
    }

    /// Return true only for an explicit allow result.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self.kind, DecisionKind::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn resource() -> Resource {
        Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/src/lib.rs").expect("fixture is valid"),
        )
    }

    #[test]
    fn identifier_rejects_ambiguous_or_control_values() {
        assert!(ResourceId::new("").is_err());
        assert!(ResourceId::new("../secret").is_err());
        assert!(ResourceId::new("line\nfeed").is_err());
        assert!(ResourceId::new("zero\u{200b}width").is_err());
        assert!(ResourceId::new("unsafe space").is_err());
        assert!(ResourceId::new("a".repeat(MAX_ID_BYTES + 1)).is_err());
    }

    #[test]
    fn trusted_control_cannot_be_model_or_data() {
        let provenance = Provenance::from_source(ProvenanceSource::System).unwrap();
        assert!(
            SecurityContext::try_new(
                Principal::Model,
                Authority::TrustedControl,
                Trust::Trusted,
                Lane::Control,
                provenance.clone(),
                Classification::Public,
            )
            .is_err()
        );
        assert!(
            SecurityContext::try_new(
                Principal::System,
                Authority::TrustedControl,
                Trust::Trusted,
                Lane::Data,
                provenance,
                Classification::Public,
            )
            .is_err()
        );
    }

    #[test]
    fn data_context_retains_untrusted_lane_and_lineage() {
        let context = SecurityContext::untrusted_data(
            Principal::Model,
            Provenance::from_source(ProvenanceSource::Web(
                Identity::new("example.test").expect("fixture is valid"),
            ))
            .expect("fixture is valid"),
            Classification::Unknown,
        );
        assert_eq!(context.lane(), Lane::Data);
        assert_eq!(context.authority(), Authority::None);
        assert_eq!(context.trust(), Trust::Untrusted);
        assert_eq!(context.provenance().lineage().len(), 1);
    }

    #[test]
    fn derived_provenance_is_not_originless() {
        let source = Provenance::from_source(ProvenanceSource::Database(
            ResourceId::new("customer.db").expect("fixture is valid"),
        ))
        .expect("fixture is valid");
        let derived = Provenance::derived_from(&[source]);
        assert_eq!(derived.source(), &ProvenanceSource::Derived);
        assert!(derived.lineage().contains(&ProvenanceSource::Database(
            ResourceId::new("customer.db").unwrap()
        )));
    }

    #[test]
    fn exact_scope_does_not_match_other_kind_or_id() {
        let target = resource();
        let scope = ResourceScope::exact(&target);
        assert!(scope.contains(&target));
        assert!(!scope.contains(&Resource::new(
            ResourceKind::Database,
            ResourceId::new("workspace/src/lib.rs").unwrap(),
        )));
        assert!(!scope.contains(&Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/src/main.rs").unwrap(),
        )));
    }

    #[test]
    fn serde_round_trip_preserves_validated_domain() {
        let request = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            resource(),
            Destination::Model,
            CapabilityName::new("file.read").expect("fixture is valid"),
        );
        let encoded = serde_json::to_string(&request).expect("serialize request");
        let decoded: ActionRequest = serde_json::from_str(&encoded).expect("deserialize request");
        assert_eq!(decoded, request);
        assert!(serde_json::from_str::<ResourceId>("\"line\\nfeed\"").is_err());
    }

    #[test]
    fn deserialization_cannot_bypass_context_invariants() {
        let forged = serde_json::json!({
            "principal": "Model",
            "authority": "TrustedControl",
            "trust": "Trusted",
            "lane": "Control",
            "provenance": {"source": "System", "lineage": ["System"]},
            "classification": "Public"
        });
        assert!(serde_json::from_value::<SecurityContext>(forged).is_err());

        let stripped = serde_json::json!({
            "principal": "Model",
            "authority": "None",
            "trust": "Untrusted",
            "lane": "Data",
            "provenance": {"source": "System", "lineage": []},
            "classification": "Public"
        });
        assert!(serde_json::from_value::<SecurityContext>(stripped).is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_identifier_never_accepts_control_or_whitespace(value in any::<String>()) {
            let result = ResourceId::new(value.clone());
            if value.is_empty()
                || value.len() > MAX_ID_BYTES
                || value.bytes().any(|byte| {
                    !byte.is_ascii_alphanumeric()
                        && !matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
                })
            {
                prop_assert!(result.is_err());
            }
        }

        #[test]
        fn classification_join_is_commutative(
            left in prop::sample::select(vec![
                Classification::Public,
                Classification::Internal,
                Classification::Confidential,
                Classification::Sensitive,
                Classification::Secret,
                Classification::Unknown,
            ]),
            right in prop::sample::select(vec![
                Classification::Public,
                Classification::Internal,
                Classification::Confidential,
                Classification::Sensitive,
                Classification::Secret,
                Classification::Unknown,
            ])
        ) {
            prop_assert_eq!(left.join(right), right.join(left));
        }
    }
}
