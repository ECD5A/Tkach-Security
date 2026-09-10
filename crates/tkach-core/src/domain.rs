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
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use thiserror::Error;

const MAX_ID_BYTES: usize = 128;
pub(crate) const MAX_DERIVATION_PARENTS: usize = 256;
pub(crate) const MAX_PROVENANCE_LINEAGE: usize = 256;

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
    /// A bounded collection or value exceeded the core's fixed budget.
    #[error("core resource limit exceeded for {kind}")]
    ResourceLimit {
        /// The non-sensitive bounded type name.
        kind: &'static str,
    },
}

pub(crate) fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MAX: usize>(PhantomData<T>);

    impl<'de, T, const MAX: usize> serde::de::Visitor<'de> for BoundedVecVisitor<T, MAX>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence with at most {MAX} elements")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() >= MAX {
                    return Err(serde::de::Error::custom("sequence exceeds core bound"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(PhantomData))
}

pub(crate) fn deserialize_bounded_string<'de, D, const MAX: usize>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoundedStringVisitor<const MAX: usize>;

    impl<const MAX: usize> serde::de::Visitor<'_> for BoundedStringVisitor<MAX> {
        type Value = String;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a string with at most {MAX} bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX {
                return Err(E::custom("string exceeds core bound"));
            }
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX {
                return Err(E::custom("string exceeds core bound"));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_str(BoundedStringVisitor::<MAX>)
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
                let value = deserialize_bounded_string::<D, MAX_ID_BYTES>(deserializer)?;
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
    /// marker, which is valid only when parent lineage is supplied, or with
    /// `System`, which requires a future trusted constructor.
    pub fn from_source(source: ProvenanceSource) -> Result<Self, CoreError> {
        if source == ProvenanceSource::Derived {
            return Err(CoreError::InvalidContext {
                reason: "derived provenance requires parent lineage",
            });
        }
        if source == ProvenanceSource::System {
            return Err(CoreError::InvalidContext {
                reason: "system provenance requires trusted construction",
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
        if parents.len() > MAX_DERIVATION_PARENTS {
            return Self::originless_derived();
        }
        let mut lineage = Vec::new();
        let mut seen = HashSet::new();
        let mut overflowed = false;
        for parent in parents {
            for source in &parent.lineage {
                if source == &ProvenanceSource::Derived {
                    continue;
                }
                if seen.insert(source.clone()) {
                    if lineage.len() >= MAX_PROVENANCE_LINEAGE - 1 {
                        overflowed = true;
                        break;
                    }
                    lineage.push(source.clone());
                }
            }
            if overflowed {
                break;
            }
        }
        if overflowed || lineage.is_empty() {
            return Self::originless_derived();
        }
        lineage.push(ProvenanceSource::Derived);
        Self {
            source: ProvenanceSource::Derived,
            lineage,
        }
    }

    fn originless_derived() -> Self {
        Self {
            source: ProvenanceSource::Derived,
            lineage: vec![ProvenanceSource::Unknown, ProvenanceSource::Derived],
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
    #[serde(deserialize_with = "deserialize_provenance_lineage")]
    lineage: Vec<ProvenanceSource>,
}

fn deserialize_provenance_lineage<'de, D>(
    deserializer: D,
) -> Result<Vec<ProvenanceSource>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ProvenanceSource, MAX_PROVENANCE_LINEAGE>(deserializer)
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
        if wire
            .lineage
            .iter()
            .any(|source| source == &ProvenanceSource::System)
        {
            return Err(serde::de::Error::custom(CoreError::InvalidSerialization {
                kind: "trusted provenance in untrusted wire value",
            }));
        }
        let valid = match wire.source {
            ProvenanceSource::Derived => {
                wire.lineage.len() > 1
                    && wire.lineage.last() == Some(&ProvenanceSource::Derived)
                    && wire.lineage[..wire.lineage.len() - 1]
                        .iter()
                        .all(|source| source != &ProvenanceSource::Derived)
                    && wire.lineage[..wire.lineage.len() - 1]
                        .iter()
                        .cloned()
                        .collect::<HashSet<_>>()
                        .len()
                        == wire.lineage.len() - 1
            }
            ref source => {
                wire.lineage.len() == 1
                    && wire.lineage.first() == Some(source)
                    && source != &ProvenanceSource::Derived
            }
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

/// A canonical relative path used by a file-prefix scope.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
struct CanonicalPath(String);

impl CanonicalPath {
    fn new(value: &str) -> Result<Self, CoreError> {
        let valid = !value.is_empty()
            && value.len() <= MAX_ID_BYTES * 8
            && !value.starts_with('/')
            && !value.ends_with('/')
            && !value.contains('\\')
            && value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '/' | '-')
            })
            && !value
                .split('/')
                .any(|segment| segment.is_empty() || matches!(segment, "." | ".."));
        valid
            .then_some(Self(value.to_owned()))
            .ok_or(CoreError::InvalidResourceScope)
    }
}

impl<'de> Deserialize<'de> for CanonicalPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = deserialize_bounded_string::<D, { MAX_ID_BYTES * 8 }>(deserializer)?;
        Self::new(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum ScopePattern {
    Exact(ResourceId),
    FilePrefix(CanonicalPath),
}

/// A canonical resource scope. Prefix scopes are available only for relative
/// file paths and match complete path segments, never string lookalikes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct ResourceScope {
    kind: ResourceKind,
    pattern: ScopePattern,
}

impl ResourceScope {
    /// Grant an exact scope for one typed resource.
    #[must_use]
    pub fn exact(resource: &Resource) -> Self {
        Self {
            kind: resource.kind,
            pattern: ScopePattern::Exact(resource.id.clone()),
        }
    }

    /// Grant a canonical relative file-path prefix scope.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidResourceScope`] for ambiguous, absolute,
    /// oversized, non-ASCII, or traversal-containing paths.
    pub fn file_prefix(prefix: &str) -> Result<Self, CoreError> {
        Ok(Self {
            kind: ResourceKind::File,
            pattern: ScopePattern::FilePrefix(CanonicalPath::new(prefix)?),
        })
    }

    /// Return whether this exact scope contains the resource.
    #[must_use]
    pub fn contains(&self, resource: &Resource) -> bool {
        if self.kind != resource.kind {
            return false;
        }
        match &self.pattern {
            ScopePattern::Exact(id) => id == &resource.id,
            ScopePattern::FilePrefix(prefix) => {
                resource.id.as_str() == prefix.0
                    || resource
                        .id
                        .as_str()
                        .strip_prefix(&prefix.0)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
        }
    }
}

#[derive(Deserialize)]
struct ResourceScopeWire {
    kind: ResourceKind,
    pattern: ScopePattern,
}

impl<'de> Deserialize<'de> for ResourceScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ResourceScopeWire::deserialize(deserializer)?;
        if matches!(wire.pattern, ScopePattern::FilePrefix(_)) && wire.kind != ResourceKind::File {
            return Err(serde::de::Error::custom(CoreError::InvalidResourceScope));
        }
        Ok(Self {
            kind: wire.kind,
            pattern: wire.pattern,
        })
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
        if wire.principal != Principal::Model
            || wire.authority != Authority::None
            || wire.trust != Trust::Untrusted
            || wire.lane != Lane::Data
            || wire.provenance != unknown_provenance()
            || wire.classification != Classification::Unknown
        {
            return Err(serde::de::Error::custom(CoreError::InvalidSerialization {
                kind: "untrusted security context",
            }));
        }
        Ok(Self::untrusted_data())
    }
}

impl SecurityContext {
    /// Construct the canonical public untrusted data context.
    ///
    /// Public callers cannot choose identity, provenance, or classification.
    /// All three are conservative model/data values. Trusted ingress adapters
    /// must use a crate-internal authenticated boundary before constructing
    /// richer context.
    #[must_use]
    pub fn untrusted_data() -> Self {
        Self::untrusted_with_metadata(
            Principal::Model,
            unknown_provenance(),
            Classification::Unknown,
        )
    }

    pub(crate) fn untrusted_with_metadata(
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

fn unknown_provenance() -> Provenance {
    Provenance::from_source(ProvenanceSource::Unknown).expect("static unknown provenance is valid")
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

/// Payload-free principal category retained in kernel evidence.
///
/// Request-controlled identities are deliberately reduced to a stable category
/// before they cross into Sled. This keeps the trace explainable without making
/// it a transport for attacker-selected identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum EvidencePrincipal {
    /// The model principal.
    Model,
    /// A user principal, without its identity.
    User,
    /// The system principal.
    System,
    /// A service principal, without its identity.
    Service,
}

impl From<&Principal> for EvidencePrincipal {
    fn from(principal: &Principal) -> Self {
        match principal {
            Principal::Model => Self::Model,
            Principal::User(_) => Self::User,
            Principal::System => Self::System,
            Principal::Service(_) => Self::Service,
        }
    }
}

/// Payload-free operation category retained in kernel evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum EvidenceOperation {
    /// Read operation.
    Read,
    /// Write operation.
    Write,
    /// Execute operation.
    Execute,
    /// Network-send operation.
    NetworkSend,
    /// Secret-reveal operation.
    RevealSecret,
    /// Declassification operation.
    Declassify,
    /// Policy-mutation operation.
    MutatePolicy,
    /// An unknown operation, without its payload.
    Unknown,
}

impl From<&Operation> for EvidenceOperation {
    fn from(operation: &Operation) -> Self {
        match operation {
            Operation::Read => Self::Read,
            Operation::Write => Self::Write,
            Operation::Execute => Self::Execute,
            Operation::NetworkSend => Self::NetworkSend,
            Operation::RevealSecret => Self::RevealSecret,
            Operation::Declassify => Self::Declassify,
            Operation::MutatePolicy => Self::MutatePolicy,
            Operation::Unknown(_) => Self::Unknown,
        }
    }
}

/// Payload-free capability category retained in kernel evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum EvidenceCapability {
    /// File read capability.
    FileRead,
    /// File write capability.
    FileWrite,
    /// Database read capability.
    DatabaseRead,
    /// Database write capability.
    DatabaseWrite,
    /// Network send capability.
    NetworkSend,
    /// Tool execution capability.
    ToolExecute,
    /// Secret use capability.
    SecretUse,
    /// Secret reveal capability.
    SecretReveal,
    /// Ruslo boundary evaluation capability.
    RusloFlow,
    /// Zaslon content boundary capability.
    ZaslonContent,
    /// Zaslon action boundary capability.
    ZaslonAction,
    /// Policy mutation capability.
    PolicyMutate,
    /// Declassification capability.
    Declassify,
    /// An unknown capability, without its payload.
    Unknown,
}

impl From<&CapabilityName> for EvidenceCapability {
    fn from(capability: &CapabilityName) -> Self {
        match capability.as_str() {
            "file.read" => Self::FileRead,
            "file.write" => Self::FileWrite,
            "database.read" => Self::DatabaseRead,
            "database.write" => Self::DatabaseWrite,
            "network.send" => Self::NetworkSend,
            "tool.execute" => Self::ToolExecute,
            "secret.use" => Self::SecretUse,
            "secret.reveal" => Self::SecretReveal,
            "ruslo.flow" => Self::RusloFlow,
            "zaslon.content" => Self::ZaslonContent,
            "zaslon.action" => Self::ZaslonAction,
            "policy.mutate" => Self::PolicyMutate,
            "data.declassify" => Self::Declassify,
            _ => Self::Unknown,
        }
    }
}

/// Payload-free provenance category retained in kernel evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum EvidenceProvenance {
    /// User-originated data.
    User,
    /// System-originated data.
    System,
    /// File-originated data, without its resource identifier.
    File,
    /// Database-originated data, without its resource identifier.
    Database,
    /// Web-originated data, without its identity.
    Web,
    /// Retrieval-augmented data, without its identity.
    Rag,
    /// API-originated data, without its identity.
    Api,
    /// MCP-originated data, without its identity.
    Mcp,
    /// Tool-originated data, without its identity.
    Tool,
    /// Model-originated data.
    Model,
    /// Derived data.
    Derived,
    /// Unknown provenance.
    Unknown,
}

impl From<&ProvenanceSource> for EvidenceProvenance {
    fn from(source: &ProvenanceSource) -> Self {
        match source {
            ProvenanceSource::User => Self::User,
            ProvenanceSource::System => Self::System,
            ProvenanceSource::File(_) => Self::File,
            ProvenanceSource::Database(_) => Self::Database,
            ProvenanceSource::Web(_) => Self::Web,
            ProvenanceSource::Rag(_) => Self::Rag,
            ProvenanceSource::Api(_) => Self::Api,
            ProvenanceSource::Mcp(_) => Self::Mcp,
            ProvenanceSource::Tool(_) => Self::Tool,
            ProvenanceSource::Model => Self::Model,
            ProvenanceSource::Derived => Self::Derived,
            ProvenanceSource::Unknown => Self::Unknown,
        }
    }
}

/// Payload-free destination category retained in kernel evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum EvidenceDestination {
    /// Model destination.
    Model,
    /// Internal destination, without its identity.
    Internal,
    /// Public external destination.
    PublicExternal,
    /// Secret broker destination.
    SecretBroker,
    /// Unknown destination, without its identity.
    Unknown,
}

impl From<&Destination> for EvidenceDestination {
    fn from(destination: &Destination) -> Self {
        match destination {
            Destination::Model => Self::Model,
            Destination::Internal(_) => Self::Internal,
            Destination::PublicExternal => Self::PublicExternal,
            Destination::SecretBroker => Self::SecretBroker,
            Destination::Unknown(_) => Self::Unknown,
        }
    }
}

/// Structured, payload-free evidence attached to an important decision.
///
/// The fields are crate-visible because only kernel primitives may construct
/// evidence. External callers receive read-only accessors. In particular, this
/// type is intentionally not deserializable: serialized traces are diagnostic
/// output, never an input authority format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SledEvidence {
    /// The matched rule, if one exists.
    pub(crate) rule_id: Option<RuleId>,
    /// Principal involved in the decision.
    pub(crate) principal: EvidencePrincipal,
    /// Requested operation.
    pub(crate) operation: EvidenceOperation,
    /// Requested capability name.
    pub(crate) capability: EvidenceCapability,
    /// Provenance source, without content.
    pub(crate) provenance: EvidenceProvenance,
    /// Conservative classification.
    pub(crate) classification: Classification,
    /// Destination involved in the decision.
    pub(crate) destination: EvidenceDestination,
    /// Direction of the boundary, when the decision concerns one.
    pub(crate) direction: Option<FlowDirection>,
    /// Controlled reason code.
    pub(crate) reason: SledReason,
}

impl SledEvidence {
    /// Return the trusted policy rule label, if one matched.
    #[must_use]
    pub fn rule_id(&self) -> Option<&RuleId> {
        self.rule_id.as_ref()
    }

    /// Return the payload-free principal category.
    #[must_use]
    pub const fn principal(&self) -> EvidencePrincipal {
        self.principal
    }

    /// Return the payload-free operation category.
    #[must_use]
    pub const fn operation(&self) -> EvidenceOperation {
        self.operation
    }

    /// Return the payload-free capability category.
    #[must_use]
    pub const fn capability(&self) -> EvidenceCapability {
        self.capability
    }

    /// Return the payload-free provenance category.
    #[must_use]
    pub const fn provenance(&self) -> EvidenceProvenance {
        self.provenance
    }

    /// Return the conservative classification.
    #[must_use]
    pub const fn classification(&self) -> Classification {
        self.classification
    }

    /// Return the payload-free destination category.
    #[must_use]
    pub const fn destination(&self) -> EvidenceDestination {
        self.destination
    }

    /// Return the flow direction, when the decision concerns one.
    #[must_use]
    pub const fn direction(&self) -> Option<FlowDirection> {
        self.direction
    }

    /// Return the controlled decision reason.
    #[must_use]
    pub const fn reason(&self) -> SledReason {
        self.reason
    }
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Decision {
    /// The deterministic result class.
    pub(crate) kind: DecisionKind,
    /// Safe structured explanation for the result.
    pub(crate) evidence: SledEvidence,
}

impl Decision {
    /// Construct a decision with its structured evidence.
    #[must_use]
    pub(crate) const fn new(kind: DecisionKind, evidence: SledEvidence) -> Self {
        Self { kind, evidence }
    }

    /// Return the deterministic result class.
    #[must_use]
    pub const fn kind(&self) -> DecisionKind {
        self.kind
    }

    /// Return the safe structured explanation.
    #[must_use]
    pub const fn evidence(&self) -> &SledEvidence {
        &self.evidence
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
    fn data_context_retains_untrusted_lane_and_lineage() {
        let context = SecurityContext::untrusted_with_metadata(
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
    fn oversized_lineage_wire_is_rejected_before_domain_construction() {
        let forged = serde_json::json!({
            "source": "Derived",
            "lineage": vec!["User"; MAX_PROVENANCE_LINEAGE + 1]
        });
        assert!(serde_json::from_value::<Provenance>(forged).is_err());
    }

    #[test]
    fn provenance_wire_requires_canonical_root_or_derived_shape() {
        let root_with_extra = serde_json::json!({
            "source": "User",
            "lineage": ["User", "Derived"]
        });
        let impossible_derived = serde_json::json!({
            "source": "Derived",
            "lineage": ["Derived", "Derived"]
        });
        assert!(serde_json::from_value::<Provenance>(root_with_extra).is_err());
        assert!(serde_json::from_value::<Provenance>(impossible_derived).is_err());
    }

    #[test]
    fn nested_derivation_keeps_one_terminal_derived_marker() {
        let root = Provenance::from_source(ProvenanceSource::User).unwrap();
        let first = Provenance::derived_from(&[root]);
        let second = Provenance::derived_from(&[first]);
        assert_eq!(
            second.lineage(),
            &[ProvenanceSource::User, ProvenanceSource::Derived]
        );
        let encoded = serde_json::to_value(&second).unwrap();
        assert!(serde_json::from_value::<Provenance>(encoded).is_ok());
    }

    #[test]
    fn oversized_derived_lineage_fails_closed_to_unknown() {
        let parent = Provenance::from_source(ProvenanceSource::User).unwrap();
        let parents = vec![parent; MAX_DERIVATION_PARENTS + 1];
        let derived = Provenance::derived_from(&parents);
        assert_eq!(derived.source(), &ProvenanceSource::Derived);
        assert_eq!(
            derived.lineage(),
            &[ProvenanceSource::Unknown, ProvenanceSource::Derived]
        );
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
    fn file_prefix_scope_matches_only_complete_segments() {
        let scope = ResourceScope::file_prefix("workspace/src").unwrap();
        assert!(scope.contains(&Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/src/lib.rs").unwrap(),
        )));
        assert!(scope.contains(&Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/src").unwrap(),
        )));
        assert!(!scope.contains(&Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/src-private/file.rs").unwrap(),
        )));
        assert!(!scope.contains(&Resource::new(
            ResourceKind::Database,
            ResourceId::new("workspace/src/lib.rs").unwrap(),
        )));
    }

    #[test]
    fn file_prefix_rejects_path_ambiguity_and_invalid_wire_kind() {
        assert!(ResourceScope::file_prefix("/workspace/src").is_err());
        assert!(ResourceScope::file_prefix("workspace//src").is_err());
        assert!(ResourceScope::file_prefix("workspace/../secret").is_err());
        assert!(ResourceScope::file_prefix("workspace\\src").is_err());
        let forged = serde_json::json!({
            "kind": "Database",
            "pattern": {"FilePrefix": "workspace/src"}
        });
        assert!(serde_json::from_value::<ResourceScope>(forged).is_err());
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

        let spoofed_principal = serde_json::json!({
            "principal": "System",
            "authority": "None",
            "trust": "Untrusted",
            "lane": "Data",
            "provenance": {"source": "User", "lineage": ["User"]},
            "classification": "Public"
        });
        assert!(serde_json::from_value::<SecurityContext>(spoofed_principal).is_err());
    }

    #[test]
    fn sled_evidence_projection_preserves_only_safe_categories() {
        let capability_cases = [
            ("file.read", EvidenceCapability::FileRead),
            ("file.write", EvidenceCapability::FileWrite),
            ("database.read", EvidenceCapability::DatabaseRead),
            ("database.write", EvidenceCapability::DatabaseWrite),
            ("network.send", EvidenceCapability::NetworkSend),
            ("tool.execute", EvidenceCapability::ToolExecute),
            ("secret.use", EvidenceCapability::SecretUse),
            ("secret.reveal", EvidenceCapability::SecretReveal),
            ("ruslo.flow", EvidenceCapability::RusloFlow),
            ("zaslon.content", EvidenceCapability::ZaslonContent),
            ("zaslon.action", EvidenceCapability::ZaslonAction),
            ("policy.mutate", EvidenceCapability::PolicyMutate),
            ("data.declassify", EvidenceCapability::Declassify),
            ("attacker.payload", EvidenceCapability::Unknown),
        ];
        for (name, expected) in capability_cases {
            let capability = CapabilityName::new(name).unwrap();
            assert_eq!(EvidenceCapability::from(&capability), expected);
            let encoded = serde_json::to_string(&EvidenceCapability::from(&capability)).unwrap();
            assert!(!encoded.contains(name));
        }
        assert_eq!(
            EvidenceOperation::from(&Operation::Unknown(
                CapabilityName::new("attacker.operation").unwrap()
            )),
            EvidenceOperation::Unknown
        );
        assert_eq!(
            EvidenceDestination::from(&Destination::Unknown(
                Identity::new("attacker.destination").unwrap()
            )),
            EvidenceDestination::Unknown
        );
        assert_eq!(
            EvidenceProvenance::from(&ProvenanceSource::Web(
                Identity::new("attacker.provenance").unwrap()
            )),
            EvidenceProvenance::Web
        );
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
