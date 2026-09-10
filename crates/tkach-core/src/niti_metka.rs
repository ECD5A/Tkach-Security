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

//! Niti provenance and Metka conservative classification.
//!
//! The model may produce a derived value, but it cannot erase its lineage or
//! lower its classification by assertion. A real declassification permit is an
//! opaque trusted capability and is intentionally not issued by the public API
//! in the current Strong Core.

use crate::domain::{Classification, MAX_DERIVATION_PARENTS, Provenance, ProvenanceSource};
use serde::Serialize;
use std::fmt::{Debug, Formatter};
use thiserror::Error;

/// Errors from provenance/classification transformations.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum NitiMetkaError {
    /// A requested declassification has no trusted authority.
    #[error("trusted declassification authority is required")]
    MissingDeclassificationAuthority,
    /// A target classification is not less restrictive than the current one.
    #[error("declassification target is not less restrictive")]
    InvalidDeclassificationTarget,
    /// A provenance value cannot be represented as Niti.
    #[error("invalid provenance for Niti")]
    InvalidProvenance,
}

/// Branded provenance/lineage thread. It has no stripping or replacement API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Niti {
    provenance: Provenance,
}

impl Niti {
    fn unknown() -> Self {
        Self {
            provenance: Provenance::from_source(ProvenanceSource::Unknown)
                .expect("static unknown provenance is valid"),
        }
    }

    /// Create Niti from a validated provenance root.
    ///
    /// # Errors
    ///
    /// Returns [`NitiMetkaError::InvalidProvenance`] if the source marker is an
    /// unrooted derived value.
    #[cfg(test)]
    pub(crate) fn from_source(source: ProvenanceSource) -> Result<Self, NitiMetkaError> {
        Ok(Self {
            provenance: Provenance::from_source(source)
                .map_err(|_| NitiMetkaError::InvalidProvenance)?,
        })
    }

    /// Create derived Niti while retaining every parent thread.
    #[must_use]
    pub fn derived_from(parents: &[&Self]) -> Self {
        if parents.len() > MAX_DERIVATION_PARENTS {
            return Self {
                provenance: Provenance::derived_from(&[]),
            };
        }
        let provenance: Vec<Provenance> = parents
            .iter()
            .map(|parent| parent.provenance.clone())
            .collect();
        Self {
            provenance: Provenance::derived_from(&provenance),
        }
    }

    /// Return the complete retained provenance.
    #[must_use]
    pub const fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    fn declassified(&self) -> Self {
        Self {
            provenance: Provenance::derived_from(std::slice::from_ref(&self.provenance)),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Niti {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Wire {
            provenance: Provenance,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            provenance: wire.provenance,
        })
    }
}

/// Branded conservative classification marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
pub struct Metka(Classification);

impl Metka {
    /// Construct a classification marker.
    #[must_use]
    pub const fn new(classification: Classification) -> Self {
        Self(classification)
    }

    /// Return the classification.
    #[must_use]
    pub const fn classification(self) -> Classification {
        self.0
    }

    /// Conservatively join two markers.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        Self(self.0.join(other.0))
    }
}

/// A value carrying immutable lineage and conservative classification.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct TaggedData<T> {
    value: T,
    niti: Niti,
    metka: Metka,
}

impl<T> Debug for TaggedData<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaggedData")
            .field("value", &"REDACTED")
            .field("niti", &self.niti)
            .field("metka", &self.metka)
            .finish()
    }
}

impl<T> TaggedData<T> {
    /// Create a tagged root value from an explicit source and classification.
    ///
    /// # Errors
    ///
    /// Returns [`NitiMetkaError::InvalidProvenance`] for an invalid root source.
    #[cfg(test)]
    pub(crate) fn from_source(
        value: T,
        source: ProvenanceSource,
        classification: Classification,
    ) -> Result<Self, NitiMetkaError> {
        Ok(Self {
            niti: Niti::from_source(source)?,
            metka: Metka::new(classification),
            value,
        })
    }

    /// Create a model-facing root whose unverifiable metadata is conservative.
    ///
    /// Public callers cannot choose a provenance source or classification.
    /// Values that carry trusted source metadata must be created by an
    /// authenticated crate-internal ingress boundary.
    #[must_use]
    pub fn from_untrusted(value: T) -> Self {
        Self {
            value,
            niti: Niti::unknown(),
            metka: Metka::new(Classification::Unknown),
        }
    }

    /// Derive a value from parents, retaining lineage and maximum classification.
    #[must_use]
    pub fn derived_from(parents: &[&Self], value: T) -> Self {
        if parents.len() > MAX_DERIVATION_PARENTS {
            return Self {
                value,
                niti: Niti::derived_from(&[]),
                metka: Metka::new(Classification::Unknown),
            };
        }
        let metka = if parents.is_empty() {
            Metka::new(Classification::Unknown)
        } else {
            parents
                .iter()
                .fold(Metka::new(Classification::Public), |current, parent| {
                    current.join(parent.metka)
                })
        };
        let niti = Niti::derived_from(
            &parents
                .iter()
                .map(|parent| &parent.niti)
                .collect::<Vec<_>>(),
        );
        Self { value, niti, metka }
    }

    /// Return the model-visible value without dropping security metadata.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Return the retained Niti thread.
    #[must_use]
    pub const fn niti(&self) -> &Niti {
        &self.niti
    }

    /// Return the conservative Metka.
    #[must_use]
    pub const fn metka(&self) -> Metka {
        self.metka
    }

    /// Model-originated self-declassification is always rejected.
    ///
    /// # Errors
    ///
    /// Always returns [`NitiMetkaError::MissingDeclassificationAuthority`].
    pub fn try_self_declassify(&self, _target: Classification) -> Result<Self, NitiMetkaError> {
        Err(NitiMetkaError::MissingDeclassificationAuthority)
    }

    /// Apply a trusted declassification permit to a less restrictive target.
    ///
    /// The permit type has no public constructor. This method is therefore not
    /// reachable by model data through the public API.
    ///
    /// # Errors
    ///
    /// Returns an error if the target is not less restrictive.
    pub fn declassify(
        &self,
        _permit: &DeclassificationPermit,
        target: Classification,
    ) -> Result<Self, NitiMetkaError>
    where
        T: Clone,
    {
        if target.rank() >= self.metka.classification().rank() {
            return Err(NitiMetkaError::InvalidDeclassificationTarget);
        }
        Ok(Self {
            value: self.value.clone(),
            niti: self.niti.declassified(),
            metka: Metka::new(target),
        })
    }
}

/// Opaque trusted authority required for declassification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclassificationPermit {
    _sealed: (),
}

#[cfg(test)]
impl DeclassificationPermit {
    fn for_test() -> Self {
        Self { _sealed: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ProvenanceSource, ResourceId};
    use proptest::prelude::*;

    fn secret_source() -> ProvenanceSource {
        ProvenanceSource::Database(ResourceId::new("customer.db").unwrap())
    }

    #[test]
    fn mixed_model_output_inherits_secret_metka_and_lineage() {
        let public = TaggedData::from_source(
            "hello".to_owned(),
            ProvenanceSource::User,
            Classification::Public,
        )
        .unwrap();
        let secret =
            TaggedData::from_source("record".to_owned(), secret_source(), Classification::Secret)
                .unwrap();
        let output = TaggedData::derived_from(&[&public, &secret], "summary".to_owned());
        assert_eq!(output.metka().classification(), Classification::Secret);
        assert!(
            output
                .niti()
                .provenance()
                .lineage()
                .contains(&secret_source())
        );
        assert!(
            output
                .niti()
                .provenance()
                .lineage()
                .contains(&ProvenanceSource::User)
        );
    }

    #[test]
    fn model_cannot_self_declassify_and_permit_is_required() {
        let secret =
            TaggedData::from_source("secret".to_owned(), secret_source(), Classification::Secret)
                .unwrap();
        assert_eq!(
            secret.try_self_declassify(Classification::Public),
            Err(NitiMetkaError::MissingDeclassificationAuthority)
        );
        let permit = DeclassificationPermit::for_test();
        let public = secret.declassify(&permit, Classification::Public).unwrap();
        assert_eq!(public.metka().classification(), Classification::Public);
        assert!(
            public
                .niti()
                .provenance()
                .lineage()
                .contains(&ProvenanceSource::Derived)
        );
        assert!(secret.declassify(&permit, Classification::Secret).is_err());
    }

    #[test]
    fn metka_join_is_conservative() {
        assert_eq!(
            Metka::new(Classification::Public)
                .join(Metka::new(Classification::Sensitive))
                .classification(),
            Classification::Sensitive
        );
    }

    #[test]
    fn forged_niti_wire_value_cannot_strip_lineage() {
        let stripped = serde_json::json!({
            "provenance": {"source": "System", "lineage": []}
        });
        assert!(serde_json::from_value::<Niti>(stripped).is_err());
        let secret =
            TaggedData::from_source("secret".to_owned(), secret_source(), Classification::Secret)
                .unwrap();
        let encoded = serde_json::to_string(&secret).unwrap();
        assert!(encoded.contains("customer.db"));
    }

    #[test]
    fn niti_serialization_round_trip_preserves_lineage() {
        let original = Niti::from_source(secret_source()).unwrap();
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: Niti = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn debug_does_not_echo_tagged_payload() {
        let marker = "protected-tagged-marker";
        let value =
            TaggedData::from_source(marker.to_owned(), secret_source(), Classification::Secret)
                .unwrap();
        assert!(!format!("{value:?}").contains(marker));
    }

    #[test]
    fn originless_derived_tag_is_unknown_not_public() {
        let value = TaggedData::derived_from(&[], "originless output".to_owned());
        assert_eq!(value.metka(), Metka::new(Classification::Unknown));
        assert!(
            value
                .niti()
                .provenance()
                .lineage()
                .contains(&ProvenanceSource::Unknown)
        );
    }

    #[test]
    fn oversized_parent_set_becomes_unknown_instead_of_laundering_classification() {
        let parent = TaggedData::from_source(
            "parent".to_owned(),
            ProvenanceSource::User,
            Classification::Secret,
        )
        .unwrap();
        let parents = vec![&parent; MAX_DERIVATION_PARENTS + 1];
        let derived = TaggedData::derived_from(&parents, "derived".to_owned());
        assert_eq!(derived.metka().classification(), Classification::Unknown);
        assert!(
            derived
                .niti()
                .provenance()
                .lineage()
                .contains(&ProvenanceSource::Unknown)
        );
    }

    proptest! {
        #[test]
        fn classification_join_never_lowers_sensitivity(
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
            let joined = left.join(right);
            prop_assert!(joined.rank() >= left.rank());
            prop_assert!(joined.rank() >= right.rank());
        }
    }
}
