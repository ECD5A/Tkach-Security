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

//! Strict, bounded external request representation.

use crate::{
    MAX_MESSAGE_BYTES, MAX_MESSAGES, MAX_METADATA_ENTRIES, MAX_METADATA_KEY_BYTES,
    MAX_METADATA_VALUE_BYTES, MAX_TOOL_DECLARATIONS,
};
use serde::Deserialize;
use serde::de::{Deserializer, Error as DeError, SeqAccess, Visitor};
use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};
use thiserror::Error;

/// Errors returned before a request can enter the gateway lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RequestParseError {
    /// The raw body exceeds the pre-deserialization gateway limit.
    #[error("request body exceeds gateway limit")]
    BodyTooLarge,
    /// The body is not valid JSON or violates the strict request schema.
    #[error("request is invalid")]
    Invalid,
}

/// The only roles accepted at the external boundary.
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalRole {
    /// Client-authored task content.
    User,
    /// Attacker-controlled imported/document content.
    Data,
}

impl Debug for ExternalRole {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::User => "User",
            Self::Data => "Data",
        })
    }
}

/// One bounded untrusted message.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMessage {
    role: ExternalRole,
    #[serde(deserialize_with = "deserialize_message_content")]
    content: String,
}

impl Debug for ExternalMessage {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalMessage")
            .field("role", &self.role)
            .field("content", &"REDACTED")
            .finish()
    }
}

impl ExternalMessage {
    /// Construct a bounded message through the same validation used by JSON.
    ///
    /// # Errors
    ///
    /// Returns [`RequestParseError::Invalid`] for empty or oversized content.
    pub fn new(role: ExternalRole, content: String) -> Result<Self, RequestParseError> {
        if content.is_empty() || content.len() > MAX_MESSAGE_BYTES {
            return Err(RequestParseError::Invalid);
        }
        Ok(Self { role, content })
    }

    /// Return the external role.
    #[must_use]
    pub const fn role(&self) -> ExternalRole {
        self.role
    }

    /// Return message content for the trusted gateway-to-Gnezdo mapping.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }
}

/// One bounded metadata entry. Metadata is data, never authority.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataEntry {
    #[serde(deserialize_with = "deserialize_metadata_key")]
    name: String,
    #[serde(deserialize_with = "deserialize_metadata_value")]
    value: String,
}

impl Debug for MetadataEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MetadataEntry")
            .field("name", &self.name)
            .field("value", &"REDACTED")
            .finish()
    }
}

impl MetadataEntry {
    /// Return the non-secret metadata key.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the metadata value for an untrusted provider context.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A bounded tool declaration supplied as data by the client.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDeclaration {
    #[serde(deserialize_with = "deserialize_tool_name")]
    name: String,
}

impl Debug for ToolDeclaration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ToolDeclaration")
            .field("name", &self.name)
            .finish()
    }
}

impl ToolDeclaration {
    /// Return the declared tool label. It is never used as an authorization
    /// grant or to extend the trusted tool catalog.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A strict request accepted by the provider-independent gateway.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalRequest {
    messages: Vec<ExternalMessage>,
    metadata: Vec<MetadataEntry>,
    tool_declarations: Vec<ToolDeclaration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalRequestWire {
    #[serde(deserialize_with = "deserialize_messages")]
    messages: Vec<ExternalMessage>,
    #[serde(default, deserialize_with = "deserialize_metadata")]
    metadata: Vec<MetadataEntry>,
    #[serde(default, deserialize_with = "deserialize_tool_declarations")]
    tool_declarations: Vec<ToolDeclaration>,
}

impl Debug for ExternalRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExternalRequest")
            .field("message_count", &self.messages.len())
            .field("metadata_count", &self.metadata.len())
            .field("tool_declaration_count", &self.tool_declarations.len())
            .finish()
    }
}

impl ExternalRequest {
    /// Parse a request after checking its raw byte budget.
    ///
    /// # Errors
    ///
    /// Returns [`RequestParseError::BodyTooLarge`] before deserialization when
    /// the raw body exceeds the gateway budget, or
    /// [`RequestParseError::Invalid`] for malformed/invalid input.
    pub fn from_json(body: &[u8]) -> Result<Self, RequestParseError> {
        if body.len() > crate::MAX_REQUEST_BODY_BYTES {
            return Err(RequestParseError::BodyTooLarge);
        }
        let wire: ExternalRequestWire =
            serde_json::from_slice(body).map_err(|_| RequestParseError::Invalid)?;
        let request = Self {
            messages: wire.messages,
            metadata: wire.metadata,
            tool_declarations: wire.tool_declarations,
        };
        request.validate()?;
        Ok(request)
    }

    /// Construct a request through the same structural checks as JSON input.
    ///
    /// # Errors
    ///
    /// Returns [`RequestParseError::Invalid`] for an empty request, duplicate
    /// metadata key, invalid token, or collection over its budget.
    pub fn new(
        messages: Vec<ExternalMessage>,
        metadata: Vec<MetadataEntry>,
        tool_declarations: Vec<ToolDeclaration>,
    ) -> Result<Self, RequestParseError> {
        let request = Self {
            messages,
            metadata,
            tool_declarations,
        };
        request.validate()?;
        Ok(request)
    }

    /// Return bounded messages in their supplied order.
    #[must_use]
    pub fn messages(&self) -> &[ExternalMessage] {
        &self.messages
    }

    /// Return bounded metadata as data, not control.
    #[must_use]
    pub fn metadata(&self) -> &[MetadataEntry] {
        &self.metadata
    }

    /// Return bounded client-declared tool labels.
    #[must_use]
    pub fn tool_declarations(&self) -> &[ToolDeclaration] {
        &self.tool_declarations
    }

    fn validate(&self) -> Result<(), RequestParseError> {
        if self.messages.is_empty() || self.messages.len() > MAX_MESSAGES {
            return Err(RequestParseError::Invalid);
        }
        let total_message_bytes = self.messages.iter().try_fold(0usize, |total, message| {
            total
                .checked_add(message.content.len())
                .ok_or(RequestParseError::Invalid)
        })?;
        if total_message_bytes == 0 {
            return Err(RequestParseError::Invalid);
        }
        if self.metadata.len() > MAX_METADATA_ENTRIES {
            return Err(RequestParseError::Invalid);
        }
        let mut names = BTreeSet::new();
        for entry in &self.metadata {
            if !names.insert(entry.name.as_str()) || !is_token(entry.name.as_bytes()) {
                return Err(RequestParseError::Invalid);
            }
        }
        if self.tool_declarations.len() > MAX_TOOL_DECLARATIONS
            || self
                .tool_declarations
                .iter()
                .any(|tool| !is_token(tool.name.as_bytes()))
        {
            return Err(RequestParseError::Invalid);
        }

        // The raw JSON budget is not enough for callers using `ExternalRequest::new`:
        // every public construction path must enforce the same aggregate
        // envelope budget as the wire path.  Keep separate component sums so
        // a future increase in one collection cannot silently consume another
        // collection's budget.
        let metadata_bytes = self.metadata.iter().try_fold(0usize, |total, entry| {
            total
                .checked_add(entry.name.len())
                .and_then(|value| value.checked_add(entry.value.len()))
                .filter(|value| *value <= crate::MAX_METADATA_TOTAL_BYTES)
                .ok_or(RequestParseError::Invalid)
        })?;
        let tool_declaration_bytes =
            self.tool_declarations
                .iter()
                .try_fold(0usize, |total, tool| {
                    total
                        .checked_add(tool.name.len())
                        .filter(|value| *value <= crate::MAX_TOOL_DECLARATION_TOTAL_BYTES)
                        .ok_or(RequestParseError::Invalid)
                })?;
        total_message_bytes
            .checked_add(metadata_bytes)
            .and_then(|total| total.checked_add(tool_declaration_bytes))
            .filter(|value| *value <= crate::MAX_REQUEST_BODY_BYTES)
            .ok_or(RequestParseError::Invalid)?;
        Ok(())
    }
}

fn is_token(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn deserialize_bounded_string<'de, D, const MAX: usize>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedStringVisitor<const MAX: usize>;

    impl<const MAX: usize> Visitor<'_> for BoundedStringVisitor<MAX> {
        type Value = String;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a string with at most {MAX} bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if value.len() > MAX {
                return Err(E::custom("string exceeds gateway bound"));
            }
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if value.len() > MAX {
                return Err(E::custom("string exceeds gateway bound"));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_string(BoundedStringVisitor::<MAX>)
}

fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MAX: usize>(std::marker::PhantomData<T>);

    impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence with at most {MAX} elements")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() >= MAX {
                    return Err(DeError::custom("sequence exceeds gateway bound"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(std::marker::PhantomData))
}

fn deserialize_message_content<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_MESSAGE_BYTES>(deserializer)
}

fn deserialize_metadata_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_METADATA_KEY_BYTES>(deserializer)
}

fn deserialize_metadata_value<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_METADATA_VALUE_BYTES>(deserializer)
}

fn deserialize_tool_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string::<D, MAX_METADATA_KEY_BYTES>(deserializer)
}

fn deserialize_messages<'de, D>(deserializer: D) -> Result<Vec<ExternalMessage>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ExternalMessage, MAX_MESSAGES>(deserializer)
}

fn deserialize_metadata<'de, D>(deserializer: D) -> Result<Vec<MetadataEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, MetadataEntry, MAX_METADATA_ENTRIES>(deserializer)
}

fn deserialize_tool_declarations<'de, D>(deserializer: D) -> Result<Vec<ToolDeclaration>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<D, ToolDeclaration, MAX_TOOL_DECLARATIONS>(deserializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(content: &str) -> ExternalMessage {
        ExternalMessage::new(ExternalRole::User, content.to_owned()).unwrap()
    }

    #[test]
    fn public_constructor_enforces_empty_count_and_aggregate_request_limits() {
        assert!(ExternalRequest::new(Vec::new(), Vec::new(), Vec::new()).is_err());

        let exact_messages = (0..MAX_MESSAGES).map(|_| message("x")).collect();
        assert!(ExternalRequest::new(exact_messages, Vec::new(), Vec::new()).is_ok());

        let too_many_messages = (0..=MAX_MESSAGES).map(|_| message("x")).collect();
        assert!(ExternalRequest::new(too_many_messages, Vec::new(), Vec::new()).is_err());

        let exact_payload = (0..4)
            .map(|_| message(&"x".repeat(MAX_MESSAGE_BYTES)))
            .collect();
        assert!(ExternalRequest::new(exact_payload, Vec::new(), Vec::new()).is_ok());

        let over_payload = vec![message(&"x".repeat(MAX_MESSAGE_BYTES)); 4];
        let extra = ExternalRequest::from_json(
            br#"{"messages":[{"role":"user","content":"x"}],"metadata":[{"name":"n","value":"v"}]}"#,
        )
        .unwrap();
        assert_eq!(extra.messages().len(), 1);
        assert!(ExternalRequest::new(over_payload, extra.metadata().to_vec(), Vec::new()).is_err());
    }

    #[test]
    fn wire_accessors_and_strict_fields_preserve_untrusted_data_only() {
        let request = ExternalRequest::from_json(
            br#"{"messages":[{"role":"data","content":"document"}],"metadata":[{"name":"trace","value":"one"}],"tool_declarations":[{"name":"shell"}]}"#,
        )
        .unwrap();
        assert_eq!(request.messages()[0].role(), ExternalRole::Data);
        assert_eq!(request.messages()[0].content(), "document");
        assert_eq!(request.metadata()[0].name(), "trace");
        assert_eq!(request.metadata()[0].value(), "one");
        assert_eq!(request.tool_declarations()[0].name(), "shell");

        for invalid in [
            br#"{"messages":[{"role":"user","content":"x","extra":1}]}"#
                .as_slice(),
            br#"{"messages":[{"role":"user","content":"x"}],"metadata":null}"#
                .as_slice(),
            br#"{"messages":[{"role":"user","content":"x"}],"metadata":[{"name":"","value":"v"}]}"#
                .as_slice(),
            br#"{"messages":[{"role":"user","content":"x"}],"tool_declarations":[{"name":"bad name"}]}"#
                .as_slice(),
        ] {
            assert!(ExternalRequest::from_json(invalid).is_err());
        }
    }

    #[test]
    fn exact_wire_collection_boundaries_and_aggregate_metadata_are_bounded() {
        let messages = (0..MAX_MESSAGES)
            .map(|_| r#"{"role":"user","content":"x"}"#)
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            ExternalRequest::from_json(format!(r#"{{"messages":[{messages}]}}"#).as_bytes())
                .is_ok()
        );

        let metadata = (0..MAX_METADATA_ENTRIES)
            .map(|index| {
                format!(
                    r#"{{"name":"n{index}{}","value":"{}"}}"#,
                    "k".repeat(MAX_METADATA_KEY_BYTES - index.to_string().len() - 1),
                    "v".repeat(MAX_METADATA_VALUE_BYTES)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            ExternalRequest::from_json(
                format!(
                    r#"{{"messages":[{{"role":"user","content":"x"}}],"metadata":[{metadata}]}}"#
                )
                .as_bytes()
            )
            .is_ok()
        );

        let tools = (0..MAX_TOOL_DECLARATIONS)
            .map(|index| format!(r#"{{"name":"tool-{index}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(ExternalRequest::from_json(
            format!(r#"{{"messages":[{{"role":"user","content":"x"}}],"tool_declarations":[{tools}]}}"#)
                .as_bytes()
        )
        .is_ok());

        let exact_sized_tools = (0..MAX_TOOL_DECLARATIONS)
            .map(|index| {
                format!(
                    r#"{{"name":"t{index}{}"}}"#,
                    "k".repeat(MAX_METADATA_KEY_BYTES - index.to_string().len() - 1)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        assert!(ExternalRequest::from_json(
            format!(
                r#"{{"messages":[{{"role":"user","content":"x"}}],"tool_declarations":[{exact_sized_tools}]}}"#
            )
            .as_bytes()
        )
        .is_ok());
    }

    #[test]
    fn owned_string_deserialization_path_enforces_the_same_bound() {
        let exact = serde::de::value::StringDeserializer::<serde_json::Error>::new(
            "x".repeat(MAX_MESSAGE_BYTES),
        );
        assert_eq!(
            deserialize_message_content(exact).unwrap().len(),
            MAX_MESSAGE_BYTES
        );

        let oversized = serde::de::value::StringDeserializer::<serde_json::Error>::new(
            "x".repeat(MAX_MESSAGE_BYTES + 1),
        );
        assert!(deserialize_message_content(oversized).is_err());
    }
}
