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

//! Strict, bounded `OpenAI` Responses wire mapping.

use crate::{
    MAX_FUNCTION_ARGUMENT_BYTES, MAX_PROVIDER_ID_BYTES, MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_CONTENT_ITEMS, MAX_RESPONSE_ITEMS,
};
use serde::de::{Deserializer, Error as DeError, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use tkach_gateway::MAX_MODEL_OUTPUT_BYTES;

pub(crate) const TOOL_NAMES: [&str; 5] = [
    "protected_read",
    "protected_write",
    "external_send",
    "harmless_read",
    "secret_backed_use",
];

/// Payload-free provider wire parsing failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    Invalid,
    DuplicateField,
    TooManyItems,
    StringTooLarge,
    Unsupported,
}

impl Display for ParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid OpenAI provider response")
    }
}

impl std::error::Error for ParseError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParsedResponse {
    pub(crate) id: String,
    pub(crate) items: Vec<ParsedItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ParsedItem {
    Message(String),
    FunctionCall(ParsedFunctionCall),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParsedFunctionCall {
    pub(crate) id: String,
    pub(crate) call_id: String,
    pub(crate) name: String,
    pub(crate) arguments: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConversationItem {
    UserMessage(String),
    AssistantMessage(String),
    FunctionCall(ParsedFunctionCall),
    FunctionCallOutput { call_id: String, output: String },
}

#[derive(Serialize)]
pub(crate) struct ResponsesRequest {
    model: String,
    input: Vec<RequestItem>,
    tools: Vec<FunctionTool>,
    tool_choice: &'static str,
    parallel_tool_calls: bool,
    store: bool,
    background: bool,
}

impl ResponsesRequest {
    pub(crate) fn encode(model: &str, input: Vec<RequestItem>) -> Result<Vec<u8>, ParseError> {
        let request = Self {
            model: model.to_owned(),
            input,
            tools: TOOL_NAMES
                .iter()
                .map(|name| FunctionTool::new(name))
                .collect(),
            tool_choice: "auto",
            parallel_tool_calls: false,
            store: false,
            background: false,
        };
        let body = serde_json::to_vec(&request).map_err(|_| ParseError::Invalid)?;
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(ParseError::StringTooLarge);
        }
        Ok(body)
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum RequestItem {
    UserMessage {
        role: &'static str,
        content: Vec<InputText>,
    },
    AssistantMessage {
        #[serde(rename = "type")]
        kind: &'static str,
        role: &'static str,
        content: Vec<OutputText>,
    },
    FunctionCall {
        #[serde(rename = "type")]
        kind: &'static str,
        id: String,
        call_id: String,
        name: String,
        arguments: String,
    },
    FunctionCallOutput {
        #[serde(rename = "type")]
        kind: &'static str,
        call_id: String,
        output: String,
    },
}

#[derive(Serialize)]
pub(crate) struct InputText {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

#[derive(Serialize)]
pub(crate) struct OutputText {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

#[derive(Serialize)]
struct FunctionTool {
    #[serde(rename = "type")]
    kind: &'static str,
    name: &'static str,
    description: &'static str,
    parameters: Value,
    strict: bool,
}

impl FunctionTool {
    fn new(name: &'static str) -> Self {
        Self {
            kind: "function",
            name,
            description: "Tkach-controlled proposal; authorization remains outside the provider.",
            parameters: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            strict: true,
        }
    }
}

#[cfg(test)]
pub(crate) fn user_message(value: &str) -> RequestItem {
    RequestItem::UserMessage {
        role: "user",
        content: vec![InputText {
            kind: "input_text",
            text: value.to_owned(),
        }],
    }
}

#[cfg(test)]
pub(crate) fn function_call_output(call_id: &str, value: &str) -> RequestItem {
    RequestItem::FunctionCallOutput {
        kind: "function_call_output",
        call_id: call_id.to_owned(),
        output: value.to_owned(),
    }
}

impl ConversationItem {
    pub(crate) fn into_request_item(self) -> RequestItem {
        match self {
            Self::UserMessage(text) => RequestItem::UserMessage {
                role: "user",
                content: vec![InputText {
                    kind: "input_text",
                    text,
                }],
            },
            Self::AssistantMessage(text) => RequestItem::AssistantMessage {
                kind: "message",
                role: "assistant",
                content: vec![OutputText {
                    kind: "output_text",
                    text,
                }],
            },
            Self::FunctionCall(call) => RequestItem::FunctionCall {
                kind: "function_call",
                id: call.id,
                call_id: call.call_id,
                name: call.name,
                arguments: call.arguments,
            },
            Self::FunctionCallOutput { call_id, output } => RequestItem::FunctionCallOutput {
                kind: "function_call_output",
                call_id,
                output,
            },
        }
    }
}

pub(crate) fn user_conversation_item(value: &str) -> ConversationItem {
    ConversationItem::UserMessage(value.to_owned())
}

pub(crate) fn parse_response(body: &[u8]) -> Result<ParsedResponse, ParseError> {
    let wire = serde_json::from_slice::<ResponseWire>(body).map_err(|_| ParseError::Invalid)?;
    if wire.object.as_deref() != Some("response") || wire.status.as_deref() != Some("completed") {
        return Err(ParseError::Unsupported);
    }
    let id = validate_id(wire.id.ok_or(ParseError::Invalid)?)?;
    let output = wire.output.ok_or(ParseError::Invalid)?.0;
    let mut items = Vec::with_capacity(output.len());
    let mut text_bytes = 0usize;
    for item in output {
        match item.into_parsed()? {
            ParsedItem::Message(text) => {
                text_bytes = text_bytes
                    .checked_add(text.len())
                    .ok_or(ParseError::StringTooLarge)?;
                if text_bytes > MAX_MODEL_OUTPUT_BYTES {
                    return Err(ParseError::StringTooLarge);
                }
                items.push(ParsedItem::Message(text));
            }
            ParsedItem::FunctionCall(call) => items.push(ParsedItem::FunctionCall(call)),
        }
    }
    Ok(ParsedResponse { id, items })
}

fn validate_id(value: String) -> Result<String, ParseError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ParseError::Invalid);
    }
    Ok(value)
}

fn validate_name(value: String) -> Result<String, ParseError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ParseError::Invalid);
    }
    Ok(value)
}

struct ResponseWire {
    id: Option<String>,
    object: Option<String>,
    status: Option<String>,
    output: Option<BoundedOutputItems>,
}

impl<'de> Deserialize<'de> for ResponseWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Clone, Copy, Deserialize, Hash, PartialEq, Eq)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Id,
            Object,
            Status,
            Output,
            CreatedAt,
            Error,
            IncompleteDetails,
            Instructions,
            MaxOutputTokens,
            Metadata,
            Model,
            ParallelToolCalls,
            PreviousResponseId,
            Prompt,
            PromptCacheDiagnostics,
            PromptCacheKey,
            PromptCacheOptions,
            Reasoning,
            SafetyIdentifier,
            ServiceTier,
            Store,
            Temperature,
            Text,
            ToolChoice,
            Tools,
            TopLogprobs,
            TopP,
            Truncation,
            Usage,
            User,
            Background,
            CompletedAt,
            Conversation,
        }

        struct ResponseVisitor;

        impl<'de> Visitor<'de> for ResponseVisitor {
            type Value = ResponseWire;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a strict OpenAI response object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut id = None;
                let mut object = None;
                let mut status = None;
                let mut output = None;
                while let Some(field) = map.next_key::<Field>()? {
                    if !seen.insert(field) {
                        return Err(A::Error::custom(ParseError::DuplicateField));
                    }
                    match field {
                        Field::Id => id = Some(map.next_value()?),
                        Field::Object => object = Some(map.next_value()?),
                        Field::Status => status = Some(map.next_value()?),
                        Field::Output => output = Some(map.next_value()?),
                        _ => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(ResponseWire {
                    id,
                    object,
                    status,
                    output,
                })
            }
        }

        deserializer.deserialize_map(ResponseVisitor)
    }
}

struct BoundedOutputItems(Vec<OutputWire>);

impl<'de> Deserialize<'de> for BoundedOutputItems {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ItemsVisitor;

        impl<'de> Visitor<'de> for ItemsVisitor {
            type Value = BoundedOutputItems;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded Responses output array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::with_capacity(MAX_RESPONSE_ITEMS);
                while let Some(item) = sequence.next_element()? {
                    if items.len() >= MAX_RESPONSE_ITEMS {
                        return Err(A::Error::custom(ParseError::TooManyItems));
                    }
                    items.push(item);
                }
                Ok(BoundedOutputItems(items))
            }
        }

        deserializer.deserialize_seq(ItemsVisitor)
    }
}

struct OutputWire {
    kind: Option<String>,
    id: Option<String>,
    status: Option<String>,
    role: Option<String>,
    content: Option<BoundedOutputContents>,
    call_id: Option<String>,
    name: Option<String>,
    arguments: Option<String>,
}

impl OutputWire {
    fn into_parsed(self) -> Result<ParsedItem, ParseError> {
        match self.kind.as_deref() {
            Some("message") => {
                if self.role.as_deref() != Some("assistant")
                    || self
                        .status
                        .as_deref()
                        .is_some_and(|status| status != "completed")
                {
                    return Err(ParseError::Unsupported);
                }
                let content = self.content.ok_or(ParseError::Invalid)?.0;
                let mut text = String::new();
                for item in content {
                    text.push_str(&item.text);
                }
                Ok(ParsedItem::Message(text))
            }
            Some("function_call") => {
                if self
                    .status
                    .as_deref()
                    .is_some_and(|status| status != "completed")
                {
                    return Err(ParseError::Unsupported);
                }
                let id = validate_id(self.id.ok_or(ParseError::Invalid)?)?;
                let call_id = validate_id(self.call_id.ok_or(ParseError::Invalid)?)?;
                let name = validate_name(self.name.ok_or(ParseError::Invalid)?)?;
                let arguments = self.arguments.ok_or(ParseError::Invalid)?;
                if arguments.len() > MAX_FUNCTION_ARGUMENT_BYTES {
                    return Err(ParseError::StringTooLarge);
                }
                let arguments_value: Value =
                    serde_json::from_str(&arguments).map_err(|_| ParseError::Invalid)?;
                if !arguments_value.is_object() {
                    return Err(ParseError::Invalid);
                }
                Ok(ParsedItem::FunctionCall(ParsedFunctionCall {
                    id,
                    call_id,
                    name,
                    arguments,
                }))
            }
            _ => Err(ParseError::Unsupported),
        }
    }
}

impl<'de> Deserialize<'de> for OutputWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Clone, Copy, Deserialize, Hash, PartialEq, Eq)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Type,
            Id,
            Status,
            Role,
            Content,
            CallId,
            Name,
            Arguments,
            Phase,
        }

        struct ItemVisitor;

        impl<'de> Visitor<'de> for ItemVisitor {
            type Value = OutputWire;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a strict Responses output item")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut value = OutputWire {
                    kind: None,
                    id: None,
                    status: None,
                    role: None,
                    content: None,
                    call_id: None,
                    name: None,
                    arguments: None,
                };
                while let Some(field) = map.next_key::<Field>()? {
                    if !seen.insert(field) {
                        return Err(A::Error::custom(ParseError::DuplicateField));
                    }
                    match field {
                        Field::Type => value.kind = Some(map.next_value()?),
                        Field::Id => value.id = Some(map.next_value()?),
                        Field::Status => value.status = Some(map.next_value()?),
                        Field::Role => value.role = Some(map.next_value()?),
                        Field::Content => value.content = Some(map.next_value()?),
                        Field::CallId => value.call_id = Some(map.next_value()?),
                        Field::Name => value.name = Some(map.next_value()?),
                        Field::Arguments => value.arguments = Some(map.next_value()?),
                        Field::Phase => {
                            let _: IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(value)
            }
        }

        deserializer.deserialize_map(ItemVisitor)
    }
}

struct BoundedOutputContents(Vec<OutputContent>);

impl<'de> Deserialize<'de> for BoundedOutputContents {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ContentsVisitor;

        impl<'de> Visitor<'de> for ContentsVisitor {
            type Value = BoundedOutputContents;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded assistant content array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::with_capacity(MAX_RESPONSE_CONTENT_ITEMS);
                while let Some(item) = sequence.next_element()? {
                    if items.len() >= MAX_RESPONSE_CONTENT_ITEMS {
                        return Err(A::Error::custom(ParseError::TooManyItems));
                    }
                    items.push(item);
                }
                Ok(BoundedOutputContents(items))
            }
        }

        deserializer.deserialize_seq(ContentsVisitor)
    }
}

struct OutputContent {
    text: String,
}

impl<'de> Deserialize<'de> for OutputContent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Clone, Copy, Deserialize, Hash, PartialEq, Eq)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Type,
            Text,
            Annotations,
            Logprobs,
        }

        struct ContentVisitor;

        impl<'de> Visitor<'de> for ContentVisitor {
            type Value = OutputContent;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a strict assistant output-text item")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut kind = None;
                let mut text = None;
                while let Some(field) = map.next_key::<Field>()? {
                    if !seen.insert(field) {
                        return Err(A::Error::custom(ParseError::DuplicateField));
                    }
                    match field {
                        Field::Type => kind = Some(map.next_value::<String>()?),
                        Field::Text => text = Some(map.next_value::<String>()?),
                        Field::Annotations | Field::Logprobs => {
                            let _: EmptyArray = map.next_value()?;
                        }
                    }
                }
                if kind.as_deref() != Some("output_text") {
                    return Err(A::Error::custom(ParseError::Unsupported));
                }
                let text = text.ok_or_else(|| A::Error::custom(ParseError::Invalid))?;
                if text.len() > MAX_MODEL_OUTPUT_BYTES {
                    return Err(A::Error::custom(ParseError::StringTooLarge));
                }
                Ok(OutputContent { text })
            }
        }

        deserializer.deserialize_map(ContentVisitor)
    }
}

struct EmptyArray;

impl<'de> Deserialize<'de> for EmptyArray {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EmptyArrayVisitor;

        impl<'de> Visitor<'de> for EmptyArrayVisitor {
            type Value = EmptyArray;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an empty array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom(ParseError::Unsupported));
                }
                Ok(EmptyArray)
            }
        }

        deserializer.deserialize_seq(EmptyArrayVisitor)
    }
}

impl Serialize for ConversationItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.clone().into_request_item().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(output: &str) -> Vec<u8> {
        format!(
            r#"{{"id":"resp_test_1","object":"response","status":"completed","output":{output}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn normal_text_is_parsed_and_unknown_items_fail_closed() {
        let parsed = parse_response(&response(
            r#"[{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"hello","annotations":[],"logprobs":[]}]}]"#,
        ))
        .unwrap();
        assert_eq!(parsed.id, "resp_test_1");
        assert_eq!(parsed.items, vec![ParsedItem::Message("hello".to_owned())]);

        assert_eq!(
            parse_response(&response(r#"[{"type":"web_search_call","id":"search_1"}]"#,)),
            Err(ParseError::Unsupported)
        );
    }

    #[test]
    fn committed_fixtures_cover_normal_and_hostile_response_shapes() {
        let normal = parse_response(include_bytes!("../fixtures/normal_text.json")).unwrap();
        assert_eq!(normal.id, "resp_fixture_text");
        assert_eq!(
            normal.items,
            vec![ParsedItem::Message("bounded fixture response".to_owned())]
        );

        assert!(matches!(
            parse_response(include_bytes!("../fixtures/function_call.json"))
                .unwrap()
                .items
                .as_slice(),
            [ParsedItem::FunctionCall(_)]
        ));
        assert_eq!(
            parse_response(include_bytes!("../fixtures/unknown_item.json")),
            Err(ParseError::Unsupported)
        );
        assert_eq!(
            parse_response(include_bytes!("../fixtures/duplicate_field.json")),
            Err(ParseError::Invalid)
        );
        assert!(parse_response(include_bytes!("../fixtures/incomplete_response.json")).is_err());
        assert!(parse_response(include_bytes!("../fixtures/provider_error.json")).is_err());
    }

    #[test]
    fn function_calls_require_complete_known_shape_and_bound_arguments() {
        let parsed = parse_response(&response(
            r#"[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"protected_read","arguments":"{}","status":"completed"}]"#,
        ))
        .unwrap();
        assert!(matches!(parsed.items[0], ParsedItem::FunctionCall(_)));

        for output in [
            r#"[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"protected_read","arguments":"{\"x\":1}","status":"completed","name":"duplicate"}]"#,
            r#"[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"protected_read","arguments":"[]","status":"completed"}]"#,
            r#"[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"protected_read","arguments":"{}","status":"in_progress"}]"#,
        ] {
            assert!(parse_response(&response(output)).is_err());
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn parser_rejects_identity_status_argument_and_output_boundaries() {
        for output in [
            r#"[{"type":"message","id":"msg_1","status":"completed","role":"user","content":[{"type":"output_text","text":"x"}]}]"#,
            r#"[{"type":"message","id":"msg_1","status":"in_progress","role":"assistant","content":[{"type":"output_text","text":"x"}]}]"#,
            r#"[{"type":"function_call","id":"bad/id","call_id":"call_1","name":"harmless_read","arguments":"{}","status":"completed"}]"#,
            r#"[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"bad/name","arguments":"{}","status":"completed"}]"#,
        ] {
            assert!(parse_response(&response(output)).is_err());
        }

        let exact_argument_value = format!(
            r#"{{"x":"{}"}}"#,
            "x".repeat(MAX_FUNCTION_ARGUMENT_BYTES - 8)
        );
        assert_eq!(exact_argument_value.len(), MAX_FUNCTION_ARGUMENT_BYTES);
        let exact_arguments = format!(
            r#"[{{"type":"function_call","id":"fc_exact","call_id":"call_exact","name":"harmless_read","arguments":{},"status":"completed"}}]"#,
            serde_json::to_string(&exact_argument_value).unwrap()
        );
        assert!(parse_response(&response(&exact_arguments)).is_ok());
        let oversized_argument_value = format!(
            r#"{{"x":"{}"}}"#,
            "x".repeat(MAX_FUNCTION_ARGUMENT_BYTES - 7)
        );
        let oversized_arguments = format!(
            r#"[{{"type":"function_call","id":"fc_large","call_id":"call_large","name":"harmless_read","arguments":{},"status":"completed"}}]"#,
            serde_json::to_string(&oversized_argument_value).unwrap()
        );
        assert!(parse_response(&response(&oversized_arguments)).is_err());

        let oversized_text = format!(
            r#"[{{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{{"type":"output_text","text":"{}"}}]}}]"#,
            "x".repeat(MAX_MODEL_OUTPUT_BYTES + 1)
        );
        assert!(parse_response(&response(&oversized_text)).is_err());

        let oversized_id = format!(
            r#"{{"id":"{}","object":"response","status":"completed","output":[]}}"#,
            "i".repeat(MAX_PROVIDER_ID_BYTES + 1)
        );
        assert!(parse_response(oversized_id.as_bytes()).is_err());
        let exact_id = format!(
            r#"{{"id":"{}","object":"response","status":"completed","output":[]}}"#,
            "i".repeat(MAX_PROVIDER_ID_BYTES)
        );
        assert!(parse_response(exact_id.as_bytes()).is_ok());

        let exact_name = format!(
            r#"[{{"type":"function_call","id":"fc_name","call_id":"call_name","name":"{}","arguments":"{{}}","status":"completed"}}]"#,
            "n".repeat(MAX_PROVIDER_ID_BYTES)
        );
        assert!(parse_response(&response(&exact_name)).is_ok());
        let oversized_name = format!(
            r#"[{{"type":"function_call","id":"fc_name_large","call_id":"call_name_large","name":"{}","arguments":"{{}}","status":"completed"}}]"#,
            "n".repeat(MAX_PROVIDER_ID_BYTES + 1)
        );
        assert!(parse_response(&response(&oversized_name)).is_err());

        let exact_text = "x".repeat(MAX_MODEL_OUTPUT_BYTES);
        let exact_text_response = response(
            &serde_json::json!([{
                "type": "message",
                "id": "msg_exact",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": exact_text}]
            }])
            .to_string(),
        );
        assert!(parse_response(&exact_text_response).is_ok());

        let half = MAX_MODEL_OUTPUT_BYTES / 2;
        let aggregate_exact = response(
            &serde_json::json!([
                {
                    "type": "message",
                    "id": "msg_a",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "a".repeat(half)}]
                },
                {
                    "type": "message",
                    "id": "msg_b",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "b".repeat(MAX_MODEL_OUTPUT_BYTES - half)}]
                }
            ])
            .to_string(),
        );
        assert!(parse_response(&aggregate_exact).is_ok());
        let aggregate_over = response(
            &serde_json::json!([
                {
                    "type": "message",
                    "id": "msg_a2",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "a".repeat(half)}]
                },
                {
                    "type": "message",
                    "id": "msg_b2",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "b".repeat(MAX_MODEL_OUTPUT_BYTES - half + 1)}]
                }
            ])
            .to_string(),
        );
        assert!(parse_response(&aggregate_over).is_err());
    }

    #[test]
    fn request_and_response_budgets_fail_closed_at_serialization_boundary() {
        let oversized = "x".repeat(MAX_REQUEST_BODY_BYTES);
        assert!(ResponsesRequest::encode("gpt-4.1-mini", vec![user_message(&oversized)]).is_err());

        let mut low = 0;
        let mut high = MAX_REQUEST_BODY_BYTES;
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if ResponsesRequest::encode("gpt-4.1-mini", vec![user_message(&"x".repeat(middle))])
                .is_ok()
            {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        let exact =
            ResponsesRequest::encode("gpt-4.1-mini", vec![user_message(&"x".repeat(low))]).unwrap();
        assert_eq!(exact.len(), MAX_REQUEST_BODY_BYTES);
        assert!(
            ResponsesRequest::encode("gpt-4.1-mini", vec![user_message(&"x".repeat(low + 1))])
                .is_err()
        );
    }

    #[test]
    fn duplicate_top_level_fields_and_response_items_are_rejected() {
        let duplicate = br#"{"id":"resp_1","id":"resp_2","object":"response","status":"completed","output":[]}"#;
        assert_eq!(parse_response(duplicate), Err(ParseError::Invalid));

        let too_many = format!(
            "{{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[{}]}}",
            (0..=MAX_RESPONSE_ITEMS)
                .map(|_| r#"{"type":"message","role":"assistant","content":[{"type":"output_text","text":"x"}]}"#)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(parse_response(too_many.as_bytes()).is_err());
    }

    #[test]
    fn requests_explicitly_disable_provider_persistence_and_built_ins() {
        let body = ResponsesRequest::encode("gpt-4.1-mini", vec![user_message("hello")]).unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["store"], false);
        assert_eq!(value["background"], false);
        assert_eq!(value["parallel_tool_calls"], false);
        assert_eq!(value["tools"].as_array().unwrap().len(), TOOL_NAMES.len());
        assert!(
            value["tools"]
                .as_array()
                .unwrap()
                .iter()
                .all(|tool| tool["type"] == "function" && tool["strict"] == true)
        );
        assert!(
            !body
                .windows(b"web_search".len())
                .any(|window| window == b"web_search")
        );
    }

    #[test]
    fn conversation_items_are_data_only_representations() {
        let call = ParsedFunctionCall {
            id: "fc_1".to_owned(),
            call_id: "call_1".to_owned(),
            name: "protected_read".to_owned(),
            arguments: "{}".to_owned(),
        };
        let body = ResponsesRequest::encode(
            "gpt-4.1-mini",
            vec![
                ConversationItem::FunctionCall(call).into_request_item(),
                function_call_output("call_1", "protected-data"),
            ],
        )
        .unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("function_call_output")
        );
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("protected-data")
        );
    }
}
