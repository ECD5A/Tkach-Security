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

//! `OpenAI` Responses API implementation of the provider-only Gateway trait.

use crate::MAX_CONVERSATION_ITEMS;
use crate::config::{ConfigError, OpenAiConfig};
use crate::transport::{ReqwestTransport, Transport, TransportError};
use crate::wire::{
    self, ConversationItem, ParseError, ParsedFunctionCall, ParsedItem, ResponsesRequest,
    TOOL_NAMES,
};
use std::collections::{BTreeSet, HashSet};
use std::fmt::{Debug, Formatter};
use tkach_core::domain::{ActionRequest, Operation};
use tkach_gateway::{
    MAX_PROVIDER_CHUNK_BYTES, MAX_TOOL_RESULT_BYTES, ModelInput, Provider, ProviderError,
    ProviderRequest, ProviderSink, ProviderStep, external_send_request, harmless_read_request,
    protected_read_request, protected_write_request, secret_use_request,
};

const MAX_REPLAY_IDENTIFIERS: usize = 4_096;

/// A synchronous `OpenAI` Responses API provider.
///
/// The adapter is intentionally a thin wire boundary. It can create only raw
/// `ActionRequest` proposals for the Gateway sink; it has no Krosna, Propusk,
/// executor, Pechat, or release capability.
pub struct OpenAiProvider {
    config: OpenAiConfig,
    transport: Box<dyn Transport>,
    history: Vec<ConversationItem>,
    pending_call_ids: Vec<String>,
    tool_inputs_seen: usize,
    expected_turn: usize,
    seen_response_ids: BTreeSet<String>,
    seen_call_ids: BTreeSet<String>,
}

impl Debug for OpenAiProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenAiProvider")
            .field("config", &self.config)
            .field("history_count", &self.history.len())
            .field("pending_call_count", &self.pending_call_ids.len())
            .field("expected_turn", &self.expected_turn)
            .field("seen_response_count", &self.seen_response_ids.len())
            .field("seen_call_count", &self.seen_call_ids.len())
            .finish_non_exhaustive()
    }
}

impl OpenAiProvider {
    /// Construct a provider with the mature HTTPS transport and trusted
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns a static configuration error if the HTTPS client cannot be
    /// initialized. The credential is never included in that error.
    pub fn new(config: OpenAiConfig) -> Result<Self, ConfigError> {
        let transport =
            ReqwestTransport::new(&config).map_err(|_| ConfigError::HttpClientUnavailable)?;
        Ok(Self::with_transport(config, Box::new(transport)))
    }

    /// Load `OPENAI_API_KEY` and construct a provider for a trusted model
    /// label.
    ///
    /// # Errors
    ///
    /// Returns a static configuration error for missing credentials or invalid
    /// trusted configuration.
    pub fn from_env(model: impl Into<String>) -> Result<Self, ConfigError> {
        Self::new(OpenAiConfig::from_env(model)?)
    }

    fn with_transport(config: OpenAiConfig, transport: Box<dyn Transport>) -> Self {
        Self {
            config,
            transport,
            history: Vec::new(),
            pending_call_ids: Vec::new(),
            tool_inputs_seen: 0,
            expected_turn: 0,
            seen_response_ids: BTreeSet::new(),
            seen_call_ids: BTreeSet::new(),
        }
    }

    fn reset_lifecycle(&mut self) {
        self.history.clear();
        self.pending_call_ids.clear();
        self.tool_inputs_seen = 0;
        self.expected_turn = 0;
    }

    fn validate_tool_catalog(request: &ProviderRequest) -> Result<(), ProviderError> {
        if request.tools().len() != TOOL_NAMES.len()
            || request
                .tools()
                .iter()
                .zip(TOOL_NAMES)
                .any(|(actual, expected)| actual.name() != expected)
        {
            return Err(ProviderError::Malformed);
        }
        Ok(())
    }

    fn seed_history(&mut self, request: &ProviderRequest) -> Result<(), ProviderError> {
        if request
            .inputs()
            .iter()
            .any(|input| matches!(input, ModelInput::Tool(_)))
        {
            return Err(ProviderError::Malformed);
        }
        self.history = request
            .inputs()
            .iter()
            .map(|input| wire::user_conversation_item(input.text()))
            .collect();
        if self.history.len() > MAX_CONVERSATION_ITEMS {
            return Err(ProviderError::OutputLimitExceeded);
        }
        Ok(())
    }

    fn append_tool_results(&mut self, request: &ProviderRequest) -> Result<(), ProviderError> {
        let tool_inputs: Vec<&ModelInput> = request
            .inputs()
            .iter()
            .filter(|input| matches!(input, ModelInput::Tool(_)))
            .collect();
        if tool_inputs.len() < self.tool_inputs_seen {
            return Err(ProviderError::Malformed);
        }
        let new_inputs = &tool_inputs[self.tool_inputs_seen..];
        if new_inputs.len() != self.pending_call_ids.len() || new_inputs.is_empty() {
            return Err(ProviderError::Malformed);
        }
        if self.history.len().saturating_add(new_inputs.len()) > MAX_CONVERSATION_ITEMS {
            return Err(ProviderError::OutputLimitExceeded);
        }
        if new_inputs
            .iter()
            .any(|input| input.text().len() > MAX_TOOL_RESULT_BYTES)
        {
            return Err(ProviderError::OutputLimitExceeded);
        }
        let pending_call_ids = std::mem::take(&mut self.pending_call_ids);
        for (input, call_id) in new_inputs.iter().zip(pending_call_ids) {
            self.history.push(ConversationItem::FunctionCallOutput {
                call_id,
                output: input.text().to_owned(),
            });
        }
        self.tool_inputs_seen = tool_inputs.len();
        Ok(())
    }

    fn request_body(&self) -> Result<Vec<u8>, ProviderError> {
        let input = self
            .history
            .iter()
            .cloned()
            .map(ConversationItem::into_request_item)
            .collect();
        ResponsesRequest::encode(self.config.model(), input).map_err(map_parse_error)
    }

    fn validate_replay_state(&self, response: &wire::ParsedResponse) -> Result<(), ProviderError> {
        if self.seen_response_ids.contains(&response.id)
            || self.seen_response_ids.len() >= MAX_REPLAY_IDENTIFIERS
        {
            return Err(ProviderError::Malformed);
        }
        let mut call_ids = HashSet::new();
        for item in &response.items {
            if let ParsedItem::FunctionCall(call) = item {
                if !call_ids.insert(call.call_id.as_str())
                    || self.seen_call_ids.contains(&call.call_id)
                    || self.seen_call_ids.len() >= MAX_REPLAY_IDENTIFIERS
                {
                    return Err(ProviderError::Malformed);
                }
            }
        }
        Ok(())
    }

    fn stage_response(
        &mut self,
        response: wire::ParsedResponse,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        self.validate_replay_state(&response)?;
        let mut actions = Vec::new();
        for item in &response.items {
            if let ParsedItem::FunctionCall(call) = item {
                actions.push(action_for_call(call)?);
            }
        }
        for item in &response.items {
            match item {
                ParsedItem::Message(text) => stage_text(sink, text)?,
                ParsedItem::FunctionCall(_) => {}
            }
        }
        for action in &actions {
            sink.action(action.clone())
                .map_err(|_| ProviderError::OutputLimitExceeded)?;
        }

        if self.history.len().saturating_add(response.items.len()) > MAX_CONVERSATION_ITEMS {
            return Err(ProviderError::OutputLimitExceeded);
        }
        let pending_call_ids: Vec<String> = response
            .items
            .iter()
            .filter_map(|item| match item {
                ParsedItem::FunctionCall(call) => Some(call.call_id.clone()),
                ParsedItem::Message(_) => None,
            })
            .collect();
        self.history
            .extend(response.items.iter().map(|item| match item {
                ParsedItem::Message(text) => ConversationItem::AssistantMessage(text.clone()),
                ParsedItem::FunctionCall(call) => ConversationItem::FunctionCall(call.clone()),
            }));
        self.seen_response_ids.insert(response.id);
        self.seen_call_ids.extend(pending_call_ids.iter().cloned());

        let all_reads = !actions.is_empty()
            && actions
                .iter()
                .all(|action| action.operation() == &Operation::Read);
        if all_reads {
            self.pending_call_ids = pending_call_ids;
            self.expected_turn = self.expected_turn.saturating_add(1);
            Ok(ProviderStep::AwaitToolResults)
        } else {
            Ok(ProviderStep::Complete)
        }
    }
}

impl Provider for OpenAiProvider {
    fn invoke(
        &mut self,
        request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        if request.turn() == 0 {
            self.reset_lifecycle();
            Self::validate_tool_catalog(request)?;
            self.seed_history(request)?;
        } else {
            if request.turn() != self.expected_turn {
                return Err(ProviderError::Malformed);
            }
            Self::validate_tool_catalog(request)?;
            self.append_tool_results(request)?;
        }
        let body = self.request_body()?;
        let response_body = self
            .transport
            .post(&self.config, &body)
            .map_err(map_transport_error)?;
        let response = wire::parse_response(&response_body).map_err(map_parse_error)?;
        self.stage_response(response, sink)
    }
}

fn action_for_call(call: &ParsedFunctionCall) -> Result<ActionRequest, ProviderError> {
    let arguments: serde_json::Value =
        serde_json::from_str(&call.arguments).map_err(|_| ProviderError::Malformed)?;
    if !arguments.as_object().is_some_and(serde_json::Map::is_empty) {
        return Err(ProviderError::Malformed);
    }
    match call.name.as_str() {
        "protected_read" => Ok(protected_read_request()),
        "protected_write" => Ok(protected_write_request()),
        "external_send" => Ok(external_send_request()),
        "harmless_read" => Ok(harmless_read_request()),
        "secret_backed_use" => Ok(secret_use_request()),
        _ => Err(ProviderError::Malformed),
    }
}

fn stage_text(sink: &mut dyn ProviderSink, text: &str) -> Result<(), ProviderError> {
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + MAX_PROVIDER_CHUNK_BYTES).min(text.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Err(ProviderError::Malformed);
        }
        sink.text_chunk(&text[start..end])
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        start = end;
    }
    Ok(())
}

fn map_transport_error(error: TransportError) -> ProviderError {
    match error {
        TransportError::Timeout => ProviderError::Timeout,
        TransportError::ResponseTooLarge => ProviderError::OutputLimitExceeded,
        TransportError::HttpStatus | TransportError::Read | TransportError::ClientUnavailable => {
            ProviderError::Failed
        }
    }
}

fn map_parse_error(error: ParseError) -> ProviderError {
    match error {
        ParseError::StringTooLarge | ParseError::TooManyItems => ProviderError::OutputLimitExceeded,
        ParseError::Invalid | ParseError::DuplicateField | ParseError::Unsupported => {
            ProviderError::Malformed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OpenAiConfig;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use tkach_core::diode::{Diode, FlowMatcher, FlowOperation, FlowRule, FlowSource};
    use tkach_core::domain::{
        CapabilityName, Classification, Destination, Identity, Resource, ResourceId, ResourceKind,
        ResourceScope, RuleId,
    };
    use tkach_core::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};
    use tkach_core::propusk::{ExecutionError, Propusk, ProtectedExecutor};
    use tkach_core::zaslon::Zaslon;
    use tkach_gateway::{
        ExternalMessage, ExternalRequest, ExternalRole, FakeToolBroker, Gateway, GatewayErrorKind,
        ProviderSinkError, ToolResult,
    };

    type FakeResponse = Result<Vec<u8>, TransportError>;

    #[derive(Clone)]
    struct FakeTransport {
        responses: Arc<Mutex<Vec<FakeResponse>>>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Transport for FakeTransport {
        fn post(&self, _config: &OpenAiConfig, body: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.requests.lock().unwrap().push(body.to_vec());
            self.responses.lock().unwrap().remove(0)
        }
    }

    fn provider_with(
        responses: Vec<Result<Vec<u8>, TransportError>>,
    ) -> (OpenAiProvider, Arc<Mutex<Vec<Vec<u8>>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let transport = FakeTransport {
            responses: Arc::new(Mutex::new(responses)),
            requests: requests.clone(),
        };
        let config = OpenAiConfig::new("sk-test-only", "gpt-4.1-mini").unwrap();
        (
            OpenAiProvider::with_transport(config, Box::new(transport)),
            requests,
        )
    }

    fn request(turn: usize, inputs: Vec<ModelInput>) -> ProviderRequest {
        ProviderRequest::new(inputs, Vec::new(), turn)
    }

    fn response(id: &str, output: &str) -> Vec<u8> {
        format!(r#"{{"id":"{id}","object":"response","status":"completed","output":{output}}}"#)
            .into_bytes()
    }

    struct SharedBroker {
        broker: Rc<RefCell<FakeToolBroker>>,
    }

    impl ProtectedExecutor for SharedBroker {
        type Output = ToolResult;

        fn execute(&mut self, action: Propusk) -> Result<Self::Output, ExecutionError> {
            self.broker.borrow_mut().execute(action)
        }
    }

    fn gateway_for_status_read() -> (Gateway, Rc<RefCell<FakeToolBroker>>) {
        let status = Resource::new(
            ResourceKind::Database,
            ResourceId::new("status").expect("static status resource is valid"),
        );
        let client =
            Destination::Internal(Identity::new("client").expect("static client is valid"));
        let policy = Policy::new(
            tkach_core::domain::PolicyId::new("provider-integration-policy")
                .expect("static policy id is valid"),
            vec![PolicyRule::allow(
                RuleId::new("allow-status-read").expect("static rule id is valid"),
                RuleMatcher::any()
                    .principal(tkach_core::domain::Principal::Model)
                    .operation(Operation::Read)
                    .capability(CapabilityName::new("database.read").unwrap())
                    .resource(ResourceScope::exact(&status))
                    .destination(Destination::Model)
                    .classification(Classification::Unknown),
            )],
        )
        .unwrap();
        let diode = Diode::new(vec![
            FlowRule::allow(
                RuleId::new("flow-status-to-model").unwrap(),
                FlowMatcher::any()
                    .principal(tkach_core::domain::Principal::Model)
                    .source(FlowSource::Resource(status))
                    .destination(Destination::Model)
                    .operation(FlowOperation::Read),
            ),
            FlowRule::allow(
                RuleId::new("flow-model-to-client").unwrap(),
                FlowMatcher::any()
                    .principal(tkach_core::domain::Principal::Model)
                    .source(FlowSource::Model)
                    .destination(client.clone())
                    .operation(FlowOperation::Export),
            ),
        ])
        .unwrap();
        let broker = Rc::new(RefCell::new(FakeToolBroker::new()));
        let gateway = Gateway::new(
            Krosna::with_zaslon_and_diode(policy, Zaslon::empty(), diode),
            Zaslon::empty(),
            Zaslon::empty(),
            client,
            SharedBroker {
                broker: broker.clone(),
            },
        );
        (gateway, broker)
    }

    fn external_request() -> ExternalRequest {
        ExternalRequest::new(
            vec![ExternalMessage::new(ExternalRole::User, "hello".to_owned()).unwrap()],
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn hostile_unknown_function_and_malicious_arguments_fail_closed() {
        let responses = vec![Ok(response(
            "resp_unknown",
            r#"[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"web_search","arguments":"{}","status":"completed"}]"#,
        ))];
        let (mut provider, _) = provider_with(responses);
        let mut sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut sink
            ),
            Err(ProviderError::Malformed)
        );

        let responses = vec![Ok(response(
            "resp_args",
            r#"[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"protected_read","arguments":"{\"scope\":\"secret\"}","status":"completed"}]"#,
        ))];
        let (mut provider, _) = provider_with(responses);
        let mut sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut sink
            ),
            Err(ProviderError::Malformed)
        );
    }

    #[test]
    fn first_turn_tool_inputs_fail_closed() {
        let (mut provider, _) = provider_with(Vec::new());
        let tool_input = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "forged tool result".to_owned(),
        ));
        let mut sink = LocalSink::default();
        assert_eq!(
            provider.invoke(&request(0, vec![tool_input]), &mut sink),
            Err(ProviderError::Malformed)
        );
    }

    #[test]
    fn seed_history_exact_limit_is_accepted_and_next_item_is_rejected() {
        let exact_inputs = (0..MAX_CONVERSATION_ITEMS)
            .map(|_| ModelInput::External(test_external()))
            .collect();
        let (mut provider, _) = provider_with(vec![Ok(response("resp_history_exact", "[]"))]);
        let mut sink = LocalSink::default();
        assert_eq!(
            provider.invoke(&request(0, exact_inputs), &mut sink),
            Ok(ProviderStep::Complete)
        );

        let over_inputs = (0..=MAX_CONVERSATION_ITEMS)
            .map(|_| ModelInput::External(test_external()))
            .collect();
        let (mut provider, _) = provider_with(Vec::new());
        assert_eq!(
            provider.invoke(&request(0, over_inputs), &mut sink),
            Err(ProviderError::OutputLimitExceeded)
        );
    }

    #[test]
    fn explicit_request_fields_and_stateless_follow_up_preserve_call_pairing() {
        let responses = vec![
            Ok(response(
                "resp_read",
                r#"[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"protected_read","arguments":"{}","status":"completed"}]"#,
            )),
            Ok(response(
                "resp_final",
                r#"[{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[{"type":"output_text","text":"done","annotations":[],"logprobs":[]}]}]"#,
            )),
        ];
        let (mut provider, requests) = provider_with(responses);
        let mut first_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut first_sink
            ),
            Ok(ProviderStep::AwaitToolResults)
        );
        let tool = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "protected result".to_owned(),
        ));
        let mut second_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(1, vec![ModelInput::External(test_external()), tool]),
                &mut second_sink,
            ),
            Ok(ProviderStep::Complete)
        );
        let request_body = String::from_utf8(requests.lock().unwrap()[1].clone()).unwrap();
        assert!(request_body.contains("store"));
        assert!(request_body.contains("\"store\":false"));
        assert!(request_body.contains("function_call_output"));
        assert!(request_body.contains("call_1"));
        assert!(request_body.contains("protected result"));
    }

    #[test]
    fn follow_up_requires_exactly_the_pending_tool_results() {
        let first = response(
            "resp_follow_up_shape",
            r#"[{"type":"function_call","id":"fc_follow_up","call_id":"call_follow_up","name":"harmless_read","arguments":"{}","status":"completed"}]"#,
        );
        for follow_up in [
            Vec::new(),
            vec![
                ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
                    "one".to_owned(),
                )),
                ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
                    "two".to_owned(),
                )),
            ],
        ] {
            let (mut provider, _) = provider_with(vec![Ok(first.clone())]);
            let mut sink = LocalSink::default();
            assert_eq!(
                provider.invoke(
                    &request(0, vec![ModelInput::External(test_external())]),
                    &mut sink,
                ),
                Ok(ProviderStep::AwaitToolResults)
            );
            let mut follow_up_sink = LocalSink::default();
            let inputs = std::iter::once(ModelInput::External(test_external()))
                .chain(follow_up)
                .collect();
            assert_eq!(
                provider.invoke(&request(1, inputs), &mut follow_up_sink),
                Err(ProviderError::Malformed)
            );
        }

        let (mut provider, _) =
            provider_with(vec![Ok(first), Ok(response("resp_follow_up_final", "[]"))]);
        let mut first_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut first_sink,
            ),
            Ok(ProviderStep::AwaitToolResults)
        );
        let valid = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "status=ok".to_owned(),
        ));
        let mut final_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(1, vec![ModelInput::External(test_external()), valid]),
                &mut final_sink,
            ),
            Ok(ProviderStep::Complete)
        );
        assert_eq!(
            provider.invoke(
                &request(1, vec![ModelInput::External(test_external())]),
                &mut final_sink,
            ),
            Err(ProviderError::Malformed)
        );
    }

    #[test]
    fn follow_up_history_limit_accepts_exact_boundary_and_rejects_next_item() {
        let (mut exact_provider, _) =
            provider_with(vec![Ok(response("resp_history_follow_up_exact", "[]"))]);
        exact_provider.history = (0..(MAX_CONVERSATION_ITEMS - 1))
            .map(|_| ConversationItem::UserMessage("x".to_owned()))
            .collect();
        exact_provider
            .pending_call_ids
            .push("call_exact_history".to_owned());
        exact_provider.expected_turn = 1;
        let exact_tool = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "x".to_owned(),
        ));
        let mut sink = LocalSink::default();
        assert_eq!(
            exact_provider.invoke(
                &request(1, vec![ModelInput::External(test_external()), exact_tool]),
                &mut sink,
            ),
            Ok(ProviderStep::Complete)
        );

        let (mut over_provider, _) = provider_with(Vec::new());
        over_provider.history = (0..MAX_CONVERSATION_ITEMS)
            .map(|_| ConversationItem::UserMessage("x".to_owned()))
            .collect();
        over_provider
            .pending_call_ids
            .push("call_over_history".to_owned());
        over_provider.expected_turn = 1;
        let over_tool = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "x".to_owned(),
        ));
        assert_eq!(
            over_provider.invoke(
                &request(1, vec![ModelInput::External(test_external()), over_tool]),
                &mut sink,
            ),
            Err(ProviderError::OutputLimitExceeded)
        );
    }

    #[test]
    fn follow_up_accepts_one_new_result_after_prior_tool_items() {
        let (mut provider, _) = provider_with(vec![Ok(response("resp_prior_tool", "[]"))]);
        provider
            .history
            .push(ConversationItem::UserMessage("old".to_owned()));
        provider
            .pending_call_ids
            .push("call_new_after_old".to_owned());
        provider.tool_inputs_seen = 1;
        provider.expected_turn = 1;
        let old_tool = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "old-result".to_owned(),
        ));
        let new_tool = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "new-result".to_owned(),
        ));
        let mut sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(
                    1,
                    vec![ModelInput::External(test_external()), old_tool, new_tool],
                ),
                &mut sink,
            ),
            Ok(ProviderStep::Complete)
        );
    }

    #[test]
    fn response_and_call_identifier_capacity_is_fail_closed() {
        let (mut response_provider, _) = provider_with(vec![Ok(response(
            "resp_capacity",
            r#"[{"type":"message","id":"msg_capacity","status":"completed","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]"#,
        ))]);
        response_provider
            .seen_response_ids
            .extend((0..MAX_REPLAY_IDENTIFIERS).map(|index| format!("resp_{index}")));
        let mut sink = LocalSink::default();
        assert_eq!(
            response_provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut sink,
            ),
            Err(ProviderError::Malformed)
        );

        let (mut call_provider, _) = provider_with(vec![Ok(response(
            "resp_call_capacity",
            r#"[{"type":"function_call","id":"fc_capacity","call_id":"call_capacity","name":"harmless_read","arguments":"{}","status":"completed"}]"#,
        ))]);
        call_provider
            .seen_call_ids
            .extend((0..MAX_REPLAY_IDENTIFIERS).map(|index| format!("call_{index}")));
        assert_eq!(
            call_provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut sink,
            ),
            Err(ProviderError::Malformed)
        );
    }

    #[test]
    fn lifecycle_reset_discards_stale_pending_tool_state() {
        let (mut provider, _) = provider_with(vec![
            Ok(response(
                "resp_reset_read",
                r#"[{"type":"function_call","id":"fc_reset","call_id":"call_reset","name":"harmless_read","arguments":"{}","status":"completed"}]"#,
            )),
            Ok(response(
                "resp_reset_final",
                r#"[{"type":"message","id":"msg_reset_final","status":"completed","role":"assistant","content":[{"type":"output_text","text":"reset"}]}]"#,
            )),
        ]);
        provider.pending_call_ids.push("stale_call".to_owned());
        provider.tool_inputs_seen = 1;
        provider.expected_turn = 9;
        let mut first_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut first_sink,
            ),
            Ok(ProviderStep::AwaitToolResults)
        );
        let mut final_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(
                    1,
                    vec![
                        ModelInput::External(test_external()),
                        ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
                            "status=ok".to_owned(),
                        )),
                    ],
                ),
                &mut final_sink,
            ),
            Ok(ProviderStep::Complete)
        );
    }

    #[test]
    fn real_provider_path_executes_only_after_gateway_authorization() {
        let responses = vec![
            Ok(include_bytes!("../fixtures/function_call.json").to_vec()),
            Ok(response(
                "resp_fixture_final",
                r#"[{"type":"message","id":"msg_fixture_final","status":"completed","role":"assistant","content":[{"type":"output_text","text":"done","annotations":[],"logprobs":[] }]}]"#,
            )),
        ];
        let (mut provider, _) = provider_with(responses);
        let (mut gateway, broker) = gateway_for_status_read();
        let result = gateway.run(&mut provider, &external_request()).unwrap();
        assert_eq!(result.output(), Some("done"));
        assert_eq!(broker.borrow().read_count(), 1);

        let (mut hostile_provider, _) = provider_with(vec![Ok(response(
            "resp_fixture_denied",
            r#"[{"type":"function_call","id":"fc_denied","call_id":"call_denied","name":"external_send","arguments":"{}","status":"completed"}]"#,
        ))]);
        let (mut denying_gateway, denied_broker) = gateway_for_status_read();
        let error = denying_gateway
            .run(&mut hostile_provider, &external_request())
            .unwrap_err();
        assert!(matches!(error.kind(), GatewayErrorKind::ActionDenied(_)));
        assert_eq!(denied_broker.borrow().external_send_count(), 0);
    }

    #[test]
    fn response_and_call_replays_are_rejected_without_retry() {
        let body = response(
            "resp_replay",
            r#"[{"type":"function_call","id":"fc_1","call_id":"call_1","name":"harmless_read","arguments":"{}","status":"completed"}]"#,
        );
        let (mut provider, _) = provider_with(vec![Ok(body.clone()), Ok(body)]);
        let mut first_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut first_sink
            ),
            Ok(ProviderStep::AwaitToolResults)
        );
        let mut second_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(
                    1,
                    vec![
                        ModelInput::External(test_external()),
                        ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
                            "status=ok".to_owned(),
                        )),
                    ],
                ),
                &mut second_sink,
            ),
            Err(ProviderError::Malformed)
        );
    }

    #[test]
    fn duplicate_call_ids_in_one_response_are_rejected() {
        let (mut provider, _) = provider_with(vec![Ok(response(
            "resp_duplicate_calls",
            r#"[{"type":"function_call","id":"fc_1","call_id":"call_same","name":"harmless_read","arguments":"{}","status":"completed"},{"type":"function_call","id":"fc_2","call_id":"call_same","name":"harmless_read","arguments":"{}","status":"completed"}]"#,
        ))]);
        let mut sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut sink,
            ),
            Err(ProviderError::Malformed)
        );
    }

    #[test]
    fn oversized_tool_result_does_not_consume_pending_call_state() {
        let (mut provider, _) = provider_with(vec![
            Ok(response(
                "resp_pending",
                r#"[{"type":"function_call","id":"fc_pending","call_id":"call_pending","name":"harmless_read","arguments":"{}","status":"completed"}]"#,
            )),
            Ok(response(
                "resp_after_rejection",
                r#"[{"type":"message","id":"msg_after_rejection","status":"completed","role":"assistant","content":[{"type":"output_text","text":"recovered","annotations":[],"logprobs":[] }]}]"#,
            )),
        ]);
        let mut first_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut first_sink,
            ),
            Ok(ProviderStep::AwaitToolResults)
        );

        let oversized = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "x".repeat(MAX_TOOL_RESULT_BYTES + 1),
        ));
        let mut rejected_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(1, vec![ModelInput::External(test_external()), oversized]),
                &mut rejected_sink,
            ),
            Err(ProviderError::OutputLimitExceeded)
        );

        let valid = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "status=ok".to_owned(),
        ));
        let mut final_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(1, vec![ModelInput::External(test_external()), valid]),
                &mut final_sink,
            ),
            Ok(ProviderStep::Complete)
        );
        assert_eq!(final_sink.text, "recovered");
    }

    #[test]
    fn exact_tool_result_limit_is_accepted() {
        let (mut provider, _) = provider_with(vec![
            Ok(response(
                "resp_exact_tool",
                r#"[{"type":"function_call","id":"fc_exact_tool","call_id":"call_exact_tool","name":"harmless_read","arguments":"{}","status":"completed"}]"#,
            )),
            Ok(response(
                "resp_exact_tool_final",
                r#"[{"type":"message","id":"msg_exact_tool_final","status":"completed","role":"assistant","content":[{"type":"output_text","text":"ok"}]}]"#,
            )),
        ]);
        let mut first_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut first_sink,
            ),
            Ok(ProviderStep::AwaitToolResults)
        );
        let exact = ModelInput::Tool(tkach_core::niti_metka::TaggedData::from_untrusted(
            "x".repeat(MAX_TOOL_RESULT_BYTES),
        ));
        let mut final_sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(1, vec![ModelInput::External(test_external()), exact]),
                &mut final_sink,
            ),
            Ok(ProviderStep::Complete)
        );
    }

    #[test]
    fn transport_timeout_and_oversize_are_static_provider_errors() {
        let (mut provider, _) = provider_with(vec![Err(TransportError::Timeout)]);
        let mut sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut sink
            ),
            Err(ProviderError::Timeout)
        );
        let (mut provider, _) = provider_with(vec![Err(TransportError::ResponseTooLarge)]);
        let mut sink = LocalSink::default();
        assert_eq!(
            provider.invoke(
                &request(0, vec![ModelInput::External(test_external())]),
                &mut sink
            ),
            Err(ProviderError::OutputLimitExceeded)
        );
    }

    fn test_external() -> tkach_core::gnezdo::UntrustedContent {
        tkach_core::gnezdo::Gnezdo::new()
            .contain("hello".to_owned())
            .unwrap()
    }

    // This local sink mirrors only the public ProviderSink contract. It is
    // deliberately not the Gateway's production staging implementation.
    #[derive(Default)]
    struct LocalSink {
        text: String,
        chunks: Vec<String>,
        actions: Vec<ActionRequest>,
    }

    impl ProviderSink for LocalSink {
        fn text_chunk(&mut self, chunk: &str) -> Result<(), ProviderSinkError> {
            self.chunks.push(chunk.to_owned());
            self.text.push_str(chunk);
            Ok(())
        }

        fn action(&mut self, action: ActionRequest) -> Result<(), ProviderSinkError> {
            self.actions.push(action);
            Ok(())
        }
    }

    #[test]
    fn action_mapping_is_raw_proposal_not_authorization() {
        let call = ParsedFunctionCall {
            id: "fc_1".to_owned(),
            call_id: "call_1".to_owned(),
            name: "protected_write".to_owned(),
            arguments: "{}".to_owned(),
        };
        let action = action_for_call(&call).unwrap();
        assert_eq!(action.principal(), &tkach_core::domain::Principal::Model);
        assert_eq!(action.operation(), &Operation::Write);
        let mut sink = LocalSink::default();
        stage_text(&mut sink, "model data").unwrap();
        assert_eq!(sink.text, "model data");
        assert!(sink.actions.is_empty());

        let secret_call = ParsedFunctionCall {
            id: "fc_secret".to_owned(),
            call_id: "call_secret".to_owned(),
            name: "secret_backed_use".to_owned(),
            arguments: "{}".to_owned(),
        };
        let secret_action = action_for_call(&secret_call).unwrap();
        assert_eq!(secret_action.operation(), &Operation::Execute);
        assert_eq!(
            secret_action.destination(),
            &tkach_core::domain::Destination::SecretBroker
        );
    }

    #[test]
    fn provider_text_chunking_preserves_utf8_and_exact_bytes() {
        let text = format!("{}😀tail", "a".repeat(MAX_PROVIDER_CHUNK_BYTES - 1));
        let mut sink = LocalSink::default();
        stage_text(&mut sink, &text).unwrap();
        assert_eq!(sink.text, text);
        assert!(sink.chunks.len() >= 2);
        assert!(
            sink.chunks
                .iter()
                .all(|chunk| chunk.len() <= MAX_PROVIDER_CHUNK_BYTES)
        );
    }
}
