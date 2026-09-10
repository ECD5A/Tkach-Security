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

use std::cell::RefCell;
use std::rc::Rc;

use tkach_core::diode::{Diode, FlowMatcher, FlowOperation, FlowRule, FlowSource};
use tkach_core::domain::{
    CapabilityName, Classification, Destination, FlowDirection, Identity, Operation, Principal,
    ProvenanceSource, Resource, ResourceId, ResourceKind, ResourceScope, RuleId,
};
use tkach_core::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};
use tkach_core::propusk::{ExecutionError, Propusk, ProtectedExecutor};
use tkach_core::zaslon::{ContentRule, Zaslon};
use tkach_gateway::{
    CancelledProvider, DeterministicProvider, ExternalRequest, FailureProvider, FakeToolBroker,
    Gateway, GatewayErrorKind, HostileProvider, MAX_MESSAGES, MAX_METADATA_KEY_BYTES,
    MAX_METADATA_VALUE_BYTES, MAX_PROVIDER_CHUNK_BYTES, MAX_REQUEST_BODY_BYTES,
    MAX_TOOL_DECLARATIONS, MAX_TOOL_RESULT_BYTES, MalformedProvider, ModelInput, Provider,
    ProviderError, ProviderRequest, ProviderSink, ProviderStep, ScriptedStep, TimeoutProvider,
    ToolDescription, external_send_request, harmless_read_request, protected_read_request,
    protected_write_request, secret_reveal_request,
};

struct SharedExecutor {
    broker: Rc<RefCell<FakeToolBroker>>,
    replacement_data_bytes: Option<usize>,
}

impl ProtectedExecutor for SharedExecutor {
    type Output = tkach_gateway::ToolResult;

    fn execute(&mut self, action: Propusk) -> Result<Self::Output, ExecutionError> {
        let result = self.broker.borrow_mut().execute(action)?;
        if let Some(bytes) = self.replacement_data_bytes {
            if matches!(result, tkach_gateway::ToolResult::Data(_)) {
                return Ok(tkach_gateway::ToolResult::Data(
                    tkach_core::niti_metka::TaggedData::from_trusted_ingress(
                        "x".repeat(bytes),
                        ProvenanceSource::Tool(Identity::new("test-tool").unwrap()),
                        Classification::Public,
                    )
                    .map_err(|_| ExecutionError::Rejected)?,
                ));
            }
        }
        Ok(result)
    }
}

fn id(value: &str) -> ResourceId {
    ResourceId::new(value).unwrap()
}

fn cap(value: &str) -> CapabilityName {
    CapabilityName::new(value).unwrap()
}

fn rule(value: &str) -> RuleId {
    RuleId::new(value).unwrap()
}

fn resource(kind: ResourceKind, value: &str) -> Resource {
    Resource::new(kind, id(value))
}

fn action_allow(
    name: &str,
    capability: &str,
    operation: Operation,
    resource: &Resource,
    destination: Destination,
) -> PolicyRule {
    PolicyRule::allow(
        rule(name),
        RuleMatcher::any()
            .principal(Principal::Model)
            .operation(operation)
            .capability(cap(capability))
            .resource(ResourceScope::exact(resource))
            .destination(destination)
            .classification(Classification::Unknown),
    )
}

fn flow_allow(
    name: &str,
    source: FlowSource,
    destination: Destination,
    operation: FlowOperation,
) -> FlowRule {
    FlowRule::allow(
        rule(name),
        FlowMatcher::any()
            .principal(Principal::Model)
            .source(source)
            .destination(destination)
            .operation(operation),
    )
}

#[allow(clippy::too_many_lines)]
fn gateway(
    release_destination: Destination,
    ingress_zaslon: Zaslon,
    egress_zaslon: Zaslon,
) -> (Gateway, Rc<RefCell<FakeToolBroker>>) {
    gateway_with_replacement(release_destination, ingress_zaslon, egress_zaslon, None)
}

#[allow(clippy::too_many_lines)]
fn gateway_with_replacement(
    release_destination: Destination,
    ingress_zaslon: Zaslon,
    egress_zaslon: Zaslon,
    replacement_data_bytes: Option<usize>,
) -> (Gateway, Rc<RefCell<FakeToolBroker>>) {
    let database = resource(ResourceKind::Database, "customer-db");
    let network = resource(ResourceKind::Network, "public-api");
    let file = resource(ResourceKind::File, "workspace/output.txt");
    let secret = tkach_core::pechat::SecretHandle::new("github-prod")
        .unwrap()
        .resource();
    let tool = resource(ResourceKind::Database, "status");
    let storage = Destination::Internal(Identity::new("storage").unwrap());
    let client = Destination::Internal(Identity::new("client").unwrap());

    let policy = Policy::new(
        tkach_core::domain::PolicyId::new("gateway-policy").unwrap(),
        vec![
            action_allow(
                "allow-database-read",
                "database.read",
                Operation::Read,
                &database,
                Destination::Model,
            ),
            action_allow(
                "allow-network-send",
                "network.send",
                Operation::NetworkSend,
                &network,
                Destination::PublicExternal,
            ),
            action_allow(
                "allow-file-write",
                "file.write",
                Operation::Write,
                &file,
                storage.clone(),
            ),
            action_allow(
                "allow-secret-use",
                "secret.use",
                Operation::Execute,
                &secret,
                Destination::SecretBroker,
            ),
            action_allow(
                "allow-status-read",
                "database.read",
                Operation::Read,
                &tool,
                Destination::Model,
            ),
        ],
    )
    .unwrap();

    let mut diode_rules = vec![
        flow_allow(
            "flow-database-read",
            FlowSource::Resource(database),
            Destination::Model,
            FlowOperation::Read,
        ),
        flow_allow(
            "flow-tool-read",
            FlowSource::Resource(tool.clone()),
            Destination::Model,
            FlowOperation::Read,
        ),
        flow_allow(
            "flow-secret-use",
            FlowSource::Model,
            Destination::SecretBroker,
            FlowOperation::Transfer,
        ),
        flow_allow(
            "flow-file-write",
            FlowSource::Model,
            storage,
            FlowOperation::Transfer,
        ),
        flow_allow(
            "flow-release-client",
            FlowSource::Model,
            client,
            FlowOperation::Export,
        ),
    ];
    if release_destination != Destination::Internal(Identity::new("client").unwrap()) {
        diode_rules.push(flow_allow(
            "flow-release-configured",
            FlowSource::Model,
            release_destination.clone(),
            FlowOperation::Export,
        ));
    }
    let diode = Diode::new(diode_rules).unwrap();
    let kernel = Krosna::with_zaslon_and_diode(policy, Zaslon::empty(), diode);
    let broker = Rc::new(RefCell::new(FakeToolBroker::new()));
    let executor = SharedExecutor {
        broker: broker.clone(),
        replacement_data_bytes,
    };
    (
        Gateway::new(
            kernel,
            ingress_zaslon,
            egress_zaslon,
            release_destination,
            executor,
        ),
        broker,
    )
}

fn request_json(content: &str) -> Vec<u8> {
    format!(
        r#"{{"messages":[{{"role":"user","content":{}}}]}}"#,
        serde_json::to_string(content).unwrap()
    )
    .into_bytes()
}

#[test]
fn ordinary_output_is_released_only_after_core_flow_gate() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["safe response".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let result = gateway
        .run_json(&mut provider, &request_json("hello"))
        .unwrap();
    assert_eq!(result.output(), Some("safe response"));
    assert!(result.effects().is_empty());
    assert!(broker.borrow().effects().is_empty());
    assert_eq!(result.trace().len(), 1);
}

#[test]
fn canonical_hostile_provider_can_read_but_cannot_exfiltrate() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut provider = HostileProvider::new();
    let error = gateway
        .run_json(&mut provider, &request_json("legitimate task"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::ActionDenied(_)));
    assert_eq!(broker.borrow().read_count(), 1);
    assert_eq!(broker.borrow().external_send_count(), 0);
    assert!(!error.trace().to_json().unwrap().contains("customer-secret"));
}

struct ReadThenRespondProvider {
    turn: usize,
    saw_protected: Rc<RefCell<bool>>,
    source: Rc<RefCell<Option<ProvenanceSource>>>,
}

impl Provider for ReadThenRespondProvider {
    fn invoke(
        &mut self,
        request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        if self.turn == 0 {
            self.turn += 1;
            sink.action(protected_read_request())
                .map_err(|_| ProviderError::OutputLimitExceeded)?;
            return Ok(ProviderStep::AwaitToolResults);
        }
        let protected = request.inputs().iter().find_map(|input| match input {
            ModelInput::Tool(value) => Some(value),
            ModelInput::External(_) => None,
        });
        if let Some(value) = protected {
            *self.saw_protected.borrow_mut() = true;
            *self.source.borrow_mut() = Some(value.niti().provenance().source().clone());
        }
        sink.text_chunk("protected summary")
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        Ok(ProviderStep::Complete)
    }
}

#[test]
fn niti_and_metka_survive_tool_provider_boundary() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let saw_protected = Rc::new(RefCell::new(false));
    let source = Rc::new(RefCell::new(None));
    let mut provider = ReadThenRespondProvider {
        turn: 0,
        saw_protected: saw_protected.clone(),
        source: source.clone(),
    };
    let result = gateway
        .run_json(&mut provider, &request_json("read customer"))
        .unwrap();
    assert_eq!(result.output(), Some("protected summary"));
    assert!(*saw_protected.borrow());
    assert_eq!(
        source.borrow().as_ref(),
        Some(&ProvenanceSource::Database(id("customer-db")))
    );
    assert_eq!(broker.borrow().read_count(), 1);
}

struct MetadataStrippingProvider {
    turn: usize,
}

impl Provider for MetadataStrippingProvider {
    fn invoke(
        &mut self,
        _request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        if self.turn == 0 {
            self.turn += 1;
            sink.action(protected_read_request())
                .map_err(|_| ProviderError::OutputLimitExceeded)?;
            return Ok(ProviderStep::AwaitToolResults);
        }
        sink.text_chunk("claimed-public")
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        Ok(ProviderStep::Complete)
    }
}

#[test]
fn provider_cannot_strip_protected_metadata_to_public_egress() {
    let (mut gateway, broker) = gateway(
        Destination::PublicExternal,
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut provider = MetadataStrippingProvider { turn: 0 };
    let error = gateway
        .run_json(&mut provider, &request_json("read then export"))
        .unwrap_err();
    assert!(
        matches!(error.kind(), GatewayErrorKind::EgressDenied(_)),
        "kind was {:?}",
        error.kind()
    );
    assert_eq!(broker.borrow().read_count(), 1);
    assert_eq!(broker.borrow().external_send_count(), 0);
}

struct PublicToolThenRespondProvider {
    turn: usize,
}

impl Provider for PublicToolThenRespondProvider {
    fn invoke(
        &mut self,
        _request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        if self.turn == 0 {
            self.turn += 1;
            sink.action(harmless_read_request())
                .map_err(|_| ProviderError::OutputLimitExceeded)?;
            return Ok(ProviderStep::AwaitToolResults);
        }
        sink.text_chunk("claimed-public")
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        Ok(ProviderStep::Complete)
    }
}

#[test]
fn untrusted_external_input_is_not_laundered_by_a_public_tool_result() {
    let (mut gateway, broker) = gateway(
        Destination::PublicExternal,
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut provider = PublicToolThenRespondProvider { turn: 0 };
    let error = gateway
        .run_json(&mut provider, &request_json("untrusted task"))
        .unwrap_err();
    assert!(
        matches!(error.kind(), GatewayErrorKind::EgressDenied(_)),
        "kind was {:?}",
        error.kind()
    );
    assert_eq!(broker.borrow().read_count(), 1);
}

#[test]
fn streaming_chunks_are_buffered_and_egress_zaslon_sees_cross_chunk_sequence() {
    let rule = ContentRule::new(
        RuleId::new("block-egress-secret").unwrap(),
        FlowDirection::Egress,
        "secret token",
    )
    .unwrap();
    let egress = Zaslon::new(Vec::new(), vec![rule]).unwrap();
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        egress,
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["secret ".to_owned(), "token".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut provider, &request_json("task"))
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        GatewayErrorKind::EgressContentDenied(_)
    ));
    assert!(broker.borrow().effects().is_empty());
}

#[test]
fn rejected_final_output_cannot_leave_an_authorized_write_side_effect() {
    let rule = ContentRule::new(
        RuleId::new("block-egress-marker").unwrap(),
        FlowDirection::Egress,
        "blocked",
    )
    .unwrap();
    let egress = Zaslon::new(Vec::new(), vec![rule]).unwrap();
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        egress,
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["blocked".to_owned()],
        actions: vec![protected_write_request()],
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut provider, &request_json("write"))
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        GatewayErrorKind::EgressContentDenied(_)
    ));
    assert_eq!(broker.borrow().effect_count(), 0);
}

#[test]
fn invalid_release_destination_fails_before_provider_invocation() {
    let (mut gateway, broker) =
        gateway(Destination::SecretBroker, Zaslon::empty(), Zaslon::empty());
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["must not run".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut provider, &request_json("invalid sink"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::InvalidLifecycle));
    assert!(format!("{error:?}").contains("GatewayError"));
    assert_eq!(
        error.to_string(),
        "provider lifecycle transition is invalid"
    );
    assert_eq!(broker.borrow().effect_count(), 0);
}

#[test]
fn malformed_or_timed_out_provider_cannot_execute_staged_actions() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut timeout = TimeoutProvider;
    let timeout_error = gateway
        .run_json(&mut timeout, &request_json("timeout"))
        .unwrap_err();
    assert!(matches!(
        timeout_error.kind(),
        GatewayErrorKind::Provider(ProviderError::Timeout)
    ));
    assert_eq!(broker.borrow().effect_count(), 0);

    let mut malformed = MalformedProvider;
    let malformed_error = gateway
        .run_json(&mut malformed, &request_json("malformed"))
        .unwrap_err();
    assert!(matches!(
        malformed_error.kind(),
        GatewayErrorKind::Provider(ProviderError::Malformed)
    ));
    assert_eq!(broker.borrow().effect_count(), 0);

    let mut failure = FailureProvider;
    let failure_error = gateway
        .run_json(&mut failure, &request_json("failure"))
        .unwrap_err();
    assert!(matches!(
        failure_error.kind(),
        GatewayErrorKind::Provider(ProviderError::Failed)
    ));
    assert_eq!(broker.borrow().effect_count(), 0);

    let mut cancelled = CancelledProvider;
    let cancelled_error = gateway
        .run_json(&mut cancelled, &request_json("cancelled"))
        .unwrap_err();
    assert!(matches!(
        cancelled_error.kind(),
        GatewayErrorKind::Provider(ProviderError::Cancelled)
    ));
    assert_eq!(broker.borrow().effect_count(), 0);
}

#[test]
fn provider_chunk_limit_fails_before_any_effect() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["x".repeat(MAX_PROVIDER_CHUNK_BYTES + 1)],
        actions: vec![external_send_request()],
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut provider, &request_json("oversized chunk"))
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        GatewayErrorKind::Provider(ProviderError::OutputLimitExceeded)
    ));
    assert_eq!(broker.borrow().effect_count(), 0);
}

#[test]
fn denied_batch_is_preflighted_before_any_protected_effect() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: Vec::new(),
        actions: vec![protected_read_request(), external_send_request()],
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut provider, &request_json("write and export"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::ActionDenied(_)));
    assert_eq!(broker.borrow().effect_count(), 0);
    assert_eq!(broker.borrow().external_send_count(), 0);
}

#[test]
fn awaited_turns_reject_mutations_and_batches_reject_multiple_effects() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut awaited_write = DeterministicProvider::new(vec![ScriptedStep {
        chunks: Vec::new(),
        actions: vec![protected_write_request()],
        continuation: ProviderStep::AwaitToolResults,
    }]);
    let error = gateway
        .run_json(&mut awaited_write, &request_json("await write"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::InvalidLifecycle));
    assert_eq!(broker.borrow().effect_count(), 0);

    let mut multiple_effects = DeterministicProvider::new(vec![ScriptedStep {
        chunks: Vec::new(),
        actions: vec![protected_write_request(), external_send_request()],
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut multiple_effects, &request_json("two effects"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::InvalidLifecycle));
    assert_eq!(broker.borrow().effect_count(), 0);
}

#[test]
fn pechat_reveal_is_denied_but_authorized_secret_use_is_internal_only() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut reveal = DeterministicProvider::new(vec![ScriptedStep {
        chunks: Vec::new(),
        actions: vec![secret_reveal_request()],
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut reveal, &request_json("reveal"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::ActionDenied(_)));
    assert_eq!(broker.borrow().effect_count(), 0);

    let secret_resource = tkach_core::pechat::SecretHandle::new("github-prod")
        .unwrap()
        .resource();
    let secret_action = tkach_core::domain::ActionRequest::new(
        Principal::Model,
        Operation::Execute,
        secret_resource,
        Destination::SecretBroker,
        cap("secret.use"),
    );
    let mut use_secret = DeterministicProvider::new(vec![ScriptedStep {
        chunks: Vec::new(),
        actions: vec![secret_action],
        continuation: ProviderStep::Complete,
    }]);
    let result = gateway
        .run_json(&mut use_secret, &request_json("use handle"))
        .unwrap();
    assert!(result.output().is_none());
    assert_eq!(broker.borrow().effect_count(), 1);
    let serialized = serde_json::to_string(result.trace()).unwrap();
    assert!(!serialized.contains("fake-github-production-secret"));
}

#[test]
fn ingress_and_input_limits_fail_closed_before_provider_invocation() {
    let block_rule = ContentRule::new(
        RuleId::new("block-ingress").unwrap(),
        FlowDirection::Ingress,
        "disable security",
    )
    .unwrap();
    let ingress = Zaslon::new(Vec::new(), vec![block_rule]).unwrap();
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        ingress,
        Zaslon::empty(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["should never run".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut provider, &request_json("disable security"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::IngressDenied(_)));
    assert_eq!(broker.borrow().effect_count(), 0);

    let oversized = vec![b'x'; MAX_REQUEST_BODY_BYTES + 1];
    let error = gateway.run_json(&mut provider, &oversized).unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::InvalidRequest));

    let duplicate = br#"{"messages":[{"role":"user","content":"ok"}],"messages":[]}"#;
    let error = gateway.run_json(&mut provider, duplicate).unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::InvalidRequest));
}

#[test]
fn client_tool_declarations_cannot_extend_trusted_catalog() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let body = br#"{"messages":[{"role":"user","content":"inspect"}],"tool_declarations":[{"name":"shell"}]}"#;
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["catalog remains fixed".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let result = gateway.run_json(&mut provider, body).unwrap();
    assert_eq!(result.output(), Some("catalog remains fixed"));
    assert_eq!(broker.borrow().effect_count(), 0);
}

struct RequestSurfaceProvider {
    saw_surface: Rc<RefCell<bool>>,
}

impl Provider for RequestSurfaceProvider {
    fn invoke(
        &mut self,
        request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        let tool_names: Vec<&str> = request.tools().iter().map(ToolDescription::name).collect();
        *self.saw_surface.borrow_mut() = request.turn() == 0
            && request.inputs().first().is_some_and(|input| {
                input.text() == "inspect"
                    && input.is_protected()
                    && input.classification() == Classification::Unknown
            })
            && request
                .metadata()
                .first()
                .is_some_and(|entry| entry.name() == "trace" && entry.value() == "one")
            && tool_names
                == [
                    "protected_read",
                    "protected_write",
                    "external_send",
                    "harmless_read",
                    "secret_backed_use",
                ];
        sink.text_chunk("surface inspected")
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        Ok(ProviderStep::Complete)
    }
}

#[test]
fn provider_request_exposes_only_bounded_data_and_fixed_tool_surface() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let saw_surface = Rc::new(RefCell::new(false));
    let mut provider = RequestSurfaceProvider {
        saw_surface: saw_surface.clone(),
    };
    let body = br#"{"messages":[{"role":"data","content":"inspect"}],"metadata":[{"name":"trace","value":"one"}],"tool_declarations":[{"name":"shell"}]}"#;
    let result = gateway.run_json(&mut provider, body).unwrap();
    assert_eq!(result.output(), Some("surface inspected"));
    assert!(*saw_surface.borrow());
    assert!(broker.borrow().effects().is_empty());
}

#[test]
fn duplicate_metadata_names_and_duplicate_action_replays_fail_closed() {
    let duplicate_metadata = br#"{"messages":[{"role":"user","content":"ok"}],"metadata":[{"name":"trace","value":"one"},{"name":"trace","value":"two"}]}"#;
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["must not run".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut provider, duplicate_metadata)
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::InvalidRequest));

    let mut replay = DeterministicProvider::new(vec![
        ScriptedStep {
            chunks: Vec::new(),
            actions: vec![protected_read_request()],
            continuation: ProviderStep::AwaitToolResults,
        },
        ScriptedStep {
            chunks: vec!["replay".to_owned()],
            actions: vec![protected_read_request()],
            continuation: ProviderStep::Complete,
        },
    ]);
    let error = gateway
        .run_json(&mut replay, &request_json("replay"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::InvalidLifecycle));
    assert_eq!(broker.borrow().read_count(), 1);
}

#[test]
fn exact_wire_limits_are_accepted_and_the_next_byte_or_item_is_rejected() {
    let exact_message = request_json(&"x".repeat(16 * 1024));
    assert!(ExternalRequest::from_json(&exact_message).is_ok());
    let oversized_message = request_json(&"x".repeat(16 * 1024 + 1));
    assert!(ExternalRequest::from_json(&oversized_message).is_err());

    let mut exact_body = request_json("ok");
    exact_body.resize(MAX_REQUEST_BODY_BYTES, b' ');
    assert!(ExternalRequest::from_json(&exact_body).is_ok());
    exact_body.push(b' ');
    assert!(ExternalRequest::from_json(&exact_body).is_err());

    let metadata_key = "k".repeat(MAX_METADATA_KEY_BYTES);
    let metadata_value = "v".repeat(MAX_METADATA_VALUE_BYTES);
    let exact_metadata = format!(
        r#"{{"messages":[{{"role":"user","content":"ok"}}],"metadata":[{{"name":"{metadata_key}","value":"{metadata_value}"}}]}}"#
    );
    assert!(ExternalRequest::from_json(exact_metadata.as_bytes()).is_ok());
    let too_long_key = format!(
        r#"{{"messages":[{{"role":"user","content":"ok"}}],"metadata":[{{"name":"{}","value":"v"}}]}}"#,
        "k".repeat(MAX_METADATA_KEY_BYTES + 1)
    );
    assert!(ExternalRequest::from_json(too_long_key.as_bytes()).is_err());

    let messages = (0..MAX_MESSAGES)
        .map(|_| r#"{"role":"user","content":"x"}"#)
        .collect::<Vec<_>>()
        .join(",");
    let exact_messages = format!(r#"{{"messages":[{messages}]}}"#);
    assert!(ExternalRequest::from_json(exact_messages.as_bytes()).is_ok());
    let too_many_messages =
        format!(r#"{{"messages":[{messages},{{"role":"user","content":"x"}}]}}"#);
    assert!(ExternalRequest::from_json(too_many_messages.as_bytes()).is_err());

    let tools = (0..MAX_TOOL_DECLARATIONS)
        .map(|index| format!(r#"{{"name":"tool-{index}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let exact_tools = format!(
        r#"{{"messages":[{{"role":"user","content":"x"}}],"tool_declarations":[{tools}]}}"#
    );
    assert!(ExternalRequest::from_json(exact_tools.as_bytes()).is_ok());
    let too_many_tools = format!(
        r#"{{"messages":[{{"role":"user","content":"x"}}],"tool_declarations":[{tools},{{"name":"extra"}}]}}"#
    );
    assert!(ExternalRequest::from_json(too_many_tools.as_bytes()).is_err());
}

#[test]
fn exact_provider_and_final_output_limits_are_enforced() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let exact_chunks = vec!["x".repeat(16 * 1024)];
    let mut exact_provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: exact_chunks,
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let result = gateway
        .run_json(&mut exact_provider, &request_json("exact"))
        .unwrap();
    assert_eq!(result.output().map(str::len), Some(16 * 1024));

    let mut oversized_provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["x".repeat(MAX_PROVIDER_CHUNK_BYTES); 5],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut oversized_provider, &request_json("oversized final"))
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        GatewayErrorKind::Provider(ProviderError::OutputLimitExceeded)
    ));
    assert!(broker.borrow().effects().is_empty());
}

#[test]
fn gateway_results_and_diagnostics_are_nonempty_and_payload_safe() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let gateway_debug = format!("{gateway:?}");
    assert!(gateway_debug.contains("Gateway"));
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: Vec::new(),
        actions: vec![protected_write_request()],
        continuation: ProviderStep::Complete,
    }]);
    let result = gateway
        .run_json(&mut provider, &request_json("write"))
        .unwrap();
    assert_eq!(result.effects().len(), 1);
    let result_debug = format!("{result:?}");
    assert!(result_debug.contains("GatewayResult"));
    assert!(!result_debug.contains("workspace/output.txt"));
    assert_eq!(broker.borrow().effect_count(), 1);
}

struct BoundaryReadProvider {
    turn: usize,
}

struct ReadThenFailureProvider {
    turn: usize,
}

impl Provider for ReadThenFailureProvider {
    fn invoke(
        &mut self,
        _request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        if self.turn == 0 {
            self.turn += 1;
            sink.action(protected_read_request())
                .map_err(|_| ProviderError::OutputLimitExceeded)?;
            return Ok(ProviderStep::AwaitToolResults);
        }
        Err(ProviderError::Failed)
    }
}

impl Provider for BoundaryReadProvider {
    fn invoke(
        &mut self,
        _request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        if self.turn == 0 {
            self.turn += 1;
            sink.action(protected_read_request())
                .map_err(|_| ProviderError::OutputLimitExceeded)?;
            return Ok(ProviderStep::AwaitToolResults);
        }
        sink.text_chunk("done")
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        Ok(ProviderStep::Complete)
    }
}

#[test]
fn tool_result_exact_limit_is_accepted_and_next_byte_is_rejected() {
    let (mut exact_gateway, exact_broker) = gateway_with_replacement(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
        Some(MAX_TOOL_RESULT_BYTES),
    );
    let mut exact_provider = BoundaryReadProvider { turn: 0 };
    assert!(
        exact_gateway
            .run_json(&mut exact_provider, &request_json("boundary"))
            .is_ok()
    );
    assert_eq!(exact_broker.borrow().read_count(), 1);

    let (mut oversized_gateway, oversized_broker) = gateway_with_replacement(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
        Some(MAX_TOOL_RESULT_BYTES + 1),
    );
    let mut oversized_provider = BoundaryReadProvider { turn: 0 };
    let error = oversized_gateway
        .run_json(&mut oversized_provider, &request_json("boundary"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::ToolRejected));
    assert_eq!(oversized_broker.borrow().read_count(), 1);
}

#[test]
fn second_turn_failure_after_a_read_cannot_release_or_create_an_effect() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut provider = ReadThenFailureProvider { turn: 0 };
    let error = gateway
        .run_json(&mut provider, &request_json("cancel after read"))
        .unwrap_err();
    assert!(matches!(
        error.kind(),
        GatewayErrorKind::Provider(ProviderError::Failed)
    ));
    assert_eq!(broker.borrow().read_count(), 1);
    assert_eq!(broker.borrow().external_send_count(), 0);
    assert!(
        broker
            .borrow()
            .effects()
            .iter()
            .all(|receipt| { receipt.operation() == &Operation::Read })
    );
}

#[test]
fn denied_read_then_write_is_preflighted_without_read_effect() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let denied_write = tkach_core::domain::ActionRequest::new(
        Principal::Model,
        Operation::Write,
        resource(ResourceKind::File, "workspace/other.txt"),
        Destination::Internal(Identity::new("storage").unwrap()),
        cap("file.write"),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: Vec::new(),
        actions: vec![protected_read_request(), denied_write],
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut provider, &request_json("read then denied write"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::ActionDenied(_)));
    assert_eq!(broker.borrow().read_count(), 0);
    assert_eq!(broker.borrow().effect_count(), 0);
}

#[test]
fn multiple_irreversible_actions_are_rejected_before_execution() {
    let (mut gateway, broker) = gateway(
        Destination::Internal(Identity::new("client").unwrap()),
        Zaslon::empty(),
        Zaslon::empty(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: Vec::new(),
        actions: vec![protected_write_request(), protected_write_request()],
        continuation: ProviderStep::Complete,
    }]);
    let error = gateway
        .run_json(&mut provider, &request_json("two writes"))
        .unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::InvalidLifecycle));
    assert_eq!(broker.borrow().effect_count(), 0);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleState {
    Received,
    Validated,
    Contained,
    ProviderRunning,
    OutputStaged,
    EgressApproved,
    ActionsEvaluated,
    EffectsCommitted,
    Released,
    TerminalDenied,
    TerminalError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleAction {
    Read,
    Write,
    ExternalSend,
    SecretUse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OracleEgress {
    NotEvaluated,
    Approved,
    Denied,
}

fn oracle_allows_irreversible_effect(
    state: OracleState,
    action: OracleAction,
    egress: OracleEgress,
    cancelled: bool,
) -> bool {
    !cancelled
        && matches!(
            state,
            OracleState::EgressApproved | OracleState::EffectsCommitted
        )
        && matches!(egress, OracleEgress::Approved)
        && !matches!(action, OracleAction::Read)
}

#[test]
fn independent_lifecycle_oracle_rejects_effects_on_terminal_denial_or_error() {
    let valid = [
        OracleState::Received,
        OracleState::Validated,
        OracleState::Contained,
        OracleState::ProviderRunning,
        OracleState::OutputStaged,
        OracleState::EgressApproved,
        OracleState::ActionsEvaluated,
        OracleState::EffectsCommitted,
        OracleState::Released,
    ];
    assert_eq!(valid.last(), Some(&OracleState::Released));

    for terminal in [OracleState::TerminalDenied, OracleState::TerminalError] {
        for action in [
            OracleAction::Write,
            OracleAction::ExternalSend,
            OracleAction::SecretUse,
        ] {
            assert!(!oracle_allows_irreversible_effect(
                terminal,
                action,
                OracleEgress::Approved,
                false
            ));
        }
    }
    for action in [
        OracleAction::Write,
        OracleAction::ExternalSend,
        OracleAction::SecretUse,
    ] {
        assert!(!oracle_allows_irreversible_effect(
            OracleState::OutputStaged,
            action,
            OracleEgress::NotEvaluated,
            false
        ));
        assert!(!oracle_allows_irreversible_effect(
            OracleState::EgressApproved,
            action,
            OracleEgress::Denied,
            false
        ));
        assert!(!oracle_allows_irreversible_effect(
            OracleState::EgressApproved,
            action,
            OracleEgress::Approved,
            true
        ));
    }
    assert!(!oracle_allows_irreversible_effect(
        OracleState::EgressApproved,
        OracleAction::Read,
        OracleEgress::Approved,
        false
    ));
}
