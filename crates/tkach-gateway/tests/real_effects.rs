use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tkach_core::domain::{
    ActionRequest, CapabilityName, Classification, Destination, Identity, Operation,
    ProvenanceSource, Resource, ResourceId, ResourceKind, ResourceScope, RuleId, SecurityContext,
};
use tkach_core::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};
use tkach_core::niti_metka::TaggedData;
use tkach_core::propusk::{ExecutionError, Propusk, ProtectedExecutor};
use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
use tkach_gateway::{
    DeterministicProvider, EffectOutcome, EffectReceipt, ExternalMessage, ExternalRequest,
    ExternalRole, Gateway, GatewayErrorKind, MAX_TOOL_RESULT_BYTES, ProviderStep,
    REAL_FILE_WRITE_CONTENT, REAL_NETWORK_PATH, REAL_NETWORK_PAYLOAD, RealEffectExecutor,
    RealExecutorConfigError, ScriptedStep, ToolResult, external_send_request,
    protected_write_request,
};

static NEXT_SANDBOX_ID: AtomicU64 = AtomicU64::new(1);

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let process = std::process::id();
        loop {
            let id = NEXT_SANDBOX_ID.fetch_add(1, Ordering::Relaxed);
            let root = base.join(format!("tkach-real-effects-{process}-{id}"));
            if fs::create_dir(&root).is_ok() {
                fs::create_dir(root.join("workspace")).unwrap();
                fs::write(root.join("workspace/input.txt"), b"sandbox-input").unwrap();
                return Self { root };
            }
        }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Receiver {
    address: SocketAddr,
    handle: JoinHandle<ReceiverReport>,
}

#[derive(Debug)]
struct ReceiverReport {
    requests_received: usize,
    exact_request: bool,
}

impl Receiver {
    fn start(status: u16, delay: Duration) -> Self {
        Self::start_with_body(status, delay, 0)
    }

    fn start_with_body(status: u16, delay: Duration, response_body_bytes: usize) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let expected_head = format!(
            "POST {REAL_NETWORK_PATH} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            REAL_NETWORK_PAYLOAD.len()
        );
        let mut expected = expected_head.into_bytes();
        expected.extend_from_slice(REAL_NETWORK_PAYLOAD);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(1_500);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_millis(750)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut chunk = [0_u8; 512];
                        loop {
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(count) => {
                                    if request.len().saturating_add(count) > 8 * 1024 {
                                        break;
                                    }
                                    request.extend_from_slice(&chunk[..count]);
                                    // The harness knows the exact bounded request it
                                    // expects. Respond as soon as it is complete rather
                                    // than waiting for the peer's half-close; this keeps
                                    // the real-effect test deterministic on macOS while
                                    // retaining exact-request verification below.
                                    if request.len() >= expected.len() {
                                        break;
                                    }
                                }
                            }
                            if request.len() >= expected.len() {
                                break;
                            }
                        }
                        if request.is_empty() {
                            return ReceiverReport {
                                requests_received: 0,
                                exact_request: false,
                            };
                        }
                        if delay > Duration::ZERO {
                            thread::sleep(delay);
                        }
                        let reason = match status {
                            200 => "OK",
                            500 => "Internal Server Error",
                            _ => "Test Status",
                        };
                        let response_body = vec![b'R'; response_body_bytes];
                        let response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            response_body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.write_all(&response_body);
                        let _ = stream.flush();
                        // Complete the response half-close before dropping the
                        // socket, then wait for the client half-close. This
                        // avoids a macOS race where the receiver closes while
                        // the executor is still calling shutdown(Write), which
                        // must remain a terminal unknown outcome in production.
                        let _ = stream.shutdown(Shutdown::Write);
                        let mut client_close = [0_u8; 1];
                        loop {
                            match stream.read(&mut client_close) {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        return ReceiverReport {
                            requests_received: 1,
                            exact_request: request == expected,
                        };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return ReceiverReport {
                                requests_received: 0,
                                exact_request: false,
                            };
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => {
                        return ReceiverReport {
                            requests_received: 0,
                            exact_request: false,
                        };
                    }
                }
            }
        });
        Self { address, handle }
    }

    fn finish(self) -> ReceiverReport {
        self.handle.join().unwrap()
    }
}

fn file_read_request(resource_id: &str) -> ActionRequest {
    ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Read,
        Resource::new(ResourceKind::File, ResourceId::new(resource_id).unwrap()),
        Destination::Model,
        CapabilityName::new("file.read").unwrap(),
    )
}

fn exact_kernel(action: &ActionRequest, classification: Classification) -> Krosna {
    let policy = Policy::new(
        tkach_core::domain::PolicyId::new("real-effect-test-policy").unwrap(),
        vec![PolicyRule::allow(
            RuleId::new("allow-exact-effect").unwrap(),
            RuleMatcher::any()
                .principal(tkach_core::domain::Principal::Model)
                .operation(action.operation().clone())
                .capability(action.capability().clone())
                .resource(ResourceScope::exact(action.resource()))
                .destination(action.destination().clone())
                .classification(classification),
        )],
    )
    .unwrap();
    Krosna::new(policy)
}

fn unknown_permit(action: &ActionRequest) -> Propusk {
    exact_kernel(action, Classification::Unknown)
        .authorize(&SecurityContext::untrusted_data(), action)
        .unwrap()
}

fn public_network_kernel(action: &ActionRequest) -> Krosna {
    let policy = Policy::new(
        tkach_core::domain::PolicyId::new("real-public-effect-policy").unwrap(),
        vec![PolicyRule::allow(
            RuleId::new("allow-public-network-effect").unwrap(),
            RuleMatcher::any()
                .principal(tkach_core::domain::Principal::Model)
                .operation(Operation::NetworkSend)
                .capability(action.capability().clone())
                .resource(ResourceScope::exact(action.resource()))
                .destination(Destination::PublicExternal)
                .classification(Classification::Public),
        )],
    )
    .unwrap();
    let ruslo = Ruslo::new(vec![FlowRule::allow(
        RuleId::new("allow-explicit-public-export").unwrap(),
        FlowMatcher::any()
            .principal(tkach_core::domain::Principal::Model)
            .source(FlowSource::Model)
            .destination(Destination::PublicExternal)
            .operation(FlowOperation::Export)
            .classification(Classification::Public),
    )])
    .unwrap();
    Krosna::with_ruslo(policy, ruslo)
}

fn gateway_write_kernel(action: &ActionRequest) -> Krosna {
    let policy = Policy::new(
        tkach_core::domain::PolicyId::new("real-gateway-write-policy").unwrap(),
        vec![PolicyRule::allow(
            RuleId::new("allow-gateway-write").unwrap(),
            RuleMatcher::any()
                .principal(tkach_core::domain::Principal::Model)
                .operation(action.operation().clone())
                .capability(action.capability().clone())
                .resource(ResourceScope::exact(action.resource()))
                .destination(action.destination().clone())
                .classification(Classification::Unknown),
        )],
    )
    .unwrap();
    let storage = Destination::Internal(Identity::new("storage").unwrap());
    let client = Destination::Internal(Identity::new("client").unwrap());
    let ruslo = Ruslo::new(vec![
        FlowRule::allow(
            RuleId::new("allow-gateway-storage-transfer").unwrap(),
            FlowMatcher::any()
                .principal(tkach_core::domain::Principal::Model)
                .source(FlowSource::Model)
                .destination(storage)
                .operation(FlowOperation::Transfer),
        ),
        FlowRule::allow(
            RuleId::new("allow-gateway-client-export").unwrap(),
            FlowMatcher::any()
                .principal(tkach_core::domain::Principal::Model)
                .source(FlowSource::Model)
                .destination(client)
                .operation(FlowOperation::Export),
        ),
    ])
    .unwrap();
    Krosna::with_ruslo(policy, ruslo)
}

fn trusted_public_data() -> TaggedData<&'static str> {
    TaggedData::from_trusted_ingress(
        "public-local-effect",
        ProvenanceSource::Tool(Identity::new("trusted-local-source").unwrap()),
        Classification::Public,
    )
    .unwrap()
}

fn receipt(result: ToolResult) -> EffectReceipt {
    match result {
        ToolResult::Effect(receipt) => receipt,
        ToolResult::Data(_) => panic!("expected an effect receipt"),
    }
}

#[test]
fn real_filesystem_read_is_exact_and_retains_conservative_metadata() {
    let sandbox = Sandbox::new();
    let mut executor =
        RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([127, 0, 0, 1], 1))).unwrap();
    let action = file_read_request("workspace/input.txt");
    let result = executor.execute(unknown_permit(&action)).unwrap();
    match result {
        ToolResult::Data(data) => {
            assert_eq!(data.value(), "sandbox-input");
            assert_eq!(data.metka().classification(), Classification::Confidential);
            assert!(format!("{data:?}").contains("REDACTED"));
            assert!(!format!("{data:?}").contains("sandbox-input"));
        }
        ToolResult::Effect(_) => panic!("read must return tagged data"),
    }
    assert_eq!(executor.attempt_count(), 1);
    assert_eq!(executor.successful_read_count(), 1);
    assert_eq!(executor.committed_effect_count(), 0);
    let debug = format!("{executor:?}");
    assert!(debug.contains("attempts"));
    assert!(!debug.contains(sandbox.path().to_string_lossy().as_ref()));
}

#[test]
fn real_filesystem_read_accepts_exact_limit_but_rejects_the_next_byte() {
    let sandbox = Sandbox::new();
    let input = sandbox.path().join("workspace/input.txt");
    fs::write(&input, vec![b'a'; MAX_TOOL_RESULT_BYTES]).unwrap();
    let mut executor =
        RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([127, 0, 0, 1], 1))).unwrap();
    let action = file_read_request("workspace/input.txt");
    match executor.execute(unknown_permit(&action)).unwrap() {
        ToolResult::Data(data) => assert_eq!(data.value().len(), MAX_TOOL_RESULT_BYTES),
        ToolResult::Effect(_) => panic!("read must return tagged data"),
    }

    fs::write(&input, vec![b'a'; MAX_TOOL_RESULT_BYTES + 1]).unwrap();
    // The bounded reader has already opened and consumed the protected file;
    // rejecting the oversized result does not prove that no read occurred.
    assert_eq!(
        executor.execute(unknown_permit(&action)).unwrap_err(),
        ExecutionError::OutcomeUnknown
    );
    assert_eq!(executor.unknown_effect_count(), 1);
}

#[test]
fn real_filesystem_read_dispatch_requires_the_exact_action_shape() {
    let wrong_resource = file_read_request("workspace/other.txt");
    let wrong_destination = ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Read,
        Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/input.txt").unwrap(),
        ),
        Destination::Internal(Identity::new("storage").unwrap()),
        CapabilityName::new("file.read").unwrap(),
    );
    for action in [wrong_resource, wrong_destination] {
        let sandbox = Sandbox::new();
        let mut executor =
            RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([127, 0, 0, 1], 1))).unwrap();
        assert_eq!(
            executor.execute(unknown_permit(&action)).unwrap_err(),
            ExecutionError::FailedBeforeEffect
        );
        assert_eq!(executor.successful_read_count(), 0);
    }
}

#[test]
fn real_filesystem_write_is_create_only_and_cannot_widen_scope() {
    let sandbox = Sandbox::new();
    let mut executor =
        RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([127, 0, 0, 1], 1))).unwrap();
    let action = protected_write_request();
    let first = receipt(executor.execute(unknown_permit(&action)).unwrap());
    assert_eq!(
        fs::read(sandbox.path().join("workspace/output.txt")).unwrap(),
        REAL_FILE_WRITE_CONTENT
    );
    assert_eq!(first.execution_id(), 1);
    assert_eq!(first.outcome(), EffectOutcome::Committed);
    assert_eq!(executor.committed_effect_count(), 1);

    let second = executor.execute(unknown_permit(&action)).unwrap_err();
    assert_eq!(second, ExecutionError::FailedBeforeEffect);
    assert_eq!(
        fs::read(sandbox.path().join("workspace/output.txt")).unwrap(),
        REAL_FILE_WRITE_CONTENT
    );

    for resource_id in [
        "workspace/other.txt",
        "workspace/output.txt/child",
        "C:/outside.txt",
    ] {
        let hostile = ActionRequest::new(
            tkach_core::domain::Principal::Model,
            Operation::Write,
            Resource::new(ResourceKind::File, ResourceId::new(resource_id).unwrap()),
            Destination::Internal(Identity::new("storage").unwrap()),
            CapabilityName::new("file.write").unwrap(),
        );
        assert_eq!(
            executor.execute(unknown_permit(&hostile)).unwrap_err(),
            ExecutionError::FailedBeforeEffect
        );
    }
    assert_eq!(executor.unknown_effect_count(), 0);
}

#[test]
fn real_filesystem_write_dispatch_requires_the_exact_action_shape() {
    let wrong_capability = ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Write,
        Resource::new(
            ResourceKind::Database,
            ResourceId::new("workspace/output.txt").unwrap(),
        ),
        Destination::Internal(Identity::new("storage").unwrap()),
        CapabilityName::new("database.write").unwrap(),
    );
    let wrong_resource = ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Write,
        Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/other.txt").unwrap(),
        ),
        Destination::Internal(Identity::new("storage").unwrap()),
        CapabilityName::new("file.write").unwrap(),
    );
    let wrong_destination = ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::Write,
        Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/output.txt").unwrap(),
        ),
        Destination::Internal(Identity::new("other-storage").unwrap()),
        CapabilityName::new("file.write").unwrap(),
    );
    for action in [wrong_capability, wrong_resource, wrong_destination] {
        let sandbox = Sandbox::new();
        let mut executor =
            RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([127, 0, 0, 1], 1))).unwrap();
        assert_eq!(
            executor.execute(unknown_permit(&action)).unwrap_err(),
            ExecutionError::FailedBeforeEffect
        );
        assert!(!sandbox.path().join("workspace/output.txt").exists());
    }
}

#[test]
fn gateway_dispatches_an_authorized_write_to_the_real_filesystem() {
    let sandbox = Sandbox::new();
    let action = protected_write_request();
    let kernel = gateway_write_kernel(&action);
    let mut gateway = Gateway::new(
        kernel,
        tkach_core::zaslon::Zaslon::empty(),
        tkach_core::zaslon::Zaslon::empty(),
        Destination::Internal(Identity::new("client").unwrap()),
        RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([127, 0, 0, 1], 1))).unwrap(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["gateway-committed".to_owned()],
        actions: vec![action],
        continuation: ProviderStep::Complete,
    }]);
    let request = ExternalRequest::new(
        vec![ExternalMessage::new(ExternalRole::User, "write".to_owned()).unwrap()],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let result = gateway.run(&mut provider, &request).unwrap();
    assert_eq!(result.output(), Some("gateway-committed"));
    assert_eq!(result.effects().len(), 1);
    assert_eq!(result.effects()[0].outcome(), EffectOutcome::Committed);
    assert_eq!(
        fs::read(sandbox.path().join("workspace/output.txt")).unwrap(),
        REAL_FILE_WRITE_CONTENT
    );
}

#[test]
fn real_executor_rejects_invalid_sandbox_and_non_loopback_bindings() {
    let sandbox = Sandbox::new();
    let file = sandbox.path().join("workspace/input.txt");
    assert_eq!(
        RealEffectExecutor::new(&file, SocketAddr::from(([127, 0, 0, 1], 1))).unwrap_err(),
        RealExecutorConfigError::InvalidSandboxRoot
    );
    assert_eq!(
        RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([8, 8, 8, 8], 53))).unwrap_err(),
        RealExecutorConfigError::InvalidLoopbackEndpoint
    );
    assert_eq!(
        RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([127, 0, 0, 1], 0))).unwrap_err(),
        RealExecutorConfigError::InvalidLoopbackEndpoint
    );
}

#[cfg(unix)]
#[test]
fn real_executor_rejects_symlinked_files_and_parents() {
    use std::os::unix::fs::symlink;

    let sandbox = Sandbox::new();
    let outside = Sandbox::new();
    fs::write(outside.path().join("workspace/input.txt"), b"outside").unwrap();
    fs::remove_file(sandbox.path().join("workspace/input.txt")).unwrap();
    symlink(
        outside.path().join("workspace/input.txt"),
        sandbox.path().join("workspace/input.txt"),
    )
    .unwrap();
    let mut executor =
        RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([127, 0, 0, 1], 1))).unwrap();
    assert_eq!(
        executor
            .execute(unknown_permit(&file_read_request("workspace/input.txt")))
            .unwrap_err(),
        ExecutionError::FailedBeforeEffect
    );

    fs::remove_file(sandbox.path().join("workspace/input.txt")).unwrap();
    fs::write(sandbox.path().join("workspace/inside.txt"), b"inside").unwrap();
    symlink(
        sandbox.path().join("workspace/inside.txt"),
        sandbox.path().join("workspace/input.txt"),
    )
    .unwrap();
    assert_eq!(
        executor
            .execute(unknown_permit(&file_read_request("workspace/input.txt")))
            .unwrap_err(),
        ExecutionError::FailedBeforeEffect
    );

    fs::remove_file(sandbox.path().join("workspace/input.txt")).unwrap();
    fs::remove_file(sandbox.path().join("workspace/inside.txt")).unwrap();
    fs::remove_dir(sandbox.path().join("workspace")).unwrap();
    symlink(
        outside.path().join("workspace"),
        sandbox.path().join("workspace"),
    )
    .unwrap();
    let write = protected_write_request();
    assert_eq!(
        executor.execute(unknown_permit(&write)).unwrap_err(),
        ExecutionError::FailedBeforeEffect
    );
    assert!(!outside.path().join("workspace/output.txt").exists());
}

#[cfg(windows)]
#[test]
fn real_executor_rejects_a_windows_junction_parent() {
    use std::os::windows::fs::MetadataExt;
    use std::process::Command;

    let sandbox = Sandbox::new();
    let alternate = sandbox.path().join("alternate");
    fs::create_dir(&alternate).unwrap();
    fs::write(alternate.join("input.txt"), b"junction-target").unwrap();
    fs::remove_file(sandbox.path().join("workspace/input.txt")).unwrap();
    fs::remove_dir(sandbox.path().join("workspace")).unwrap();
    let link = sandbox.path().join("workspace");
    let link_text = link.to_string_lossy().into_owned();
    let alternate_text = alternate.to_string_lossy().into_owned();
    let result = Command::new("cmd.exe")
        .args(["/C", "mklink", "/J", &link_text, &alternate_text])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "mklink failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let metadata = fs::symlink_metadata(&link).unwrap();
    assert_ne!(metadata.file_attributes() & 0x400, 0);

    let mut executor =
        RealEffectExecutor::new(sandbox.path(), SocketAddr::from(([127, 0, 0, 1], 1))).unwrap();
    assert_eq!(
        executor
            .execute(unknown_permit(&file_read_request("workspace/input.txt")))
            .unwrap_err(),
        ExecutionError::FailedBeforeEffect
    );
}

#[test]
fn authorized_public_ruslo_flow_reaches_only_the_exact_loopback_receiver() {
    for iteration in 0..16 {
        let sandbox = Sandbox::new();
        let receiver = Receiver::start(200, Duration::ZERO);
        let action = external_send_request();
        let kernel = public_network_kernel(&action);
        let permit = kernel
            .authorize_tagged_public_send(&trusted_public_data(), &action)
            .unwrap();
        let mut executor = RealEffectExecutor::new(sandbox.path(), receiver.address).unwrap();
        let result = executor.execute(permit);
        let report = receiver.finish();
        let effect = receipt(result.unwrap_or_else(|error| {
            panic!(
                "iteration {iteration} returned {error:?}; receiver={report:?}"
            )
        }));

        assert_eq!(report.requests_received, 1);
        assert!(report.exact_request);
        assert_eq!(effect.operation(), &Operation::NetworkSend);
        assert_eq!(effect.destination(), &Destination::PublicExternal);
        assert_eq!(effect.execution_id(), 1);
        assert_eq!(effect.outcome(), EffectOutcome::Committed);
        assert_eq!(executor.committed_effect_count(), 1);
        assert!(!format!("{effect:?}").contains(REAL_NETWORK_PATH));
        assert!(!format!("{effect:?}").contains("local-network-effect"));
    }
}

#[test]
fn denied_or_mutated_network_requests_never_connect_to_the_receiver() {
    let sandbox = Sandbox::new();
    let receiver = Receiver::start(200, Duration::ZERO);
    let action = external_send_request();
    let kernel = public_network_kernel(&action);
    let protected_data = TaggedData::from_trusted_ingress(
        "protected",
        ProvenanceSource::Tool(Identity::new("trusted-local-source").unwrap()),
        Classification::Confidential,
    )
    .unwrap();
    assert!(
        kernel
            .authorize_tagged_public_send(&protected_data, &action)
            .is_err()
    );

    let wrong_resource = ActionRequest::new(
        tkach_core::domain::Principal::Model,
        Operation::NetworkSend,
        Resource::new(ResourceKind::Network, ResourceId::new("other-api").unwrap()),
        Destination::PublicExternal,
        CapabilityName::new("network.send").unwrap(),
    );
    let wrong_policy_kernel = public_network_kernel(&wrong_resource);
    let wrong_permit = wrong_policy_kernel
        .authorize_tagged_public_send(&trusted_public_data(), &wrong_resource)
        .unwrap();
    let mut wrong_executor = RealEffectExecutor::new(sandbox.path(), receiver.address).unwrap();
    assert_eq!(
        wrong_executor.execute(wrong_permit).unwrap_err(),
        ExecutionError::FailedBeforeEffect
    );

    let wrong_endpoint = Receiver::start(200, Duration::ZERO);
    let endpoint_kernel = public_network_kernel(&action);
    let endpoint_permit = endpoint_kernel
        .authorize_tagged_public_send(&trusted_public_data(), &action)
        .unwrap();
    let mut endpoint_executor = RealEffectExecutor::new(
        sandbox.path(),
        SocketAddr::from(([127, 0, 0, 2], wrong_endpoint.address.port())),
    )
    .unwrap();
    assert_eq!(
        endpoint_executor.execute(endpoint_permit).unwrap_err(),
        ExecutionError::FailedBeforeEffect
    );
    let wrong_endpoint_report = wrong_endpoint.finish();
    assert_eq!(wrong_endpoint_report.requests_received, 0);

    let report = receiver.finish();
    assert_eq!(report.requests_received, 0);
    assert_eq!(wrong_executor.attempt_count(), 1);
}

#[test]
fn gateway_untrusted_network_proposal_is_denied_before_real_connect() {
    let sandbox = Sandbox::new();
    let receiver = Receiver::start(200, Duration::ZERO);
    let action = external_send_request();
    let policy = Policy::new(
        tkach_core::domain::PolicyId::new("real-gateway-network-policy").unwrap(),
        vec![PolicyRule::allow(
            RuleId::new("allow-network-shape-only").unwrap(),
            RuleMatcher::any()
                .principal(tkach_core::domain::Principal::Model)
                .operation(Operation::NetworkSend)
                .capability(CapabilityName::new("network.send").unwrap())
                .resource(ResourceScope::exact(action.resource()))
                .destination(Destination::PublicExternal)
                .classification(Classification::Unknown),
        )],
    )
    .unwrap();
    let client = Destination::Internal(Identity::new("client").unwrap());
    let ruslo = Ruslo::new(vec![FlowRule::allow(
        RuleId::new("allow-internal-release").unwrap(),
        FlowMatcher::any()
            .principal(tkach_core::domain::Principal::Model)
            .source(FlowSource::Model)
            .destination(client.clone())
            .operation(FlowOperation::Export),
    )])
    .unwrap();
    let mut gateway = Gateway::new(
        Krosna::with_ruslo(policy, ruslo),
        tkach_core::zaslon::Zaslon::empty(),
        tkach_core::zaslon::Zaslon::empty(),
        client,
        RealEffectExecutor::new(sandbox.path(), receiver.address).unwrap(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["attempt".to_owned()],
        actions: vec![action],
        continuation: ProviderStep::Complete,
    }]);
    let request = ExternalRequest::new(
        vec![ExternalMessage::new(ExternalRole::User, "network".to_owned()).unwrap()],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let error = gateway.run(&mut provider, &request).unwrap_err();
    assert!(matches!(error.kind(), GatewayErrorKind::ActionDenied(_)));
    let report = receiver.finish();
    assert_eq!(report.requests_received, 0);
}

#[test]
fn network_failure_after_send_is_reported_as_unknown_and_timeout_is_not_a_success() {
    let sandbox = Sandbox::new();
    let failed_receiver = Receiver::start(500, Duration::ZERO);
    let action = external_send_request();
    let kernel = public_network_kernel(&action);
    let mut failed_executor =
        RealEffectExecutor::new(sandbox.path(), failed_receiver.address).unwrap();
    let failed_permit = kernel
        .authorize_tagged_public_send(&trusted_public_data(), &action)
        .unwrap();
    assert_eq!(
        failed_executor.execute(failed_permit).unwrap_err(),
        ExecutionError::OutcomeUnknown
    );
    let failed_report = failed_receiver.finish();
    assert_eq!(failed_report.requests_received, 1);
    assert!(failed_report.exact_request);
    assert_eq!(failed_executor.committed_effect_count(), 0);
    assert_eq!(failed_executor.unknown_effect_count(), 1);

    let bounded_receiver = Receiver::start_with_body(200, Duration::ZERO, 2 * 1024);
    let mut bounded_executor =
        RealEffectExecutor::new(sandbox.path(), bounded_receiver.address).unwrap();
    let bounded_permit = kernel
        .authorize_tagged_public_send(&trusted_public_data(), &action)
        .unwrap();
    let bounded_effect = receipt(bounded_executor.execute(bounded_permit).unwrap());
    let bounded_report = bounded_receiver.finish();
    assert_eq!(bounded_report.requests_received, 1);
    assert!(bounded_report.exact_request);
    assert_eq!(bounded_effect.execution_id(), 1);
    assert_eq!(bounded_executor.committed_effect_count(), 1);

    let oversized_receiver = Receiver::start_with_body(200, Duration::ZERO, 8 * 1024 + 1);
    let mut oversized_executor =
        RealEffectExecutor::new(sandbox.path(), oversized_receiver.address).unwrap();
    let oversized_permit = kernel
        .authorize_tagged_public_send(&trusted_public_data(), &action)
        .unwrap();
    assert_eq!(
        oversized_executor.execute(oversized_permit).unwrap_err(),
        ExecutionError::OutcomeUnknown
    );
    let oversized_report = oversized_receiver.finish();
    assert_eq!(oversized_report.requests_received, 1);
    assert!(oversized_report.exact_request);
    assert_eq!(oversized_executor.committed_effect_count(), 0);
    assert_eq!(oversized_executor.unknown_effect_count(), 1);

    let timeout_receiver = Receiver::start(200, Duration::from_millis(700));
    let mut timeout_executor =
        RealEffectExecutor::new(sandbox.path(), timeout_receiver.address).unwrap();
    let timeout_permit = kernel
        .authorize_tagged_public_send(&trusted_public_data(), &action)
        .unwrap();
    assert_eq!(
        timeout_executor.execute(timeout_permit).unwrap_err(),
        ExecutionError::OutcomeUnknown
    );
    let timeout_report = timeout_receiver.finish();
    assert_eq!(timeout_report.requests_received, 1);
    assert!(timeout_report.exact_request);
    assert_eq!(timeout_executor.committed_effect_count(), 0);
    assert_eq!(timeout_executor.unknown_effect_count(), 1);
}

#[test]
fn real_executor_rejects_untrusted_public_flow_without_an_execution_token() {
    let sandbox = Sandbox::new();
    let receiver = Receiver::start(200, Duration::ZERO);
    let action = external_send_request();
    let kernel = public_network_kernel(&action);
    let untrusted = TaggedData::from_untrusted("model-claimed-public");
    assert!(
        kernel
            .authorize_tagged_public_send(&untrusted, &action)
            .is_err()
    );
    let report = receiver.finish();
    assert_eq!(report.requests_received, 0);
    let executor = RealEffectExecutor::new(sandbox.path(), receiver_address_for_test()).unwrap();
    assert_eq!(executor.attempt_count(), 0);
}

fn receiver_address_for_test() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 1))
}
