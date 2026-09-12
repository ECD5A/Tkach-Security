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

//! Small offline proof of the Tkach value proposition.
//!
//! A trusted host configures one exact local write scope. That scope commits
//! and releases a bounded result; a sibling-path proposal and a compromised
//! provider proposal are denied before the executor can widen authority.

use std::cell::Cell;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use tkach_core::domain::{
    ActionRequest, CapabilityName, Classification, Destination, Identity, Operation, PolicyId,
    Principal, Resource, ResourceId, ResourceKind, ResourceScope, RuleId,
};
use tkach_core::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};
use tkach_core::propusk::{ExecutionError, Propusk, ProtectedExecutor};
use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
use tkach_core::zaslon::Zaslon;
use tkach_gateway::{
    DeterministicProvider, EffectOutcome, ExternalMessage, ExternalRequest, ExternalRole, Gateway,
    GatewayErrorKind, ProviderStep, REAL_FILE_WRITE_CONTENT, RealEffectExecutor, ScriptedStep,
    ToolResult, protected_write_request,
};

struct CountingExecutor {
    calls: Rc<Cell<usize>>,
}

impl ProtectedExecutor for CountingExecutor {
    type Output = ToolResult;

    fn execute(&mut self, _action: Propusk) -> Result<Self::Output, ExecutionError> {
        self.calls.set(self.calls.get() + 1);
        Err(ExecutionError::FailedBeforeEffect)
    }
}

fn gateway(calls: Rc<Cell<usize>>) -> Gateway {
    let client = Destination::Internal(Identity::new("client").expect("static identity"));
    let flow = FlowRule::allow(
        RuleId::new("allow-model-output").expect("static rule"),
        FlowMatcher::any()
            .principal(Principal::Model)
            .source(FlowSource::Model)
            .destination(client.clone())
            .operation(FlowOperation::Export),
    );
    let ruslo = Ruslo::new(vec![flow]).expect("static flow is valid");
    let policy = Policy::new(
        PolicyId::new("golden-case-policy").expect("static policy"),
        Vec::new(),
    )
    .expect("static policy is valid");
    let kernel = Krosna::with_zaslon_and_ruslo(policy, Zaslon::empty(), ruslo);
    Gateway::new(
        kernel,
        Zaslon::empty(),
        Zaslon::empty(),
        client,
        CountingExecutor { calls },
    )
}

fn request() -> ExternalRequest {
    ExternalRequest::new(
        vec![
            ExternalMessage::new(ExternalRole::User, "perform the bounded task".to_owned())
                .expect("static message"),
        ],
        Vec::new(),
        Vec::new(),
    )
    .expect("static request is valid")
}

/// Trusted host configuration for the positive proof. The model supplies only
/// an untrusted ActionRequest; it cannot choose this policy, destination, or
/// executor binding.
fn trusted_write_gateway(root: &Path) -> Gateway {
    let action = protected_write_request();
    let storage = Destination::Internal(Identity::new("storage").expect("static identity"));
    let client = Destination::Internal(Identity::new("client").expect("static identity"));
    let policy = Policy::new(
        PolicyId::new("golden-case-write-policy").expect("static policy id"),
        vec![PolicyRule::allow(
            RuleId::new("allow-exact-output-write").expect("static rule id"),
            RuleMatcher::any()
                .principal(Principal::Model)
                .operation(action.operation().clone())
                .capability(action.capability().clone())
                .resource(ResourceScope::exact(action.resource()))
                .destination(storage.clone())
                .classification(Classification::Unknown),
        )],
    )
    .expect("static policy is valid");
    let ruslo = Ruslo::new(vec![
        FlowRule::allow(
            RuleId::new("allow-model-storage-transfer").expect("static rule id"),
            FlowMatcher::any()
                .principal(Principal::Model)
                .source(FlowSource::Model)
                .destination(storage)
                .operation(FlowOperation::Transfer),
        ),
        FlowRule::allow(
            RuleId::new("allow-model-client-export").expect("static rule id"),
            FlowMatcher::any()
                .principal(Principal::Model)
                .source(FlowSource::Model)
                .destination(client.clone())
                .operation(FlowOperation::Export),
        ),
    ])
    .expect("static flow policy is valid");
    let kernel = Krosna::with_zaslon_and_ruslo(policy, Zaslon::empty(), ruslo);
    Gateway::new(
        kernel,
        Zaslon::empty(),
        Zaslon::empty(),
        client,
        RealEffectExecutor::new(root, SocketAddr::from(([127, 0, 0, 1], 1)))
            .expect("trusted local effect profile is valid"),
    )
}

fn out_of_scope_write_request() -> ActionRequest {
    ActionRequest::new(
        Principal::Model,
        Operation::Write,
        Resource::new(
            ResourceKind::File,
            ResourceId::new("workspace/other.txt").expect("static resource id"),
        ),
        Destination::Internal(Identity::new("storage").expect("static identity")),
        CapabilityName::new("file.write").expect("static capability"),
    )
}

struct ExampleSandbox(PathBuf);

impl ExampleSandbox {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "tkach-golden-case-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after the Unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("golden-case sandbox must be new");
        fs::create_dir(root.join("workspace")).expect("golden-case workspace must be new");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ExampleSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn main() {
    let sandbox = ExampleSandbox::new();
    let mut allowed_gateway = trusted_write_gateway(sandbox.path());
    let mut allowed_provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["authorized write completed".to_owned()],
        actions: vec![protected_write_request()],
        continuation: ProviderStep::Complete,
    }]);
    let allowed = allowed_gateway
        .run(&mut allowed_provider, &request())
        .expect("the trusted exact-scope write should commit");
    assert_eq!(allowed.output(), Some("authorized write completed"));
    assert_eq!(allowed.effects().len(), 1);
    assert_eq!(allowed.effects()[0].outcome(), EffectOutcome::Committed);
    assert_eq!(
        fs::read(sandbox.path().join("workspace/output.txt")).expect("output is inside sandbox"),
        REAL_FILE_WRITE_CONTENT
    );

    let mut out_of_scope_gateway = trusted_write_gateway(sandbox.path());
    let mut out_of_scope_provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["attempted scope escape".to_owned()],
        actions: vec![out_of_scope_write_request()],
        continuation: ProviderStep::Complete,
    }]);
    let out_of_scope = out_of_scope_gateway
        .run(&mut out_of_scope_provider, &request())
        .expect_err("a sibling path must fail the exact policy scope");
    assert!(matches!(
        out_of_scope.kind(),
        GatewayErrorKind::ActionDenied(_)
    ));
    assert!(!sandbox.path().join("workspace/other.txt").exists());

    let safe_calls = Rc::new(Cell::new(0));
    let mut safe_gateway = gateway(Rc::clone(&safe_calls));
    let mut safe_provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["bounded useful response".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let safe_result = safe_gateway
        .run(&mut safe_provider, &request())
        .expect("safe bounded output should be released");
    assert_eq!(safe_result.output(), Some("bounded useful response"));
    assert_eq!(safe_calls.get(), 0);

    let hostile_calls = Rc::new(Cell::new(0));
    let mut hostile_gateway = gateway(Rc::clone(&hostile_calls));
    let mut compromised_provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["attempted protected write".to_owned()],
        actions: vec![protected_write_request()],
        continuation: ProviderStep::Complete,
    }]);
    let denial = hostile_gateway
        .run(&mut compromised_provider, &request())
        .expect_err("compromised model action must be denied");
    assert!(matches!(denial.kind(), GatewayErrorKind::ActionDenied(_)));
    assert_eq!(hostile_calls.get(), 0);

    // Keep the output stable so this can be copied into a release README or
    // used as a tiny CI smoke without exposing request/provider payloads.
    println!(
        "GOLDEN_CASE|safe_output=released|allowed_write=committed|out_of_scope=denied|compromised_action=denied|compromised_executor_calls={}",
        hostile_calls.get()
    );
}
