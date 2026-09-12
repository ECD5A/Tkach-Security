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
//! A useful bounded response is released. A compromised provider can propose
//! a protected write, but Strong Core denies it before the executor boundary.

use std::cell::Cell;
use std::rc::Rc;

use tkach_core::domain::{Destination, Identity, PolicyId, Principal, RuleId};
use tkach_core::krosna::{Krosna, Policy};
use tkach_core::propusk::{ExecutionError, Propusk, ProtectedExecutor};
use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
use tkach_core::zaslon::Zaslon;
use tkach_gateway::{
    DeterministicProvider, ExternalMessage, ExternalRequest, ExternalRole, Gateway,
    GatewayErrorKind, ProviderStep, ScriptedStep, ToolResult, protected_write_request,
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

fn main() {
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
        "GOLDEN_CASE|safe_output=released|compromised_action=denied|executor_calls={}",
        hostile_calls.get()
    );
}
