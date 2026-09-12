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

//! Deterministic local latency and payload-memory evidence.
//!
//! This is an observation tool, not an SLA or a process-RSS profiler. The
//! memory field is the sum of published bounded payload budgets, so it proves
//! the contract's accounting surface rather than claiming a complete OS
//! memory measurement.

use std::time::Instant;

use tkach_core::domain::{Destination, Identity, PolicyId, Principal, RuleId};
use tkach_core::krosna::{Krosna, Policy};
use tkach_core::ruslo::{FlowMatcher, FlowOperation, FlowRule, FlowSource, Ruslo};
use tkach_core::zaslon::Zaslon;
use tkach_gateway::{
    DeterministicProvider, ExternalMessage, ExternalRequest, ExternalRole, FakeToolBroker, Gateway,
    MAX_MODEL_CONTEXT_BYTES, MAX_REQUEST_BODY_BYTES, MAX_RUNTIME_FRAME_BYTES,
    MAX_RUNTIME_RESPONSE_BYTES, MAX_STREAMING_OUTPUT_BYTES, ProviderStep, ScriptedStep,
};

const ITERATIONS: usize = 128;
const WARMUP_ITERATIONS: usize = 8;

fn gateway() -> Gateway {
    let client = Destination::Internal(Identity::new("client").expect("static identity"));
    let flow = FlowRule::allow(
        RuleId::new("allow-performance-release").expect("static rule id"),
        FlowMatcher::any()
            .principal(Principal::Model)
            .source(FlowSource::Model)
            .destination(client.clone())
            .operation(FlowOperation::Export),
    );
    let kernel = Krosna::with_zaslon_and_ruslo(
        Policy::new(
            PolicyId::new("performance-baseline").expect("static policy id"),
            Vec::new(),
        )
        .expect("static policy"),
        Zaslon::empty(),
        Ruslo::new(vec![flow]).expect("static flow policy"),
    );
    Gateway::new(
        kernel,
        Zaslon::empty(),
        Zaslon::empty(),
        client,
        FakeToolBroker::new(),
    )
}

fn request() -> ExternalRequest {
    ExternalRequest::new(
        vec![
            ExternalMessage::new(ExternalRole::User, "measure one bounded request".to_owned())
                .expect("static message"),
        ],
        Vec::new(),
        Vec::new(),
    )
    .expect("static request")
}

fn run_once(gateway: &mut Gateway, request: &ExternalRequest) {
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["bounded performance response".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let result = gateway
        .run(&mut provider, request)
        .expect("deterministic baseline must remain useful");
    assert_eq!(result.output(), Some("bounded performance response"));
}

fn percentile(sorted: &[u128], numerator: usize, denominator: usize) -> u128 {
    let index = (sorted.len() * numerator)
        .div_ceil(denominator)
        .saturating_sub(1);
    sorted[index]
}

fn main() {
    let mut gateway = gateway();
    let request = request();
    for _ in 0..WARMUP_ITERATIONS {
        run_once(&mut gateway, &request);
    }

    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        run_once(&mut gateway, &request);
        samples.push(started.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let total: u128 = samples.iter().sum();
    let declared_payload_memory_bound_bytes = MAX_REQUEST_BODY_BYTES
        + MAX_MODEL_CONTEXT_BYTES
        + MAX_STREAMING_OUTPUT_BYTES
        + MAX_RUNTIME_FRAME_BYTES
        + MAX_RUNTIME_RESPONSE_BYTES;
    println!(
        "TKACH_PERF|iterations={ITERATIONS}|warmup={WARMUP_ITERATIONS}|latency_ns_min={}|latency_ns_median={}|latency_ns_p95={}|latency_ns_max={}|latency_ns_mean={}|declared_payload_memory_bound_bytes={declared_payload_memory_bound_bytes}|memory_measurement=bounded_payload_accounting_not_process_rss",
        samples[0],
        percentile(&samples, 1, 2),
        percentile(&samples, 95, 100),
        samples[ITERATIONS - 1],
        total / ITERATIONS as u128,
    );
}
