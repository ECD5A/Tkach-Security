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

//! Minimal Basic Gateway integration smoke.

use tkach_core::diode::{Diode, FlowMatcher, FlowOperation, FlowRule, FlowSource};
use tkach_core::domain::{Destination, Identity, PolicyId, Principal, RuleId};
use tkach_core::krosna::{Krosna, Policy};
use tkach_core::zaslon::Zaslon;
use tkach_gateway::{
    DeterministicProvider, ExternalMessage, ExternalRequest, ExternalRole, FakeToolBroker, Gateway,
    ProviderStep, ScriptedStep,
};

fn main() {
    let client = Destination::Internal(Identity::new("client").unwrap());
    let flow = FlowRule::allow(
        RuleId::new("allow-basic-release").unwrap(),
        FlowMatcher::any()
            .principal(Principal::Model)
            .source(FlowSource::Model)
            .destination(client.clone())
            .operation(FlowOperation::Export),
    );
    let diode = Diode::new(vec![flow]).unwrap();
    let policy = Policy::new(PolicyId::new("quickstart-basic").unwrap(), Vec::new()).unwrap();
    let kernel = Krosna::with_zaslon_and_diode(policy, Zaslon::empty(), diode);
    let mut gateway = Gateway::new(
        kernel,
        Zaslon::empty(),
        Zaslon::empty(),
        client,
        FakeToolBroker::new(),
    );
    let mut provider = DeterministicProvider::new(vec![ScriptedStep {
        chunks: vec!["bounded response".to_owned()],
        actions: Vec::new(),
        continuation: ProviderStep::Complete,
    }]);
    let request = ExternalRequest::new(
        vec![
            ExternalMessage::new(ExternalRole::User, "return a bounded response".to_owned())
                .unwrap(),
        ],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();

    let result = gateway.run(&mut provider, &request).unwrap();
    assert_eq!(result.output(), Some("bounded response"));
    println!("Basic Gateway released one bounded response");
}
