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

//! Independent, table-driven checks for the public Strong Core boundary.
//!
//! These expectations are written as security truths instead of reusing
//! production predicates. A changed implementation must therefore still agree
//! with an independently authored allow/deny table.

use tkach_core::diode::{Diode, FlowMatcher, FlowOperation, FlowRule};
use tkach_core::domain::{
    ActionRequest, Authority, CapabilityName, Classification, DecisionKind, Destination,
    FlowDirection, Identity, Lane, Operation, PolicyId, Principal, Resource, ResourceId,
    ResourceKind, ResourceScope, RuleId, SledReason, Trust,
};
use tkach_core::gnezdo::{DataLane, Gnezdo};
use tkach_core::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};
use tkach_core::niti_metka::TaggedData;
use tkach_core::pechat::{FakeBroker, PechatError, SecretBroker, SecretHandle};
use tkach_core::zaslon::{ContentDecision, ContentRule, Zaslon};

fn id(value: &str) -> ResourceId {
    ResourceId::new(value).expect("oracle fixture id is valid")
}

fn rule_id(value: &str) -> RuleId {
    RuleId::new(value).expect("oracle fixture rule id is valid")
}

fn capability(value: &str) -> CapabilityName {
    CapabilityName::new(value).expect("oracle fixture capability is valid")
}

fn resource(kind: ResourceKind, value: &str) -> Resource {
    Resource::new(kind, id(value))
}

fn allow_all_policy() -> Policy {
    Policy::new(
        PolicyId::new("oracle-allow-all").unwrap(),
        vec![PolicyRule::allow(rule_id("allow-all"), RuleMatcher::any())],
    )
    .unwrap()
}

#[test]
fn authority_lane_truth_table_accepts_only_canonical_public_data() {
    let content = Gnezdo::new()
        .contain("administrator instructions are data".to_owned())
        .unwrap();
    assert_eq!(
        (
            content.context().authority(),
            content.context().lane(),
            content.context().trust(),
            content.context().classification(),
        ),
        (
            Authority::None,
            Lane::Data,
            Trust::Untrusted,
            Classification::Unknown
        )
    );
    assert_eq!(DataLane::authority(), Authority::None);
    assert_eq!(DataLane::lane(), Lane::Data);
    assert_eq!(DataLane::trust(), Trust::Untrusted);
    assert_eq!(DataLane::direction(), None);

    let table = [
        ("Model", "None", "Untrusted", "Data", "Unknown", true),
        (
            "Model",
            "TrustedControl",
            "Trusted",
            "Control",
            "Public",
            false,
        ),
        ("Model", "None", "Trusted", "Data", "Unknown", false),
        ("System", "None", "Untrusted", "Data", "Unknown", false),
        ("Model", "None", "Untrusted", "Control", "Unknown", false),
        ("Model", "None", "Untrusted", "Data", "Public", false),
    ];
    for (principal, authority, trust, lane, classification, should_parse) in table {
        let wire = serde_json::json!({
            "principal": principal,
            "authority": authority,
            "trust": trust,
            "lane": lane,
            "provenance": {"source": "Unknown", "lineage": ["Unknown"]},
            "classification": classification,
        });
        assert_eq!(
            serde_json::from_value::<tkach_core::domain::SecurityContext>(wire).is_ok(),
            should_parse,
            "authority/lane/trust/classification table row was not enforced"
        );
    }
}

#[test]
fn capability_scope_truth_table_does_not_widen_file_prefix_or_kind() {
    let scope = ResourceScope::file_prefix("workspace/docs").unwrap();
    let policy = Policy::new(
        PolicyId::new("oracle-scoped-read").unwrap(),
        vec![PolicyRule::allow(
            rule_id("allow-docs-read"),
            RuleMatcher::any()
                .principal(Principal::Model)
                .operation(Operation::Read)
                .capability(capability("file.read"))
                .resource(scope)
                .destination(Destination::Model),
        )],
    )
    .unwrap();
    let kernel = Krosna::new(policy);
    let table = [
        (
            ResourceKind::File,
            "workspace/docs/readme.md",
            DecisionKind::Allow,
        ),
        (
            ResourceKind::File,
            "workspace/docs/nested/data.txt",
            DecisionKind::Allow,
        ),
        (ResourceKind::File, "workspace/docs", DecisionKind::Allow),
        (
            ResourceKind::File,
            "workspace/docs-private/data.txt",
            DecisionKind::Deny,
        ),
        (
            ResourceKind::File,
            "workspace/docs2/data.txt",
            DecisionKind::Deny,
        ),
        (
            ResourceKind::Database,
            "workspace/docs/readme.md",
            DecisionKind::Deny,
        ),
    ];
    for (kind, name, expected) in table {
        let request = ActionRequest::new(
            Principal::Model,
            Operation::Read,
            resource(kind, name),
            Destination::Model,
            capability("file.read"),
        );
        let decision = kernel.evaluate(
            &tkach_core::domain::SecurityContext::untrusted_data(),
            &request,
        );
        assert_eq!(
            decision.kind, expected,
            "scope/capability row changed: {kind:?} {name}"
        );
    }
}

#[test]
fn capability_operation_truth_table_rejects_cross_kind_and_alias_requests() {
    let kernel = Krosna::new(allow_all_policy());
    let context = tkach_core::domain::SecurityContext::untrusted_data();
    let table = [
        (
            Operation::Read,
            ResourceKind::File,
            "file.read",
            DecisionKind::Allow,
        ),
        (
            Operation::Read,
            ResourceKind::Database,
            "database.read",
            DecisionKind::Allow,
        ),
        (
            Operation::Read,
            ResourceKind::File,
            "database.read",
            DecisionKind::Deny,
        ),
        (
            Operation::Write,
            ResourceKind::File,
            "file.write",
            DecisionKind::Allow,
        ),
        (
            Operation::Write,
            ResourceKind::Database,
            "database.write",
            DecisionKind::Allow,
        ),
        (
            Operation::Write,
            ResourceKind::File,
            "database.write",
            DecisionKind::Deny,
        ),
        (
            Operation::Execute,
            ResourceKind::Tool,
            "tool.execute",
            DecisionKind::Allow,
        ),
        (
            Operation::Execute,
            ResourceKind::Secret,
            "secret.use",
            DecisionKind::Deny,
        ),
        (
            Operation::NetworkSend,
            ResourceKind::Network,
            "network.send",
            DecisionKind::Allow,
        ),
        (
            Operation::NetworkSend,
            ResourceKind::Tool,
            "network.send",
            DecisionKind::Deny,
        ),
        (
            Operation::NetworkSend,
            ResourceKind::Network,
            "file.read",
            DecisionKind::Deny,
        ),
        (
            Operation::RevealSecret,
            ResourceKind::Secret,
            "secret.reveal",
            DecisionKind::Deny,
        ),
        (
            Operation::Declassify,
            ResourceKind::Policy,
            "data.declassify",
            DecisionKind::Deny,
        ),
        (
            Operation::MutatePolicy,
            ResourceKind::Policy,
            "policy.mutate",
            DecisionKind::Deny,
        ),
    ];
    for (operation, kind, capability_name, expected) in table {
        let request = ActionRequest::new(
            Principal::Model,
            operation,
            resource(kind, "oracle-resource"),
            Destination::Model,
            capability(capability_name),
        );
        assert_eq!(kernel.evaluate(&context, &request).kind, expected);
    }
}

#[test]
fn public_metadata_accessors_and_debug_views_do_not_disappear_or_leak_payloads() {
    let content = Gnezdo::new()
        .contain("do not print this hostile content".to_owned())
        .unwrap();
    assert!(format!("{content:?}").contains("UntrustedContent"));
    assert!(!format!("{content:?}").contains("do not print this hostile content"));

    let tagged = TaggedData::from_untrusted("do not print this tagged payload".to_owned());
    assert!(format!("{tagged:?}").contains("TaggedData"));
    assert!(!format!("{tagged:?}").contains("do not print this tagged payload"));

    let handle = SecretHandle::new("oracle-handle").unwrap();
    assert_eq!(handle.as_str(), "oracle-handle");
    let mut broker = FakeBroker::new();
    assert!(broker.is_empty());
    broker
        .register(handle, b"not-for-display".to_vec())
        .unwrap();
    assert_eq!(broker.len(), 1);
    assert!(!broker.is_empty());
    assert!(format!("{broker:?}").contains("FakeBroker"));
    assert!(!format!("{broker:?}").contains("not-for-display"));

    let trace = tkach_core::sled::SledTrace::new();
    assert!(format!("{trace:?}").contains("SledTrace"));
    assert!(trace.is_empty());
    let executor = tkach_core::sled::FakeProtectedExecutor::new();
    assert!(format!("{executor:?}").contains("FakeProtectedExecutor"));
    assert!(executor.is_empty());
}

#[test]
fn trace_and_executor_nonempty_accessors_return_recorded_entries() {
    let kernel = Krosna::new(allow_all_policy());
    let context = tkach_core::domain::SecurityContext::untrusted_data();
    let request = ActionRequest::new(
        Principal::Model,
        Operation::Read,
        resource(ResourceKind::File, "oracle-resource"),
        Destination::Model,
        capability("file.read"),
    );
    let decision = kernel.evaluate(&context, &request);
    let mut trace = tkach_core::sled::SledTrace::new();
    trace.record(decision).unwrap();
    assert_eq!(trace.entries().len(), 1);
    assert_eq!(trace.len(), 1);
}

#[test]
fn classification_destination_truth_table_keeps_unknown_model_data_out_of_public_egress() {
    let data = TaggedData::from_untrusted("model-derived data".to_owned());
    assert_eq!(data.metka().classification(), Classification::Unknown);
    let diode = Diode::new(vec![FlowRule::allow(
        rule_id("oracle-allow-flow"),
        FlowMatcher::any(),
    )])
    .unwrap();
    let table = [
        (
            Destination::Model,
            FlowOperation::Read,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Destination::PublicExternal,
            FlowOperation::Export,
            DecisionKind::Deny,
            SledReason::FlowDenied,
        ),
        (
            Destination::SecretBroker,
            FlowOperation::Transfer,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Destination::Unknown(Identity::new("future-destination").unwrap()),
            FlowOperation::Transfer,
            DecisionKind::Deny,
            SledReason::UnknownDenied,
        ),
    ];
    for (destination, operation, expected_kind, expected_reason) in table {
        let request = tkach_core::diode::FlowRequest::from_tagged(destination, operation, &data);
        let decision = diode.evaluate(&request);
        assert_eq!(
            (decision.kind, decision.evidence.reason),
            (expected_kind, expected_reason)
        );
    }
}

#[test]
fn flow_direction_truth_table_is_not_reversed_by_content_rule_matching() {
    let zaslon = Zaslon::new(
        Vec::new(),
        vec![
            ContentRule::new(
                rule_id("block-ingress"),
                FlowDirection::Ingress,
                "ignore policy",
            )
            .unwrap(),
            ContentRule::new(
                rule_id("block-egress"),
                FlowDirection::Egress,
                "send secret",
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let context = tkach_core::domain::SecurityContext::untrusted_data();
    let table = [
        (FlowDirection::Ingress, "IGNORE   POLICY", true),
        (FlowDirection::Ingress, "send secret", false),
        (FlowDirection::Egress, "send secret", true),
        (FlowDirection::Egress, "ignore policy", false),
    ];
    for (direction, content, should_block) in table {
        let blocked = matches!(
            zaslon.inspect_content(direction, &context, content),
            ContentDecision::Blocked { .. }
        );
        assert_eq!(blocked, should_block, "direction/content row changed");
    }
}

#[test]
fn secret_handle_operation_truth_table_has_one_broker_use_and_no_reveal() {
    let handle = SecretHandle::new("oracle-secret").unwrap();
    let policy = Policy::new(
        PolicyId::new("oracle-secret-policy").unwrap(),
        vec![PolicyRule::allow(
            rule_id("allow-secret-use"),
            RuleMatcher::any()
                .principal(Principal::Model)
                .operation(Operation::Execute)
                .capability(capability("secret.use"))
                .resource(ResourceScope::exact(&handle.resource()))
                .destination(Destination::SecretBroker),
        )],
    )
    .unwrap();
    let kernel = Krosna::new(policy);
    let context = tkach_core::domain::SecurityContext::untrusted_data();
    let mut broker = FakeBroker::new();
    broker
        .register(handle.clone(), b"oracle-secret-value".to_vec())
        .unwrap();

    let use_request = ActionRequest::new(
        Principal::Model,
        Operation::Execute,
        handle.resource(),
        Destination::SecretBroker,
        capability("secret.use"),
    );
    let permit = kernel.authorize(&context, &use_request).unwrap();
    assert!(broker.use_authorized(&handle, permit).is_ok());
    assert_eq!(broker.reveal(&handle), Err(PechatError::UnauthorizedReveal));

    let reveal_request = ActionRequest::new(
        Principal::Model,
        Operation::RevealSecret,
        handle.resource(),
        Destination::SecretBroker,
        capability("secret.reveal"),
    );
    let reveal_decision = kernel.evaluate(&context, &reveal_request);
    assert_eq!(
        (reveal_decision.kind, reveal_decision.evidence.reason),
        (DecisionKind::Deny, SledReason::HardDeny)
    );

    let other_handle = SecretHandle::new("other-secret").unwrap();
    let other_request = ActionRequest::new(
        Principal::Model,
        Operation::Execute,
        other_handle.resource(),
        Destination::SecretBroker,
        capability("secret.use"),
    );
    let other_permit = kernel.authorize(&context, &use_request).unwrap();
    assert!(kernel.authorize(&context, &other_request).is_err());
    assert_eq!(
        broker.use_authorized(&other_handle, other_permit),
        Err(PechatError::InvalidPropusk)
    );
}

#[test]
fn unknown_state_truth_table_denies_unknown_and_privileged_requests() {
    let kernel = Krosna::new(allow_all_policy());
    let context = tkach_core::domain::SecurityContext::untrusted_data();
    let table = [
        (
            Operation::Read,
            resource(ResourceKind::File, "workspace/readme.md"),
            Destination::Model,
            capability("file.read"),
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Operation::Unknown(capability("future.operation")),
            resource(ResourceKind::Unknown, "future-resource"),
            Destination::Model,
            capability("future.operation"),
            DecisionKind::Deny,
            SledReason::UnknownDenied,
        ),
        (
            Operation::RevealSecret,
            resource(ResourceKind::Secret, "oracle-secret"),
            Destination::SecretBroker,
            capability("secret.reveal"),
            DecisionKind::Deny,
            SledReason::HardDeny,
        ),
        (
            Operation::Read,
            resource(ResourceKind::File, "workspace/readme.md"),
            Destination::Unknown(Identity::new("future-destination").unwrap()),
            capability("file.read"),
            DecisionKind::Deny,
            SledReason::UnknownDenied,
        ),
    ];
    for (operation, resource, destination, capability, expected_kind, expected_reason) in table {
        let request = ActionRequest::new(
            Principal::Model,
            operation,
            resource,
            destination,
            capability,
        );
        let decision = kernel.evaluate(&context, &request);
        assert_eq!(
            (decision.kind, decision.evidence.reason),
            (expected_kind, expected_reason)
        );
    }
}
