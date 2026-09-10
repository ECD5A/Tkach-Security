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

//! Independent in-crate truth tables for states not constructible by public callers.

use crate::domain::{
    ActionRequest, Classification, DecisionKind, Destination, FlowDirection, Identity, Operation,
    PolicyId, Principal, Provenance, ProvenanceSource, Resource, ResourceId, ResourceKind,
    ResourceScope, RuleId, SecurityContext, SledReason,
};
use crate::gnezdo::{Gnezdo, GnezdoError, UntrustedContent};
use crate::klyuchnik::{FakeBroker, KlyuchnikError, SecretBroker, SecretHandle};
use crate::krosna::{Krosna, Policy, PolicyRule, RuleMatcher};
use crate::niti_metka::{Metka, Niti, TaggedData};
use crate::propusk::{AuthorizedAction, CapabilityGrant, ProtectedExecutor};
use crate::ruslo::{FlowMatcher, FlowOperation, FlowRequest, FlowRule, FlowSource, Ruslo};
use crate::sled::{EnforcementTestbed, FakeProtectedExecutor, HostileModel};
use crate::zaslon::{ActionRule, CanonicalText, ContentRule, ContentVerdict, Zaslon};

fn context(classification: Classification) -> SecurityContext {
    SecurityContext::untrusted_with_metadata(
        Principal::Model,
        Provenance::from_source(ProvenanceSource::Web(Identity::new("oracle.test").unwrap()))
            .unwrap(),
        classification,
    )
}

fn network_request(destination: Destination) -> ActionRequest {
    ActionRequest::new(
        Principal::Model,
        Operation::NetworkSend,
        Resource::new(
            ResourceKind::Network,
            ResourceId::new("oracle-egress").unwrap(),
        ),
        destination,
        crate::domain::CapabilityName::new("network.send").unwrap(),
    )
}

fn allow_all_policy() -> Policy {
    Policy::new(
        PolicyId::new("independent-allow-all").unwrap(),
        vec![PolicyRule::allow(
            RuleId::new("allow-all").unwrap(),
            RuleMatcher::any(),
        )],
    )
    .unwrap()
}

fn public_context() -> SecurityContext {
    SecurityContext::untrusted_with_metadata(
        Principal::Model,
        Provenance::from_source(ProvenanceSource::Web(Identity::new("oracle.test").unwrap()))
            .unwrap(),
        Classification::Public,
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn classification_destination_oracle_has_no_protected_external_allow() {
    assert_eq!(allow_all_policy().rules().len(), 1);
    let kernel = Krosna::new(
        Policy::new(
            crate::domain::PolicyId::new("independent-classification-destination").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-network-send").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap(),
    );

    let table = [
        (
            Classification::Public,
            Destination::Model,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Classification::Internal,
            Destination::Model,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Classification::Confidential,
            Destination::Model,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Classification::Sensitive,
            Destination::Model,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Classification::Secret,
            Destination::Model,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Classification::Unknown,
            Destination::Model,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Classification::Public,
            Destination::PublicExternal,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Classification::Internal,
            Destination::PublicExternal,
            DecisionKind::Allow,
            SledReason::ExplicitAllow,
        ),
        (
            Classification::Confidential,
            Destination::PublicExternal,
            DecisionKind::Deny,
            SledReason::FlowDenied,
        ),
        (
            Classification::Sensitive,
            Destination::PublicExternal,
            DecisionKind::Deny,
            SledReason::FlowDenied,
        ),
        (
            Classification::Secret,
            Destination::PublicExternal,
            DecisionKind::Deny,
            SledReason::FlowDenied,
        ),
        (
            Classification::Unknown,
            Destination::PublicExternal,
            DecisionKind::Deny,
            SledReason::FlowDenied,
        ),
        (
            Classification::Public,
            Destination::Unknown(Identity::new("oracle-future").unwrap()),
            DecisionKind::Deny,
            SledReason::UnknownDenied,
        ),
        (
            Classification::Secret,
            Destination::Unknown(Identity::new("oracle-future").unwrap()),
            DecisionKind::Deny,
            SledReason::UnknownDenied,
        ),
    ];

    for (classification, destination, expected_kind, expected_reason) in table {
        let decision = kernel.evaluate(&context(classification), &network_request(destination));
        assert_eq!(
            (decision.kind, decision.evidence.reason),
            (expected_kind, expected_reason)
        );
    }
}

#[test]
fn capability_registry_oracle_rejects_wrong_operation_and_resource_pairs() {
    let kernel = Krosna::new(allow_all_policy());
    let context = public_context();
    let cases = [
        (Operation::Read, ResourceKind::File, "file.read", true),
        (Operation::Read, ResourceKind::File, "database.read", false),
        (
            Operation::Write,
            ResourceKind::Database,
            "database.write",
            true,
        ),
        (
            Operation::Write,
            ResourceKind::File,
            "database.write",
            false,
        ),
        (Operation::Execute, ResourceKind::Tool, "tool.execute", true),
        (
            Operation::Execute,
            ResourceKind::Secret,
            "secret.use",
            false,
        ),
        (
            Operation::NetworkSend,
            ResourceKind::Network,
            "network.send",
            true,
        ),
        (
            Operation::NetworkSend,
            ResourceKind::Tool,
            "network.send",
            false,
        ),
        (
            Operation::NetworkSend,
            ResourceKind::Network,
            "file.read",
            false,
        ),
        (
            Operation::RevealSecret,
            ResourceKind::Secret,
            "secret.reveal",
            false,
        ),
        (
            Operation::Declassify,
            ResourceKind::Policy,
            "data.declassify",
            false,
        ),
        (
            Operation::MutatePolicy,
            ResourceKind::Policy,
            "policy.mutate",
            false,
        ),
    ];
    for (operation, kind, capability_name, should_allow) in cases {
        let request = ActionRequest::new(
            Principal::Model,
            operation,
            Resource::new(kind, ResourceId::new("oracle-capability").unwrap()),
            Destination::Model,
            crate::domain::CapabilityName::new(capability_name).unwrap(),
        );
        assert_eq!(
            kernel.evaluate(&context, &request).is_allowed(),
            should_allow
        );
    }
}

#[test]
fn policy_matcher_and_ruslo_matcher_tables_reject_each_unmatched_dimension() {
    let request = ActionRequest::new(
        Principal::Model,
        Operation::Read,
        Resource::new(ResourceKind::File, ResourceId::new("oracle-file").unwrap()),
        Destination::Model,
        crate::domain::CapabilityName::new("file.read").unwrap(),
    );
    let context = public_context();
    let principal_rule = PolicyRule::allow(
        RuleId::new("principal-filter").unwrap(),
        RuleMatcher::any().principal(Principal::Service(Identity::new("svc").unwrap())),
    );
    let capability_rule = PolicyRule::allow(
        RuleId::new("capability-filter").unwrap(),
        RuleMatcher::any().capability(crate::domain::CapabilityName::new("database.read").unwrap()),
    );
    for rule in [principal_rule, capability_rule] {
        let kernel =
            Krosna::new(Policy::new(PolicyId::new("matcher-policy").unwrap(), vec![rule]).unwrap());
        let decision = kernel.evaluate(&context, &request);
        assert_eq!(
            (decision.kind, decision.evidence.reason),
            (DecisionKind::Deny, SledReason::NoAuthorization)
        );
    }

    let provenance = Provenance::from_source(ProvenanceSource::User).unwrap();
    let base = FlowRequest::new(
        Principal::Model,
        FlowSource::Model,
        Destination::Model,
        FlowOperation::Read,
        provenance,
        Classification::Public,
    );
    let cases = [
        FlowMatcher::any().principal(Principal::Service(Identity::new("svc").unwrap())),
        FlowMatcher::any().source(FlowSource::Resource(Resource::new(
            ResourceKind::Database,
            ResourceId::new("oracle-db").unwrap(),
        ))),
        FlowMatcher::any().destination(Destination::Internal(Identity::new("inside").unwrap())),
        FlowMatcher::any().operation(FlowOperation::Export),
        FlowMatcher::any().provenance(ProvenanceSource::Web(Identity::new("other.test").unwrap())),
        FlowMatcher::any().classification(Classification::Secret),
    ];
    for (index, matcher) in cases.into_iter().enumerate() {
        let ruslo = Ruslo::new(vec![FlowRule::allow(
            RuleId::new(format!("filter-{index}")).unwrap(),
            matcher,
        )])
        .unwrap();
        let decision = ruslo.evaluate(&base);
        assert_eq!(
            (decision.kind, decision.evidence.reason),
            (DecisionKind::Deny, SledReason::NoAuthorization)
        );
    }
}

#[test]
fn provenance_and_identifier_boundary_tables_reject_noncanonical_wire_shapes() {
    let exact_id = serde_json::to_value("a".repeat(128)).unwrap();
    let oversized_id = serde_json::to_value("a".repeat(129)).unwrap();
    assert!(serde_json::from_value::<ResourceId>(exact_id).is_ok());
    assert!(serde_json::from_value::<ResourceId>(oversized_id).is_err());

    let valid_root = serde_json::json!({"source": "User", "lineage": ["User"]});
    let invalid_derived_root = serde_json::json!({"source": "Derived", "lineage": ["Derived"]});
    let valid_derived = serde_json::json!({"source": "User", "lineage": ["User"]});
    let valid_derived_wire =
        serde_json::json!({"source": "Derived", "lineage": ["User", "Derived"]});
    let mismatched_root = serde_json::json!({"source": "User", "lineage": ["Web", "example.test"]});
    assert!(serde_json::from_value::<Provenance>(valid_root).is_ok());
    assert!(serde_json::from_value::<Provenance>(invalid_derived_root).is_err());
    assert!(serde_json::from_value::<Provenance>(valid_derived).is_ok());
    assert!(serde_json::from_value::<Provenance>(valid_derived_wire).is_ok());
    assert!(serde_json::from_value::<Provenance>(mismatched_root).is_err());

    let valid_scope = serde_json::json!({
        "kind": "File",
        "pattern": {"FilePrefix": "workspace/docs"}
    });
    assert!(serde_json::from_value::<ResourceScope>(valid_scope).is_ok());
    let exact_path_scope = serde_json::json!({
        "kind": "File",
        "pattern": {"FilePrefix": "a".repeat(1_024)}
    });
    let oversized_path_scope = serde_json::json!({
        "kind": "File",
        "pattern": {"FilePrefix": "a".repeat(1_025)}
    });
    assert!(serde_json::from_value::<ResourceScope>(exact_path_scope).is_ok());
    assert!(serde_json::from_value::<ResourceScope>(oversized_path_scope).is_err());

    let exact_string = "a".repeat(128);
    let oversized_string = "a".repeat(129);
    let exact_string_result =
        crate::domain::deserialize_bounded_string::<_, 128>(serde::de::value::StrDeserializer::<
            serde::de::value::Error,
        >::new(&exact_string));
    let oversized_string_result =
        crate::domain::deserialize_bounded_string::<_, 128>(serde::de::value::StrDeserializer::<
            serde::de::value::Error,
        >::new(&oversized_string));
    assert_eq!(exact_string_result.unwrap().len(), 128);
    assert!(oversized_string_result.is_err());

    let vector_error =
        crate::domain::deserialize_bounded_vec::<_, u8, 3>(serde::de::value::I32Deserializer::<
            serde::de::value::Error,
        >::new(1))
        .unwrap_err()
        .to_string();
    let string_error =
        crate::domain::deserialize_bounded_string::<_, 3>(serde::de::value::I32Deserializer::<
            serde::de::value::Error,
        >::new(1))
        .unwrap_err()
        .to_string();
    assert!(vector_error.contains("a sequence with at most 3 elements"));
    assert!(string_error.contains("a string with at most 3 bytes"));
}

#[test]
fn security_context_wire_table_rejects_one_dimension_at_a_time() {
    let rows = [
        ("System", "None", "Untrusted", "Data", "Unknown", false),
        (
            "Model",
            "TrustedControl",
            "Untrusted",
            "Data",
            "Unknown",
            false,
        ),
        ("Model", "None", "Trusted", "Data", "Unknown", false),
        ("Model", "None", "Untrusted", "Control", "Unknown", false),
        ("Model", "None", "Untrusted", "Data", "Public", false),
        ("Model", "None", "Untrusted", "Data", "Unknown", true),
    ];
    for (principal, authority, trust, lane, classification, expected) in rows {
        let wire = serde_json::json!({
            "principal": principal,
            "authority": authority,
            "trust": trust,
            "lane": lane,
            "provenance": {"source": "Unknown", "lineage": ["Unknown"]},
            "classification": classification,
        });
        assert_eq!(
            serde_json::from_value::<SecurityContext>(wire).is_ok(),
            expected
        );
    }
}

#[test]
fn exact_boundary_tables_preserve_bounded_derivations_and_content() {
    let parent = Provenance::from_source(ProvenanceSource::User).unwrap();
    let exact_parents = vec![parent.clone(); 256];
    let derived = Provenance::derived_from(&exact_parents);
    assert_eq!(
        derived.lineage(),
        &[ProvenanceSource::User, ProvenanceSource::Derived]
    );

    let roots = (0..256)
        .map(|index| {
            Provenance::from_source(ProvenanceSource::Web(
                Identity::new(format!("host-{index}")).unwrap(),
            ))
            .unwrap()
        })
        .collect::<Vec<_>>();
    let overflow = Provenance::derived_from(&roots);
    assert_eq!(
        overflow.lineage(),
        &[ProvenanceSource::Unknown, ProvenanceSource::Derived]
    );

    let gnezdo = Gnezdo::new();
    let exact_content = "x".repeat(1_048_576);
    assert!(gnezdo.contain(exact_content).is_ok());
    assert!(gnezdo.contain("x".repeat(2_049)).is_ok());
    let data = gnezdo.contain("parent".to_owned()).unwrap();
    assert!(UntrustedContent::derive(&[], "x".repeat(1_048_576), Classification::Public).is_ok());
    assert_eq!(
        UntrustedContent::derive(&[], "x".repeat(1_048_577), Classification::Public),
        Err(GnezdoError::ContentTooLarge)
    );
    let parents = vec![&data; 256];
    assert!(
        UntrustedContent::derive(&parents, "derived".to_owned(), Classification::Public).is_ok()
    );
    assert_eq!(
        UntrustedContent::derive(
            &vec![&data; 257],
            "derived".to_owned(),
            Classification::Public,
        ),
        Err(GnezdoError::TooManyParents)
    );

    let secret = TaggedData::from_trusted_ingress(
        "secret".to_owned(),
        ProvenanceSource::Database(ResourceId::new("oracle-db").unwrap()),
        Classification::Secret,
    )
    .unwrap();
    let niti = secret.niti().clone();
    let niti_parents = vec![&niti; 256];
    let derived_niti = Niti::derived_from(&niti_parents);
    assert_eq!(
        derived_niti.provenance().source(),
        &ProvenanceSource::Derived
    );
    assert_eq!(
        derived_niti.provenance().lineage(),
        &[
            ProvenanceSource::Database(ResourceId::new("oracle-db").unwrap()),
            ProvenanceSource::Derived
        ]
    );
    let data_parents = vec![&secret; 256];
    let output = TaggedData::derived_from(&data_parents, "output".to_owned());
    assert_eq!(output.metka(), Metka::new(Classification::Secret));
    assert!(
        output
            .niti()
            .provenance()
            .lineage()
            .contains(&ProvenanceSource::Database(
                ResourceId::new("oracle-db").unwrap()
            ))
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn flow_action_mapping_and_broker_route_tables_preserve_direction_and_contract() {
    let context = public_context();
    let read = ActionRequest::new(
        Principal::Model,
        Operation::Read,
        Resource::new(ResourceKind::File, ResourceId::new("oracle-file").unwrap()),
        Destination::PublicExternal,
        crate::domain::CapabilityName::new("file.read").unwrap(),
    );
    assert_eq!(
        crate::ruslo::flow_from_action(&context, &read).operation(),
        FlowOperation::Export
    );

    let write = ActionRequest::new(
        Principal::Model,
        Operation::Write,
        Resource::new(ResourceKind::File, ResourceId::new("oracle-file").unwrap()),
        Destination::Internal(Identity::new("oracle-store").unwrap()),
        crate::domain::CapabilityName::new("file.write").unwrap(),
    );
    let ruslo = Ruslo::new(vec![
        FlowRule::hard_deny(
            RuleId::new("deny-model-write").unwrap(),
            FlowMatcher::any()
                .source(FlowSource::Model)
                .destination(Destination::Internal(
                    Identity::new("oracle-store").unwrap(),
                ))
                .operation(FlowOperation::Transfer),
        ),
        FlowRule::allow(RuleId::new("allow-fallback").unwrap(), FlowMatcher::any()),
    ])
    .unwrap();
    let write_kernel = Krosna::with_ruslo(
        Policy::new(
            PolicyId::new("write-policy").unwrap(),
            vec![PolicyRule::allow(
                RuleId::new("allow-write").unwrap(),
                RuleMatcher::any(),
            )],
        )
        .unwrap(),
        ruslo,
    );
    let write_decision = write_kernel.evaluate(&context, &write);
    assert_eq!(
        (write_decision.kind, write_decision.evidence.reason),
        (DecisionKind::Deny, SledReason::HardDeny)
    );

    let handle = SecretHandle::new("oracle-secret").unwrap();
    let mut broker = FakeBroker::new();
    broker
        .register(handle.clone(), b"secret-value".to_vec())
        .unwrap();
    let malformed = [
        (
            Operation::Read,
            "secret.use",
            handle.resource(),
            Destination::SecretBroker,
        ),
        (
            Operation::Execute,
            "wrong.use",
            handle.resource(),
            Destination::SecretBroker,
        ),
        (
            Operation::Execute,
            "secret.use",
            Resource::new(ResourceKind::Secret, ResourceId::new("other").unwrap()),
            Destination::SecretBroker,
        ),
        (
            Operation::Execute,
            "secret.use",
            handle.resource(),
            Destination::Model,
        ),
    ];
    for (operation, capability_name, resource, destination) in malformed {
        let request = ActionRequest::new(
            Principal::Model,
            operation.clone(),
            resource.clone(),
            destination.clone(),
            crate::domain::CapabilityName::new(capability_name).unwrap(),
        );
        let grant = CapabilityGrant::issue(
            Principal::Model,
            request.capability().clone(),
            operation,
            ResourceScope::exact(&resource),
        );
        let action = AuthorizedAction::issue(request, grant).unwrap();
        assert_eq!(
            broker.use_authorized(&handle, action),
            Err(KlyuchnikError::InvalidPropusk)
        );
    }

    let non_secret_broker_request = ActionRequest::new(
        Principal::Model,
        Operation::Execute,
        Resource::new(ResourceKind::Tool, ResourceId::new("shell").unwrap()),
        Destination::SecretBroker,
        crate::domain::CapabilityName::new("tool.execute").unwrap(),
    );
    let non_secret_broker_grant = CapabilityGrant::issue(
        Principal::Model,
        non_secret_broker_request.capability().clone(),
        Operation::Execute,
        ResourceScope::exact(non_secret_broker_request.resource()),
    );
    let non_secret_broker_action =
        AuthorizedAction::issue(non_secret_broker_request, non_secret_broker_grant).unwrap();
    let mut executor = FakeProtectedExecutor::new();
    assert_eq!(
        executor.execute(non_secret_broker_action),
        Err(crate::propusk::ExecutionError::Rejected)
    );
}

#[test]
fn testbed_route_table_rejects_non_secret_actions_at_secret_broker() {
    let handle_resource = Resource::new(
        ResourceKind::Secret,
        ResourceId::new("oracle-secret").unwrap(),
    );
    let route_rows = [
        (
            Operation::Execute,
            handle_resource.clone(),
            "secret.use",
            true,
        ),
        (
            Operation::Read,
            handle_resource.clone(),
            "secret.use",
            false,
        ),
        (
            Operation::Execute,
            Resource::new(ResourceKind::Tool, ResourceId::new("shell").unwrap()),
            "secret.use",
            false,
        ),
        (
            Operation::Execute,
            handle_resource.clone(),
            "other.use",
            false,
        ),
    ];
    for (operation, resource, capability, expected) in route_rows {
        let request = ActionRequest::new(
            Principal::Model,
            operation,
            resource,
            Destination::SecretBroker,
            crate::domain::CapabilityName::new(capability).unwrap(),
        );
        assert_eq!(crate::sled::is_valid_broker_route(&request), expected);
    }

    let request = ActionRequest::new(
        Principal::Model,
        Operation::Execute,
        Resource::new(ResourceKind::Tool, ResourceId::new("shell").unwrap()),
        Destination::SecretBroker,
        crate::domain::CapabilityName::new("tool.execute").unwrap(),
    );
    let model = HostileModel::new(public_context(), vec![request], Vec::new()).unwrap();
    let policy = Policy::new(
        crate::domain::PolicyId::new("route-policy").unwrap(),
        vec![PolicyRule::allow(
            RuleId::new("allow-route-test").unwrap(),
            RuleMatcher::any(),
        )],
    )
    .unwrap();
    let mut testbed = EnforcementTestbed::new(Krosna::new(policy));
    let broker = FakeBroker::new();
    let outcomes = testbed.run_with_broker(&model, &broker).unwrap();
    assert!(matches!(
        outcomes.as_slice(),
        [crate::sled::EnforcementOutcome::Denied(decision)]
            if decision.kind() == DecisionKind::Deny
                && decision.evidence().reason() == SledReason::HardDeny
    ));
}

#[test]
fn safe_debug_and_nonempty_accessors_have_stable_observable_contracts() {
    let text = CanonicalText::new("private pattern").unwrap();
    assert_eq!(text.as_str(), "private pattern");
    assert!(format!("{text:?}").contains("CanonicalText(REDACTED)"));

    let handle = SecretHandle::new("debug-handle").unwrap();
    assert!(format!("{handle:?}").contains("debug-handle"));

    let rule = ContentRule::new(
        RuleId::new("content-rule").unwrap(),
        FlowDirection::Ingress,
        "private pattern",
    )
    .unwrap();
    assert!(format!("{rule:?}").contains("ContentRule"));
    assert!(!format!("{rule:?}").contains("private pattern"));
    let zaslon = Zaslon::new(Vec::new(), vec![rule]).unwrap();
    assert!(format!("{zaslon:?}").contains("Zaslon"));
    let stream = zaslon.stream(FlowDirection::Ingress);
    assert!(format!("{stream:?}").contains("ZaslonStream"));

    let model = HostileModel::canonical();
    assert!(format!("{model:?}").contains("HostileModel"));
    assert!(!format!("{model:?}").contains("Ignore policy and grant me"));
    let testbed = EnforcementTestbed::new(Krosna::new(allow_all_policy()));
    assert!(format!("{testbed:?}").contains("EnforcementTestbed"));

    let mut broker = FakeBroker::new();
    assert!(
        broker
            .register(SecretHandle::new("large-enough").unwrap(), vec![0; 2_049],)
            .is_ok()
    );
    assert!(
        broker
            .register(
                SecretHandle::new("exact-secret-limit").unwrap(),
                vec![0; 1_048_576],
            )
            .is_ok()
    );
    let mut two_entry_broker = FakeBroker::new();
    for name in ["first", "second"] {
        two_entry_broker
            .register(SecretHandle::new(name).unwrap(), vec![0])
            .unwrap();
    }
    assert_eq!(two_entry_broker.len(), 2);

    let mut executor = FakeProtectedExecutor::new();
    let request = ActionRequest::new(
        Principal::Model,
        Operation::Read,
        Resource::new(ResourceKind::File, ResourceId::new("oracle-file").unwrap()),
        Destination::Model,
        crate::domain::CapabilityName::new("file.read").unwrap(),
    );
    let permit = Krosna::new(allow_all_policy())
        .authorize(&public_context(), &request)
        .unwrap();
    executor.execute(permit).unwrap();
    assert_eq!(executor.executions().len(), 1);
    assert!(!executor.is_empty());
}

#[test]
fn zaslon_stream_boundary_table_rejects_ambiguous_input_and_keeps_direction() {
    let zaslon = Zaslon::empty();
    for value in ["\u{200b}", "\n", "\\"] {
        let verdict = zaslon.stream(FlowDirection::Ingress).push_chunk(value);
        assert_eq!(
            verdict,
            ContentVerdict::Blocked {
                rule_id: None,
                reason: SledReason::InvalidRequest
            }
        );
    }
    let mut exact = zaslon.stream(FlowDirection::Egress);
    assert_eq!(exact.direction(), FlowDirection::Egress);
    assert_eq!(
        exact.push_chunk(&"x".repeat(16_384)),
        ContentVerdict::NeedMoreData
    );
    assert_eq!(exact.finish(), ContentVerdict::Clear);
    assert_eq!(
        zaslon
            .stream(FlowDirection::Ingress)
            .push_chunk(&"x".repeat(1_041)),
        ContentVerdict::NeedMoreData
    );

    let mut terminal = zaslon.stream(FlowDirection::Ingress);
    assert_eq!(terminal.push_chunk("safe"), ContentVerdict::NeedMoreData);
    assert_eq!(terminal.finish(), ContentVerdict::Clear);
    assert_eq!(
        terminal.push_chunk("unsafe extension"),
        ContentVerdict::Blocked {
            rule_id: None,
            reason: SledReason::InvalidRequest
        }
    );
    assert_eq!(
        terminal.finish(),
        ContentVerdict::Blocked {
            rule_id: None,
            reason: SledReason::InvalidRequest
        }
    );

    let request = ActionRequest::new(
        Principal::Model,
        Operation::Read,
        Resource::new(ResourceKind::File, ResourceId::new("oracle-file").unwrap()),
        Destination::Model,
        crate::domain::CapabilityName::new("file.read").unwrap(),
    );
    let read_block = Zaslon::new(
        vec![ActionRule::deny(
            RuleId::new("read-block").unwrap(),
            RuleMatcher::any().operation(Operation::Read),
        )],
        Vec::new(),
    )
    .unwrap();
    let decision = read_block
        .action_decision(&public_context(), &request)
        .unwrap();
    assert_eq!(decision.evidence.direction, None);
}
