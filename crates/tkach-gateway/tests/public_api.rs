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

//! Consumer-side compile and behavior smoke tests for the documented v0.1 API.

use tkach_gateway::{
    CancellationToken, ExternalRequest, LifecycleId, RequestId, RuntimeAuthenticator,
    RuntimeFailure, RuntimeLimits, RuntimeResponse,
};

#[test]
fn documented_gateway_api_constructs_only_bounded_inputs() {
    let request = ExternalRequest::from_json(
        br#"{"messages":[{"role":"user","content":"hello"}],"metadata":[],"tool_declarations":[]}"#,
    )
    .expect("documented request schema is valid");
    assert_eq!(request.messages().len(), 1);

    let request_id = RequestId::new("request-api-smoke").expect("documented id is valid");
    let lifecycle_id =
        LifecycleId::new("lifecycle-api-smoke").expect("documented lifecycle id is valid");
    let authenticator =
        RuntimeAuthenticator::new(b"api-smoke-proof".to_vec()).expect("proof is bounded");
    let limits = RuntimeLimits::default();
    let cancellation = CancellationToken::new();
    assert!(!cancellation.is_cancelled());
    assert!(limits.max_frame_bytes() > 0);

    let response = RuntimeResponse::Failure {
        request_id: Some(request_id),
        lifecycle_id: Some(lifecycle_id),
        failure: RuntimeFailure::AuthenticationFailed,
        receipt: None,
    };
    let encoded = response.to_json().expect("safe response is encodable");
    assert!(!encoded.is_empty());
    drop(authenticator);
}
