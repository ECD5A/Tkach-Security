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

//! Provider-independent Tkach Gateway Phase 1 boundary.
//!
//! The gateway owns bounded external input, provider lifecycle, response
//! staging, and orchestration. It does not implement a second authorization
//! policy: all protected actions and flows are evaluated by `tkach-core`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod gateway;
mod input;
mod provider;
mod runtime;
mod tools;

pub use gateway::{Gateway, GatewayError, GatewayErrorKind, GatewayResult};
pub use input::{
    ExternalMessage, ExternalRequest, ExternalRole, MetadataEntry, RequestParseError,
    ToolDeclaration,
};
pub use provider::{
    CancelledProvider, DeterministicProvider, FailureProvider, HostileProvider, MalformedProvider,
    ModelInput, Provider, ProviderError, ProviderRequest, ProviderSink, ProviderSinkError,
    ProviderStep, ScriptedStep, TimeoutProvider, ToolDescription,
};
pub use runtime::{
    CancellationToken, DEFAULT_MAX_ACTIVE_REQUESTS, LifecycleId, MAX_RUNTIME_AUTH_BYTES,
    MAX_RUNTIME_FRAME_BYTES, MAX_RUNTIME_ID_BYTES, MAX_RUNTIME_REPLAY_ENTRIES,
    MAX_RUNTIME_RESPONSE_BYTES, RequestId, RuntimeAuthenticator, RuntimeConfigError, RuntimeEffect,
    RuntimeEffectOutcome, RuntimeFailure, RuntimeLimits, RuntimeListener, RuntimeOutcome,
    RuntimeReceipt, RuntimeResponse, RuntimeService, RuntimeTransportError,
};
pub use tools::{
    EffectOutcome, EffectReceipt, FakeToolBroker, REAL_FILE_WRITE_CONTENT, REAL_NETWORK_PATH,
    REAL_NETWORK_PAYLOAD, RealEffectExecutor, RealExecutorConfigError, ToolResult,
    external_send_request, harmless_read_request, protected_read_request, protected_write_request,
    secret_reveal_request, secret_use_request,
};

/// Maximum raw external request body accepted before JSON deserialization.
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
/// Maximum number of external messages in one request.
pub const MAX_MESSAGES: usize = 32;
/// Maximum bytes in one external message.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Maximum metadata entries in one request.
pub const MAX_METADATA_ENTRIES: usize = 32;
/// Maximum bytes in a metadata key.
pub const MAX_METADATA_KEY_BYTES: usize = 128;
/// Maximum bytes in a metadata value.
pub const MAX_METADATA_VALUE_BYTES: usize = 1024;
/// Maximum aggregate bytes in all metadata keys and values.
pub const MAX_METADATA_TOTAL_BYTES: usize =
    MAX_METADATA_ENTRIES * (MAX_METADATA_KEY_BYTES + MAX_METADATA_VALUE_BYTES);
/// Maximum untrusted tool declarations in one request.
pub const MAX_TOOL_DECLARATIONS: usize = 16;
/// Maximum aggregate bytes in all client-supplied tool labels.
pub const MAX_TOOL_DECLARATION_TOTAL_BYTES: usize = MAX_TOOL_DECLARATIONS * MAX_METADATA_KEY_BYTES;
/// Maximum bytes in a provider text chunk.
pub const MAX_PROVIDER_CHUNK_BYTES: usize = 16 * 1024;
/// Maximum provider chunks in one turn.
pub const MAX_PROVIDER_CHUNKS: usize = 64;
/// Maximum bytes in one protected tool result handed back to a provider.
pub const MAX_TOOL_RESULT_BYTES: usize = 16 * 1024;
/// Maximum model-context bytes retained across provider/tool turns.
pub const MAX_MODEL_CONTEXT_BYTES: usize = 256 * 1024;
/// Maximum model-context items retained across provider/tool turns.
pub const MAX_MODEL_INPUT_ITEMS: usize = 64;
/// Maximum cumulative staged provider output across a gateway run.
pub const MAX_STREAMING_OUTPUT_BYTES: usize = 256 * 1024;
/// Maximum final provider output that may be considered for release.
pub const MAX_MODEL_OUTPUT_BYTES: usize = 64 * 1024;
/// Maximum action proposals in one provider turn.
pub const MAX_ACTIONS_PER_TURN: usize = 32;
/// Maximum provider/tool turns in one request lifecycle.
pub const MAX_PROVIDER_TURNS: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_budget_constants_keep_their_protocol_values() {
        assert_eq!(
            MAX_METADATA_TOTAL_BYTES,
            MAX_METADATA_ENTRIES * (MAX_METADATA_KEY_BYTES + MAX_METADATA_VALUE_BYTES)
        );
        assert_eq!(MAX_TOOL_RESULT_BYTES, 16 * 1024);
    }
}
