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

//! Provider boundary and hostile provider test doubles.

use crate::input::MetadataEntry;
use crate::{
    MAX_ACTIONS_PER_TURN, MAX_PROVIDER_CHUNK_BYTES, MAX_PROVIDER_CHUNKS, MAX_STREAMING_OUTPUT_BYTES,
};
use std::fmt::{Debug, Formatter};
use thiserror::Error;
use tkach_core::domain::{ActionRequest, Classification, Provenance};
use tkach_core::gnezdo::UntrustedContent;
use tkach_core::niti_metka::TaggedData;

/// A model-visible input item with immutable core metadata.
#[derive(Clone, PartialEq, Eq)]
pub enum ModelInput {
    /// External content contained in Gnezdo's DATA lane.
    External(UntrustedContent),
    /// A protected tool result carrying Niti and Metka.
    Tool(TaggedData<String>),
}

impl Debug for ModelInput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::External(value) => formatter.debug_tuple("External").field(value).finish(),
            Self::Tool(value) => formatter.debug_tuple("Tool").field(value).finish(),
        }
    }
}

impl ModelInput {
    /// Return the model-visible text.
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::External(value) => value.content(),
            Self::Tool(value) => value.value(),
        }
    }

    /// Return the conservative classification carried by the input.
    #[must_use]
    pub fn classification(&self) -> Classification {
        match self {
            Self::External(value) => value.context().classification(),
            Self::Tool(value) => value.metka().classification(),
        }
    }

    /// Return the retained provenance of the input.
    #[must_use]
    pub fn provenance(&self) -> &Provenance {
        match self {
            Self::External(value) => value.context().provenance(),
            Self::Tool(value) => value.niti().provenance(),
        }
    }

    /// Return whether the input must be treated as protected.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        self.classification().is_protected()
    }

    pub(crate) fn tagged_projection(&self) -> TaggedData<String> {
        match self {
            Self::External(value) => TaggedData::from_untrusted(value.content().to_owned()),
            Self::Tool(value) => value.clone(),
        }
    }
}

/// A trusted, fixed tool description exposed to the provider as capability
/// vocabulary only. Client declarations never extend this list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolDescription {
    name: &'static str,
}

impl ToolDescription {
    pub(crate) const fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Return the fixed tool name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }
}

/// The bounded request the provider is allowed to inspect.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRequest {
    inputs: Vec<ModelInput>,
    metadata: Vec<MetadataEntry>,
    tools: Vec<ToolDescription>,
    turn: usize,
}

impl Debug for ProviderRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderRequest")
            .field("input_count", &self.inputs.len())
            .field("metadata_count", &self.metadata.len())
            .field("tool_count", &self.tools.len())
            .field("turn", &self.turn)
            .finish()
    }
}

impl ProviderRequest {
    pub(crate) fn new(inputs: Vec<ModelInput>, metadata: Vec<MetadataEntry>, turn: usize) -> Self {
        Self {
            inputs,
            metadata,
            tools: vec![
                ToolDescription::new("protected_read"),
                ToolDescription::new("protected_write"),
                ToolDescription::new("external_send"),
                ToolDescription::new("harmless_read"),
                ToolDescription::new("secret_backed_use"),
            ],
            turn,
        }
    }

    /// Return model-visible input items.
    #[must_use]
    pub fn inputs(&self) -> &[ModelInput] {
        &self.inputs
    }

    /// Return untrusted metadata; metadata is never treated as authority.
    #[must_use]
    pub fn metadata(&self) -> &[MetadataEntry] {
        &self.metadata
    }

    /// Return the fixed gateway tool catalog.
    #[must_use]
    pub fn tools(&self) -> &[ToolDescription] {
        &self.tools
    }

    /// Return the provider turn number, starting at zero.
    #[must_use]
    pub const fn turn(&self) -> usize {
        self.turn
    }

    pub(crate) fn with_tool_inputs(&self, inputs: Vec<ModelInput>) -> Self {
        Self {
            inputs,
            metadata: self.metadata.clone(),
            tools: self.tools.clone(),
            turn: self.turn + 1,
        }
    }
}

/// Provider lifecycle result after a completely staged turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderStep {
    /// No more provider turns are required.
    Complete,
    /// The gateway must execute read-only tool proposals and invoke again.
    AwaitToolResults,
}

/// Provider failures are static and payload-free by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProviderError {
    /// The provider returned malformed structured behavior.
    #[error("provider response is malformed")]
    Malformed,
    /// The provider exceeded its lifecycle deadline.
    #[error("provider timed out")]
    Timeout,
    /// The provider failed before a complete turn.
    #[error("provider failed")]
    Failed,
    /// The provider or gateway cancelled the turn.
    #[error("provider turn cancelled")]
    Cancelled,
    /// A scripted provider had no remaining response.
    #[error("provider script exhausted")]
    Exhausted,
    /// The provider exceeded a gateway staging budget.
    #[error("provider output budget exceeded")]
    OutputLimitExceeded,
}

/// Errors returned to a provider that attempts to overrun the staging sink.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProviderSinkError {
    /// A text chunk exceeded its per-chunk limit.
    #[error("provider chunk exceeds gateway limit")]
    ChunkTooLarge,
    /// The cumulative staged output exceeded its limit.
    #[error("provider stream exceeds gateway limit")]
    StreamTooLarge,
    /// The provider emitted too many chunks in one turn.
    #[error("provider emitted too many chunks")]
    TooManyChunks,
    /// The provider emitted too many actions in one turn.
    #[error("provider emitted too many actions")]
    TooManyActions,
    /// Empty chunks are not meaningful lifecycle events.
    #[error("provider emitted an empty chunk")]
    EmptyChunk,
}

/// Sink through which a provider proposes output and actions.
///
/// The sink only stages values. It has no method for executing tools, issuing
/// Propusk, accessing Pechat, or releasing bytes to an external destination.
pub trait ProviderSink {
    /// Stage one bounded text chunk.
    ///
    /// # Errors
    ///
    /// Returns a sink error when the chunk or cumulative stream exceeds a
    /// gateway budget.
    fn text_chunk(&mut self, chunk: &str) -> Result<(), ProviderSinkError>;

    /// Stage one typed action proposal. The proposal is not authorization.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderSinkError::TooManyActions`] when the turn budget is
    /// exhausted.
    fn action(&mut self, action: ActionRequest) -> Result<(), ProviderSinkError>;
}

/// Provider adapter contract for one synchronous bounded turn.
pub trait Provider {
    /// Invoke the provider against an immutable model request and a staging
    /// sink. Provider output remains untrusted until the gateway completes all
    /// core evaluations.
    ///
    /// # Errors
    ///
    /// Returns a provider or staging failure before the gateway authorizes or
    /// releases the staged response.
    fn invoke(
        &mut self,
        request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError>;
}

pub(crate) struct StagedResponse {
    pub(crate) text: String,
    pub(crate) actions: Vec<ActionRequest>,
    pub(crate) total_stream_bytes: usize,
}

pub(crate) struct StagingSink {
    response: StagedResponse,
    chunk_count: usize,
    action_count: usize,
    cumulative_before: usize,
}

impl StagingSink {
    pub(crate) fn new(cumulative_before: usize) -> Self {
        Self {
            response: StagedResponse {
                text: String::new(),
                actions: Vec::new(),
                total_stream_bytes: cumulative_before,
            },
            chunk_count: 0,
            action_count: 0,
            cumulative_before,
        }
    }

    pub(crate) fn finish(self) -> StagedResponse {
        self.response
    }
}

impl ProviderSink for StagingSink {
    fn text_chunk(&mut self, chunk: &str) -> Result<(), ProviderSinkError> {
        if chunk.is_empty() {
            return Err(ProviderSinkError::EmptyChunk);
        }
        if chunk.len() > MAX_PROVIDER_CHUNK_BYTES {
            return Err(ProviderSinkError::ChunkTooLarge);
        }
        if self.chunk_count >= MAX_PROVIDER_CHUNKS {
            return Err(ProviderSinkError::TooManyChunks);
        }
        let next_total = self
            .cumulative_before
            .checked_add(self.response.text.len())
            .and_then(|total| total.checked_add(chunk.len()))
            .ok_or(ProviderSinkError::StreamTooLarge)?;
        if next_total > MAX_STREAMING_OUTPUT_BYTES {
            return Err(ProviderSinkError::StreamTooLarge);
        }
        self.response.text.push_str(chunk);
        self.response.total_stream_bytes = next_total;
        self.chunk_count += 1;
        Ok(())
    }

    fn action(&mut self, action: ActionRequest) -> Result<(), ProviderSinkError> {
        if self.action_count >= MAX_ACTIONS_PER_TURN {
            return Err(ProviderSinkError::TooManyActions);
        }
        self.response.actions.push(action);
        self.action_count += 1;
        Ok(())
    }
}

/// A deterministic provider driven by an immutable scripted sequence.
pub struct DeterministicProvider {
    steps: Vec<ScriptedStep>,
    next: usize,
}

impl DeterministicProvider {
    /// Construct a provider from bounded test steps.
    #[must_use]
    pub fn new(steps: Vec<ScriptedStep>) -> Self {
        Self { steps, next: 0 }
    }
}

impl Debug for DeterministicProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeterministicProvider")
            .field("step_count", &self.steps.len())
            .field("next", &self.next)
            .finish()
    }
}

impl Provider for DeterministicProvider {
    fn invoke(
        &mut self,
        _request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        let step = self
            .steps
            .get(self.next)
            .ok_or(ProviderError::Exhausted)?
            .clone();
        self.next += 1;
        for chunk in &step.chunks {
            sink.text_chunk(chunk)
                .map_err(|_| ProviderError::OutputLimitExceeded)?;
        }
        for action in step.actions {
            sink.action(action)
                .map_err(|_| ProviderError::OutputLimitExceeded)?;
        }
        Ok(step.continuation)
    }
}

/// One deterministic provider step used by tests and local demonstrations.
#[derive(Clone)]
pub struct ScriptedStep {
    /// Text chunks emitted by this provider turn.
    pub chunks: Vec<String>,
    /// Typed model action proposals emitted by this provider turn.
    pub actions: Vec<ActionRequest>,
    /// Whether the gateway must execute read-only results and invoke again.
    pub continuation: ProviderStep,
}

impl Debug for ScriptedStep {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptedStep")
            .field("chunk_count", &self.chunks.len())
            .field("action_count", &self.actions.len())
            .field("continuation", &self.continuation)
            .finish()
    }
}

/// Alias emphasizing that the scripted provider is a fake provider boundary.
pub type ScriptedProvider = DeterministicProvider;

/// A hostile provider that requests a protected read and then attempts export.
pub struct HostileProvider {
    turn: usize,
}

impl HostileProvider {
    /// Construct the canonical completely compromised provider.
    #[must_use]
    pub const fn new() -> Self {
        Self { turn: 0 }
    }
}

impl Default for HostileProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for HostileProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostileProvider")
            .field("turn", &self.turn)
            .finish()
    }
}

impl Provider for HostileProvider {
    fn invoke(
        &mut self,
        request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        let current = self.turn;
        self.turn += 1;
        if current == 0 {
            sink.action(crate::tools::protected_read_request())
                .map_err(|_| ProviderError::OutputLimitExceeded)?;
            return Ok(ProviderStep::AwaitToolResults);
        }
        if !request.inputs().iter().any(ModelInput::is_protected) {
            return Err(ProviderError::Malformed);
        }
        sink.text_chunk("customer-secret=attempted-exfiltration")
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        sink.action(crate::tools::external_send_request())
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        Ok(ProviderStep::Complete)
    }
}

/// A provider that returns no structured response.
pub struct MalformedProvider;

impl Provider for MalformedProvider {
    fn invoke(
        &mut self,
        _request: &ProviderRequest,
        _sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        Ok(ProviderStep::Complete)
    }
}

/// A provider that fails before the gateway can authorize staged proposals.
pub struct TimeoutProvider;

impl Provider for TimeoutProvider {
    fn invoke(
        &mut self,
        _request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        sink.action(crate::tools::external_send_request())
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        Err(ProviderError::Timeout)
    }
}

/// A provider that reports a non-timeout failure after staging a proposal.
pub struct FailureProvider;

impl Provider for FailureProvider {
    fn invoke(
        &mut self,
        _request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        sink.action(crate::tools::external_send_request())
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        Err(ProviderError::Failed)
    }
}

/// A provider that reports cancellation after staging a proposal.
pub struct CancelledProvider;

impl Provider for CancelledProvider {
    fn invoke(
        &mut self,
        _request: &ProviderRequest,
        sink: &mut dyn ProviderSink,
    ) -> Result<ProviderStep, ProviderError> {
        sink.action(crate::tools::external_send_request())
            .map_err(|_| ProviderError::OutputLimitExceeded)?;
        Err(ProviderError::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::protected_read_request;
    use tkach_core::gnezdo::Gnezdo;

    #[test]
    fn model_input_protection_reflects_immutable_metadata() {
        let external = Gnezdo::new().contain("external".to_owned()).unwrap();
        assert!(ModelInput::External(external).is_protected());

        let public_tool = TaggedData::from_trusted_ingress(
            "public".to_owned(),
            tkach_core::domain::ProvenanceSource::Tool(
                tkach_core::domain::Identity::new("tool").unwrap(),
            ),
            Classification::Public,
        )
        .unwrap();
        assert!(!ModelInput::Tool(public_tool).is_protected());

        let tool = TaggedData::from_trusted_ingress(
            "secret".to_owned(),
            tkach_core::domain::ProvenanceSource::Database(
                tkach_core::domain::ResourceId::new("db").unwrap(),
            ),
            Classification::Secret,
        )
        .unwrap();
        assert!(ModelInput::Tool(tool).is_protected());
    }

    #[test]
    fn provider_turn_and_tool_context_progress_are_monotonic() {
        let request = ProviderRequest::new(Vec::new(), Vec::new(), 0);
        assert_eq!(request.turn(), 0);
        let next = request.with_tool_inputs(vec![]);
        assert_eq!(next.turn(), 1);
    }

    #[test]
    fn staging_sink_enforces_chunk_and_cumulative_boundaries() {
        let mut exact = StagingSink::new(MAX_STREAMING_OUTPUT_BYTES - 1);
        exact.text_chunk("x").unwrap();
        assert_eq!(
            exact.finish().total_stream_bytes,
            MAX_STREAMING_OUTPUT_BYTES
        );

        let mut over = StagingSink::new(MAX_STREAMING_OUTPUT_BYTES);
        assert_eq!(over.text_chunk("x"), Err(ProviderSinkError::StreamTooLarge));

        let mut chunk = StagingSink::new(0);
        assert!(
            chunk
                .text_chunk(&"x".repeat(MAX_PROVIDER_CHUNK_BYTES))
                .is_ok()
        );
        assert_eq!(
            chunk.text_chunk(&"x".repeat(MAX_PROVIDER_CHUNK_BYTES + 1)),
            Err(ProviderSinkError::ChunkTooLarge)
        );
    }

    #[test]
    fn staging_sink_enforces_chunk_and_action_counts() {
        let mut chunks = StagingSink::new(0);
        for _ in 0..MAX_PROVIDER_CHUNKS {
            chunks.text_chunk("x").unwrap();
        }
        assert_eq!(
            chunks.text_chunk("x"),
            Err(ProviderSinkError::TooManyChunks)
        );

        let mut actions = StagingSink::new(0);
        for _ in 0..MAX_ACTIONS_PER_TURN {
            actions.action(protected_read_request()).unwrap();
        }
        assert_eq!(
            actions.action(protected_read_request()),
            Err(ProviderSinkError::TooManyActions)
        );
    }

    #[test]
    fn deterministic_provider_advances_to_the_next_scripted_turn() {
        let mut provider = DeterministicProvider::new(vec![
            ScriptedStep {
                chunks: vec!["first".to_owned()],
                actions: Vec::new(),
                continuation: ProviderStep::AwaitToolResults,
            },
            ScriptedStep {
                chunks: vec!["second".to_owned()],
                actions: Vec::new(),
                continuation: ProviderStep::Complete,
            },
        ]);
        let request = ProviderRequest::new(Vec::new(), Vec::new(), 0);
        let mut first_sink = StagingSink::new(0);
        assert_eq!(
            provider.invoke(&request, &mut first_sink).unwrap(),
            ProviderStep::AwaitToolResults
        );
        let mut second_sink = StagingSink::new(first_sink.finish().total_stream_bytes);
        assert_eq!(
            provider.invoke(&request, &mut second_sink).unwrap(),
            ProviderStep::Complete
        );
        assert_eq!(second_sink.finish().text, "second");
    }
}
