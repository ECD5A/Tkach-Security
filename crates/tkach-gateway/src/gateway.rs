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

//! Gateway lifecycle and enforcement ordering.

use crate::input::{ExternalRequest, RequestParseError};
use crate::provider::{
    ModelInput, Provider, ProviderError, ProviderRequest, ProviderStep, StagingSink,
};
use crate::tools::{EffectReceipt, ToolResult};
use crate::{
    MAX_MODEL_CONTEXT_BYTES, MAX_MODEL_INPUT_ITEMS, MAX_MODEL_OUTPUT_BYTES, MAX_PROVIDER_TURNS,
    MAX_TOOL_RESULT_BYTES,
};
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;
use tkach_core::diode::{FlowOperation, FlowRequest};
use tkach_core::domain::{Decision, Destination, FlowDirection, SecurityContext};
use tkach_core::gnezdo::Gnezdo;
use tkach_core::krosna::Krosna;
use tkach_core::niti_metka::TaggedData;
use tkach_core::propusk::{AuthorizationError, ExecutionError, ProtectedExecutor};
use tkach_core::sled::{SledError, SledTrace};
use tkach_core::zaslon::{ContentDecision, Zaslon};

const MAX_NON_READ_ACTIONS_PER_TURN: usize = 1;

/// Internal lifecycle states.  The state is deliberately not exposed to a
/// provider or release adapter: it is a gateway-owned ordering proof, not an
/// authority object that untrusted code can construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LifecycleState {
    Received,
    Validated,
    Contained,
    ProviderRunning,
    OutputStaged,
    EgressApproved,
    ActionsEvaluated,
    EffectsCommitted,
    Released,
}

impl LifecycleState {
    fn transition(self, next: Self) -> Option<Self> {
        let allowed = match self {
            Self::Received => next == Self::Validated,
            Self::Validated => next == Self::Contained,
            Self::Contained => next == Self::ProviderRunning,
            Self::ProviderRunning => next == Self::OutputStaged,
            Self::OutputStaged => {
                matches!(next, Self::EgressApproved | Self::ActionsEvaluated)
            }
            Self::EgressApproved => next == Self::ActionsEvaluated,
            Self::ActionsEvaluated => next == Self::EffectsCommitted,
            Self::EffectsCommitted => {
                matches!(next, Self::ProviderRunning | Self::Released)
            }
            Self::Released => false,
        };
        allowed.then_some(next)
    }
}

/// A payload-free gateway failure classification with its core decision when
/// applicable.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum GatewayErrorKind {
    /// External input was rejected before any provider or protected effect.
    #[error("invalid external request")]
    InvalidRequest,
    /// Input content was blocked by ingress Zaslon.
    #[error("ingress content was denied")]
    IngressDenied(Box<Decision>),
    /// Provider failure or malformed provider lifecycle.
    #[error("provider failure: {0}")]
    Provider(ProviderError),
    /// A provider-proposed action was denied by Strong Core.
    #[error("provider action was denied")]
    ActionDenied(Box<Decision>),
    /// A provider turn attempted a state transition that could create partial
    /// effects, such as a mutating action before a follow-up turn.
    #[error("provider lifecycle transition is invalid")]
    InvalidLifecycle,
    /// A protected executor rejected a kernel-issued action.
    #[error("protected tool rejected the authorized action")]
    ToolRejected,
    /// Sled could not record a decision without exceeding its fixed budget.
    #[error("gateway decision trace is full")]
    TraceCapacityExceeded,
    /// Final output was denied by directional flow policy.
    #[error("provider output flow was denied")]
    EgressDenied(Box<Decision>),
    /// Final output was denied by formal egress content policy.
    #[error("provider output content was denied")]
    EgressContentDenied(Box<Decision>),
    /// The provider requested more turns than the bounded lifecycle permits.
    #[error("provider lifecycle exceeded gateway turn limit")]
    TurnLimitExceeded,
}

/// Gateway failure carrying the safe Sled trace accumulated before failure.
pub struct GatewayError {
    kind: GatewayErrorKind,
    trace: SledTrace,
}

impl GatewayError {
    pub(crate) fn new(kind: GatewayErrorKind) -> Self {
        Self {
            kind,
            trace: SledTrace::new(),
        }
    }

    fn with_trace(kind: GatewayErrorKind, trace: SledTrace) -> Self {
        Self { kind, trace }
    }

    /// Return the payload-free failure classification.
    #[must_use]
    pub const fn kind(&self) -> &GatewayErrorKind {
        &self.kind
    }

    /// Return safe decisions recorded before the failure.
    #[must_use]
    pub const fn trace(&self) -> &SledTrace {
        &self.trace
    }
}

impl Debug for GatewayError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayError")
            .field("kind", &self.kind)
            .field("trace", &self.trace)
            .finish()
    }
}

impl Display for GatewayError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.kind, formatter)
    }
}

impl std::error::Error for GatewayError {}

/// Successful gateway output. The actual release string is intentionally
/// available only through an explicit accessor and is redacted by Debug.
pub struct GatewayResult {
    output: Option<String>,
    effects: Vec<EffectReceipt>,
    trace: SledTrace,
}

impl Debug for GatewayResult {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayResult")
            .field("has_output", &self.output.is_some())
            .field("effect_count", &self.effects.len())
            .field("trace", &self.trace)
            .finish()
    }
}

impl GatewayResult {
    /// Return the final output only after all gateway egress checks passed.
    #[must_use]
    pub fn output(&self) -> Option<&str> {
        self.output.as_deref()
    }

    /// Return payload-free effect receipts.
    #[must_use]
    pub fn effects(&self) -> &[EffectReceipt] {
        &self.effects
    }

    /// Return the safe Sled trace for this completed lifecycle.
    #[must_use]
    pub const fn trace(&self) -> &SledTrace {
        &self.trace
    }
}

/// The provider-independent Gateway Phase 1 execution boundary.
pub struct Gateway {
    kernel: Krosna,
    ingress_zaslon: Zaslon,
    egress_zaslon: Zaslon,
    release_destination: Destination,
    executor: Box<dyn ProtectedExecutor<Output = ToolResult>>,
}

impl Debug for Gateway {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Gateway")
            .field("release_destination", &self.release_destination)
            .finish_non_exhaustive()
    }
}

impl Gateway {
    /// Construct a gateway around an already-configured Strong Core kernel.
    ///
    /// `kernel` must contain the action Zaslon and Diode policy used for
    /// protected operations. The separate ingress/egress Zaslon values own
    /// formal content boundaries. The executor is stored privately and is
    /// reachable only from gateway code through `Propusk`.
    #[must_use]
    pub fn new(
        kernel: Krosna,
        ingress_zaslon: Zaslon,
        egress_zaslon: Zaslon,
        release_destination: Destination,
        executor: impl ProtectedExecutor<Output = ToolResult> + 'static,
    ) -> Self {
        Self {
            kernel,
            ingress_zaslon,
            egress_zaslon,
            release_destination,
            executor: Box::new(executor),
        }
    }

    /// Parse bounded JSON and run one complete gateway lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a payload-free error and safe trace when parsing, provider,
    /// authorization, tool, lifecycle, or egress enforcement fails.
    pub fn run_json<P: Provider>(
        &mut self,
        provider: &mut P,
        body: &[u8],
    ) -> Result<GatewayResult, GatewayError> {
        let request = ExternalRequest::from_json(body)
            .map_err(|error| GatewayError::new(map_request_error(&error)))?;
        self.run(provider, &request)
    }

    /// Run a previously validated request through the complete bounded
    /// provider lifecycle.
    ///
    /// No provider bytes are released while a turn is in progress. A provider
    /// timeout, malformed step, denied action, or failed final gate discards
    /// the staged response.
    ///
    /// # Errors
    ///
    /// Returns a payload-free [`GatewayError`] with the safe Sled trace when
    /// any lifecycle, authorization, tool, or egress check fails.
    pub fn run<P: Provider>(
        &mut self,
        provider: &mut P,
        request: &ExternalRequest,
    ) -> Result<GatewayResult, GatewayError> {
        let mut trace = SledTrace::new();
        let mut state = LifecycleState::Received;
        if !is_valid_release_destination(&self.release_destination) {
            return Err(Self::failure(GatewayErrorKind::InvalidLifecycle, trace));
        }
        Self::transition(&mut state, LifecycleState::Validated, &trace)?;
        let envelope = self.prepare_ingress(request, &mut trace)?;
        Self::transition(&mut state, LifecycleState::Contained, &trace)?;
        let mut provider_request = ProviderRequest::new(envelope.inputs, envelope.metadata, 0);
        let mut cumulative_stream_bytes = 0usize;
        let mut effects = Vec::new();
        let mut seen_actions = Vec::new();

        for _turn in 0..MAX_PROVIDER_TURNS {
            Self::transition(&mut state, LifecycleState::ProviderRunning, &trace)?;
            let mut sink = StagingSink::new(cumulative_stream_bytes);
            let step = provider
                .invoke(&provider_request, &mut sink)
                .map_err(|error| Self::failure(GatewayErrorKind::Provider(error), trace.clone()))?;
            let staged = sink.finish();
            cumulative_stream_bytes = staged.total_stream_bytes;
            Self::transition(&mut state, LifecycleState::OutputStaged, &trace)?;

            if step == ProviderStep::Complete && staged.text.is_empty() && staged.actions.is_empty()
            {
                return Err(Self::failure(
                    GatewayErrorKind::Provider(ProviderError::Malformed),
                    trace,
                ));
            }
            // A final response is fully checked before any action in that
            // response can execute. This prevents a later egress denial or
            // output budget failure from leaving a partial protected effect.
            let final_output = if step == ProviderStep::Complete {
                let output =
                    self.validate_final_output(&provider_request, &staged.text, &mut trace)?;
                Self::transition(&mut state, LifecycleState::EgressApproved, &trace)?;
                output
            } else {
                None
            };

            let permits =
                self.authorize_actions(&staged.actions, step, &mut trace, &mut seen_actions)?;
            Self::transition(&mut state, LifecycleState::ActionsEvaluated, &trace)?;
            let tool_inputs = self.execute_actions(permits, &mut effects, &mut trace)?;
            Self::transition(&mut state, LifecycleState::EffectsCommitted, &trace)?;

            match step {
                ProviderStep::AwaitToolResults => {
                    let next_inputs: Vec<ModelInput> = provider_request
                        .inputs()
                        .iter()
                        .cloned()
                        .chain(tool_inputs)
                        .collect();
                    if !context_within_budget(&next_inputs) {
                        return Err(Self::failure(GatewayErrorKind::InvalidLifecycle, trace));
                    }
                    provider_request = provider_request.with_tool_inputs(next_inputs);
                }
                ProviderStep::Complete => {
                    Self::transition(&mut state, LifecycleState::Released, &trace)?;
                    return Ok(GatewayResult {
                        output: final_output,
                        effects,
                        trace,
                    });
                }
            }
        }
        Err(Self::failure(GatewayErrorKind::TurnLimitExceeded, trace))
    }

    fn prepare_ingress(
        &self,
        request: &ExternalRequest,
        trace: &mut SledTrace,
    ) -> Result<SecurityEnvelope, GatewayError> {
        let gnezdo = Gnezdo::new();
        let mut inputs = Vec::with_capacity(request.messages().len());
        for message in request.messages() {
            let content = gnezdo
                .contain(message.content().to_owned())
                .map_err(|_| GatewayError::new(GatewayErrorKind::InvalidRequest))?;
            let ingress_context = content.context().clone();
            match self.ingress_zaslon.inspect_content(
                FlowDirection::Ingress,
                &ingress_context,
                content.content(),
            ) {
                ContentDecision::Clear => inputs.push(ModelInput::External(content)),
                ContentDecision::Blocked { decision } => {
                    Self::record(trace, decision.clone())?;
                    return Err(Self::failure(
                        GatewayErrorKind::IngressDenied(Box::new(decision)),
                        trace.clone(),
                    ));
                }
            }
        }
        Ok(SecurityEnvelope {
            inputs,
            metadata: request.metadata().to_vec(),
        })
    }

    fn authorize_actions(
        &mut self,
        actions: &[tkach_core::domain::ActionRequest],
        step: ProviderStep,
        trace: &mut SledTrace,
        seen_actions: &mut Vec<tkach_core::domain::ActionRequest>,
    ) -> Result<Vec<tkach_core::propusk::Propusk>, GatewayError> {
        if actions.is_empty() {
            if step == ProviderStep::AwaitToolResults {
                return Err(Self::failure(
                    GatewayErrorKind::InvalidLifecycle,
                    trace.clone(),
                ));
            }
            return Ok(Vec::new());
        }
        let non_read_count = actions
            .iter()
            .filter(|action| action.operation() != &tkach_core::domain::Operation::Read)
            .count();
        if step == ProviderStep::AwaitToolResults && non_read_count > 0
            || non_read_count > MAX_NON_READ_ACTIONS_PER_TURN
        {
            return Err(Self::failure(
                GatewayErrorKind::InvalidLifecycle,
                trace.clone(),
            ));
        }

        // Preflight every proposal before executing any one of them. A denied
        // action in a batch therefore cannot leave a partial mutation behind.
        let context = SecurityContext::untrusted_data();
        let mut permits = Vec::with_capacity(actions.len());
        for action in actions {
            if seen_actions.contains(action) {
                return Err(Self::failure(
                    GatewayErrorKind::InvalidLifecycle,
                    trace.clone(),
                ));
            }
            seen_actions.push(action.clone());
            let decision = self.kernel.evaluate(&context, action);
            Self::record(trace, decision.clone())?;
            if !decision.is_allowed() {
                return Err(Self::failure(
                    GatewayErrorKind::ActionDenied(Box::new(decision)),
                    trace.clone(),
                ));
            }
            let permit = self
                .kernel
                .authorize(&context, action)
                .map_err(|error| authorization_failure(error, trace.clone()))?;
            permits.push(permit);
        }

        Ok(permits)
    }

    fn execute_actions(
        &mut self,
        permits: Vec<tkach_core::propusk::Propusk>,
        effects: &mut Vec<EffectReceipt>,
        trace: &mut SledTrace,
    ) -> Result<Vec<ModelInput>, GatewayError> {
        let mut tool_inputs = Vec::new();
        for permit in permits {
            let result = self.executor.execute(permit).map_err(|_: ExecutionError| {
                Self::failure(GatewayErrorKind::ToolRejected, trace.clone())
            })?;
            match result {
                ToolResult::Data(data) => {
                    if data.value().len() > MAX_TOOL_RESULT_BYTES {
                        return Err(Self::failure(GatewayErrorKind::ToolRejected, trace.clone()));
                    }
                    tool_inputs.push(ModelInput::Tool(data));
                }
                ToolResult::Effect(receipt) => effects.push(receipt),
            }
        }
        Ok(tool_inputs)
    }

    fn validate_final_output(
        &self,
        provider_request: &ProviderRequest,
        text: &str,
        trace: &mut SledTrace,
    ) -> Result<Option<String>, GatewayError> {
        if text.is_empty() {
            return Ok(None);
        }
        validate_output_size(text).map_err(|kind| Self::failure(kind, trace.clone()))?;
        let tagged_output = derive_provider_output(provider_request, text.to_owned());
        let flow = FlowRequest::from_tagged(
            self.release_destination.clone(),
            FlowOperation::Export,
            &tagged_output,
        );
        let flow_decision = self.kernel.evaluate_flow(&flow);
        Self::record(trace, flow_decision.clone())?;
        if !flow_decision.is_allowed() {
            return Err(Self::failure(
                GatewayErrorKind::EgressDenied(Box::new(flow_decision)),
                trace.clone(),
            ));
        }
        let context = SecurityContext::untrusted_data();
        match self.egress_zaslon.inspect_content(
            FlowDirection::Egress,
            &context,
            tagged_output.value(),
        ) {
            ContentDecision::Clear => Ok(Some(tagged_output.value().clone())),
            ContentDecision::Blocked { decision } => {
                Self::record(trace, decision.clone())?;
                Err(Self::failure(
                    GatewayErrorKind::EgressContentDenied(Box::new(decision)),
                    trace.clone(),
                ))
            }
        }
    }

    fn record(trace: &mut SledTrace, decision: Decision) -> Result<(), GatewayError> {
        trace
            .record_kernel_decision(decision)
            .map(|_| ())
            .map_err(|error| map_sled_error(&error, trace))
    }

    fn transition(
        state: &mut LifecycleState,
        next: LifecycleState,
        trace: &SledTrace,
    ) -> Result<(), GatewayError> {
        *state = state
            .transition(next)
            .ok_or_else(|| Self::failure(GatewayErrorKind::InvalidLifecycle, trace.clone()))?;
        Ok(())
    }

    fn failure(kind: GatewayErrorKind, trace: SledTrace) -> GatewayError {
        GatewayError::with_trace(kind, trace)
    }
}

struct SecurityEnvelope {
    inputs: Vec<ModelInput>,
    metadata: Vec<crate::input::MetadataEntry>,
}

fn derive_provider_output(request: &ProviderRequest, text: String) -> TaggedData<String> {
    let projected: Vec<TaggedData<String>> = request
        .inputs()
        .iter()
        .map(ModelInput::tagged_projection)
        .collect();
    let parents: Vec<&TaggedData<String>> = projected.iter().collect();
    if parents.is_empty() {
        TaggedData::from_untrusted(text)
    } else {
        TaggedData::derived_from(&parents, text)
    }
}

fn context_within_budget(inputs: &[ModelInput]) -> bool {
    if inputs.len() > MAX_MODEL_INPUT_ITEMS {
        return false;
    }
    inputs
        .iter()
        .try_fold(0usize, |total, input| total.checked_add(input.text().len()))
        .is_some_and(|total| total <= MAX_MODEL_CONTEXT_BYTES)
}

fn validate_output_size(text: &str) -> Result<(), GatewayErrorKind> {
    if text.len() > MAX_MODEL_OUTPUT_BYTES {
        return Err(GatewayErrorKind::Provider(
            ProviderError::OutputLimitExceeded,
        ));
    }
    Ok(())
}

fn is_valid_release_destination(destination: &Destination) -> bool {
    matches!(
        destination,
        Destination::Internal(_) | Destination::PublicExternal
    )
}

fn map_request_error(error: &RequestParseError) -> GatewayErrorKind {
    let _ = error;
    GatewayErrorKind::InvalidRequest
}

fn map_sled_error(error: &SledError, trace: &SledTrace) -> GatewayError {
    let _ = error;
    GatewayError::with_trace(GatewayErrorKind::TraceCapacityExceeded, trace.clone())
}

fn authorization_failure(error: AuthorizationError, trace: SledTrace) -> GatewayError {
    match error {
        AuthorizationError::Denied(decision) => {
            GatewayError::with_trace(GatewayErrorKind::ActionDenied(decision), trace)
        }
        AuthorizationError::InvalidGrant => {
            GatewayError::with_trace(GatewayErrorKind::InvalidLifecycle, trace)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_state_oracle_accepts_only_ordered_transitions() {
        let ordered = [
            LifecycleState::Received,
            LifecycleState::Validated,
            LifecycleState::Contained,
            LifecycleState::ProviderRunning,
            LifecycleState::OutputStaged,
            LifecycleState::EgressApproved,
            LifecycleState::ActionsEvaluated,
            LifecycleState::EffectsCommitted,
            LifecycleState::Released,
        ];
        for pair in ordered.windows(2) {
            assert_eq!(pair[0].transition(pair[1]), Some(pair[1]));
        }
        assert_eq!(
            LifecycleState::EffectsCommitted.transition(LifecycleState::ProviderRunning),
            Some(LifecycleState::ProviderRunning)
        );
    }

    #[test]
    fn lifecycle_state_oracle_rejects_replay_and_phase_skips() {
        for (current, next) in [
            (LifecycleState::Received, LifecycleState::Released),
            (LifecycleState::Released, LifecycleState::ProviderRunning),
            (LifecycleState::OutputStaged, LifecycleState::Released),
            (
                LifecycleState::ActionsEvaluated,
                LifecycleState::EgressApproved,
            ),
            (
                LifecycleState::EffectsCommitted,
                LifecycleState::ActionsEvaluated,
            ),
        ] {
            assert_eq!(current.transition(next), None);
        }
    }

    #[test]
    fn context_budget_accepts_exact_bytes_and_rejects_items_or_bytes_over_budget() {
        let exact = (0..16)
            .map(|_| {
                ModelInput::External(
                    Gnezdo::new()
                        .contain("x".repeat(MAX_MODEL_CONTEXT_BYTES / 16))
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert!(context_within_budget(&exact));

        let exact_item_count = (0..MAX_MODEL_INPUT_ITEMS)
            .map(|_| ModelInput::External(Gnezdo::new().contain("x".to_owned()).unwrap()))
            .collect::<Vec<_>>();
        assert!(context_within_budget(&exact_item_count));

        let mut over_bytes = exact.clone();
        over_bytes.push(ModelInput::External(
            Gnezdo::new().contain("x".to_owned()).unwrap(),
        ));
        assert!(!context_within_budget(&over_bytes));

        let too_many = (0..=MAX_MODEL_INPUT_ITEMS)
            .map(|_| ModelInput::External(Gnezdo::new().contain("x".to_owned()).unwrap()))
            .collect::<Vec<_>>();
        assert!(!context_within_budget(&too_many));
    }

    #[test]
    fn final_output_size_boundary_is_exact() {
        assert!(validate_output_size(&"x".repeat(MAX_MODEL_OUTPUT_BYTES)).is_ok());
        assert!(matches!(
            validate_output_size(&"x".repeat(MAX_MODEL_OUTPUT_BYTES + 1)),
            Err(GatewayErrorKind::Provider(
                ProviderError::OutputLimitExceeded
            ))
        ));
    }

    #[test]
    fn gateway_transition_wrapper_rejects_invalid_transition() {
        let mut state = LifecycleState::Released;
        let trace = SledTrace::new();
        let error =
            Gateway::transition(&mut state, LifecycleState::ProviderRunning, &trace).unwrap_err();
        assert!(matches!(error.kind(), GatewayErrorKind::InvalidLifecycle));
        assert_eq!(state, LifecycleState::Released);
    }
}
