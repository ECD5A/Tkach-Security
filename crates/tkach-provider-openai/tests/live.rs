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

//! Explicitly opt-in live protocol smoke test for the `OpenAI` adapter.

use std::env;
use tkach_core::domain::ActionRequest;
use tkach_core::gnezdo::Gnezdo;
use tkach_gateway::{
    ModelInput, Provider, ProviderRequest, ProviderSink, ProviderSinkError, ProviderStep,
};
use tkach_provider_openai::OpenAiProvider;

#[derive(Default)]
struct Sink {
    text: String,
    actions: Vec<ActionRequest>,
}

impl ProviderSink for Sink {
    fn text_chunk(&mut self, chunk: &str) -> Result<(), ProviderSinkError> {
        self.text.push_str(chunk);
        Ok(())
    }

    fn action(&mut self, action: ActionRequest) -> Result<(), ProviderSinkError> {
        self.actions.push(action);
        Ok(())
    }
}

#[test]
fn live_openai_responses_smoke_is_explicitly_opt_in() {
    if env::var("TKACH_LIVE_OPENAI_TESTS").ok().as_deref() != Some("1") {
        eprintln!("live OpenAI test skipped; set TKACH_LIVE_OPENAI_TESTS=1 to opt in");
        return;
    }

    let model = env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4.1-mini".to_owned());
    let mut provider = OpenAiProvider::from_env(model).expect("trusted live OpenAI configuration");
    let input = Gnezdo::new()
        .contain("Return exactly one short plain-text greeting. Do not call tools.".to_owned())
        .expect("static live test input is bounded");
    let request = ProviderRequest::new(vec![ModelInput::External(input)], Vec::new(), 0);
    let mut sink = Sink::default();
    let step = provider.invoke(&request, &mut sink);

    assert_eq!(step, Ok(ProviderStep::Complete));
    assert!(!sink.text.is_empty());
    assert!(sink.actions.is_empty());
}
