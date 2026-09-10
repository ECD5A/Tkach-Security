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

#![no_main]

use libfuzzer_sys::fuzz_target;
use tkach_core::domain::{Provenance, ResourceScope, SecurityContext};

fuzz_target!(|input: &[u8]| {
    let _ = serde_json::from_slice::<Provenance>(input);
    let _ = serde_json::from_slice::<ResourceScope>(input);
    let _ = serde_json::from_slice::<SecurityContext>(input);
});
