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
use tkach_core::zaslon::CanonicalText;

fuzz_target!(|input: &str| {
    if let Ok(canonical) = CanonicalText::new(input) {
        let _ = canonical.as_str();
    }
});
