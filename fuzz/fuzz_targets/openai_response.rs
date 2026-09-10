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
use tkach_provider_openai::fuzz_response;

fuzz_target!(|input: &[u8]| {
    let _ = fuzz_response(input);
});
