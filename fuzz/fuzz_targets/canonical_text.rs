#![no_main]

use libfuzzer_sys::fuzz_target;
use tkach_core::zaslon::CanonicalText;

fuzz_target!(|input: &str| {
    if let Ok(canonical) = CanonicalText::new(input) {
        let _ = canonical.as_str();
    }
});
