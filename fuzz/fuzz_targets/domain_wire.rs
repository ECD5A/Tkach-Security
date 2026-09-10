#![no_main]

use libfuzzer_sys::fuzz_target;
use tkach_core::domain::{Provenance, ResourceScope, SecurityContext};

fuzz_target!(|input: &[u8]| {
    let _ = serde_json::from_slice::<Provenance>(input);
    let _ = serde_json::from_slice::<ResourceScope>(input);
    let _ = serde_json::from_slice::<SecurityContext>(input);
});
