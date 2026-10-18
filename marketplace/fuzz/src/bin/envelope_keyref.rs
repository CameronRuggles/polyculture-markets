//! Fuzz target (§22.5, envelope surface): `KeyRef::from_fingerprint`.
//!
//! Split out from `envelope_validate` because it takes text, not packet
//! bytes. This target found its bug before it ever ran: constructing it
//! prompted the char-boundary check that showed the original
//! `fpr[fpr.len() - 16..]` slice panics on multi-byte input whose
//! len-16 offset is mid-character (fixed 2026-10-17 with a regression
//! test in the envelope crate). It stays as a target so the fix — and
//! any future handle-derivation change — remains under fuzz coverage.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let k = envelope::KeyRef::from_fingerprint(s);
        let _ = k.fingerprint();
    }
    let _ = envelope::KeyRef::from_cert(data);
});
