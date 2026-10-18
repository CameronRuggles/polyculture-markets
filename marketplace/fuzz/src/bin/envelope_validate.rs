//! Fuzz target (§22.5): the OpenPGP envelope validator.
//!
//! Entry points are the real ones the app calls when a buyer submits a
//! ciphertext message: `envelope::validate_envelope` and
//! `envelope::extra_recipient_key_id`, with a fixed dummy context (the
//! same shape `crates/app/src/messages.rs` builds from stored certs),
//! plus `KeyRef::from_cert` — the parser for user-supplied key material.
#![no_main]

use envelope::{EnvelopeContext, KeyRef};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ctx = EnvelopeContext {
        sender: KeyRef::from_fingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        recipient: KeyRef::from_fingerprint("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
        recipient_retired_shown: vec![KeyRef::from_fingerprint(
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        )],
    };
    let _ = envelope::validate_envelope(data, &ctx);
    let _ = envelope::extra_recipient_key_id(data, &ctx);
    let _ = KeyRef::from_cert(data);
});
