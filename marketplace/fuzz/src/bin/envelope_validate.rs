//! Fuzz target (§22.5): the OpenPGP envelope validator.
//!
//! Entry points are the real ones the app calls when a buyer submits a
//! ciphertext message: `envelope::validate_envelope` and
//! `envelope::extra_recipient_key_id`, plus `KeyRef::from_cert` — the
//! parser for user-supplied key material.
//!
//! Modules Audit BL2 (2026-10-19): the context is built from the REAL
//! GnuPG fixtures (crates/app/tests/fixtures/gpg) — Alice sends, Bob
//! receives — instead of dummy all-same-letter fingerprints that no
//! real message can ever match. The corpus is seeded with the
//! fixtures' real messages, so the fuzzer starts from inputs the
//! validator ACCEPTS and mutates around them, instead of never
//! reaching an accepted envelope at all (the audit's finding: with
//! the dummy context the target could only ever explore the
//! parser's outermost layer).
#![no_main]

use envelope::{EnvelopeContext, KeyRef};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static CERT_ALICE: &[u8] =
    include_bytes!("../../../crates/app/tests/fixtures/gpg/cert-alice.asc");
static CERT_BOB: &[u8] =
    include_bytes!("../../../crates/app/tests/fixtures/gpg/cert-bob.asc");

fn fixture_context() -> EnvelopeContext {
    static PARTIES: OnceLock<(KeyRef, KeyRef)> = OnceLock::new();
    let (sender, recipient) = PARTIES.get_or_init(|| {
        (
            KeyRef::from_cert(CERT_ALICE).expect("alice fixture cert parses"),
            KeyRef::from_cert(CERT_BOB).expect("bob fixture cert parses"),
        )
    });
    EnvelopeContext {
        sender: sender.clone(),
        recipient: recipient.clone(),
        recipient_retired_shown: vec![],
    }
}

fuzz_target!(|data: &[u8]| {
    let ctx = fixture_context();
    let _ = envelope::validate_envelope(data, &ctx);
    let _ = envelope::extra_recipient_key_id(data, &ctx);
    let _ = KeyRef::from_cert(data);
});
