//! Fuzz target (Modules Audit BL2, 2026-10-19): the unwrapped-
//! disclosure extractor — `app::keys::extract_unwrapped_message`,
//! the parser that reads a moderator-pasted `gpg --unwrap` output
//! during dispute disclosure verification (the V4 flow). The
//! certificates are the real GnuPG fixtures: Bob is the disclosure
//! signer, Alice the other party.
#![no_main]

use libfuzzer_sys::fuzz_target;

static CERT_ALICE: &[u8] =
    include_bytes!("../../../crates/app/tests/fixtures/gpg/cert-alice.asc");
static CERT_BOB: &[u8] =
    include_bytes!("../../../crates/app/tests/fixtures/gpg/cert-bob.asc");

fuzz_target!(|data: &[u8]| {
    let _ = app::keys::extract_unwrapped_message(CERT_BOB, data);
    let _ = app::keys::extract_unwrapped_message(CERT_ALICE, data);
});
