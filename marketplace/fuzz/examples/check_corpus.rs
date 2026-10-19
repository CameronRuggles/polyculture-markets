//! BL2 acceptance check: run `envelope::validate_envelope`, under
//! the same fixture context the envelope_validate fuzz target
//! uses, over every file in a corpus directory and report how
//! many inputs the validator ACCEPTS. The audit criterion: after
//! seeding with the real GnuPG fixtures and a bounded fuzz run,
//! the corpus must hold at least one accepted input (before BL2
//! it held none — the dummy context matched no real message).
//!
//! Usage: cargo +nightly run --example check_corpus -- corpus/envelope_validate

use envelope::{EnvelopeContext, KeyRef};

static CERT_ALICE: &[u8] =
    include_bytes!("../../crates/app/tests/fixtures/gpg/cert-alice.asc");
static CERT_BOB: &[u8] =
    include_bytes!("../../crates/app/tests/fixtures/gpg/cert-bob.asc");

fn main() {
    let dir = std::env::args().nth(1).expect("corpus directory argument");
    let ctx = EnvelopeContext {
        sender: KeyRef::from_cert(CERT_ALICE).expect("alice fixture cert parses"),
        recipient: KeyRef::from_cert(CERT_BOB).expect("bob fixture cert parses"),
        recipient_retired_shown: vec![],
    };
    let mut total = 0usize;
    let mut accepted = 0usize;
    let mut names: Vec<String> = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("corpus dir readable")
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let data = std::fs::read(&path).expect("corpus file readable");
        total += 1;
        if envelope::validate_envelope(&data, &ctx).is_ok() {
            accepted += 1;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    println!("{total} corpus inputs, {accepted} accepted by validate_envelope");
    for n in &names {
        println!("  accepted: {n}");
    }
    if accepted == 0 {
        std::process::exit(1);
    }
}
