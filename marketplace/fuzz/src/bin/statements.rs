//! Fuzz target (§22.5): the canonical statement parsers.
//!
//! Real entry points:
//! * `domain::statements::parse_invoice_statement`
//! * `domain::statements::parse_pool_statement`
//! * `app::keys::parse_rotation_statement` (the key-rotation statement;
//!   reachable as a library function via the app crate's lib target)
//! * `modules_api::Subaddress::validate` and
//!   `modules_api::validate_standard_address` (Monero address parsing,
//!   called by both statement parsers on attacker-supplied text)
//! * `domain::Atomic::parse_decimal` and
//!   `domain::validate_canonical_timestamp` (the field-level parsers)
//!
//! Any statement that parses must also re-serialize byte-identically —
//! the parsers themselves enforce that (§4), so a parse Ok is already
//! the round-trip assertion.
#![no_main]

use libfuzzer_sys::fuzz_target;
use modules_api::Network;

const MKT: &str = "mkt_4f9c2a7e1b3d5f60718293a4b5c6d7e8";
const MAX: u64 = 1_000_000_000_000_000;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = domain::statements::parse_invoice_statement(text, MKT, Network::Stagenet, MAX);
    let _ = domain::statements::parse_pool_statement(text, MKT, Network::Stagenet);
    let _ = app::keys::parse_rotation_statement(text, MKT);
    let _ = modules_api::Subaddress::validate(text, Network::Stagenet);
    let _ = modules_api::validate_standard_address(text, Network::Stagenet);
    let _ = domain::Atomic::parse_decimal(text);
    let _ = domain::validate_canonical_timestamp(text);
});
