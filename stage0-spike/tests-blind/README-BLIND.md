# Blind security tests — Stage 0 spike

Authored independently, per spec §22, from **only**:

1. Spec v2 (`Privacy-First_Noncustodial_Marketplace___Spec_v2_0_4b7b.md`), focusing on §3, §10, §14, §23.
2. The interface contract `API-CONTRACT.md`.

The author did **not** read anything under `stage0-spike/src/`, nor any
`Cargo.toml`, and did not run `cargo test` (compiling/running is not the
blind author's job). These files use **std only** — no dev-dependencies —
so a harness can drop them into a Cargo `tests/` layout unchanged. (They
live in `tests-blind/` as instructed, which is not itself a Cargo test
directory; whoever wires them in owns that step.)

Test counts: `blind_address.rs` 16, `blind_statement.rs` 19,
`blind_envelope.rs` 12 — 47 tests total.

## Traceability — which spec clauses each test covers

### blind_address.rs → §3 invariant 7, §23 “Payments”

Contract rule under test: only a subaddress on the expected network is
accepted; primary/integrated → `Err(NotSubaddress)`; wrong network →
`Err(WrongNetwork)`; unparseable/bad checksum → `Err(Parse)`.

| Test | Clause |
|---|---|
| `valid_mainnet_subaddress_accepted_on_mainnet` | §3 #7 (accept path) |
| `second_valid_mainnet_subaddress_accepted_on_mainnet` | §3 #7 (second independent fixture) |
| `valid_stagenet_subaddress_accepted_on_stagenet` | §3 #7 (network is configured, not hard-coded) |
| `valid_testnet_subaddress_accepted_on_testnet` | §3 #7 |
| `primary_address_rejected_as_not_subaddress` | §3 #7; §23 “Primary … addresses are rejected” |
| `integrated_address_rejected_as_not_subaddress` | §3 #7; §23 “integrated … rejected” |
| `stagenet_primary_rejected_as_not_subaddress_on_stagenet` | §3 #7 — isolates kind-check from network-check |
| `mainnet_subaddress_rejected_as_wrong_network_on_stagenet` | §3 #7; §23 wrong-network |
| `stagenet_subaddress_rejected_as_wrong_network_on_mainnet` | §3 #7; §23 wrong-network |
| `mainnet_subaddress_rejected_as_wrong_network_on_testnet` | §3 #7; §23 wrong-network |
| `stagenet_primary_on_mainnet_is_rejected` | §3 #7 — rejection only; variant deliberately unasserted (ambiguity A1) |
| `garbage_string_rejected_as_parse` | contract: unparseable → `Parse` |
| `empty_string_rejected_as_parse` | contract: unparseable → `Parse` |
| `bad_checksum_rejected_as_parse` | contract: bad checksum → `Parse` |
| `truncated_address_rejected_as_parse` | contract: unparseable → `Parse` |
| `non_base58_characters_rejected_as_parse` | contract: unparseable → `Parse` |

### blind_statement.rs → §10 (all rules), §23 “Payments”

| Test | Clause |
|---|---|
| `serialize_invoice_matches_spec_layout_byte_for_byte` | §10 invoice example layout; fixed key order; single space after colon; LF only; exactly one final LF |
| `parse_invoice_accepts_canonical_and_recovers_every_field` | §10 field set |
| `parse_then_serialize_is_byte_identical` | §10 / contract: re-serialization identity |
| `parse_invoice_accepts_64_hex_fingerprint` | §10: fingerprints are 40 **or** 64 hex |
| `rejects_crlf_line_endings` | §10: LF only, no CR |
| `rejects_tab` | §10: no tabs; single space after colon |
| `rejects_trailing_space_on_a_line` | §10: no trailing spaces |
| `rejects_blank_line_in_the_middle` | §10: no blank lines |
| `rejects_missing_final_lf` | §10: exactly one final LF |
| `rejects_extra_final_lf` | §10: exactly one final LF / no blank lines |
| `rejects_two_spaces_after_colon` | §10: a single space after the colon |
| `rejects_wrong_key_order` | §10: keys in a fixed order |
| `rejects_lowercase_fingerprint` | §10: fingerprints are uppercase hex |
| `rejects_uppercase_digest` | §10: digests are lowercase hex |
| `rejects_extra_unknown_key` | §10: keys from a fixed list |
| `rejects_missing_key` | §10: fixed field set |
| `rejects_amount_with_leading_zero` | §10 + contract (see ambiguity S5) |
| `rejects_non_ascii_bytes` | §10: printable ASCII 0x20–0x7E only |
| `rejects_clearsigned_style_input` | §10: clearsigned statements rejected; §23 same |

### blind_envelope.rs → §14, §3 invariant 13, §23 “Messaging”

| Test | Clause |
|---|---|
| `accept_sign_encrypt_to_recipient_and_sender_armored` | §14.2/§14.3; §23: recipient + sender's own key accepted |
| `accept_encrypt_to_recipient_only_armored` | §14.3: “at least one PKESK must name … the recipient's” |
| `accept_sign_encrypt_to_recipient_and_sender_binary` | contract: input may be armored **or binary** |
| `reject_plaintext` | §3 #13; §23: plaintext rejected |
| `reject_symmetric_only_skesk` | §14.2: SKESK rejected |
| `reject_encrypt_to_stranger_only` | §14.3; §23: wrong-recipient rejected |
| `reject_encrypt_to_recipient_and_stranger` | §14.3: any other PKESK must be the sender's own |
| `reject_throw_keyids_wildcard_recipient` | §14.3: wildcard (hidden) recipients rejected |
| `reject_legacy_packet_without_integrity_protection` | §14.2: legacy packets without integrity protection rejected |
| `reject_oversize_input_before_parsing` | §14.1 / contract: 64 KiB cap checked before parsing |
| `reject_oversize_but_otherwise_valid_message` | §14.1: 64 KiB cap |
| `reject_empty_input` | §3 #13 (only OpenPGP messages accepted) |

## Fixtures

### Monero addresses — sourced and independently verified

Every hardcoded address was decoded and checksum-verified **by the blind
author** with a throwaway standalone script implementing the published
Monero address format (Monero block-base58; checksum = first 4 bytes of
Keccak-256 of the payload) — never with project code.

- **Mainnet subaddress (accept fixture #1)** — published in the
  Moneropedia “address” entry in the Monero project website source as the
  Monero donation address. Verified: 95 chars, prefix byte 42, checksum OK.
- **Mainnet subaddress (accept fixture #2), mainnet primary, mainnet
  integrated** — published as worked examples on the Coin Wallet
  “Monero address example” page (coin.space). Verified: prefix bytes
  42 / 18 / 19, lengths 95 / 95 / 106, checksums OK.
- **Stagenet primary** — published test-wallet address in the
  bh-php-monero-explorer `TestingWithMoneroStagenet` example. Verified:
  prefix byte 24, checksum OK.

### Fixtures I could not source as published, and what was done instead

- **Stagenet / testnet subaddresses:** no published example could be found
  in the sources searched. Instead of leaving wrong-network coverage
  untested, the blind author *constructed* them by re-encoding the
  published stagenet wallet's public spend/view keys under the documented
  subaddress prefix bytes (36 stagenet, 63 testnet) with a recomputed
  checksum, per the address format described in Moneropedia. Both were
  re-verified after construction (length, prefix, checksum) and carry real
  public keys copied from the published wallet. Provenance is also stated
  in the `blind_address.rs` header. A human reviewer should decide whether
  constructed fixtures are acceptable, or replace them with subaddresses
  generated by a real stagenet/testnet wallet.
- **Discarded source:** one site's published “example” addresses
  (StealthEX) **failed** checksum/block decoding under independent
  verification and were deliberately *not* used. Published ≠ valid.
- **Bad-checksum fixture:** derived by changing the final character of
  the verified Moneropedia subaddress (`H` → `J`), altering only checksum
  material.

### OpenPGP fixtures

Generated at test time via the system `gpg` (2.4.4 in the author's
environment): three fresh ed25519 (sign) + cv25519 (encryption subkey)
keys — recipient, sender, stranger — in a per-test throwaway `GNUPGHOME`.
No fixture files are read. Known fixture gaps:

- **SEIPD v2 (AEAD) acceptance is not exercised.** §14 accepts SEIPD v1
  (MDC) or v2 (AEAD); the local `gpg` emits v1, and the author found no
  dependable std-only way to make it emit v2 for a fixture. The v2 accept
  path is therefore claimed-but-untested by this suite — it belongs in
  `docs/unverified.md` until a fixture exists.
- **§14.1's “at most 32 packets” and bounded nesting depth are not
  tested.** The contract's `validate_envelope` description names only the
  64 KiB cap explicitly, so it is ambiguous whether the spike is expected
  to enforce the packet-count/depth limits (ambiguity E5).

## Contract ambiguities found (recorded, NOT resolved by peeking)

### Address

- **A1 — Rejection precedence unspecified.** An address that is both
  wrong-network *and* not a subaddress (e.g. a stagenet primary checked
  against mainnet) matches two contract rules with two different
  variants. Neither spec nor contract orders the checks.
  `stagenet_primary_on_mainnet_is_rejected` therefore asserts only
  `is_err()`.
- **A2 — Input normalization unspecified.** Nothing states whether
  surrounding whitespace or a trailing newline on an address is trimmed
  or rejected. Deliberately untested; the safe behaviour (reject) is a
  human-review decision, not something the blind author will assert
  unilaterally.
- **A3 — `kind` is a free `String`.** The contract documents exactly one
  value (`"subaddress"`); tests assert that exact string for accepted
  addresses. If other kinds were ever intended, the contract doesn't say.
- **A4 — Curve-point validity unspecified.** Neither spec nor contract
  says whether validation must check that the embedded public keys are
  valid curve points beyond prefix/checksum parsing (“parsed with a
  maintained Monero library”, §3 #7). All fixtures carry real keys, so
  the tests pass under either reading.

### Statements

- **S1 — Destination validation inside the statement parser unspecified.**
  §10 lists per-field “patterns”, but neither spec nor contract says
  whether `parse_invoice` must parse `destination` as a Monero address,
  nor whether it must agree with the `network:` field. Not asserted
  either way (the fixture uses a consistent pair).
- **S2 — ID patterns unspecified in detail.** The shapes of
  `marketplace-id` / `invoice-id` / `order-id` values are exemplified,
  not formally patterned, in §10. Tests do not assert rejection of
  malformed IDs (beyond the non-ASCII byte rule).
- **S3 — Timestamp validation depth unspecified.** §10 requires
  “RFC 3339 UTC with seconds and a `Z`”, but whether semantic validity
  (e.g. month ≤ 12) is checked is unstated. Not tested.
- **S4 — `network:` value set.** The contract comments the three allowed
  strings, but §10 does not state a rejection rule for other values in
  the statement parser. Not tested.
- **S5 — Leading-zero amount is an inference, flagged.** No §10 rule
  literally says “no leading zeros”. The rejection test is derived from
  two contract facts: `amount_atomic` is a `u64`, and the parser “MUST
  reject any input whose re-serialization is not byte-identical”. If a
  human reviewer reads the contract differently, this is the test to
  strike — do not weaken the parser to pass it without that review.

### Envelope

- **E1 — Variant classification of non-messages.** Raw plaintext bytes and
  empty input could plausibly map to `Plaintext`, `Malformed`, or
  `NotArmoredOrBinary`; the contract names all three variants without a
  classification rule. Tests assert rejection with any of the plausible
  variants.
- **E2 — Stranger-recipient variant.** A PKESK belonging to neither cert
  could be `WrongRecipient` or `UnknownRecipient`; §14.3 gives the
  rejection rule, not the variant. Tests assert either.
- **E3 — What the 64 KiB cap measures.** §14.1 says “messages up to
  64 KiB **armored**”; the contract says “size cap checked before
  parsing: 64 KiB” of the input. These agree if the input is the armored
  bytes, but a boundary case (decoded ≤ 64 KiB, armored > 64 KiB, or
  vice-versa) is untested by design, because the two readings disagree
  there. The oversize-valid test uses a plaintext that exceeds the cap
  on *either* reading.
- **E4 — Fixture dependence on `gpg` behaviour.** The legacy-packet test
  relies on `gpg --disable-mdc` actually producing an unprotected data
  packet (true for GnuPG 2.4). If a future `gpg` ignores the flag, this
  test would fail against a correct implementation — check the fixture
  before “fixing” the implementation.
- **E5 — Packet-count / nesting limits.** See “OpenPGP fixtures” above:
  §14.1 limits packets (32) and nesting depth, the contract excerpt for
  `validate_envelope` does not mention them, and no test asserts them.

## Blindness statement

These tests were written from the spec and the API contract only. The
author did not open `stage0-spike/src/**` or any `Cargo.toml`, did not
run the implementation, and resolved no ambiguity by inspecting code —
ambiguities are listed above for human review, per §22 rule 3 (“never
weaken to pass”).
