# Stage 0 Feasibility Spike — Report

> **ARCHIVED 2026-10-18** — this spike is preserved history, not a
> component. See `ARCHIVED.md` in this directory before building or
> citing anything here (its pinned lockfile is deliberately frozen,
> including a rustls version with known advisories).

Date: 2026-10-13 · Scope: the four make-or-break assumptions named before the
build estimate, plus the §22 blind-test workflow. This is a spike, not
Stage 0 proper: the threat-model doc, `modules-api` traits, and initial
schema from §24 Stage 0 are still to do before Stage 1.
Code: `stage0-spike/` (crate `stage0_spike`, Rust 1.99, deps pinned in
Cargo.lock: monero 0.22.0, sequoia-openpgp 2.4.1, ureq 3.4, serde_json).

## Verdict: GO — all four assumptions hold, with three spec clarifications needed

| # | Assumption | Result |
|---|---|---|
| 1 | `monero` crate parses type + network, rejects primary/integrated/wrong-network/bad checksum | **PROVEN** |
| 2 | Sequoia gives packet-level envelope validation per §14 | **PROVEN, with finding F1 (AED packet)** |
| 3 | Canonical statements: byte-exact format + detached-sig verification | **PROVEN** |
| 4 | `check_tx_proof` via monero-wallet-rpc works as §12 assumes | **API + client PROVEN; crypto verification ENVIRONMENT-DEFERRED** |
| 5 | Blind-test workflow (§22) is workable with a separate agent session | **PROVEN — and it caught real things** |

## Test evidence

- Implementation unit tests: **19/19 pass** (address 5, statement 3,
  envelope 7, txproof 4).
- Blind suite (47 tests, written from spec + API contract only):
  address **16/16**, statement **19/19**, envelope **10/12**.
  The 2 envelope failures are fixture-construction failures, evidenced
  below — per §22.3 the blind tests were NOT modified.

## Spike 1 — Monero addresses (§3.7, §11)

`Address::from_str` (monero-rs) verifies base58 checksum + key validity
and exposes `network` + `addr_type`. Accept = SubAddress on the expected
network only; standard/integrated → rejected; wrong network → rejected;
garbage/bad checksum → rejected.
External (non-self-generated) fixture: the address published in the
official wallet-RPC docs' `get_tx_proof` example parses as a stagenet
subaddress and validates; the blind author independently sourced and
checksum-verified published mainnet subaddress/primary/integrated
fixtures (Moneropedia, Coin Wallet examples) — all behave correctly.
Blind author also *discarded* one site's "example" addresses that failed
checksum verification: published ≠ valid.

## Spike 2 — Envelope validation (§14)

Sequoia 2.4 `PacketPile` exposes top-level packets; PKESK recipients come
back as key handles (wildcard = `None` / all-zero key ID); cert key IDs
are collectable from primary + subkeys. Validator passes: recipient-only,
recipient+sender, armored and binary; rejects plaintext, SKESK
(symmetric), stranger-only, recipient+stranger, --throw-keyids wildcard,
and >64 KiB before parsing.

**FINDING F1 — the AED wrinkle (needs a spec decision).** GnuPG 2.4.4
emits the LibrePGP **AEAD Encrypted Data packet (tag 20)** by default —
*not* RFC 9580 SEIPD v2 (tag 18). Sequoia parses tag 20 as
`Packet::Unknown`. §14 says "SEIPD v1 with MDC, or v2 AEAD", and §14's own
suggested command (`gpg --armor --sign --encrypt`) produces tag-20 AED on
a current GnuPG. The spike accepts tag-20 AED as integrity-protected
(it is — AEAD), and also accepts SEIPD v1 (exercised via
`gpg --openpgp --force-mdc`). **Decision needed before Stage 5:** name
tag-20 AED explicitly in §14, or restrict to SEIP and change the guide's
commands. RFC 9580 SEIP v2 itself remains untested — no tool in this
environment emits it.

**FINDING F2 — Sequoia crypto backend.** The pure-Rust (RustCrypto)
backend is gated behind two explicit opt-in features and upstream says
it is "not considered production ready" and not constant-time. Our use is
parse + public-key signature verification only — no secret key material
ever — which is the case upstream's warning carves out; still, the
production decision (Nettle backend = upstream's production choice,
needs system nettle/clang; could not be installed in this sandbox —
apt was locked/unavailable at attempt time) belongs in Stage 0 proper.

**Blind envelope failures, both fixture-side:**
1. *Legacy packet:* GnuPG 2.4.4 silently ignores `--disable-mdc` (and
   `--rfc2440` / `--openpgp` modes, and RSA parameter-file keys) — every
   attempt emits AED tag 20 (`gpg --list-packets` evidence). A genuine
   no-integrity SED fixture **cannot be produced with this GnuPG**; the
   reject path exists structurally but is UNVERIFIED against a real SED
   packet. Stage 5 must build that fixture with a packet-level tool
   (Sequoia serializer / rnp) or an older GnuPG container.
   The blind author had flagged exactly this risk (their note E4).
2. *Oversize valid message:* the test's plaintext (72 KiB of one repeated
   byte) compresses to almost nothing under gpg's default compression,
   so the encrypted message never exceeded the cap — test construction
   failed before the assertion. The cap-before-parse property is proven
   by the sibling test (oversize garbage → `TooLarge`) and the spike's
   own oversize test; the blind test needs `--compress-algo none` at
   construction, a test-side fix for human review.

## Spike 3 — Canonical statements (§10)

Serializer + strict parser implemented exactly as specified: ASCII/LF
alphabet check, fixed key order, `: ` spacing, fingerprint/digest case
rules, RFC 3339 `Z` shape, and the re-serialization byte-identity check
(which is also what rejects leading-zero amounts — blind ambiguity S5
notes this is an inference from the contract, for human review).
Detached signature verification via Sequoia `DetachedVerifierBuilder`:
valid gpg detached signature verifies; one-byte amount tamper fails;
garbage signature fails. Blind suite: 19/19 incl. byte-for-byte layout
against the spec's example.

## Spike 4 — Tx proofs (§12)

Official wallet-RPC docs confirm `check_tx_proof` with inputs
{txid, address, message, signature} and outputs {good, received,
confirmations, in_pool, untrusted} — exactly the shape §12 assumes.
Client implemented with ureq: request-shape test, documented-response
parse test, and a live end-to-end call against a mock wallet-rpc server
all pass. **Not proven:** the cryptographic verification itself, which
happens inside the real wallet against a synced node. That needs a
stagenet `monerod` + verify-only wallet with a real stagenet payment —
Stage 8 work, environment-deferred here, and the single largest
remaining external dependency in the whole design.

## Blind-test workflow (§22)

Worked as designed, first try: a separate agent session wrote 47 tests +
a traceability README from the spec and an interface contract alone,
never reading the implementation. It surfaced 11 recorded ambiguities
(address A1–A4, statement S1–S5, envelope E1–E5) — notably rejection-
precedence (A1: my implementation checks network before kind) and the
packet-count/nesting limits (E5: spike now enforces the 32-packet cap at
top level; packets nested inside the encrypted container are invisible
to any envelope check, which the spec should acknowledge). Correlation
caveat from the estimate stands: same model family authored both sides.

## Unverified / deferred list (seed for docs/unverified.md)

1. Real stagenet tx-proof verification (needs synced node + wallet) → Stage 8.
2. RFC 9580 SEIP v2 accept path — no fixture exists in this environment.
3. Legacy SED reject path — no fixture producible with GnuPG 2.4.4.
4. Sequoia production backend choice (Nettle vs RustCrypto) — decision + build test on a machine with nettle/clang.
5. Tor Browser Safest / onion cookie behaviour (§18) — untouched by this spike.
6. Timestamp semantic validity (month ≤ 12 etc.) in statement parser — shape-only in spike (blind S3).
7. Packet-count limit applies to top-level packets only in spike (E5).

## Remaining Stage 0 work before Stage 1

Threat-model document, `modules-api` crate (traits + closed enums as
sketched in §4), initial SQL schema (§16), repo/CODEOWNERS layout with
`tests/security/` locked — est. 1–2 focused days. The clarifications in
F1 (AED in §14) and S5/A1 should be settled by Cameron as spec owner
before the locked suite is finalized.
