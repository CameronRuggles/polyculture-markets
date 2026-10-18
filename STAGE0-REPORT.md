# Stage 0 — Completion Report

Date: 2026-10-13 · Basis: spec v2 as amended (`SPEC-V2-AMENDMENTS.md`),
decisions in `DECISIONS-LOG-2026-10-13.md` (Q9/Q10 confirmed by Cameron).

## Deliverables (spec §24, Stage 0)

| Item | Location | Status |
|---|---|---|
| Threat model | `marketplace/docs/threat-model.md` | Done — assets, actors, T1–T10, out-of-scope, open items |
| Invariants doc (locked) | `marketplace/docs/invariants.md` | Done — §3 invariants + amendment additions 20–21 |
| modules-api traits + closed enums | `marketplace/crates/modules-api/` | Done, compiles, tests pass |
| Domain state machines + money | `marketplace/crates/domain/` | Done, compiles, tests pass |
| Initial schema | `marketplace/migrations/0001_initial.sql` | Done — §16 tables + `orders.settlement`, pinned ID patterns |
| Locked-suite scaffolding | `marketplace/tests/security/README.md` + `CODEOWNERS` | Done — plain-language assertion list included; copy-in checklist below |
| Repo basics | `marketplace/` (workspace, `rust-toolchain.toml` pin 1.99.0, AGPL `LICENSE`, `SECURITY.md`) | Done |
| Unverified list | `marketplace/docs/unverified.md` | Done — 2 items already closed (below) |

Workspace tests: **modules-api 4/4, domain 4/4** — including the Subaddress
newtype against real-wallet fixtures (torsion check active), canonical-integer
and ID-pattern rules, form-layer normalization with invisible-character
rejection, exact money arithmetic, semantic timestamp validation via the
`time` crate (leap seconds rejected), and the §9 transition table with the
buyer-report-never-Paid guard.

## Decision-review homework closed during Stage 0

- **Q8 (Nettle):** spike suite re-run under Sequoia's Nettle backend —
  **19/19 pass**. RustCrypto no longer needed anywhere; production crates use
  Nettle from the start.
- **Q11 (SEIPD v2):** the RFC 9580 Appendix A.8 vector (v6 PKESK + SEIPD v2,
  A.3 cert) is accepted by the envelope validator. Fixtures in
  `stage0-spike/fixtures-rfc9580/`, test in the spike suite. Remaining
  sub-item: a derived v6 hidden-recipient fixture (unverified 2a).
- **Q7b (real fixtures):** `monero-wallet-cli` v0.18.4.3, `--offline`:
  stagenet/testnet/mainnet wallets generated; subaddresses for all three
  networks validate correctly across the full network matrix (own network OK,
  others WrongNetwork, stagenet primary → NotSubaddress). Fixture wallet seed
  (stagenet, empty, fixture-only) recorded in
  `stage0-spike/fixtures-wallet/FIXTURES.md`; mainnet/testnet keys deleted.
- **Post-review fixes applied:** Q14 locked-fixture retention and the Q16
  `RecipientKeyRetired` conversation-scoping rule are in the decisions log,
  the amendments, the invariants doc (#20), and the threat model (T5).

## What remains before the suite locks (Stage 1 entry checklist)

From `marketplace/tests/security/README.md`: copy the blind seed suite in
with (a) Q7a fixture constructions (synthetic tag-9; `--compress-algo none`
oversize), (b) Q16 taxonomy + retired-key probe test, (c) Q17 newtype API,
(d) Q14 fixtures, (e) real-wallet address fixtures (done above), (f) RFC 9580
test (done above). Then the §22 stage gate applies from Stage 1 onward.

## Park state

Per Q10: the project **parks here until after the Nov 15** WorldExpanders
checkpoint. Nothing is left running; no external accounts exist; the tree is
self-contained. Resume word from Cameron starts Stage 1 (accounts, sessions,
CSRF, `authorize()`, throttles, Argon2 guard, admission modules) with its
stage gate per the Q10 limits.
