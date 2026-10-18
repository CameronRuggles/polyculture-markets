# Review Pack — Marketplace Spec v2, Stage 6 CORE (canonical statements, QR/URI, xmr-only pricing)

**How to use:** paste whole into Claude Opus. This is the §22
stage-gate review for Stage 6 CORE, produced in the 2026-10-14 gate
run (STAGE6-REPORT.md has the full evidence). Cameron (owner) makes
final calls; your job is verdicts with file:line evidence. Note the
scope: the §24 Stage 6 invoice *flow* (pages/routes wired into
orders) is held pending the owner's payment-design decision — this
pack covers only the library layer defined in STAGE6-PREFLIGHT's
"Safe to build regardless" section. Do not fault the code for the
absence of the held flow, and do not propose building it.

## Instructions to the reviewer

1. For each invariant listed, give: HOLDS / VIOLATED / CANNOT-TELL,
   with the file and line you relied on. Abstract concern without a
   mechanism doesn't count; name who does what to whom.
2. The code is at `marketplace/crates/domain/src/statements.rs` (the
   statement library), `marketplace/crates/domain/src/lib.rs`
   (`xmr_only_total`, `PRICING_MODULE_XMR_ONLY`, `Atomic`,
   `Subaddress`), and one wiring line plus the inbox timestamp format
   in `marketplace/crates/app/src/orders.rs`. The spec is
   "Privacy-First Noncustodial Marketplace — Spec v2" (§10, §11, §24)
   plus `SPEC-V2-AMENDMENTS.md` (Q13, Q15, Q17) and the canonical
   contract `marketplace/docs/api-contract.md` §12 (the Stage 6 core
   surface, written before the code). If you cannot see the files, say
   so and review against the claims and evidence summarized here
   instead — flag that limitation.
3. End with: (a) any test a future locked suite must add for this
   surface, stated as plain-language assertions; (b) anything that
   must be fixed before the held invoice flow builds on this library.

## What was built (claims to check)

The parser accepts an invoice or pool statement only when every field
validates **and** the input equals the canonical re-serialization byte
for byte: fixed field order, `key: value` lines with exactly one
space, LF endings with exactly one trailing LF, no leading/trailing
blank lines. Integers are canonical (digits only, no sign, no leading
zeros except `0` itself, u64 range plus per-field bounds).
Timestamps are semantic RFC 3339: shape, real calendar dates (leap
years honoured), hour ≤ 23, minute/second ≤ 59 with leap-second `:60`
rejected in every position, offsets `Z` or `±HH:MM` within real
ranges; the supplied spelling is preserved so equivalent instants in
different spellings are different bytes. IDs match
`^(mkt|inv|ord|pool|acct)_[0-9a-f]{32}$` with the correct prefix per
field, and `marketplace-id` must additionally equal the instance's own
ID. The `network:` line must be one of the closed three-value set and
equal the instance network. Destinations are the `Subaddress` newtype
(Q17): standard/integrated addresses and other networks' addresses
are rejected, and no success type carries `kind`/`network` as
strings. Fingerprints are uppercase hex of exactly 40 or 64 chars;
`terms-sha256` is exactly 64 lowercase hex chars. Invoice amounts are
canonical, > 0, and ≤ the caller-supplied cap. Pool `address-count`
is canonical, 1–200, exactly the number of address lines; duplicate
addresses within one pool are rejected (contract §12 pin: an entry
index must identify one address). Nothing in the library trims (Q13):
leading/trailing whitespace anywhere is a rejection, never a cleanup.
`payment_uri` is deterministic — `monero:` + the canonical addres
...[truncated 3702 chars]