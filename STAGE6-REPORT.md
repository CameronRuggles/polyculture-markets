# Stage 6 CORE Report — canonical statements, QR/URI, xmr-only pricing (spec §10, §24 Stage 6)

**Label, honestly:** this is Stage 6 **CORE** only. The §24 Stage 6
invoice *flow* (invoice pages/routes wired into orders, signed-invoice
lifecycle) is **held pending the owner's payment-design decision**
(payments parked 2026-10-14). What was built is exactly the
STAGE6-PREFLIGHT "Safe to build regardless" set — the library layer
every payment strategy will stand on, whichever one the owner picks.

## Verdict: PASS (core scope)

Blind suite 83/83 on its first run against the implementation and on
every re-run; workspace 327 passed / 0 failed (baseline 239 + 83 blind
+ 5 new unit tests); cargo-mutants run with survivors triaged in §6;
crypto guard green (§7). No locked test was edited; no code fix was
needed after the blind suite first ran.

## 1. Scope — what was built, what was not touched

Built:
1. **Canonical statement library** — `crates/domain/src/statements.rs`:
   `parse_invoice_statement` / `parse_pool_statement` /
   `InvoiceStatement::to_bytes` / `PoolStatement::to_bytes`,
   implementing §10 with the ratified byte-identity rules (canonical
   integers digits-only, u64 + per-field range; RFC 3339 semantic
   timestamps with byte-identical reformatting, leap-second `:60`
   rejected; closed three-value `network:` set matched against the
   instance network). Acceptance requires the input to equal the
   canonical re-serialization byte for byte.
2. **Destination typing (Q17)** — statement destinations are the
   existing `Subaddress` newtype; no success type carries kind/network
   as strings (`kind`/`network` exist only in the rejection enums).
3. **QR + payment URI** — `payment_uri` (`monero:` + canonical address
   + `?tx_amount=` + `Atomic::format_decimal`, no other parameters)
   and `payment_qr_png` (deterministic PNG bytes: black on white,
   4-module quiet zone, 8 px/module). One normalization path: the
   library never trims (Q13); form input reaches it only through the
   existing `normalize_form_lines`.
4. **`xmr-only` pricing** — `PRICING_MODULE_XMR_ONLY = "xmr-only"` and
   `domain::xmr_only_total` (checked multiplication, `None` on
   overflow). Order creation in `crates/app/src/orders.rs` now computes
   its total through this function with identical error behaviour.

Also applied, under the task's single exception: the **`inbox()`
timestamp fix** (orders.rs ~line 393): `YYYY-MM-DD HH24:MI` →
canonical RFC 3339 UTC (`YYYY-MM-DD"T"HH24:MI:SS"Z"`), mirroring the
format order timestamps already used. Safety was verified *before*
applying: the locked blind_stage4 suite asserts only non-emptiness and
newest-first lexicographic order of inbox times, both preserved by the
canonical format; blind_stage4 passes 58/58 with the fix in the final
full-suite run.

Not touched (payments parked / out of scope): no invoice routes or
pages, no order-flow or Stage 4 state-machine changes, nothing from
ENCRYPTED-ORDERS-PLAN (no acceptance statements, reservation
certificates, commitments, or listing snapshots), and **none of the
seven UNRATIFIED Stage 4 owner-item spec pins** were folded into the
spec. The uploaded spec file itself was not edited.

## 2. Contract first (gate step 1)

The API contract gained **§12 "Stage 6 core surface"**
(`marketplace/docs/api-contract.md`) before implementation: type and
function signatures, the pinned validation rules (field order; ID
patterns `^(mkt|inv|ord|pool|acct)_[0-9a-f]{32}$`; fingerprints
uppercase hex 40/64; `terms-sha256` exactly 64 lowercase hex;
`address-count` 1–200 and exactly the number of address lines;
**duplicate address lines within one pool statement are rejected** —
contract pin: an entry index must identify one address, §11), and the
**regenerated §10 examples at the pinned 32-hex ID length**:

- marketplace `mkt_4f9c2a7e1b3d5f60718293a4b5c6d7e8`
- invoice `inv_8d1e5b0c3a7f2b4d6f8091a3b5c7d9e0`
- order `ord_2b6a9e4d1c083f5a7c9e1b2d4f607182`
- pool `pool_6c0e3f9a5b7d9f1a2c4e6a8b0d2f4a6b`

New dependencies: `qrcode = "0.14"` (0.14.1) and
`image = 0.25` (png feature only), both in the domain crate.

## 3. The blind suite

Authored by an independent subagent from the spec text, amendments,
and contract only — it never saw implementation code. Locked at
`marketplace/tests/security/blind_stage6.rs`: **83 tests** across
valid-statement acceptance, byte-identity attacks (spacing, CRLF,
trailing content, leading zeros, signs, unicode digits, reordered /
duplicated / missing fields), ID patterns, fingerprints and digests,
network/destination validation, numbers (boundaries, overflow,
atomic↔decimal rendering), timestamps (offset equivalence, `:60`
rejection, malformed shapes), pool structure (count range, pool
indexing, duplicates), the no-trimming rule, URI exactness and
determinism, QR (PNG magic, byte determinism, amount sensitivity),
Q17 typing, pricing, and supporting-type checks.

**Fixtures (Q7b discipline):** all addresses are real, valueless, and
were generated offline with monero-wallet-cli/RPC v0.18.4.3 and
verified per-network with the wallet's own `validate_address` —
stagenet standard/integrated/subaddresses, a 200-entry stagenet pool
(indices 1–200) plus index 201 for boundary rejections, a mainnet
subaddress, and a testnet subaddress (both used only as cross-network
negatives).

The author's four flagged interpretations, recorded verbatim for the
owner (all four match the contract as written; none needed a ruling
mid-gate):
(a) `xmr_only_total(123, 0) == Some(0)` — the helper is checked
arithmetic only; quantity ≥ 1 is the order layer's rule;
(b) `Atomic(0).format_decimal() == "0"`;
(c) the address-count-0 rejection must come from the 1–200 range rule;
(d) QR pixel dimensions are deliberately **not** asserted (documents
pin quiet zone/module size in prose, but no total is testable for a
given URI) — see the survivor triage in §6.

**First run: 83 passed / 0 failed.** No implementation fix was needed
after the blind suite first ran — the only first-run failures anywhere
in this gate were two media tests on the very first baseline attempt,
caused by missing harness env (`MEDIA_WORKER`/`MEDIA_DIR`, the
RETROFIT-REPORT §4.8 harness requirement), green once the documented
env was set. That is an environment fact, not a code result.

## 4. Baseline and final counts

- Baseline (environment recovered, §8): **239 passed / 0 failed** —
  app lib 14, stage1_db 1, domain 7, envelope lib 4, blind_stage5 35
  (3 ignored), modules-api 7, blind_stage1 41, blind_stage2 38,
  blind_stage3 34, blind_stage4 58 (6 ignored).
- Final: **327 passed / 0 failed / 9 ignored** (ignores all
  pre-existing: 6 in blind_stage4, 3 in blind_stage5). Delta = 83
  blind_stage6 + 4 statement unit tests + 1 pricing unit test.
  Independently re-run by the coordinator after all hand-verification
  restores: 327/0, blind_stage6 83/83.

## 5. Code changes (complete list)

- `crates/domain/src/statements.rs` — **new** (library + 4 unit tests).
- `crates/domain/src/lib.rs` — `pub mod statements;`,
  `PRICING_MODULE_XMR_ONLY`, `xmr_only_total` + 1 unit test.
- `crates/domain/Cargo.toml` — `qrcode`, `image` (png only).
- `Cargo.lock` — updated by Cargo.
- `crates/app/src/orders.rs` — total via `domain::xmr_only_total`
  (same `.ok_or(OrderError::BadQuantity)?` behaviour); `inbox()`
  timestamp format fix (see §1).
- `marketplace/docs/api-contract.md` — new §12 (written before code).
- `tests/security/Cargo.toml` — `[[test]] blind_stage6` registration
  (appended by the blind author; the only tests-tree change).

No file under `tests/security/` other than that registration was
touched. No migration files were changed (see §8 for why one needs an
owner decision).

## 6. cargo-mutants

Tool: cargo-mutants 27.1.0, `TMPDIR` on the home disk. Outputs
preserved under `mutants-runs/stage6-statements/` (including
`handverify-blind-layer.txt` and `handverify-pricing.txt`).

**Statement library** (`statements.rs`, 94 mutants): unit layer
72 caught / 19 missed / 3 unviable
...[truncated 5537 chars] — the sentence this report
originally ended on, mid-count. The remainder of §6 and §§7–8 below
were completed on 2026-10-16 from the preserved gate artifacts
(`STAGE6-REPORT-COMPLETION-DRAFT-2026-10-15.md`), a fresh crypto-guard
run, and fresh code-level triage — not from any summary.

**§6 remainder — hand-verification of the 19 unit-layer misses**
against the locked blind_stage6 suite (method: apply diff in the real
tree, run the blind suite, reverse, md5-verify restore; pristine md5
`0a2476ad132c64f691d31219a2c1f03e`; source:
`mutants-runs/stage6-statements/handverify-blind-layer.txt`):

- **5 KILLED by the blind layer:** fingerprint `==`→`!=` (93:31);
  `valid_terms_sha256` → true (100:5) and its `&&`→`||` (101:9);
  `parse_marketplace_id` `||`→`&&` (139:32); invoice `>`→`>=` (199:44).
- **14 SURVIVED both layers:** 3 non-QR (triaged below) and 11
  QR-geometry mutants in `payment_qr_png` (315:23, 315:31, 319:25 ×2,
  319:38, 320:39 ×2, 321:39 ×2, 324:42, 324:51) — scale, quiet-zone
  and module-offset changes no test caught, because unit + blind
  tests checked only PNG magic, byte determinism and amount
  sensitivity (blind author's note (d), §3).
- **Pricing** (`xmr_only_total`, hand-mutations in place of a
  cargo-mutants list for lib.rs): all 3 body replacements (→None,
  →Some(0), →Some(1)) **killed** by both the domain unit test and
  blind_stage6. Restore md5 verified (`handverify-pricing.txt`).

**Triage of the 3 non-QR survivors (fresh, 2026-10-16, code-checked
against `crates/domain/src/statements.rs`): accepted as
outcome-equivalent — no acceptance decision changes under any of
them, because §4's byte-identity rule does their work downstream.**

- `byte_gate` → true (88:5): every statement field is individually
  validated after the gate (closed format strings, public-ID patterns,
  uppercase/lowercase hex checks, canonical u64 and timestamp
  validators, `Subaddress::validate`), and final acceptance requires
  `statement.to_bytes() == text.as_bytes()` exactly. The serializer
  emits only printable ASCII + LF, so any byte the gate would have
  rejected either fails a field validator or breaks byte-identity.
  The gate remains as defence-in-depth; its removal is not observable
  in any parse outcome.
- `expect_end` → Some(()) (127:5) and `expect_end` `&&`→`||` (127:33):
  both mutants only weaken the trailing-content check, and the same
  byte-identity comparison runs after `expect_end` in both parse
  functions — extra trailing lines, a missing final LF, or any other
  tail difference makes the re-serialization differ from the input
  and the statement is rejected anyway.

**Post-gate closure of the 11 QR survivors (2026-10-16):** the
decode-and-compare unit test drafted in
`QR-DECODE-TEST-DRAFT-2026-10-14.md` is now applied in the
implementer unit layer of `statements.rs`
(`qr_png_decodes_back_to_the_encoded_uri_modules`): it renders the
fixture invoice, decodes the PNG, and asserts dimensions, an all-white
quiet zone, and every module's centre pixel against
`QrCode::new(payment_uri(...)).to_colors()`. Verified: `cargo test -p
domain` 14/14 including the new test; hand-applied geometry mutants
(scale 8→7, quiet zone 4→3, module offset +1) each FAIL the new test,
and the restored code passes. Diff against the pre-test file is
additions only (the renderer now lives in `payment_qr_png_for`, split
out by Direct Payments v1 with identical geometry). This does not
reopen or alter the Stage 6 PASS; it removes the blind spot the gate
named.

## 7. Crypto guard

Re-run fresh on 2026-10-16 (the original §7 detail did not survive;
this section is written from that run's output, not backfilled from
the Gate 4 precedent): `marketplace/deploy/check-crypto-backend.sh`
exits 0 — "OK: sequoia-openpgp resolves to the Nettle backend; no
RustCrypto backend features enabled". Honest scope note: the re-run
checks the current workspace tree (which now also carries Direct
Payments v1); the guard inspects the resolved `sequoia-openpgp`
feature tree, and nothing in the intervening work touched the Sequoia
dependency or its features.

## 8. Environment / migration defect — superseded

The two cross-references to this section (§4's "environment
recovered" 239 baseline, §5's "why one needs an owner decision")
pointed at the duplicate-0006 migration pair
(`0006_conversation_key_sightings.sql` / `0006_conversations.sql` —
two incompatible shapes for one table, so a fresh install failed).
That defect has since been **repaired and verified** (Option A;
fresh install from migrations 0001→0007 lands on the canonical shape,
both write paths exercised, full suite 327/0, Q16 probe green;
`MIGRATION-REPAIR-2026-10-14.md`, executed section). The original §8
defect text is deliberately not restored: a fresh install no longer
breaks, and the old text would mislead the next reader the way the
missing §8 misled the first repair brief. This paragraph is the
record; the repair file is the detail.
