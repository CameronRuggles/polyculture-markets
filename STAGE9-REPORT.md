# Stage 9 Report — Reviews, Reputation, Disputes, Moderation

**Date:** 2026-10-16 · **Stage:** 9 of spec v2 §24 (spec §13 + §9 outcomes + §20 periods)
**Verdict: COMPLETE — gate passed.** Blind suite 43/43, live smoke 33/33, full
workspace 445 passed / 0 failed / 9 ignored (baseline 387 at stage start),
seller-helper standalone 13/13.

## Owner ruling applied (2026-10-16): closure, not exclusion

"Banning is impossible so it's useless to offer it as a tool. Account
closure/deletion or whatever however makes sense." Implemented exactly as
ruled and recorded in SPEC-V2-AMENDMENTS.md ("Stage 9: moderation is closure,
not exclusion"):

- **No ban, no suspension, no re-entry blocklist exists anywhere** — no code
  path, no schema value, no copy. The registered blocklist question is
  RESOLVED: not built; repeat accounts are unprovable and the design does not
  pretend otherwise.
- The account-level moderator action is **CLOSE ACCOUNT** (see semantics
  below), plus warn and listing remove/restore. Moderators have no power over
  funds and no conversation-browsing interface, ever.

## What was built

Migration `0009_stage9.sql` (additive): accounts.status/closed_at/warned_at +
TOTP columns; orders.terminal_at; reviews edit/reply tracking + length CHECKs;
reputation_facts.order_id UNIQUE; disputes outcome workflow columns;
reports.reason; new `reputation_summaries` and `moderation_actions` tables.

**Reputation facts pipeline** (`reputation.rs`). Core produces one minimized
fact per terminal order: seller id, buyer **token** (HMAC-SHA256 from the key
file over seller+buyer ids — no buyer id anywhere in the facts table),
maturity bucket at order time (buyer ≥30 days old at order creation AND ≥3
earlier Completed/Resolved orders from ≥2 distinct sellers), evidence level,
outcome, review score when present, terminal month (YYYY-MM — nothing finer
is stored). Facts are produced by an idempotent reconciliation function
invoked at startup backfill, on profile render, on review submit, and at
dispute finalization, precisely so no locked order/payment function signature
changed. A closed seller accrues **no** facts for orders terminating after
closure; pre-closure history is untouched.

**Models** behind the existing `modules-api` `ReputationModel` trait:
`weighted-reviews-v1` (default) — weight = maturity (1.0 / 0.3) × evidence
(ProofVerified/WalletObserved 1.0, everything else 0.6 — under Direct Payments
v1 that is SellerAttested, the only level that occurs) × repeat 1/k, where k
counts earlier scored facts from the same token within the repeat window.
Facts carry month precision only (§16 storage rule), so the 90-day window is
evaluated at month precision: same month or either of the two preceding
calendar months. Total weight < 5 → "Not enough history" instead of a score.
`raw-counts` (config `REPUTATION_MODEL=raw-counts`) computes no score at all.
All parameters are config (`Stage9Config`, env-overridable); model id +
version are stored with each summary.

**Raw-facts panel** (core-rendered under every model on seller profiles):
member-since month + age in days, first completed sale month, completed
orders, distinct buyers (by token), **orders with seller-confirmed payment**
(the honest v1 line), **orders with payment verified on-chain — computed from
fact evidence, genuinely 0 under v1**, with the sentence "this marketplace
does not verify payments on-chain; sellers confirm payment themselves",
disputes opened, disputes resolved against the seller, certified/uncertified
key rotations. Profiles carry the §13 honesty line: reputation can be farmed
with sock-puppet accounts and no weighting prevents it.

**Reviews** (`reviews.rs`): one per order, buyer only, Completed/Resolved
only, score 1–5, ≤1000 chars plain text rendered escaped; editable for 7
days; exactly one seller reply. The "payment verified on-chain" badge renders
only when the order's fact evidence is ProofVerified/WalletObserved — it
cannot appear under v1 evidence (blind-tested and smoke-tested).

**Disputes** (`disputes.rs`): opening already existed as a state transition;
Stage 9 creates the dispute row atomically with it (one open dispute per
order) and closes it as `withdrawn` when the buyer completes from Disputed.
Outcomes: delivered-confirmed, refund-confirmed, seller-at-fault,
buyer-at-fault, unresolved — recorded by a moderator (TOTP-gated, below).
**Refund-confirmed is two-step** per §9: the moderator proposes it, the order
stays Disputed, and only the buyer's confirmation resolves it. Other outcomes
finalize immediately (Disputed → Resolved, fact recorded, both parties
notified via inbox). The moderator dispute record shows the public order
record: terms hash, listing, total, evidence label, and under Direct
Payments v1 the assigned subaddress with its wallet-signed message — there
is no invoice in v1 and the page does not pretend otherwise.

**Disclosed evidence**: a party decrypts locally and pastes plaintext + its
detached signature. Before the form, the page states exactly what moderators
will see and the retention ("kept until 180 days after this dispute is
resolved, then deleted" — the deletion job itself is Stage 10). Both fields
pass through `normalize_form_lines` (Q13) before verification and storage, so
the verified, stored, and displayed bytes are the same bytes. Verification is
against the **other party's** pinned key: the seller's order-pinned
fingerprint, or the buyer's key whose validity interval covers the order's
creation. Only a verifying signature is labelled evidence; self-signed,
forged, garbled, or key-missing disclosures are stored and shown as
**"unverified claim"**. Content is stored encrypted with the key file
(ChaCha20-Poly1305, Nettle). Moderators get no conversation access of any
kind.

**Moderation** (`moderation.rs`): reports on listings, profiles, and reviews
(typed target references, category set, required reason); a queue at
`/moderation` with open disputes, open reports, account search, and a link to
the existing seller-admission queue. Actions: dismiss/resolve reports, warn
(timestamped, audited, shown to the account, **no functional restriction**),
remove/restore listings (removed listings leave the catalogue), and close
accounts.

**Closure semantics** — one code path (`moderation::close_account`) for
moderator closure and self-service closure (passphrase + typed `CLOSE` on the
security page): in one transaction, status → `closed` + timestamp; sessions
revoked; published listings → `paused`; unused payment-pool entries →
`retired`; audit row (`close-account` / `close-account-self`); then inbox
notices to every counterparty holding a non-terminal order. Login refuses
closed accounts **after** passphrase verification ("This account has been
closed."), so the message leaks nothing. Profiles show "Account closed" with
the date and the honest sentence that closure does not stop anyone
registering a new account. History (orders, reviews) is retained and stays
visible to counterparties.

**TOTP step-up** (`totp.rs`, `moderation.rs`): RFC 6238 over HMAC-SHA1
(vetted `hmac`/`sha1` crates already in the locked tree; the only hand-written
part is the base32 codec), 30 s step, 6 digits, ±1 step window — verified
against the RFC 6238 Appendix B vectors in tests. **Step-up is per action**:
every moderator action POST carries a current TOTP code; a moderator with no
enrollment is refused (`TotpRequired`) — there is no bypass and no
session-level grace. Secrets are 160-bit, stored **encrypted** with the key
file, with a pending/active split: enrollment activates only when a code
from the pending secret verifies. Disabling requires a valid code; a
moderator who disables loses action capability until re-enrollment.

**Key file** (`keyfile.rs`): no suitable key material existed in config, so —
as the brief directed — a 32-byte master secret is generated and persisted
alongside the deployment (`KEY_FILE_PATH`, default `./marketplace.key`, mode
0600, hex). Subkeys are derived by HMAC with domain labels (`buyer-token-v1`,
`content-enc-v1`). Losing the file makes stored disclosures/TOTP secrets
undecryptable and orphans buyer-token history (facts themselves remain); it
must be backed up separately from the database. The operations manual entry
is a Stage 10 deliverable (docs/operations.md does not exist yet).

## Gate results (§22 discipline)

**Blind suite** — `marketplace/tests/security/blind_stage9.rs`, authored by an
independent agent given only spec §13/§9/§16/§20/§22, SPEC-V2-AMENDMENTS.md,
migration 0009, modules-api types, and the API contract (never the
implementation): **43 passed / 0 failed**, verified by the coordinator's own
run. Coverage: config defaults; token determinism/unlinkability/minimization
(incl. an information_schema check that reputation_facts has no
buyer-identifying column); RFC 6238 vectors and window; weight math incl.
repeat window boundaries (+2 months counts, +3 does not; Dec→Feb), the exact
4.8 → None and 5.0 → Some threshold with mean; raw-panel completed-set
semantics; all four maturity cases; review eligibility incl. the 7-day edit
window edges and badge-always-false under v1; dispute outcomes incl. the
refund two-step, withdrawn disputes refusing resolution, and fact outcome
codes 1–5; disclosures with runtime-generated GnuPG keys (other-party signed
→ verified; self-signed and garbage → unverified claim; stored bytes contain
no plaintext); reports; TOTP enrollment/gating incl. encrypted-at-rest
assertions; warn; listing removal; **full closure semantics and self-close
parity, with zero `suspended` accounts**; template honesty (sock-puppet
line, no "suspend" in queue/dispute copy, closure banner wording).

Five contract ambiguities were recorded by the author, all resolved as
fixture-construction readings (Q7a pattern) with no assertion weakened and no
implementation change resulting: (1) the stage-3 fixture keys are public-only,
so disclosure tests generate GnuPG keypairs at runtime (blind_stage3 pattern);
(2) several contract functions return `Result<…>` where the prose printed
bare values — unwrapped in fixtures; (3) a review on a terminal order already
yields its fact, so `record_fact_for_order` afterwards is the idempotent
second call — two tests restructured to assert exactly that; (4) summary
`total_weight` counts scored facts only — fixture includes a review and
asserts the exact 0.18; (5) raw-panel age-days rounding unpinned — asserted
as a range.

**cargo-mutants** (app-package tests as the test command; `TMPDIR=~/tmp-mutants`;
output preserved under `mutants-stage9/`):
- Batch A — reputation + TOTP + keyfile, complete run on the code as first
  built: **224 mutants tested — 123 caught, 84 missed, 17 unviable, 0
  timeouts.** Triage of the 84 missed: the bulk are DB-path and mapping
  mutants whose real coverage lives in the blind suite (a different cargo
  package — cargo-mutants ran the app package's tests only). In response,
  in-crate unit tests were added pinning the pure logic directly: every
  evidence/outcome mapping arm and round-trip, the sale/terminal sets,
  month-index arithmetic across year boundaries, a **known-answer
  buyer-token vector** (computed independently with Python HMAC-SHA256,
  pinning the subkey derivation itself), and base32 bit-edge cases (0xff
  patterns distinguishing OR from XOR accumulation, padding/space skipping
  on decode).
- Batch A2 — re-run after those tests were added: **interrupted by a runtime
  restart ~62 minutes in** (during the last reputation.rs mutants; it never
  reached batch B). Of the mutants it processed in keyfile.rs +
  reputation.rs (81 caught / 41 missed / 7 unviable at interruption), the
  comparison against batch A is unambiguous on the points the new tests
  targeted: **all** evidence-mapping mutants, the outcome round-trip mutants,
  the month-arithmetic mutants, and the **keyfile subkey constant mutants
  were caught**. Two remaining "missed" are provably **equivalent mutants**:
  deleting the `OUT_COMPLETED` arm of `outcome_str` or the `"Completed"` arm
  of `outcome_code` changes nothing, because each function's wildcard arm
  returns the same value (pinned by the round-trip test). The rest of the 41
  are DB-path mutants (maturity bucket internals, the closure accrual guard,
  fact/summary/raw-panel writes) — each is covered by name in blind_stage9
  (maturity cases; idempotency true/false; post-closure no-accrual;
  raw-panel semantics) — plus `Stage9Config::from_env` env-parsing branches
  (defaults themselves are blind-tested) and one decrypt length boundary
  (`<` vs `<=` at exactly nonce+tag length), since pinned by an
  empty-plaintext round-trip unit test, verified by name.
- Batch B (disputes + reviews + moderation) **never completed**: three
  separate attempts were killed by runtime restarts (the VM was replaced
  repeatedly during this stage). Those modules' behaviour is exercised
  directly by 20+ blind_stage9 tests and the full HTTP smoke; the mutants
  gap is recorded here honestly rather than papered over.

**Live smoke** — the real app over HTTP, fresh users through the whole cycle,
**33 checks passed / 0 failed**: register → moderator approves seller →
GnuPG key registered → listing published → payment identity + batch (2
subaddresses) → order 1 (assignment at creation, accept, mark-paid, fulfil,
complete) → review + seller reply on the profile → raw panel shows 1
seller-confirmed payment, **0** verified on-chain, "Not enough history" →
order 2 → dispute → disclosure of a genuinely GnuPG-signed seller message
classified **evidence**, garbage signature classified **unverified claim** →
moderator enrolls TOTP → resolves **seller-at-fault** with a TOTP code →
order Resolved, fact `resolved-seller-at-fault`, panel shows 1 dispute
resolved against the seller → listing report filed → dismissed with TOTP →
moderator closes the seller: listings `paused`, **login refused** with the
closure message, profile banner shows, **review history retained** → buyer
self-closes (same code path) → both closures audited in `moderation_actions`.

**Totals** (counted from the final full run's output, this report's
authority): workspace **445 passed / 0 failed / 9 ignored** (stage-start
baseline 387: +43 blind_stage9, +15 unit tests); seller-helper standalone
**13/13**. One further unit test (keyfile empty-plaintext boundary) was
added after that run and verified by name; a later workspace run reads 488
because a concurrent Stage 10 effort has since landed its own blind suite
(32 tests) and lib tests in this tree — that is not a Stage 9 number and is
not claimed here.

## Environment findings (for Stage 10 and future gates)

- This VM generation has **no nettle headers, no `nettle.pc`/`hogweed.pc`,
  and no libnettle/libhogweed/libgmp dev symlinks** — a from-scratch
  nettle-sys build fails. Working recipe (used for all verification above):
  `PKG_CONFIG_PATH=~/pkgconfig` (hand-written nettle.pc/hogweed.pc pointing
  at dev symlinks in `~/pgsys/lib`) and
  `NETTLE_PREGENERATED_BINDINGS=~/pgsys/nettle-bindings.rs`.
- **Trap, learned the hard way:** never point `NETTLE_PREGENERATED_BINDINGS`
  at a file inside `target/debug/build/`. When the building unit's OUT_DIR
  is that same file, nettle-sys's `fs::copy` self-copies and **truncates it
  to zero bytes** (this destroyed one cached bindings copy during Stage 9;
  three intact copies survived and one now lives safely at
  `~/pgsys/nettle-bindings.rs`). This, not feature reduction, is the likely
  root cause of the older "incomplete bindings file" failures.
- Direct `nettle` dependency (for the key-file AEAD) added to the app crate
  at 7.5.0 with `hmac` 0.12.1 / `sha1` 0.10.7 — all already present in the
  locked dependency tree; no other dependency changes.
- The runtime restarted twice during this stage, wiping /tmp (PostgreSQL
  included) both times; the database was re-provisioned from the persisted
  zonky binaries and migrations 0001–0009 re-applied (32 tables). There is no
  `psql` on this generation; a scratch sqlx runner was used for DDL.

## Honest deferrals

- **Disclosure deletion at resolution + 180 days is a Stage 10 job.** The
  retention period is displayed before disclosure now; nothing deletes yet.
- **Listing remove/restore has no no-JS form on the queue page yet** — the
  endpoints are routed, TOTP-gated, and covered at library level by the blind
  suite, but the queue UI only links accounts/disputes/reports. Stage 10
  UI polish.
- Facts reconciliation is trigger-based (startup / profile render / review /
  dispute finalize), not transactional with order termination — the same
  pattern as the payments expiry sweep; a general scheduler is Stage 10.
- cargo-mutants batch B (disputes/reviews/moderation) could not be completed
  — three attempts were killed by runtime restarts; batch A/A2 results and
  triage are in the gate section above.

## What the owner still owes

1. **Operator legal review before ANY public instance** (standing, unchanged).
2. **GPG usability test** with a real user (open from the missing-questions
   register; dispute disclosures depend on users producing detached
   signatures locally).
3. Stage 10 carries: retention jobs (incl. disclosure deletion), the
   operations manual (incl. the key-file backup procedure above), deployment
   profiles, signed releases / reproducible builds, and — per the 2026-10-16
   decision — the hosted demo with the §15 layout pass for owner review.
4. Direct Payments v1 leftovers (unchanged): confirm handoff settings values
   for mainnet, publish seller-helper checksums, re-run address/signature
   tests on the FCMP++ fork build.
