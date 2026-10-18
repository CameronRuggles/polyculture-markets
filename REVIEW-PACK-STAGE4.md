# Review Pack — Marketplace Spec v2, Stage 4 (orders, terms files, inbox)

**How to use:** paste whole into Claude Opus. This is the §22 stage-gate
review for Stage 4, produced in the 2026-10-14 gate run (the stage was
first built as a working draft; this pack accompanies its gate —
GATE4-REPORT.md has the full evidence). Cameron (owner) makes final
calls; your job is verdicts with file:line evidence.

## Instructions to the reviewer

1. For each invariant listed, give: HOLDS / VIOLATED / CANNOT-TELL, with
   the file and line you relied on. Abstract concern without a mechanism
   doesn't count; name who does what to whom.
2. The code is at `marketplace/crates/app/src/orders.rs` (the only
   writer of `orders.state`), `marketplace/crates/domain/src/lib.rs`
   (`order_can_transition`, `invoice_can_transition`), and
   `marketplace/crates/app/src/authz.rs` (route table). The spec is
   "Privacy-First Noncustodial Marketplace — Spec v2" (§9, §10, §15,
   §17) plus `SPEC-V2-AMENDMENTS.md` and the canonical contract
   `marketplace/docs/api-contract.md` (§10 state machines, §11 the
   Stage 4 surface). If you cannot see the files, say so and review
   against the claims and evidence summarized here instead — flag that
   limitation.
3. End with: (a) any test the locked suite must add for Stage 4, stated
   as plain-language assertions; (b) anything that must be fixed before
   Stage 5 builds on this code.

## What was built (claims to check)

Order creation accepts only published listings, refuses self-orders,
checks quantity bounds, computes the total with checked u64 arithmetic,
pins the seller's current key fingerprint into the order (a seller with
no current identity key cannot be ordered from), and builds the §10
terms file exactly once: canonical `marketplace-terms-v1` header, one
blank line, Title / Description / Delivery terms / Refund terms
sections, UTF-8 NFC with LF endings. The exact bytes and their SHA-256
are stored at creation and never regenerated — later listing edits do
not touch an existing order's terms, and the terms download serves the
stored bytes. Creation is idempotent per (buyer, idempotency key): a
resubmission returns the original order and creates nothing. Accounts
younger than 24 hours may hold at most 3 orders (§7). Every state
change goes through the domain transition table with the actor derived
from the caller's relation to the order; a non-participant is refused
for every action; `accept` additionally requires an issued invoice and
is refused with that specific reason until the payment stages land;
dispute from AwaitingPayment enforces §9's guard — a buyer report must
exist (domain table: evidence must be BuyerReported) and be 72 hours
old with no seller response (app layer, claim timestamps). A buyer's
report alone can never move an order to Paid: the Paid transition is
Core-only and requires SellerAttested, ProofVerified, or
WalletObserved. Order and terms pages are participant-only — everyone
else gets an outcome indistinguishable from a nonexistent order.
Notifications record only event type, object reference, and time,
notify the counterparty (never the actor) on requested / declined /
cancelled / fulfilled / completed / dispute-opened, and back the §15
inbox (newest first, read markers) and the unread attention count.
`GET /orders` is a declared route (owner amendment 2026-10-14):
login-required, and the handler lists only the caller's own orders.

## Invariants for the reviewer to judge (post-gate)

1. `orders.state` has exactly one writer (orders.rs), and every write
   is preceded by a successful `order_can_transition` check against
   the caller's derived actor and the order's recorded evidence level.
2. The domain table matches spec §9's table cell-for-cell, including
   the evidence guards: Paid needs Core + ≥ SellerAttested;
   AwaitingPayment→Cancelled needs evidence None;
   AwaitingPayment→Disputed needs Buyer + BuyerReported.
3. Terms bytes are written once at creation; no code path rebuilds,
   re-normalizes, or re-hashes them afterwards; the served download is
   the stored bytes.
4. Idempotency cannot be raced into a second order (unique constraint
   + replay-returns-original), and a different buyer reusing the same
   key string is independent.
5. The pinned seller fingerprint is the seller's key that was current
   at creation time, and later key rotation does not move it.
6. The new-account limit counts what §7 says it counts, and the check
   cannot be bypassed by idempotent replay or by ordering as seller.
7. Non-participant access to an order page or its terms is
   indistinguishable from a nonexistent order (web layer).
8. Notifications leak nothing beyond event type, object reference, and
   time — no amounts, no message content, no counterparty identifiers
   beyond the reference the recipient is entitled to resolve.
9. Nothing in Stage 4 lets an order progress past Requested in the
   running app until invoices exist (Stages 6–7), and auto-complete
   (14 days post-fulfilment) is absent — it is Stage 10's, not silently
   present here.

## Gate evidence (summary; full detail in GATE4-REPORT.md)

- Blind suite `marketplace/tests/security/blind_stage4.rs` (64 tests,
  authored from the spec + amendments + API contract only — the author
  never saw the implementation or STAGE4-REPORT.md): **58 passed,
  0 failed, 6 ignored**, the ignores being the author's own
  DERIVATION-UNCERTAIN marks where the documents genuinely do not
  determine a behaviour (exact 24-hour boundary; seller-side counting
  under the §7 limit; the 72-hour guard's satisfied path; core
  auto-complete through `apply_action`; non-participant
  indistinguishability at the printed surface; exact terms
  section-label bytes).
- The suite's first run failed 4 tests; all four were fixed in code,
  none in assertions: (1) the domain Disputed row ignored the evidence
  parameter — it now requires BuyerReported, matching §9's guard;
  (2)+(3) `authorize()` denied `GET /orders` for everyone — the route
  is now declared per the owner's §17 amendment (2026-10-14), and the
  Stage 1 locked suite's single superseded undeclared-row was updated
  under that ruling with the change recorded in both files and in
  GATE4-REPORT.md; (4) order `created_at` was rendered
  `YYYY-MM-DD HH24:MI` — it is now the canonical RFC 3339 UTC form the
  contract prints.
- Full workspace after the gate: **200 tests passed, 0 failed,
  6 ignored** (blind stages 1–4: 41 / 38 / 34 / 58+6 ignored).
- cargo-mutants on the Stage 4 paths (outputs in `mutants-runs/
  stage4-domain/` and `mutants-runs/stage4-app/`): domain transition
  tables 29 mutants — 9 caught by unit tests, the other 20
  hand-verified killed by the blind suite; **0 survivors**. App order
  paths (`create_order` + `apply_action` logic mutants) 36 — 29
  killed by the blind suite, **7 accepted survivors**, all triaged in
  GATE4-REPORT §5: six change only a notification's event-type label
  (the literal strings are not pinned by any document, so no blind
  assertion could name them), and one inverts the 72-hour dispute
  guard in a way the domain table's evidence rule masks in every
  state the current surface can construct (flagged as a Stage 6/7
  test obligation, not a code defect — the shipped guard is correct).
- Crypto backend guard PASS (Q8, Nettle everywhere).
- Rider closed in this gate: the Stage 2 description bound was
  ratified by the owner at 20,000 characters (pinned in the
  amendments); the Stage 2 blind oversize test was activated unchanged
  and passes (see REVIEW-PACK-STAGE2.md rider note).

## Open items handed to the owner (in GATE4-REPORT.md)

- Spec §10 lists a "selected options" terms section; listings in v2
  carry no selectable options and the built terms file has four
  sections. Owner call: amend §10 for option-less listings, or require
  an explicit (empty) section.
- The six DERIVATION-UNCERTAIN items above — each is a place the spec
  could say one more sentence.
- `inbox()` renders notification times in the same non-canonical
  `YYYY-MM-DD HH24:MI` form the gate fixed for orders; §15 does not pin
  the format, so it was noted, not changed.
