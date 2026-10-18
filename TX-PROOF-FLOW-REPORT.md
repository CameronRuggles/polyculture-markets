# Tx-Proof Flow — Completion Report (2026-10-18)

**Scope built:** audit fix-brief **task 1, expanded** per the owner's
2026-10-18 tx-proof decision, plus **task 4 (closed states only)**,
plus owner **design updates #1 and #2** (steered into this build after
work started; they override the original brief where they conflict).
Fix-brief tasks 2 and 3 were not touched. Server-side proof
verification was NOT implemented and remains OFF. Address-assignment
timing was not changed (audit Q1 still the owner's).

**Result: complete.** Workspace **515 passed / 0 failed / 9 ignored**
(baseline 494/0/9; +20 new flow tests, +1 new domain unit test),
seller-helper **17/17**, blind_direct_v1 **42/42 untouched**,
blind_stage9 43/43, blind_stage10 32/32, blind_stage4 58 passed /
6 ignored (unchanged). **Locked-test conflicts: none** (see §6).

---

## 1. Chosen state mechanics, and why

The flow plugs into the existing evidence-level machinery instead of
inventing a parallel one:

- **New domain evidence level `BuyerProofSubmitted`**, ordered
  `None < BuyerReported < BuyerProofSubmitted < SellerAttested <
  ProofVerified < WalletObserved`. The domain's money-critical row
  `(AwaitingPayment → Paid)` — *Core only* — now also accepts
  `BuyerProofSubmitted`. Invariant 11 is preserved in substance and
  its wording updated: a buyer's **bare report never** marks Paid;
  a buyer-submitted **tx proof** (evidence attached to the claim,
  carried unverified) does, per the owner decision. The
  `(AwaitingPayment → Disputed)` row accepts `BuyerReported |
  BuyerProofSubmitted`.
- **Submission** (`payments::submit_payment_proof`, mirroring
  `mark_paid`'s shape: actor check → module-level validation → domain
  table check → one transaction): buyer-only; assignment required;
  txid trimmed + lowercased, must be exactly 64 hex chars; proof
  trimmed of outer whitespace, non-empty, ≤ 16,384 chars, otherwise
  stored **verbatim and never verified**. From `Requested` /
  `AwaitingPayment` the core advances the order to Paid in the same
  transaction (`evidence_level = 'BuyerProofSubmitted'`, guarded so
  it can only rise from `None`/`BuyerReported`). In `Paid` /
  `Fulfilled` the proof is recorded alongside and the state is left
  untouched (late submission; evidence never downgrades — an
  attestation stays `SellerAttested`). In `Disputed` or any terminal
  state, submission is refused (`OrderClosed`): a disputed order's
  proof is necessarily already on file.
- **The report is the gate.** Dispute guard in `orders::apply_action`:
  for orders **with an assignment**, the gate is now "a row exists in
  `payment_reports`" — no invoice, no 72-hour wait. Orders **without**
  an assignment keep the §9 invoice-tied guard byte-identical (the
  invoice flow and its locked suites are untouched). A seller
  cancel/decline is refused whenever any report exists (the domain
  table already refused seller-cancel from AwaitingPayment once
  evidence has risen; an explicit guard in `apply_action` also covers
  decline from Requested, where the table has no evidence condition).
- **Sweep.** `expire_unpaid_orders` gained one clause:
  `NOT EXISTS (payment_proofs …)`. Proof-submitted orders are never
  eaten. A *manual* report alone does **not** exempt an order —
  design update #2.4 coordinates the sweep and the seller declaration
  to agree on this (§3).
- **Notifications.** The advancing submission notifies the **buyer**
  `order_paid` — the identical event an attestation produces. The
  seller receives nothing (see the visibility rule, §4).
- **Reputation.** `evidence_u8("BuyerProofSubmitted") = EV_BUYER_REPORTED`:
  buyer-side evidence class, never an attested/verified weight class.

## 2. Migration shape (0010_payment_proofs.sql)

`payment_evidence` cannot hold any of this (its `invoice_id` is NOT
NULL; direct orders have no invoices — the same constraint that put
attestations in their own table in 0008). Five additive tables:

| Table | Shape | Purpose |
|---|---|---|
| `payment_proofs` | `id`, `order_id UNIQUE → orders`, `pool_entry_id → payment_pool_entries`, `submitted_by → accounts`, `txid TEXT`, `proof TEXT`, `created_at`, `updated_at` | One row per order; `created_at` = FIRST submission (the report timestamp), `updated_at` = latest revision. |
| `payment_reports` | `order_id PK → orders`, `submitted_by`, `kind` (`'proof'`\|`'manual'`), `created_at`, `updated_at` | The report index the dispute gate keys on; kind upgrades manual→proof, never down. |
| `payment_declarations` | `id`, `order_id UNIQUE`, `pool_entry_id`, `declared_by`, `created_at` | Seller not-received declarations; one per order, bound to the subaddress via the entry. |
| `payment_review_flags` | `id`, `order_id`, `kind` (`'proof-unconfirmed'`\|`'proof-contradiction'`), `state` (`open`\|`cleared`\|`resolved`\|`dismissed`), `created_at`, `closed_at` + partial unique index on `(order_id, kind) WHERE state='open'` | Auto-review flags in the Stage 9 moderation queue. |

Applied to the dev DB (see §7 for the environment note).

## 3. Owner design update #2 — mechanics as implemented

1. **Per-order, subaddress-bound confirmation**
   (`payments::confirm_payment`). From `AwaitingPayment` it *is*
   `mark_paid` (the v1 attestation). On an order already Paid on a
   proof it records the same `payment_attestations` row (bound to the
   order's own pool entry), raises evidence to `SellerAttested`, and
   clears the flag in (3a). On an already-attested order it is an
   idempotent no-op. The order-page button reads "Confirm payment
   received for order {public_id} — subaddress {address}". There is
   no bulk or account-level attestation path anywhere in the code.
2. **Manual fallback** (`payments::submit_manual_report`). Buyer-only,
   `Requested`/`AwaitingPayment` only. Writes a `payment_reports`
   row of kind `manual` and raises evidence `None → BuyerReported`
   only. The order does **not** advance. The order-page proof panel
   leads with the proof form and the wallet how-to (Feather: History
   → right-click → Create Tx Proof → "Prove payment to an address" →
   Get formatted proof; Monero GUI: History → the "P" button; CLI:
   `get_tx_proof`); the manual confirm sits in a collapsed section
   worded as the weaker protection, with the concrete differences
   spelled out. *Note (as briefed): Cake Wallet / Monerujo one-tap
   proof export could not be confirmed — the how-to covers only the
   confirmed wallets and invents no steps for Cake.*
3. **Auto-review flags** (`payment_review_flags`, surfaced in the
   Stage 9 queue at `/moderation` + a moderator-only flag page at
   `/moderation/flags/{id}` showing the proof; resolve/dismiss uses
   the existing TOTP-gated moderator action pattern and logs a
   `moderation_actions` row):
   - (a) raised inside the submission transaction when a proof lands
     and **no attestation exists** for the order; cleared automatically
     by `confirm_payment` (state `cleared`, row retained).
   - (b) raised inside the declaration transaction when a proof exists
     and the seller declares not-received; moderator-resolved only.
4. **Not-received declaration** (`payments::declare_not_received`).
   Seller-only, one per order, refused before the unpaid-expiry
   horizon (`DeclarationTooEarly`, 48 h by the existing config).
   - Proof on file → declaration recorded + flag (3b); the order does
     **not** close (returns `Paid`).
   - No proof, order `Requested`/`AwaitingPayment` → closes as unpaid:
     `Cancelled` + `terminal_at`, entry retired, buyer notified
     `order_not_received`, declaration on the record — the same end
     state the sweep produces.
   - Manual report on file → closure still happens (the report does
     not block it), the report stays on the record, and the buyer
     keeps their dispute path against the declaration:
     `apply_action("dispute")` on such an order (Cancelled + a
     declaration + a manual report ⇒ `payments::declaration_dispute_reopenable`)
     reopens it as `Disputed` with its dispute row, as a core action —
     the same way the sweep performs core cancellations without
     consulting the user-facing table. Every other Cancelled order
     still hits the table and is denied, exactly as before.
   - Attested-Paid or post-shipment states → refused (`OrderClosed`):
     a seller cannot declare non-receipt against their own
     attestation; the dispute path is the remedy.

## 4. The visibility rule (owner-directed design point, update #1)

The proof, the txid, and the source of the Paid state are visible
**only** to the submitting buyer (order page: their own proof block)
and to moderators (dispute view proof block; flag page). Enforcement
is structural, not presentational:

- `order_page` fetches the proof row **only in the buyer branch**;
  the seller's render never receives the data. Seller-facing evidence
  text comes from `seller_evidence_label`, which maps
  `BuyerProofSubmitted → "Seller confirmed payment"` — the identical
  line an attestation produces. The same split applies in
  `dispute_page` (seller party: blind label, `buyer_proof: None`;
  buyer party and moderators: real label + proof).
- No notification type reveals a submission: the only notification
  is the buyer's own `order_paid`; message strings in redirects are
  worded identically regardless of proof existence (e.g., the
  declaration's "Declaration recorded." either way).
- The seller's confirm affordance renders for **every** Paid direct
  order (attested ones included, where it is an idempotent no-op), so
  its presence cannot signal a proof either.
- Rationale (owner's): a seller who can see which buyers submitted
  proofs can selectively scam the unprotected ones; late
  submittability (§1) means protection status is never observable in
  advance.

## 5. Test evidence (test-first)

New suite: `marketplace/crates/app/tests/tx_proof_flow.rs` (20 tests),
plus one domain unit test. Observed sequence:

1. **Pre-implementation run:** compile failure — 10 unresolved
   imports (the new `payments::` API) + 5 missing `PaymentError`
   variants. The failing state the tests were written against.
2. **After the function layer** (domain + payments + orders +
   reputation): 14 passed / 6 failed — the 5 web tests failing on
   missing routes/forms/labels, + 1 failure that was a wrong
   assumption in my own new test (see note below).
3. **After the web layer:** 20/20. Full workspace then 515/0/9.

Per-requirement mapping (test → requirement):

| Test | Covers |
|---|---|
| `proof_submission_marks_paid_survives_sweep_and_opens_dispute` | Brief acceptance test: dispute denied pre-report; submission → Paid/`BuyerProofSubmitted`, byte-exact stored proof; report exists; buyer `order_paid` parity + **zero proof-revealing seller notifications**; backdated 72 h + sweep → still Paid; dispute opens with row. |
| `proof_from_requested_advances_and_seller_cannot_cancel_or_decline` | Submission from Requested advances; seller cancel + decline refused; attestation-paid parity. |
| `unreported_direct_order_cannot_dispute_and_still_expires` | No report ⇒ no dispute; sweep still cancels at 49 h. |
| `late_proof_submission_records_without_disturbing_state` | Late submission after attestation and after fulfilment; evidence never downgrades; dispute works. |
| `proof_submission_rejects_non_buyer_bad_input_and_closed_orders` | `NotBuyer` (seller/stranger), `BadTxid` (short/non-hex), `BadProof` (blank), `OrderClosed` (buyer-cancelled). |
| `proof_resubmission_revises_evidence_and_keeps_first_timestamp` | Revision replaces txid/proof, `created_at` stands, exactly 1 row. |
| `buyer_submits_proof_over_http_and_order_turns_paid` | Order page offers `submit-proof`; POST → 303; order Paid/`BuyerProofSubmitted`. |
| `pay_page_closed_states_show_no_address_and_qr_404s` | Task 4: AwaitingPayment control unchanged (address + "Pay exactly" + QR 200); Cancelled/Declined/Completed pages show "This order is closed. Do not pay.", no address, no "Pay exactly"; QR 404. |
| `proof_visibility_seller_blind_buyer_and_moderator_see` | Update #1 test: seller order view = "Seller confirmed payment" for BOTH Paid paths, none of txid/proof/`BuyerProofSubmitted`/"payment proof"; buyer view shows txid + proof + "unverified"; moderator dispute view shows txid + proof; seller dispute view shows none. |
| `seller_confirmation_binds_order_and_subaddress` | #2.1: attestation row's `pool_entry_id` = order 1's entry; order 2 untouched until confirmed separately; `NotSeller`; idempotent re-confirm. |
| `manual_report_records_buyer_reported_and_opens_dispute` | #2.2: evidence `BuyerReported` (not the proof level), state stays AwaitingPayment, report kind `manual`, no proof stored, dispute opens, `NotBuyer` for seller. |
| `manual_report_does_not_block_sweep` | #2.4 coordination: manual report + 49 h + sweep → Cancelled. |
| `flag_raised_on_proof_and_cleared_on_confirmation` | #2.3a: flag `proof-unconfirmed` open at submission + present in `open_payment_flags`; after `confirm_payment`: attestation written, evidence `SellerAttested`, flag `cleared`, gone from the open queue. |
| `declaration_refused_before_48h` | #2.4: `NotSeller` for buyer; `DeclarationTooEarly`; no row written. |
| `declaration_closes_unproofed_order_after_48h` | #2.4: → Cancelled, entry `retired`, declaration row present, buyer notified `order_not_received`, second declaration `AlreadyDeclared`. |
| `declaration_with_manual_report_closes_and_buyer_can_dispute` | #2.4: closes despite the manual report; report remains; buyer dispute reopens as Disputed with an open dispute row. |
| `declaration_with_proof_flags_contradiction_and_does_not_close` | #2.3b + #2.4: declaration on a proof-paid order → stays Paid, `proof-contradiction` flag open. |
| `declaration_on_attested_paid_order_refused` | `OrderClosed` when the seller already attested. |
| `confirm_and_manual_ui_over_http` | Seller page: "Confirm payment received" naming the order's public id **and** its subaddress. Buyer page: `submit-proof` form, `get_tx_proof`, "Feather", `manual-report`, "weaker". Manual report over HTTP → 303 + `BuyerReported`; confirm over HTTP → 303 + Paid. |
| `moderation_queue_lists_flag_and_flag_page_shows_proof` | Queue lists the flag's order; moderator flag page shows txid + proof; seller gets non-200 on the flag page. |
| domain `buyer_proof_submission_reaches_paid_via_core_only` | `(AwaitingPayment→Paid, Core, BuyerProofSubmitted)` allowed; Buyer/Seller actors refused; dispute row accepts the level; ordering below SellerAttested. Existing `buyer_report_never_reaches_paid` unchanged and passing. |

**Two corrections to my own new tests during the build** (test-authoring
errors, fixed before first pass; no production behavior was bent and
no existing test was touched): (i) the declaration test asserted
`assignment_for_order(...)` is `None` after closure — that API returns
the order's entry regardless of state by design (the pay page relies
on it); the assertion now checks the entry's state is `retired`, which
is the actual sweep-parity property. (ii) The visibility test asserted
the seller sees "Paid" on an order the fixture had already driven to
Disputed; it now asserts the actual state label ("Disputed").

## 6. Locked-test conflicts

**None.** No locked/blind test was edited; `git status` shows no
modification under `marketplace/tests/security/` (only untracked
runtime media PNGs from test runs). Two near-misses were checked
explicitly:

- `blind_direct_v1::hard_rule_migration_0008_stores_no_txids_keys_or_amounts`
  scans **migration 0008's DDL only** for `txid`/`payment_proof`/etc.
  Migration 0010 is a separate file and outside its pin; the v1 rule it
  guards is amended for the new path by the owner's decision (and
  SPEC-V2-AMENDMENTS now records that). Suite: 42/42.
- Task 7's earlier partial conflict (`blind_direct_v1` assumption A7)
  is unaffected — nothing here changes batch-signature handling.
- `blind_stage4`'s 72-hour dispute guard and `blind_stage9`'s dispute
  fixtures exercise **assignment-less** orders; the reworked guard
  scopes to assignment-carrying orders, so their behavior is
  byte-identical (stage4 58/6 ignored, stage9 43/43, as at baseline).

## 7. Environment note (not a product change)

The dev PostgreSQL had died with a /tmp wipe before this build's test
phase: the user-space Zonky server was re-provisioned from `~/pgsys`
(binaries copied to /tmp/pgsys, fresh data dir, trust auth, port
5432) and migrations 0001–0010 were applied to a fresh
`marketplace_dev`. Dev-DB contents are disposable fixture state; no
production data was involved. There is no psql client on this VM
generation; migrations were applied through a minimal wire-protocol
client, one file per implicit transaction, all-or-nothing per file.

## 8. Residual limitation (documented, not improvised beyond scope)

Protection begins at submission. A seller cancel landing **before**
the buyer's first submission — or the sweep firing in the window
between payment and submission on an already-stale order — can still
close a paid-but-unreported order (the buyer cancelled/seller
cancelled paths are pre-existing; the sweep needs the order to be
48 h stale *and* unreported). The design mitigates this by making
submission possible at any moment while the order is open and
invisible when used; a revive-on-proof window for orders closed
unreported (audit Q3) remains a possible owner follow-up, not built
here.

## 9. Deliberately not done

- Fix-brief tasks 2 and 3 (out of scope).
- Server-side signature/proof verification (stays OFF; audit Q2 is
  the owner's separate decision).
- Mandatory proof submission (owner's floated override): the build
  implements invisible + late-submittable as steered; making it
  mandatory is a policy switch on top of this, not built.
- Commits are on `main` locally; **not pushed**.
