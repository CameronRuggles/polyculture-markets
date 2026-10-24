# Audit 2 H1 — owner-decision amendment record — 2026-10-23

Repo: `~/workspace/monero-marketplace-v2`, branch `audit2-h1-proof-hold`.
Base commit: `c1950f3` (origin/main; PR #2 merge). **Local commits
only; nothing pushed, no PR.**

Source finding: Code Audit 2 (2026-10-23), §"Critical & high
findings", **H1 — An unverified buyer proof reaches `Paid` and is
labelled "Seller confirmed payment" to the seller**, and fix-list
row 1. The audit left one question open ("Decide whether buyer
proof should reach `Paid` at all before seller confirmation"). The
owner ruled on it the same day; this record is the authorization
for every test amendment in the batch, following the BL1
amendment pattern (2026-10-19).

## The ruling (owner, 2026-10-23)

> A buyer's unverified proof no longer advances the order to Paid.
> The order holds at AwaitingPayment, the seller's Confirm-payment
> prompt is the universal prompt on every unpaid order, "Paid" and
> "Seller confirmed payment" print ONLY on SellerAttested, and the
> proof stays on file, seller-invisible, and speaks only in
> disputes.

In full:

- `submit_payment_proof` records the proof and raises the existing
  `proof-unconfirmed` moderator flag, but performs **no state
  transition to Paid**. The order remains `AwaitingPayment` (from
  `Requested` it may still move to `AwaitingPayment`, exactly as a
  normal order does — no further).
- The seller's wallet-check + "Confirm payment?" prompt is the
  universal prompt on **every** unpaid order. No badge, banner,
  state, notification, or wording may distinguish a proof-submitted
  order from any other `AwaitingPayment` order on any
  seller-visible surface.
- `Paid` and the words **"Seller confirmed payment"** may render
  **only** when a `SellerAttested` exists.
- Buyer-side: the buyer still sees their honest "(unverified)"
  evidence label, and buyer copy must make clear a proof does not
  mark the order paid; the seller confirms from their wallet; the
  proof is on file for disputes and invisible to the seller.
- Payment-risks copy (and Limitations, where it repeats the claim)
  is corrected to describe this truthfully.

## What this supersedes

1. **The proof-advance element of the owner decisions of
   2026-10-18** (tx-proof flow): `submit_payment_proof` advancing
   `Requested → AwaitingPayment → Paid` on the
   `BuyerProofSubmitted` evidence level, the buyer `order_paid`
   notification it sent on that advance, and the domain-crate
   comment (crates/domain/src/lib.rs) describing
   `BuyerProofSubmitted` as able to move an order to Paid as
   exercised policy. The pure transition table itself is **not**
   amended: the capability remains in the table, and after this
   batch no production path exercises the
   `BuyerProofSubmitted → Paid` leg.
2. **`seller_evidence_label`** (crates/app/src/web.rs) mapping
   `"BuyerProofSubmitted" => "Seller confirmed payment"`.
3. **The vouching copy**: `templates/payment_risks.html` ("When an
   order says *seller confirmed payment*, the seller marked it
   paid after seeing funds in their own wallet" — untrue on the
   proof path), the parallel claim in `templates/limitations.html`
   §"Payments are attested, not verified", and the buyer-facing
   sentence in `templates/order.html` ("Submitting it marks the
   order paid on that evidence").
4. **The test pins of the superseded behaviour**, all in
   `marketplace/crates/app/tests/tx_proof_flow.rs`, amended under
   this record and named individually in the fix report with
   pre/post manifest hashes:
   - `proof_submission_marks_paid_survives_sweep_and_opens_dispute`
     (renamed; advance + buyer `order_paid` assertions),
   - `proof_from_requested_advances_and_seller_cannot_cancel_or_decline`
     (renamed; `Paid` expectation),
   - `buyer_submits_proof_over_http_and_order_turns_paid`
     (renamed; `Paid` expectation),
   - `proof_visibility_seller_blind_buyer_and_moderator_see`
     (the seller label-parity assertion),
   - `flag_raised_on_proof_and_cleared_on_confirmation`
     (confirmation now runs from `AwaitingPayment`),
   - `declaration_with_proof_flags_contradiction_and_does_not_close`
     (the order now sits at `AwaitingPayment`, not `Paid`).

## What is preserved, unchanged (owner decision 2026-10-18)

- **Proof status is invisible to the seller** (the
  selective-scamming rule). This ruling strengthens it: the state
  itself no longer moves, so there is nothing left to mask.
- A proof remains submittable **at any point while the order is
  open**, including after attestation and after fulfilment; late
  submission records alongside and never downgrades evidence.
- A proof-submitted order is **never eaten by the expiry sweep**
  (the sweep's `payment_proofs` exemption is untouched).
- Once a report is on file the seller cannot cancel or decline the
  order unilaterally; the buyer's dispute gate keys on the report.
- Only moderators see proofs, inside disputes and the flag queue;
  the `proof-unconfirmed` flag lifecycle (raise on submission,
  clear on seller confirmation) is kept.

## Consequential adjustments named in advance

- **`mark_paid` clears `proof-unconfirmed` flags.** The flag's
  clearing previously happened in `confirm_payment`'s
  already-Paid branch; seller attestation now normally arrives
  through `mark_paid` from `AwaitingPayment`, and an attestation
  settles the flag exactly as before (design update #2.3a).
- **`declare_not_received` with a proof on file now also covers
  `AwaitingPayment`.** Design update #2.4's intent — with a proof
  on file the declaration records the statement and raises the
  `proof-contradiction` flag; the order does **not** close — was
  written when proof orders were always `Paid`. Proof orders now
  sit at `AwaitingPayment`, so the guard follows the intent, not
  the old state name.
- **Legacy rows.** An order already `Paid` on
  `BuyerProofSubmitted` in existing data keeps its state, but no
  seller-visible surface may print a confirmation claim for it:
  `seller_evidence_label` uses the neutral wording
  "Payment recorded" for that legacy Paid lineage, and the pay
  page's "Seller confirmed payment." line renders only for
  `SellerAttested`. `confirm_payment`'s already-Paid branch
  (attestation recorded alongside a proof-paid order) is retained
  for exactly those rows.
