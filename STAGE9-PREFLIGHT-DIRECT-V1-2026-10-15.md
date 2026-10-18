# Stage 9 — Pre-flight brief (reviews, reputation, disputes, moderation)
## Re-mapped against Direct Payments v1

Prepared 2026-10-15 (background research, after Cameron approved the
Direct Payments v1 plan and the build started). Nothing here is a
decision, a ratification, or a build start. Stage 9 does not begin
until the Direct Payments v1 build passes its §22 gate, per the
standing gate pace. This brief exists so Stage 9 is not later built
on the pre-Direct-Payments payment assumptions by accident — the same
job the Stage 6/7 pre-flights did for invoices and pools.

## Scope (spec §24 stage 9, §13)

Reviews, reputation modules (`weighted-reviews-v1`, `raw-counts`),
disputes, disclosures, moderation, reports. Spec sources:
`Privacy-First_Noncustodial_Marketplace___Spec_v2_0_4b7b.md` §13,
§24; mapping source: `DIRECT-PAYMENTS-V1-PLAN.md` dispositions 1–6.

## What Direct Payments v1 changes for Stage 9

1. **There is no "verified payment" in v1.** The plan is explicit:
   no tx-proof, no server-side node/wallet; the seller marks Paid via
   the existing `SellerAttestation` claim (amount `None`), and the UI
   must say "seller confirmed payment", never "verified".
   Collisions in spec §13:
   - The raw-facts panel lists "orders with verified payment" — under
     v1 that count is permanently zero and the line would mislead.
     Stage 9 must drop or rename it (e.g. "orders seller-confirmed
     paid") before the panel ships.
   - The review badge "payment verified on-chain" (ProofVerified /
     WalletObserved only) simply never appears in v1. Harmless, but
     the Stage 9 test fixtures must not expect it.
   - The evidence weighting survives intact: `weighted-reviews-v1`
     already prices SellerAttested at 0.6 (vs 1.0 for verified). In
     v1 every reputational fact carries that level, so maturity and
     repeat-weighting do all the differentiating work. No formula
     change is forced; the fact schema already carries evidence level.

2. **The moderator-visible order record has no invoice in it.** Spec
   §13 gives moderators "terms, invoice, statements, and evidence
   findings" automatically. Under Direct Payments v1 there is no
   invoice and no PGP pool statement in the payment path (plan
   disposition 1: PGP stays for rotation/terms only). The v1 record
   is: terms file, the assigned subaddress with its wallet-signed
   one-line message + signature, and the seller's attestation. Stage 9
   disclosure/evidence views must be specified against that record,
   not the §13 list.

3. **History continuity is now settled in Stage 9's favour.** Cameron
   approved the plan's disposition-4 softening (2026-10-15): a primary
   address change banners and retires the pool but does NOT erase
   order/review history. Reputation facts and dispute evidence
   therefore survive a payment-identity change, which is what the
   §13 fact model assumes. No Stage 9 work needed here — recorded so
   the handoff's original "visible history reset" wording is not
   revived by accident.

4. **Refund flow is a sequencing gap.** Spec §12/§13 assume a
   "refund sent" seller report and a "refund received" buyer
   confirmation, and dispute outcomes include `refund-confirmed`.
   The Direct Payments v1 build order (plan steps 1–7) contains no
   refund report/confirmation. Either it lands as a small addition
   before Stage 9, or Stage 9's refund-confirmed outcome has nothing
   to attach to. Flagged, not decided.

5. **The trust-score question is still open — do not pre-decide it.**
   The parked encrypted-orders reviews argued against any positive
   trust score / "verified sales" label (Stage 6 pre-flight R12),
   while spec §13's default module is a weighted headline score.
   That review line was never ratified (and the pre-flight's R1–R15
   numbering collides with the review's R1–R11 — see the hazard note
   in memory 2026-10-14; use RATIFICATION-RECONCILIATION-2026-10-14.md
   if this reopens). Cameron also killed the encrypted-orders design
   itself (plan disposition 6), so which of its review conclusions
   carry into Stage 9 is his call at the Stage 9 gate, not something
   this brief settles.

## What survives unchanged

- Reputation facts: one minimized fact per terminal order (seller id,
  buyer token HMAC, maturity bucket, evidence level, outcome, month).
- Reviews: one per order, buyer only, after Completed/Resolved,
  1–5 + ≤1,000 chars, 7-day edit window, one public seller reply.
- Disputes: open from the §9 states; private messages reach
  moderators only via voluntary disclosure; only validly signed
  disclosed messages count as evidence, the rest render as
  "unverified claim". Stage 5's ciphertext messaging + sign-then-
  encrypt guide already supply this.
- Moderation: reports + queue for listings/profiles/reviews;
  moderators warn/suspend/remove, never touch funds, and never get a
  conversation-browsing interface.

## Remaining-stage map after the Direct Payments build

The build folds in the Stage 6 invoice flow's replacement (payment
page at order creation), Stage 7's pool, and Stage 8's attestation
(tx-proof deferred indefinitely). If it passes its gate, the MVP
remainder is exactly: **Stage 9 (this brief) and Stage 10**
(retention jobs, deployment profiles, backups, ops docs — note the
48h unpaid-order expiry sweep lands in minimal form in this build;
the general scheduler remains Stage 10).
