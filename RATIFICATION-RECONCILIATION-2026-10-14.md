# Ratification reconciliation — encrypted orders (prepared 2026-10-14, background)

Purpose: make Cameron's ratification pass safe. Two documents that will be
in front of him use **conflicting R-numbers**, and the plan file still
contains **superseded text from before his rulings this afternoon**.
Nothing here is a decision. Cameron ratifies; this sheet only lines the
paperwork up so a "ratify all" cannot accidentally lock in a version he
already replaced.

Checked against the files on disk at ~13:30 MDT, 2026-10-14:
`ENCRYPTED-ORDERS-PLAN-2026-10-14.md`, `STAGE6-PREFLIGHT.md`,
`encrypted-orders-design-review.md`, and the walkthrough given in chat
at 19:17 UTC (which already reflects the corrected design — the user's
understanding is ahead of the files).

## 1. The R-number collision (resolve this first)

| Source | Numbering | Status |
|---|---|---|
| External review (`encrypted-orders-design-review.md`, §9) + plan's ratification table | **R1–R11** | Current. Full text arrived 18:33 UTC; this is the set to ratify against. |
| `STAGE6-PREFLIGHT.md` ratify sheet (end of file) | **R1–R15** | **Superseded numbering.** Written 17:29 UTC from the *partial* review, before the full text landed. Its R5 = "seller-signed acceptance before payment" — in the review's numbering that topic is inside R2, and R5 there is the risk dossier. Same numbers, different items. Do not ratify against the preflight sheet. |

Mapping of the preflight items that have no direct review-R twin:
preflight R3 (terminology split: seller acknowledgement ≠ platform-verified
evidence ≠ obligation discharged) and R15 (re-plan gated on a
representative-user workflow test) are real requirements from the review
body text that the review's own R1–R11 table folds into R1/R2 — keep them
as explicit line items in the ratification log so they don't get lost.

Also stale in the preflight: its "Missing before any ratification" list.
Item 1 (rest of review 1 past §4 Phase 6) is **now satisfied** — the full
review arrived 18:33 UTC and the partial file was deleted as superseded.
Items 2–3 remain open: **the second review (ChatGPT/Claude pair) has
still not arrived, and the received review is unattributed in its own
text.** The plan already states it proceeds on the received review unless
the second materially contradicts it — that stance, not the preflight's
"do not ratify off the partial," is now the operative one.

## 2. Superseded text still live in the plan file

The plan's later sections record Cameron's rulings correctly, but the
earlier sections were not revised. If the spec amendment is drafted from
the top of the file, it will import the old design:

1. **Refund address placement — Architecture point 3** says the refund
   address is *"inside the committed order so it cannot be substituted
   later."* Superseded by the owner ruling at the end of the same file
   (and Cameron, 19:14 UTC): refund address is **signed outer metadata**,
   bound by the buyer's signature over (commitment, refund address,
   reservation) and timestamped by the core's submission receipt; fresh
   refund subaddress per order is the helper default.
2. **Plan's ratification table, closing line** still lists Cameron's
   addition as *"refund address committed inside the order"* — the exact
   wording ruling 1 replaced. Should read: refund address in the signed
   outer submission; refunds = loss resolution only, never trust.
3. **Per-order seller acceptance — Architecture point 5, Disputes
   step 1, and the Local helper section** all describe the review's
   original Phase 3: seller decrypts/recomputes/signs acceptance before
   payment; buyer pays only after verifying acceptance; helper "verifies
   seller acceptance." Superseded for standard orders by the standing-
   acceptance amendment + the listing-is-the-contract ruling (Cameron,
   19:11–19:12 UTC): the signed listing + signed pool manifest + core
   reservation certificate *are* the acceptance; adjudication is a
   conformance check (revealed order vs the listing version it cites,
   reserved address paid per that listing's terms). Interactive
   acceptance survives **only** for non-standard orders (negotiated
   price, special deadlines, anything the listing doesn't fully express).
   The helper's safety property needs rewording accordingly: on the
   standard path, conformance is mechanical because the helper builds
   the order *from* the listing snapshot — there is no acceptance
   message to verify.
4. **Disputes step 4** says the seller may *"refund to the order's
   committed refund address"* — under ruling 1 that is the **recorded
   outer refund address**; and per the staged-disclosure ruling, the
   refund layer is attempted *first*, before any order reveal (the
   walkthrough has this order right; the plan's dispute section lists
   reveal-first).

## 3. What Cameron has already ruled (direction set — formal per-line ratification still his)

- Encrypted order + hash commitment + direct payment: **likes / direction adopted** (18:53 UTC).
- Refund proof **counts for nothing as trust** — loss resolution only (18:53 UTC).
- **Listing is the contract**; orders invoke it and introduce no terms of their own; conflicts resolve for the listing (19:12 UTC).
- **No per-order acceptance round-trip** for standard orders — standing acceptance (19:11 UTC).
- **Refund address unencrypted**, signed outer metadata, fresh per order (19:14 UTC).
- **Standalone client-side helper** is the answer to the complexity problem — CLI first, tool-agnostic protocol, helper submits nothing (19:01 UTC discussion; in plan as a first-class component).

## 4. Still genuinely open for the ratification pass (review R1–R11 numbering)

- R4 — reject "commitment + payment proof = proof of scam" (the plan adopts the review's proposed rejection; Cameron has not ruled on this line by name).
- R5 — multidimensional risk dossier, no safety score.
- R6 — reject completion percentages / "verified sales" claims.
- R7 — severity-based enforcement; one proven deliberate deception can justify removal; human review + appeal.
- R8 — probation/continuity privileges, adopt *with limitations* (parallel identity farming acknowledged).
- R9 — reject blind completion tokens for v2 reputation.
- R10 — reject the Monero timelocked-to-self bond (factually dead: custom unlock times deprecated).
- R11 — adopt the added security gates: proof-spendability validation, active key/address substitution, pool restoration/lookahead, dispute-data isolation, post-ban evidence preservation.
- Plus, from the preflight (no review-R twin): the terminology split (preflight R3), the representative-user workflow test as the gate before re-planning stages — now with the **helper as the primary path**, manual as expert fallback — and the Stage 6 reservation-certificate ID prefix: the pinned ID pattern `^(mkt|inv|ord|pool|acct)_[0-9a-f]{32}$` has **no reservation prefix**, so ratifying the reservation certificate requires adding one to the pattern in the same amendment.

## 5. Unaffected by all of this

- Stage 6's safe-to-build set in the preflight (canonical statement library, `Subaddress` destination typing, QR/payment-URI generation from validated statements, xmr-only pricing) does not depend on any item above.
- The Stage 4 owner-items draft (presented in chat 18:27 UTC, `STAGE4-OWNER-ITEMS-DRAFT.md`) is a separate, non-blocking ratification — do not fold it into this one.
