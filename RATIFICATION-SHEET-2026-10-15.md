# Ratification sheet — encrypted orders (clean, single-numbering)

Prepared 2026-10-14 (background, after the duplicate-0006 migration
repair was verified). **Nothing in this sheet is a decision.**
Cameron ratifies per line; this sheet only puts the open lines in
one place, in one numbering system, with the text he has already
superseded flagged so a "ratify all" cannot lock in a replaced
version.

## Use ONLY this numbering

- The R-numbers below are the external review's own table
  (`encrypted-orders-design-review.md` §9, R1–R11) — the current set.
- **Do NOT ratify against the ratify sheet at the end of
  `STAGE6-PREFLIGHT.md`.** It uses a superseded R1–R15 numbering
  written from the partial review: its R5 is a different item than
  R5 here, etc. (`RATIFICATION-RECONCILIATION-2026-10-14.md` §1.)
- The second announced external review has still not arrived. The
  plan's operative stance stands: proceed on the received review
  unless the second materially contradicts it.

## Sequencing state (updated)

Stage 7 pre-flight recommended: (1) 0006 repair, (2) this
ratification, (3) representative-user workflow test, (4) Stage 7
contract-first. **Step 1 is now DONE** — repair executed Option A,
verified fresh-install + both write paths + full suite 327 passed /
0 failed + Q16 probe green (`MIGRATION-REPAIR-2026-10-14.md`,
executed section). This ratification is the next step; nothing in
Stage 7 should lock a pool format before it.

## Part A — already ruled by Cameron (confirm or change; not open)

Direction set 2026-10-14. Listed so they are not re-litigated, and
so the amendment is drafted from these versions, not the plan
file's older sections:

1. Encrypted order + hash commitment + direct payment: direction
   adopted.
2. Refund proof counts for nothing as trust — loss resolution only.
3. Listing is the contract; orders invoke it and introduce no terms
   of their own; conflicts resolve for the listing.
4. **No per-order acceptance round-trip for standard orders** —
   standing acceptance: signed listing + signed pool manifest +
   core reservation certificate ARE the acceptance. Interactive
   acceptance survives only for non-standard orders. (This
   *modifies* R2 below — see its note.)
5. **Refund address is unencrypted signed outer metadata**, bound
   by the buyer's signature over (commitment, refund address,
   reservation), timestamped by the core's submission receipt;
   fresh refund subaddress per order is the helper default.
   (This *replaces* the plan file's "refund address inside the
   committed order" wording — Architecture point 3, Disputes
   step 4, and the ratification table's closing line are stale
   on exactly this point.)
6. Standalone client-side helper is the answer to the complexity
   problem — CLI first, tool-agnostic protocol, helper submits
   nothing.

## Part B — the review's R1–R11 (Cameron rules per line)

Proposed decisions are the review's, not Muse's.

| ID | Recommendation (review §9 wording, shortened) | Proposed | Note |
|---|---|---|---|
| R1 | Dispute-only payment verification, private happy-path states, tested local evidence workflow | Adopt with changes | Direction already ruled (Part A.1, A.6); "changes" = happy-path states stay inside encrypted messages, else the platform still learns sale assertions |
| R2 | Encrypted orders, authenticated listings, reservation certificates, seller acceptance before payment | Adopt with changes | **Read with Part A.4:** acceptance = standing acceptance for standard orders, interactive only for non-standard. The plan file's Architecture point 5 / Disputes step 1 / helper section still describe the old per-order round-trip — stale |
| R3 | Randomized, versioned, precisely encoded commitments supporting limited disclosure | Adopt | — |
| R4 | Treat committed order + tx proof as sufficient proof of a scam | **Reject** | Not ruled by name yet |
| R5 | Multidimensional seller risk dossier (no safety score) | Adopt | Not ruled by name yet |
| R6 | Completion percentages / "verified sales" claims from receipts or tokens | **Reject** | Not ruled by name yet |
| R7 | Severity- and evidence-based enforcement; one serious intentional-deception finding may justify removal (human review + appeal) | Adopt | Not ruled by name yet |
| R8 | Limited probation and continuity-based privileges, acknowledging parallel identity farming | Adopt with limitations | Not ruled by name yet |
| R9 | Blind completion tokens for v2 reputation | **Reject** | Not ruled by name yet |
| R10 | Monero timelocked-to-self bond | **Reject** | Factually dead: Monero deprecated custom unlock times |
| R11 | Add security gates: proof-spendability, active key/address substitution, pool restoration/lookahead, dispute-data isolation, post-ban evidence preservation | Adopt | Not ruled by name yet |

## Part C — extra line items (no review-R twin; do not lose them)

From the review body text via the superseded preflight sheet
(RATIFICATION-RECONCILIATION §1, §4):

- **E1 — Terminology split:** seller acknowledgement ≠
  platform-verified evidence ≠ obligation discharged. Three
  different things, three different words, everywhere in spec/UI.
- **E2 — Workflow-test gate:** a representative-user test of the
  manual order flow gates any re-planning of stages — with the
  **helper as the primary path** and manual as expert fallback.
- **E3 — Reservation-certificate ID prefix:** the pinned ID pattern
  `^(mkt|inv|ord|pool|acct)_[0-9a-f]{32}$` has no reservation
  prefix. Ratifying the reservation certificate (R2) requires
  adding one in the same amendment — not a Stage 7 improvisation.

## Part D — stale text that must NOT be imported by a ratify-all

If the spec amendment is drafted from the top of
`ENCRYPTED-ORDERS-PLAN-2026-10-14.md`, it will import superseded
design (reconciliation §2, items 1–4). Draft the amendment from
Part A of this sheet for: refund-address placement, per-order
acceptance, dispute refund wording, and dispute order
(refund layer attempted *first*, before any order reveal).

## Explicitly separate

The Stage 4 owner-items draft (`STAGE4-OWNER-ITEMS-DRAFT.md`,
seven sentences + inbox timestamp fix, presented 2026-10-14) is a
separate, non-blocking ratification. Do not fold it into this one.
