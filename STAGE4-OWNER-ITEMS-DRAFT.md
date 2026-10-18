# Stage 4 gate — owner items: draft rulings (prepared 2026-10-14)

Source: GATE4-REPORT.md §8 (items 1–3). Each item below has the exact
spec sentence proposed, checked against the current code in
`marketplace/crates/app/src/orders.rs`. Ratifying these as written
changes **no code** — every recommendation matches the shipped
behaviour, so the sentences pin what already passed the gate. Cameron
can accept all with one word, or overrule any single line.

## 1. §10 terms file — "selected options" section

Spec §10 lists five sections; the built terms file has four, because
v2 listings carry no selectable options.

**Proposed amendment to §10:** "For a listing with no selectable
options, the terms file omits the Selected options section and
consists of exactly four sections, in order: Title, Description,
Delivery terms, Refund terms. If a future version adds listing
options, the Selected options section appears between Title and
Description, snapshotting the buyer's selections at order creation."

Code check: `build_terms` emits exactly `Title`, `Description`,
`Delivery terms`, `Refund terms` (orders.rs:82–91), byte-exact and
SHA-256-pinned per order. An empty placeholder section would change
the bytes of every future terms file for no information.

## 2. The six DERIVATION-UNCERTAIN items

Each was left ignored by the blind author because the spec does not
pin it. Proposed pinning sentence + code check for each:

1. **§7 new-account limit, 24-hour boundary.** "The limit applies
   while the account's age is strictly less than 24 hours; at exactly
   24 hours the account is unrestricted."
   Code: `if age_hours < 24.0 && order_count >= 3` (orders.rs:155). ✔

2. **Does the limit count orders held as seller?** "The §7 limit
   counts only orders the account placed as buyer."
   Code: `SELECT COUNT(*) FROM orders WHERE buyer_id = $1`
   (orders.rs:148–150). ✔

3. **72-hour dispute guard, satisfied path.** "The guard is satisfied
   when the current time is at or after the buyer's payment-report
   timestamp plus 72 hours and no seller response is recorded; the
   report timestamp is the one stored with the buyer's payment claim."
   (The refused path is already blind-tested; the app enforces the
   timing in SQL. This sentence makes the satisfied path derivable
   for the Stage 6/7 test obligation the mutants flagged.)

4. **Core/moderator actions through `apply_action`.** "The
   `apply_action` surface serves buyer and seller actions only; core
   and moderator transitions are exercised through the moderation
   surface (Stage 9) and are governed by the same domain table."
   (The pure table's core/moderator cells are already tested
   directly.)

5. **Non-participant indistinguishability.** "Order detail and terms
   download return the identical 404 response for a non-participant
   as for a nonexistent order; enforcement sits in the web layer."
   (Already review invariant 7 in REVIEW-PACK-STAGE4.md; this makes
   it a spec sentence instead of a review note.)

6. **Terms section-label bytes.** Resolved by item 1: the labels are
   exactly `Title`, `Description`, `Delivery terms`, `Refund terms`,
   each on its own line, sections separated by one blank line, after
   the canonical header. Code: orders.rs:82–91. ✔

## 3. Inbox timestamp format (report §8.3, noted not changed)

`inbox()` still renders `YYYY-MM-DD HH24:MI` (orders.rs:393) — the
pattern the gate fixed for order `created_at`. §15 does not pin the
format. **Recommendation:** no spec sentence; instead a one-line code
consistency fix to render inbox timestamps in the same canonical
RFC 3339 UTC form as `created_at`, foldable into any later stage's
work without a gate of its own.

## What this unblocks

Nothing here blocks Stage 5 (per the gate report), but items 3 and 5
feed the Stage 6/7 payment-evidence tests and the Stage 9 moderation
surface respectively — pinning them now, while the gate evidence is
fresh, is the cheap moment. On ratification, the sentences fold into
SPEC-V2-AMENDMENTS.md in the usual form.
