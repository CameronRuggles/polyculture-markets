# Audit 2 H1 fix batch — report (2026-10-23)

**Finding:** Code Audit 2, H1 — a buyer's unverified transaction
proof advanced the order to Paid, and the seller-facing evidence
label called that "Seller confirmed payment."
**Owner ruling:** 2026-10-23 (Cameron, "Good catch, yes do that") —
recorded in `AUDIT2-H1-OWNER-DECISION-2026-10-23.md` (repo root).
**Branch:** `audit2-h1-proof-hold`, from origin/main `c1950f3`.
**Code head:** `b32a6a5` (this report and the POST manifest are
committed on top; no manifested file changes after `b32a6a5`).
**Not pushed, no PR** — merging is Cameron's later call. Closure of
H1 still requires the external auditor's re-verification; this
report + the two manifests are the delta-pack material.

## Environment (re-provisioned this session)

The VM had been replaced and PostgreSQL was gone. Restored the
user-space server from `~/pgsys/postgres-linux-x86_64.txz`
(extracted to `/tmp/pgsys`, data `/tmp/pgdata`, port 5432, user
`pguser`, trust auth, database `marketplace_dev`); the txz ships
no psql, so `postgresql-client-16` was installed via apt (which
worked this generation). Gate env per AGENTS.md:
`NETTLE_PREGENERATED_BINDINGS=~/pgsys/nettle-bindings.rs`,
`PKG_CONFIG_PATH=~/pkgconfig`, disk-backed `TMPDIR=~/tmp-build`,
`MEDIA_WORKER` set.

## Baseline (before any edit, pristine `c1950f3`)

- `cargo test -p app --test tx_proof_flow`: **20 passed / 0
  failed** — the old advancing behaviour live, including the three
  pins the ruling supersedes.
- Full gate (`run-gate.sh`): **PASS — 679 passed / 0 failed / 9
  ignored, 46 suites** (marketplace workspace incl. security
  suites + seller-helper workspace).
- Log: `AUDIT2-H1-gate-baseline.log`, sha256
  `df8fa3e3be430550b33098ca75a52cc2fef9fb25867d81a0bc8e9e72951517a2`.

## Tasks

- **Task 0 — owner-decision record** (commit `6ae57bd`).
  `AUDIT2-H1-OWNER-DECISION-2026-10-23.md` quotes the ruling,
  names everything it supersedes (the 2026-10-18 proof-advance
  element, the `seller_evidence_label` mapping, the vouching copy
  in `payment_risks.html` and limitations wording, the order-page
  "marks the order paid" sentence, and the six `tx_proof_flow.rs`
  pins by name), states what is preserved (the 2026-10-18
  invisibility rule, submittable-at-any-point, sweep exemption,
  seller-cancel guard, dispute gate, moderator-only visibility,
  proof-unconfirmed flag lifecycle), and names the consequential
  adjustments in advance. The pre-amendment manifest
  `AUDIT2-H1-LOCKED-MANIFEST-PRE-2026-10-23.txt` was committed in
  the same commit.
- **Task 1 — core** (commit `68bc761`). `submit_payment_proof`
  records the report + proof, raises the evidence level on the
  open order, and raises `proof-unconfirmed` — but performs **no**
  Paid transition and sends **no notification**: from `Requested`
  the order moves to `AwaitingPayment` and holds; the return value
  is the held state. Only `mark_paid` (SellerAttestation) makes an
  order Paid. Consequential adjustments, as named in the record:
  `mark_paid` now clears proof-unconfirmed flags (the attestation
  settles them, as `confirm_payment`'s already-Paid branch did),
  and `declare_not_received`'s with-proof branch covers
  `AwaitingPayment` as well as `Paid` — design update #2.4 follows
  the proof, not the old state name. The pure domain transition
  table is **not** amended (the capability remains; no production
  path exercises the BuyerProofSubmitted→Paid leg); a comment in
  `crates/domain/src/lib.rs` records the supersession.
- **Task 2 — seller surfaces** (commit `68e641e`).
  `seller_evidence_label(level, state)`: for
  `BuyerProofSubmitted` on an open order it returns
  "No payment evidence recorded" — byte-identical to the
  no-evidence line; on a legacy Paid-lineage row it returns the
  neutral **"Payment recorded"**. "Seller confirmed payment"
  reaches a seller only via `SellerAttested`. The pay page's
  `is_paid` now requires `state == Paid &&
  evidence_level == SellerAttested`, so its
  "Seller confirmed payment." line renders only for attested
  orders (the `pay.html` template itself is unchanged). Buyer-side
  copy corrected: the order-page proof section and the
  `proof_recorded` alert now state plainly that a proof does not
  mark the order paid and that the seller confirms from their own
  wallet.
- **Task 3 — copy** (commit `7f1e145`). `payment_risks.html`: the
  '"Seller confirmed payment" means the seller said so' section
  rewritten — an order reads paid only when the seller attested
  after seeing funds in their own wallet; a new paragraph covers
  the invisible proof. `limitations.html` §"Payments are attested,
  not verified": the attestation sentence is now true as written,
  plus a sentence that a proof never changes an order's state and
  is visible only to the submitting buyer and to moderators in a
  dispute.
- **Task 4 — tests** (commit `b32a6a5`). Amendments **only** as
  named in the Task 0 record, all in `tx_proof_flow.rs` (see the
  manifest deltas); plus a comment-only fix in
  `messaging_audit.rs`. New-semantics coverage: (a) proof leaves
  the order `AwaitingPayment` (core + HTTP paths, incl. from
  `Requested`); (b) the seller attests afterwards identically
  (`flag_raised_on_proof_and_cleared_on_confirmation`,
  `seller_confirmation_binds_order_and_subaddress` unchanged);
  (c) invisibility invariant — the seller's state and evidence
  lines for a proof order are asserted **equal** to a plain
  AwaitingPayment order's, with a forbidden-string list on the
  order page and dispute view; (d) "Seller confirmed payment"
  asserted present only on the attested control's order page and
  pay page, absent from the proof order's pay page; the buyer's
  `order_paid` notification is asserted absent before and present
  after the attestation; (e) the moderator dispute view still
  surfaces txid + proof (`proof_visibility_*`,
  `moderation_queue_lists_flag_and_flag_page_shows_proof`
  unchanged).

## Amendment manifest deltas (sha256)

| File | Pre (c1950f3) | Post (b32a6a5) |
|---|---|---|
| `marketplace/crates/app/tests/tx_proof_flow.rs` | `50818065…` | `f3c10e39…` |
| `marketplace/crates/app/src/payments.rs` | `e72020b7…` | `b7d1da1b…` |
| `marketplace/crates/app/src/web.rs` | `5c35498f…` | `b4ac8f5b…` |
| `marketplace/crates/app/templates/order.html` | `cb062d63…` | `cc0d3056…` |
| `marketplace/crates/app/templates/pay.html` | `83a78a82…` | `83a78a82…` (unchanged — the fix is in `web.rs`) |
| `marketplace/crates/app/templates/payment_risks.html` | `99e43a95…` | `a4e82646…` |
| `marketplace/crates/app/templates/limitations.html` | `2a81321b…` | `7122cfaa…` |
| `marketplace/crates/app/tests/messaging_audit.rs` | `01c0038b…` | `fe8169ed…` (one doc comment) |
| `marketplace/crates/domain/src/lib.rs` | `41346ac9…` | `5735b2e1…` (comment only; table unchanged) |

Full hashes: `AUDIT2-H1-LOCKED-MANIFEST-PRE-2026-10-23.txt` /
`AUDIT2-H1-LOCKED-MANIFEST-POST-2026-10-23.txt`.

Renamed tests (same suite, count unchanged at 20):
`proof_submission_marks_paid_survives_sweep_and_opens_dispute` →
`proof_submission_holds_at_awaiting_payment_survives_sweep_and_opens_dispute`;
`proof_from_requested_advances_and_seller_cannot_cancel_or_decline`
→ `proof_from_requested_holds_at_awaiting_payment_and_seller_cannot_cancel_or_decline`;
`buyer_submits_proof_over_http_and_order_turns_paid` →
`buyer_submits_proof_over_http_and_order_holds_awaiting_payment`.

## Surfaces checked for proof-existence leakage

- **Order page (seller view)** — evidence line via the new
  state-aware label; pinned by the equality assertion in
  `proof_visibility_*`.
- **Dispute page (seller party)** — same label path; forbidden
  strings asserted.
- **Pay page** — status line gated on attested Paid; asserted
  both ways.
- **Notifications** — a proof submission now creates none (the
  buyer's `order_paid` was removed); sellers were never notified
  about proofs; asserted in two tests.
- **Orders list / home / inbox templates** — grep-verified: they
  render state only, never evidence; state no longer moves on a
  proof, so nothing distinguishes a proof order.
- **Counts / seller dashboard** — derived from order state;
  unaffected for the same reason.
- **Moderator surfaces** — intentionally unchanged: the flag queue
  and flag page still show the proof (moderators are the one role
  allowed to see it).

## Final gate

`run-gate.sh` on `b32a6a5`: **PASS — 679 passed / 0 failed / 9
ignored, 46 suites** (identical totals to baseline; amendments
renamed/restructured tests without changing the count).
`tx_proof_flow`: 20/0. Log: `AUDIT2-H1-gate-final.log`, sha256
`92ca8a8dbaf545ef70afc3c97566b8e96a83d20e2e642f283544280fcc2505fb`.

## Honest partials / notes

- **Legacy rows are handled at display only.** No data migration:
  an order already `Paid` with `BuyerProofSubmitted` in existing
  data keeps its state but renders "Payment recorded" to the
  seller and no confirmation line on the pay page. No public
  instance exists yet, so this is theoretical — stated for the
  record.
- **Notification byte-identity** is pinned at the event level (no
  event is created by a proof), not by rendering two inboxes
  side-by-side; the rendered-surface identity is pinned on the
  order page's state/evidence lines, per the ruling's wording
  invariant.
- Nothing else in Audit 2's fix list (items 2–9) was touched;
  they are not commissioned.
