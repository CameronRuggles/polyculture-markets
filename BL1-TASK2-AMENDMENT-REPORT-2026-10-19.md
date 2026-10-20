# BL1 task-2 remainder amendment pass — report — 2026-10-19

Repo: `~/workspace/monero-marketplace-v2`, branch `deployment-fix-batch`.
Pre-batch HEAD: `2960cdd`. **Local commits only; nothing pushed.** The
untracked repo-root files `OWNER-DECISIONS-2026-10-18-EVENING.md` and
`BL1-AMENDMENT-PASS-BRIEF-2026-10-19.md` were left untouched and
untracked.

## Verdict

**COMPLETE — BL1 is now fully closed.** All four tasks executed:

- **Task 1 (remove the `apply_action` invoice guard): DONE.**
- **Task 2 (amend `blind_direct_v1`): DONE.**
- **Task 3 (amend `blind_stage4`): DONE.**
- **Task 4 (`payments_db.rs` knock-on): DONE.**
- **Task 5 (full gate + manifests): DONE.** Final complete run:
  **workspace 585 passed / 0 failed / 9 ignored** — exactly the
  pre-batch baseline (585/0/9) — and **seller-helper 18/18**. The
  post-manifest differs from the pre-manifest in **exactly the two
  authorized locked files** (`blind_stage4.rs`, `blind_direct_v1.rs`);
  `blind_stage1.rs` is byte-identical to its already-amended state,
  and all other locked files are byte-identical.

One code commit, `8ee9eb8`, plus this report and the two manifest
files.

## 1. Authorization and scope discipline

This pass completes task 2 of the BL1 amendment pass reported in
`BL1-AMENDMENT-REPORT-2026-10-19.md`, which was stopped when a third
locked pin (`blind_stage4.rs`) was found outside that pass's
authorization. The decision chain is unchanged: the owner was asked
whether to authorize the BL1 amendment pass and delegated the
decision ("do whatever you think is best", 2026-10-19); the decision
taken was YES. For this remainder pass the authorization was extended
to `blind_stage4.rs`, on the same terms. Exactly **two** locked files
were authorized to change in this pass — `blind_stage4.rs` and
`blind_direct_v1.rs` — and nothing else under
`marketplace/tests/security/**`, `marketplace/docs/invariants.md`,
or the spec. Amendments follow the established pattern (the
blind_stage1 amendment in the previous pass; the blind_stage9
task-11 amendments; blind_stage10 note A8): original text kept
visible, dated owner-decision note, no silent deletions, no
unrelated edits.

What actually changed, in full: `crates/app/src/orders.rs` (guard
removed), `crates/app/tests/payments_db.rs` (non-locked knock-on
assertion updated), `tests/security/blind_stage4.rs` and
`tests/security/blind_direct_v1.rs` (the two locked amendments).
No other file was modified. The spec was not touched.

## 2. Decided end state — confirmed against the code before editing

The brief's end state was verified in the code before any edit:

- **The guard** was the accept branch of `apply_action`
  (`crates/app/src/orders.rs`, lines 569–591 at HEAD `2960cdd`):
  for an order without an assignment, accept required an `invoices`
  row in state `Issued`, else `OrderError::InvoiceRequired`. Nothing
  issues invoices (retired with Direct Payments v1).
- **`mark_paid` refuses unassigned orders with `NoAssignment`** —
  `crates/app/src/payments.rs`: after the seller and
  `AwaitingPayment` checks, it does
  `assignment_for_order(...).ok_or(PaymentError::NoAssignment)?`.
  So acceptance alone cannot fabricate a payment. ✓
- **Production orders always receive an assignment at creation** —
  `create_order` allocates at creation for sellers with a payment
  identity and refuses creation with `OrderError::PoolEmpty` when
  the pool is empty (asserted by `payments_db`'s
  `pool_empty_refuses_and_no_identity_keeps_legacy_behaviour`); the
  no-assignment path is taken only when the seller has **no payment
  identity at all**, i.e. legacy rows. ✓

The code matched the brief on every point, so the pass proceeded
as briefed. The separate §9 dispute-timing guard for unassigned
orders (`orders.rs`, the `action == "dispute"` branch) is a
different mechanism, was never named by either conflict document,
and is untouched.

## 3. Task 1 — the invoice guard is removed

The accept branch's invoice check is deleted in full. In its place
`orders.rs` carries a dated comment recording the removal, why
(the retired invoice system made assignment-less orders
unacceptable forever), and the invariant that keeps it safe
(production orders always carry an assignment; `mark_paid` still
refuses unassigned orders with `NoAssignment`). The full diff is
in §8.3.

Deliberate non-changes, recorded so they are not mistaken for
oversights:

- The `OrderError::InvoiceRequired` variant (`orders.rs:38`) is
  **kept**. It is part of the public `OrderError` API, and the web
  layer still maps it (`web.rs:2845`, a redirect arm that is now
  unreachable from `apply_action`). Removing the variant and its
  web mapping would widen this amendment's diff beyond the
  briefed scope for zero behavioural gain; both are inert. A
  future cleanup pass may retire them.

## 4. Task 2 — `blind_direct_v1` amended

- **Header:** a dated AMENDMENT note was added after item A14,
  recording that A11's final clause ("the legacy no-assignment
  accept still yields InvoiceRequired per amendment (e)") is
  SUPERSEDED, with the full owner-decision chain. A11 itself and
  the plain-language list stand verbatim, as originally locked.
- **Test:** `accept_on_legacy_order_still_requires_invoice` is
  kept visible in full, commented out in place under an AMENDED
  note, and followed by its replacement,
  `accept_on_legacy_order_succeeds_without_invoice_but_cannot_be_marked_paid`,
  which asserts the new behaviour end-to-end: the legacy order's
  accept succeeds, the returned state is
  `OrderState::AwaitingPayment` and the persisted state is
  `"AwaitingPayment"`, and `mark_paid` on the accepted order
  refuses with `PaymentError::NoAssignment`.
- Suite count unchanged: **blind_direct_v1 42 passed / 0 failed /
  0 ignored**, exactly baseline (one test replaced by one test).

## 5. Task 3 — `blind_stage4` amended

- **§C header:** the bullet "`accept` by the seller on a Requested
  order with no issued invoice yields InvoiceRequired. `accept` by
  the buyer is an error." stands verbatim; a dated AMENDMENT note
  directly beneath it marks the InvoiceRequired clause SUPERSEDED,
  records the decision chain, and points at the replacement test.
- **Test:** `c_accept_without_issued_invoice_yields_invoice_required`
  is kept visible in full, commented out in place under an AMENDED
  note, and followed by its replacement,
  `c_accept_without_issued_invoice_succeeds_since_bl1_amendment`,
  which asserts: the seller's accept succeeds and returns
  `OrderState::AwaitingPayment`; the buyer's accept attempt is an
  error; the persisted state is `"AwaitingPayment"`.
- Suite count unchanged: **blind_stage4 58 passed / 0 failed /
  6 ignored**, exactly baseline.

## 6. Task 4 — `payments_db.rs` knock-on (not locked)

`crates/app/tests/payments_db.rs`,
`pool_empty_refuses_and_no_identity_keeps_legacy_behaviour` (the
assertion at line 432 pre-pass): the closing assertion — accept on
the no-identity legacy order refuses with `InvoiceRequired` — now
asserts the new behaviour: accept succeeds into `AwaitingPayment`,
and `mark_paid` on it refuses with `PaymentError::NoAssignment`.
The test's other assertions (empty pool refuses creation with
`PoolEmpty`; no identity → order created with no assignment) are
unchanged. Full diff in §8.3. Suite: **payments_db 11/0/0**,
exactly baseline.

## 7. Task 5 — full gate, manifests, environment incident

Environment: standard gate environment (`DATABASE_URL`,
`MEDIA_WORKER`, `MEDIA_DIR`, `BLOB_DIR`, disk-backed `TMPDIR`,
`NETTLE_PREGENERATED_BINDINGS=~/pgsys/nettle-bindings.rs`,
`PKG_CONFIG_PATH=~/pkgconfig`).

**Environment incident, for the record.** This session began on a
replaced VM: Postgres (the `/tmp/pgx` binaries, the `/tmp/pgdata`
data directory, and the `pguser` account) was gone. It was
re-provisioned per `~/AGENTS.md` before any code work (Zonky
binaries extracted from `~/pgsys/postgres-linux-x86_64.txz` to
`/tmp/pgx`, fresh `initdb` in `/tmp/pgdata`, server on port 5432,
`marketplace_dev` created, migrations 0001–0015 applied via a
small sqlx runner; 38 public tables — the same count as every
prior pass). The repo itself lives under `~` and was unaffected
(HEAD verified at `2960cdd` before and after); the PRE manifest
was taken from that HEAD. The gate then ran clean, alone, to
completion — no run was discarded in this pass.

### Final complete run — per-target results

`cargo test --workspace` (**exit 0**), then
`cargo test --manifest-path seller-helper/Cargo.toml` from the
repo root (exit 0):

| Target | Passed | Failed | Ignored | Baseline |
|---|---|---|---|---|
| app (lib) | 54 | 0 | 0 | 54 |
| app bin | 0 | 0 | 0 | 0 |
| account_security | 14 | 0 | 0 | 14 |
| audit_fix_tasks | 4 | 0 | 0 | 4 |
| dispute_signature | 1 | 0 | 0 | 1 |
| media_disputes_audit | 9 | 0 | 0 | 9 |
| media_serve_http | 1 | 0 | 0 | 1 |
| media_verification | 6 | 0 | 0 | 6 |
| messaging_audit | 9 | 0 | 0 | 9 |
| modules_audit_fixes | 9 | 0 | 0 | 9 |
| payments_db | 11 | 0 | 0 | 11 |
| stage1_db | 1 | 0 | 0 | 1 |
| tx_proof_flow | 20 | 0 | 0 | 20 |
| verification_fixes | 10 | 0 | 0 | 10 |
| domain | 15 | 0 | 0 | 15 |
| envelope | 7 | 0 | 0 | 7 |
| modules-api | 8 | 0 | 0 | 8 |
| media-worker | 0 | 0 | 0 | 0 |
| security-tests (lib) | 0 | 0 | 0 | 0 |
| **blind_direct_v1 (amended)** | **42** | **0** | **0** | **42** |
| blind_stage1 (amended, prior pass) | 41 | 0 | 0 | 41 |
| blind_stage2 | 38 | 0 | 0 | 38 |
| blind_stage3 | 34 | 0 | 0 | 34 |
| **blind_stage4 (amended)** | **58** | **0** | **6** | **58/6** |
| blind_stage5 | 35 | 0 | 3 | 35/3 |
| blind_stage6 | 83 | 0 | 0 | 83 |
| blind_stage9 | 43 | 0 | 0 | 43 |
| blind_stage10 | 32 | 0 | 0 | 32 |
| (doc/empty targets) | 0 | 0 | 0 | — |
| **WORKSPACE TOTAL** | **585** | **0** | **9** | **585/0/9** |
| **seller-helper** | **18** | **0** | **0** | **18/18** |

Targeted pre-commit checks agreed: payments_db 11/0/0,
blind_direct_v1 42/0/0, blind_stage4 58/0/6.

**fmt / clippy.** `cargo clippy --workspace --all-targets` exits 0.
No clippy finding touches any code this pass wrote: the findings
in `orders.rs` are the pre-existing ones at lines 62
(`build_terms`, too many arguments) and 146 (type complexity),
far from the removed guard; `blind_stage4`'s four warnings are
pre-existing fixture/test lints (`make_listing` argument count;
three unused-`Result` in untouched tests); `payments_db.rs` and
`blind_direct_v1.rs` have none. The stricter checks
(`cargo fmt --check`, `clippy -D warnings`) remain subject to the
toolchain-generation drift documented in
`BL1-AMENDMENT-REPORT-2026-10-19.md` §5 (this generation's rustfmt
demands tree-wide reformatting, including of locked files);
reformatting is out of scope for an amendment pass and nothing in
this pass's edits follows any style but the files' own.

### Locked-path manifests (SHA-256)

Scope: `marketplace/tests/security/**` (recursive) +
`marketplace/docs/invariants.md` — 17 files. The PRE manifest was
taken at HEAD `2960cdd` before any edit; the POST manifest after
the final gate. Full contents are committed beside this report as
`BL1-TASK2-LOCKED-MANIFEST-PRE-2026-10-19.txt` and
`BL1-TASK2-LOCKED-MANIFEST-POST-2026-10-19.txt`.

Diff of the two manifests — exactly two lines:

```
< 1f027a12e5e20abb69572f2f93835e8a4d0a23ab5cc53c26b84970a05fcd3a6f  marketplace/tests/security/blind_direct_v1.rs
> 154fe7d092e3239ee92ed554a6177b6cf7b26752165d7548cc5831fbf177a76a  marketplace/tests/security/blind_direct_v1.rs
< 57331c15025ebafe6dc4defb4d9605cc3064a1474b504627e7d5d90fd863d3d7  marketplace/tests/security/blind_stage4.rs
> 0fea6f68bbc7ae627b89a4521cc413043a51e870b14ed03d5804b854dfbf8e47  marketplace/tests/security/blind_stage4.rs
```

Exactly the two authorized locked files differ.
`blind_stage1.rs` is `702a23b5…` in both manifests — byte-identical
to its state after the previous pass's amendment, as required.
Every other locked file, including `docs/invariants.md`, is
byte-identical.

## 8. Full diffs

### 8.1 `marketplace/tests/security/blind_direct_v1.rs` — the complete diff

(`git diff 2960cdd..8ee9eb8 -- marketplace/tests/security/blind_direct_v1.rs`)

```diff
diff --git a/marketplace/tests/security/blind_direct_v1.rs b/marketplace/tests/security/blind_direct_v1.rs
index c9f77ef..5bc375b 100644
--- a/marketplace/tests/security/blind_direct_v1.rs
+++ b/marketplace/tests/security/blind_direct_v1.rs
@@ -120,6 +120,25 @@
 //!       tests assert refusal + no order created + no pool entry
 //!       consumed, not a variant name.
 //!
+//! AMENDMENT (owner decision 2026-10-19 — BL1 completion, task-2
+//! remainder): A11's final clause — "the legacy no-assignment accept
+//! still yields InvoiceRequired per amendment (e)" — is SUPERSEDED.
+//! The owner was asked whether to authorize the BL1 amendment pass
+//! and delegated the decision ("do whatever you think is best",
+//! 2026-10-19); the decision was YES, and the pass was extended to
+//! this file and blind_stage4.rs for this item. The §9 invoice gate
+//! in `apply_action` was removed: the invoice system is retired,
+//! nothing issues invoices, and the gate made assignment-less
+//! (legacy, pre-Direct-Payments) orders unacceptable forever. The
+//! test `accept_on_legacy_order_still_requires_invoice` is kept
+//! visible below in its original form, followed by its replacement
+//! asserting the new behaviour: a legacy order's accept succeeds
+//! into AwaitingPayment with no invoice in existence, and
+//! mark_paid still refuses it with NoAssignment, so acceptance
+//! opens no payment path. A11 and the plain-language list below
+//! otherwise stand as originally locked; see
+//! BL1-TASK2-AMENDMENT-REPORT-2026-10-19.md.
+//!
 //! PLAIN-LANGUAGE ASSERTION LIST (grouped):
 //!   Pure helpers: payment_seller_id derives "acct-<32 hex>" from
 //!   "acct_<32 hex>" and rejects everything else; canonical_message
@@ -1831,20 +1850,54 @@ async fn mark_paid_state_and_assignment_guards() {
     assert!(mark_paid(&pool, &ghost, shop.seller_id, &cfg()).await.is_err());
 }
 
+// AMENDED 2026-10-19 (BL1 completion, task-2 remainder — owner
+// decision chain: the owner delegated the BL1 completion decision
+// to Muse with "do whatever you think is best", 2026-10-19; the
+// amendment pass authorized on that delegation was extended to
+// this file and blind_stage4.rs). The original test is kept
+// visible, commented out in place; its replacement follows.
+//
+// #[tokio::test]
+// async fn accept_on_legacy_order_still_requires_invoice() {
+//     // Amendment (e): orders without an assignment keep the Stage 4
+//     // behaviour — accept is refused with InvoiceRequired.
+//     let pool = pool().await;
+//     let legacy = make_shop(&pool).await;
+//     let buyer = make_buyer(&pool).await;
+//     let (order, _) = create_pay_order(&pool, &cfg(), buyer, &legacy)
+//         .await
+//         .unwrap();
+//     let err = apply_action(&pool, &order, "accept", legacy.seller_id)
+//         .await
+//         .expect_err("legacy accept without an issued invoice must be refused");
+//     assert!(matches!(err, OrderError::InvoiceRequired), "got {err:?}");
+// }
+
 #[tokio::test]
-async fn accept_on_legacy_order_still_requires_invoice() {
-    // Amendment (e): orders without an assignment keep the Stage 4
-    // behaviour — accept is refused with InvoiceRequired.
+async fn accept_on_legacy_order_succeeds_without_invoice_but_cannot_be_marked_paid() {
+    // Replacement for the test above (BL1 amendment, 2026-10-19):
+    // the §9 invoice gate in apply_action was removed — the invoice
+    // system is retired and nothing issues invoices — so a legacy
+    // (no-assignment) order's accept now succeeds into
+    // AwaitingPayment with no invoice in existence. No payment path
+    // opens: mark_paid still refuses the unassigned order with
+    // NoAssignment.
     let pool = pool().await;
     let legacy = make_shop(&pool).await;
     let buyer = make_buyer(&pool).await;
     let (order, _) = create_pay_order(&pool, &cfg(), buyer, &legacy)
         .await
         .unwrap();
-    let err = apply_action(&pool, &order, "accept", legacy.seller_id)
+    let state = apply_action(&pool, &order, "accept", legacy.seller_id)
+        .await
+        .expect("legacy accept must succeed since the BL1 amendment removed the invoice gate");
+    assert!(matches!(state, domain::OrderState::AwaitingPayment), "got {state:?}");
+    let order = order_by_public_id(&pool, &order.public_id).await.unwrap();
+    assert_eq!(order.state, "AwaitingPayment");
+    let err = mark_paid(&pool, &order, legacy.seller_id, &cfg())
         .await
-        .expect_err("legacy accept without an issued invoice must be refused");
-    assert!(matches!(err, OrderError::InvoiceRequired), "got {err:?}");
+        .expect_err("mark-paid without an assignment must be refused");
+    assert!(matches!(err, PaymentError::NoAssignment), "got {err:?}");
 }
 
 // =====================================================================
```

### 8.2 `marketplace/tests/security/blind_stage4.rs` — the complete diff

(`git diff 2960cdd..8ee9eb8 -- marketplace/tests/security/blind_stage4.rs`)

```diff
diff --git a/marketplace/tests/security/blind_stage4.rs b/marketplace/tests/security/blind_stage4.rs
index 17213d2..b0c89be 100644
--- a/marketplace/tests/security/blind_stage4.rs
+++ b/marketplace/tests/security/blind_stage4.rs
@@ -57,6 +57,21 @@
 //!      the six action strings.
 //!    - `accept` by the seller on a Requested order with no issued invoice
 //!      yields InvoiceRequired. `accept` by the buyer is an error.
+//!      AMENDMENT (owner decision 2026-10-19 — BL1 completion,
+//!      task-2 remainder): the InvoiceRequired clause above is
+//!      SUPERSEDED — it is kept verbatim for the record. The owner
+//!      delegated the BL1 completion decision to Muse ("do
+//!      whatever you think is best", 2026-10-19), who authorized
+//!      the BL1 amendment pass and its extension to this file and
+//!      blind_direct_v1.rs. The §9 invoice gate in `apply_action`
+//!      was removed: the invoice system is retired, nothing issues
+//!      invoices, and the gate made assignment-less orders
+//!      unacceptable forever. The test
+//!      `c_accept_without_issued_invoice_yields_invoice_required`
+//!      below is kept visible in its original form, followed by
+//!      its replacement asserting the new behaviour (seller accept
+//!      succeeds into AwaitingPayment; buyer accept remains an
+//!      error). See BL1-TASK2-AMENDMENT-REPORT-2026-10-19.md.
 //!    - `decline`: seller moves Requested -> Declined and the new state is
 //!      persisted; buyer is refused with TransitionDenied.
 //!    - `cancel`: buyer cancels from Requested; seller cancelling from
@@ -1201,30 +1216,62 @@ async fn c_non_participant_gets_transition_denied_for_every_action() {
     assert_eq!(after.state, "Requested");
 }
 
+// AMENDED 2026-10-19 (BL1 completion, task-2 remainder — owner
+// decision chain: the owner delegated the BL1 completion decision
+// to Muse with "do whatever you think is best", 2026-10-19; the
+// amendment pass authorized on that delegation was extended to
+// this file and blind_direct_v1.rs). The original test is kept
+// visible, commented out in place; its replacement follows.
+//
+// #[tokio::test]
+// async fn c_accept_without_issued_invoice_yields_invoice_required() {
+//     let pool = pool().await;
+//     let shop = make_shop(&pool, 1_000_000).await;
+//     let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
+//     let order = fresh_order(&pool, &shop, buyer_id).await;
+//
+//     // No invoice exists (invoice issuance is Stage 6/7 surface), so the
+//     // seller's accept must be refused with InvoiceRequired, per
+//     // contract §11: "until the payment stages, accept is always refused
+//     // with that reason".
+//     let err = apply_action(&pool, &order, "accept", shop.seller_id)
+//         .await
+//         .expect_err("accept without an issued invoice must be refused");
+//     assert!(matches!(err, OrderError::InvoiceRequired), "got {err:?}");
+//
+//     // The buyer attempting accept is an error too (wrong actor for the
+//     // Requested -> AwaitingPayment seller row). The documents do not pin
+//     // whether the actor check or the invoice guard fires first for a
+//     // wrong actor, so only the error itself is asserted here.
+//     assert!(apply_action(&pool, &order, "accept", buyer_id).await.is_err());
+//
+//     let after = order_by_public_id(&pool, &order.public_id).await.unwrap();
+//     assert_eq!(after.state, "Requested");
+// }
+
 #[tokio::test]
-async fn c_accept_without_issued_invoice_yields_invoice_required() {
+async fn c_accept_without_issued_invoice_succeeds_since_bl1_amendment() {
     let pool = pool().await;
     let shop = make_shop(&pool, 1_000_000).await;
     let (buyer_id, _) = make_account(&pool, "buyer", 72).await;
     let order = fresh_order(&pool, &shop, buyer_id).await;
 
-    // No invoice exists (invoice issuance is Stage 6/7 surface), so the
-    // seller's accept must be refused with InvoiceRequired, per
-    // contract §11: "until the payment stages, accept is always refused
-    // with that reason".
-    let err = apply_action(&pool, &order, "accept", shop.seller_id)
+    // Replacement for the test above (BL1 amendment, 2026-10-19):
+    // no invoice exists (nothing issues invoices since Direct
+    // Payments retired the invoice system), and with the §9 invoice
+    // gate removed from apply_action the seller's accept succeeds
+    // and the order moves to AwaitingPayment.
+    let state = apply_action(&pool, &order, "accept", shop.seller_id)
         .await
-        .expect_err("accept without an issued invoice must be refused");
-    assert!(matches!(err, OrderError::InvoiceRequired), "got {err:?}");
+        .expect("seller accept must succeed since the BL1 amendment");
+    assert!(matches!(state, OrderState::AwaitingPayment));
 
-    // The buyer attempting accept is an error too (wrong actor for the
-    // Requested -> AwaitingPayment seller row). The documents do not pin
-    // whether the actor check or the invoice guard fires first for a
-    // wrong actor, so only the error itself is asserted here.
+    // The buyer attempting accept is an error too (wrong actor for
+    // the Requested -> AwaitingPayment seller row).
     assert!(apply_action(&pool, &order, "accept", buyer_id).await.is_err());
 
     let after = order_by_public_id(&pool, &order.public_id).await.unwrap();
-    assert_eq!(after.state, "Requested");
+    assert_eq!(after.state, "AwaitingPayment");
 }
 
 #[tokio::test]
```

### 8.3 Appendix — the non-locked diffs, in full

(`git diff 2960cdd..8ee9eb8` for the two non-locked files changed by tasks 1 and 4.)

```diff
diff --git a/marketplace/crates/app/src/orders.rs b/marketplace/crates/app/src/orders.rs
index be6ac31..513b369 100644
--- a/marketplace/crates/app/src/orders.rs
+++ b/marketplace/crates/app/src/orders.rs
@@ -567,29 +567,20 @@ pub async fn apply_action(
     if !order_can_transition(from, to, actor, evidence) {
         return Err(OrderError::TransitionDenied);
     }
-    if action == "accept" {
-        // §9: Requested -> AwaitingPayment requires an issued invoice.
-        // Direct Payments v1 disposition: for direct orders the gate is
-        // assignment-exists instead (which holds by construction for
-        // payment-enabled sellers, since allocation happens at
-        // creation). Orders without an assignment keep the original
-        // invoice behaviour exactly (Stage 4 locked suite).
-        let assigned = crate::payments::has_assignment(pool, order.id)
-            .await
-            .map_err(|_| OrderError::NotFound)?;
-        if !assigned {
-            let issued: bool = sqlx::query_scalar(
-                "SELECT EXISTS(SELECT 1 FROM invoices WHERE order_id = $1 AND state = 'Issued')",
-            )
-            .bind(order.id)
-            .fetch_one(pool)
-            .await
-            .map_err(|_| OrderError::NotFound)?;
-            if !issued {
-                return Err(OrderError::InvoiceRequired);
-            }
-        }
-    }
+    // BL1 amendment (2026-10-19): the §9 invoice gate on accept is
+    // REMOVED. It required an order without a payment assignment to
+    // have an invoice in state Issued before the seller could accept;
+    // the invoice system is retired and nothing issues invoices, so
+    // the gate made assignment-less (legacy, pre-Direct-Payments)
+    // orders unacceptable forever. Production orders always carry an
+    // assignment — allocation happens at creation and creation is
+    // refused when the pool is empty — so an accepted-but-unassigned
+    // order is reachable only for legacy rows, and no payment path
+    // opens for it: mark_paid still refuses unassigned orders with
+    // NoAssignment. The locked pins that asserted the gate
+    // (blind_stage4 §C, blind_direct_v1 amendment (e)) were amended
+    // the same day under the BL1 owner-decision chain; see
+    // BL1-TASK2-AMENDMENT-REPORT-2026-10-19.md.
     if matches!(action, "cancel" | "decline") && actor_id == order.seller_id {
         // Owner decision 2026-10-18: once a buyer payment report
         // (proof or manual) is on file, the order is never the
diff --git a/marketplace/crates/app/tests/payments_db.rs b/marketplace/crates/app/tests/payments_db.rs
index 8344f7c..568fd45 100644
--- a/marketplace/crates/app/tests/payments_db.rs
+++ b/marketplace/crates/app/tests/payments_db.rs
@@ -427,9 +427,17 @@ async fn pool_empty_refuses_and_no_identity_keeps_legacy_behaviour() {
     let (o, created) = create_order_with_config(&pool, "vespiary-market", buyer, &plain_listing, 1, "pe-3", &c).await.unwrap();
     assert!(created);
     assert!(assignment_for_order(&pool, o.id, &c).await.unwrap().is_none());
-    // And accept on that legacy order keeps the Stage 4 invoice gate.
-    let err = apply_action(&pool, &o, "accept", plain_seller).await.expect_err("accept without invoice must refuse");
-    assert_eq!(err, OrderError::InvoiceRequired);
+    // Accept on that legacy order no longer meets the Stage 4 invoice
+    // gate — it was removed by the BL1 amendment (2026-10-19): nothing
+    // issues invoices, so the gate made assignment-less orders
+    // unacceptable forever. Accept succeeds into AwaitingPayment, but
+    // no payment path opens: mark_paid refuses the unassigned order
+    // with NoAssignment.
+    let state = apply_action(&pool, &o, "accept", plain_seller).await.expect("legacy accept must succeed since the BL1 amendment");
+    assert_eq!(format!("{state:?}"), "AwaitingPayment");
+    let o = app::orders::order_by_public_id(&pool, &o.public_id).await.unwrap();
+    let err = mark_paid(&pool, &o, plain_seller, &c).await.expect_err("mark_paid without an assignment must refuse");
+    assert_eq!(err, PaymentError::NoAssignment);
     cleanup(&pool, &[seller_id, plain_seller, buyer]).await;
 }
 
```
