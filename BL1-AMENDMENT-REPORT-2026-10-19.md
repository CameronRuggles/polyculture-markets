# BL1 completion amendment pass — report — 2026-10-19

Repo: `~/workspace/monero-marketplace-v2`, branch `deployment-fix-batch`.
Pre-batch HEAD: `fcf57a6`. **Local commits only; nothing pushed.** The
untracked repo-root `OWNER-DECISIONS-2026-10-18-EVENING.md` was left
untouched and untracked.

## Verdict

- **Task 1 (remove the 13 dead authorization rules + amend
  `blind_stage1`): COMPLETE.** One commit, `6bcb413`.
- **Task 2 (remove the `apply_action` invoice guard + amend
  `blind_direct_v1`): STOPPED — NOT EXECUTED.** The guard is pinned
  by a **third** locked suite the BM/BL report did not name:
  `blind_stage4.rs` asserts the identical behaviour on a materially
  identical fixture. That suite is outside this pass's two-file
  authorization, so removing the guard would turn the locked gate
  red. Full evidence in §3. `orders.rs` and `blind_direct_v1.rs`
  are untouched; the post-manifest therefore shows exactly **one**
  locked file differing, not two.
- **Task 3 (rule-to-route exception set to EMPTY): COMPLETE**,
  in the same commit as task 1. The test passes: every remaining
  authorization rule names a served route.
- **Task 4 (full gate + manifests): COMPLETE.** Final clean run:
  **workspace 585 passed / 0 failed / 9 ignored, exit 0** — exactly
  the pre-batch baseline (585/0/9) — and **seller-helper 18/18**.
  Two environment incidents (VM replacements) are documented in
  §5; only the final clean run's numbers are reported as results.

## 1. Authorization and scope discipline

The owner was asked whether to authorize this pass and delegated
the decision ("do whatever you think is best", 2026-10-19); the
decision taken was YES. The pass was authorized to amend exactly
two locked files — `marketplace/tests/security/blind_stage1.rs`
and `marketplace/tests/security/blind_direct_v1.rs` — and nothing
else under `marketplace/tests/security/**`,
`marketplace/docs/invariants.md`, or the spec. Amendments follow
the established pattern (blind_stage9 task-11 amendments;
blind_stage10 note A8): original text kept visible, dated
owner-decision note, no silent deletions, no unrelated edits.

What actually changed, in full: `crates/app/src/authz.rs` (rules
removed), `crates/app/tests/modules_audit_fixes.rs` (exception set
emptied — the app's own test file, not locked),
`tests/security/blind_stage1.rs` (the one locked amendment). No
other file was modified. The spec was not touched.

## 2. Task 1 — the 13 dead rules are gone

**Router verification (done before any edit).** The served route
set was read from `crates/app/src/web.rs` (`router()`, line 478).
None of the 13 candidate paths is served: no `/invoices`, no
`/pools`, no `/seller/pools`, no `/messages/{id}/download`, no bare
`/security` (the served security surfaces are `/security-guide`
and `/account/security`). `POST /orders/{id}/invoice` **stays**: it
matches the served `/orders/{id}/{action}` pattern.

**`crates/app/src/authz.rs`** — the 13 `RouteRule` rows removed
(rule count 93 → 80):

- `GET /invoices/{id}`, `GET /invoices/{id}/qr.png`,
  `GET /invoices/{id}/statement.txt`,
  `GET /invoices/{id}/statement.txt.asc`,
  `POST /invoices/{id}/signature`,
  `POST /invoices/{id}/evidence/{module}`
- `GET /pools/{id}/statement.txt`,
  `GET /pools/{id}/statement.txt.asc`
- `GET /seller/pools`, `POST /seller/pools`,
  `POST /seller/pools/{id}/signature`
- `GET /messages/{id}/download`
- `GET /security`

Each removal site carries a short dated comment, and the file
header records the amendment — a future handler on any of these
paths now gets `authorize()`'s default Deny instead of silently
inheriting a retired permission (one of the dead rules let any
signed-in account post invoice evidence).

**`tests/security/blind_stage1.rs` (LOCKED — amended under the
authorization)** — the 13 matching rows of the expected
`authorize()` table were commented out **in place**, each under a
`// REMOVED 2026-10-19 (BL1 amendment, …)` marker, beneath a dated
AMENDMENT note on the table recording the delegation, the
decision, what was removed and why, and that the A1–A3
plain-language list at the top of the file describes the table as
originally locked and is kept verbatim for the record. The
DERIVATION-UNCERTAIN comments attached to the invoice-signature /
evidence and pool-statement rows are original text and remain
visible. Nothing else in the file changed; the full diff is §7.

**Count accounting.** The amendment removed table *rows* (data
iterated by the matrix and CSRF tests), not tests:
`blind_stage1` still runs **41 passed / 0 failed / 0 ignored**,
exactly baseline. The cells no longer asserted are the 13 rows ×
the suite's actor set in `matrix_every_declared_route_every_actor`
and the 4 POST rows in
`csrf_every_post_route_requires_it_no_get_route_does`.

## 3. Task 2 — STOPPED: a third locked pin the BM/BL report missed

The brief for this pass (and BM-BL-FIX-REPORT §3, Conflict 2)
states the `apply_action` invoice guard is pinned by
`blind_direct_v1`'s `accept_on_legacy_order_still_requires_invoice`.
That is true but incomplete. **`blind_stage4.rs` pins the same
guard, actively, at baseline:**

- Its header's assertion list §C states (lines 58–59): "`accept`
  by the seller on a Requested order with no issued invoice yields
  InvoiceRequired", grounded in contract §11 ("until the payment
  stages, accept is always refused with that reason").
- Its test `c_accept_without_issued_invoice_yields_invoice_required`
  (line 1205) builds an order through its own `make_shop` /
  `fresh_order` fixtures and asserts the seller's accept is refused
  with `OrderError::InvoiceRequired`, and the order stays
  `Requested`.
- The fixtures are materially identical for the guard's purposes:
  both suites insert the listing directly with
  `destination_module = 'signed-address-pool'`; the seller has an
  identity key but **no payment identity and no pool**, so
  `create_order` takes the no-assignment path. `orders.rs`'s own
  comment at order creation confirms this is the same path: "No
  identity => the order proceeds exactly as before this release
  (pre-payment behaviour; **the Stage 4 locked suites exercise
  this path**), with no assignment and no payment page."
- The pin is live, not vestigial: at pre-batch HEAD, with the
  guard in place, `c_accept_without_issued_invoice_yields_invoice_required`
  passes (verified standalone in this session), and `blind_stage4`
  runs at its full baseline of **58 passed / 0 failed / 6 ignored**
  in the final gate.

The guard in question is the accept branch of `apply_action`
(`crates/app/src/orders.rs`, lines 570–591 at HEAD): for an
unassigned order, accept requires an `invoices` row in state
`Issued`, else `OrderError::InvoiceRequired`. Removing it flips
**both** suites' orders to a successful accept — there is no
property of the two fixture orders on which a narrower removal
could distinguish them (the repo working brief's phrasing about
`module_pins.destination = 'signed-invoice'` does not describe
this guard: the accept guard keys on assignment existence, not on
the destination pin, and both fixtures pin
`signed-address-pool`). Amending `blind_direct_v1` while leaving
the guard in place would fail `blind_direct_v1` instead. Every
route through task 2 therefore requires amending
`blind_stage4.rs`, which this pass is **not** authorized to touch
(exactly two locked files were authorized; "every other locked
file must be byte-identical" and the gate baseline holds
`blind_stage4` at 58/0/6).

Per the pass instructions — stop and document rather than invent
semantics or exceed the authorization — **task 2 was not
executed**: no change to `orders.rs`, no change to
`blind_direct_v1.rs`, and the non-locked knock-on identified
during scoping was also left for the same future pass
(`crates/app/tests/payments_db.rs`, line 432, asserts the same
gate in `pool_empty_refuses_and_no_identity_keeps_legacy_behaviour`).
The §9 dispute-timing guard for unassigned orders
(`orders.rs`, lines 608–638) is a separate mechanism, was never
named by either conflict document, and is also untouched.

**What unblocks task 2:** an owner decision extending the
amendment authorization to `blind_stage4.rs` — specifically its
§C header pin and `c_accept_without_issued_invoice_yields_invoice_required`
— on the same terms as this pass (originals kept visible, dated
note). With that, the originally briefed work is mechanical:
remove the accept guard in `apply_action`, amend
`blind_direct_v1`'s test to assert the new behaviour (a legacy
no-assignment order's accept succeeds with no invoice in
existence), amend the stage4 test likewise, and update the
`payments_db.rs` assertion. Note the design context the owner
would be ratifying: after removal, accept of a legacy unassigned
order lands it in `AwaitingPayment` with no address to pay;
`mark_paid` still refuses unassigned orders with `NoAssignment`
(pinned by `blind_direct_v1`'s
`mark_paid_state_and_assignment_guards`, unaffected), so
acceptance alone cannot fabricate a payment — but the owner
should confirm that "accept succeeds, payment can never be
attested" is the intended end state for pre-Direct-Payments
orders, since that is a product judgement, not a code fact.

## 4. Task 3 — exception set is EMPTY, and it passes

`crates/app/tests/modules_audit_fixes.rs`:
`PINNED_DEAD_RULES` is now `&[]`, with the comment rewritten to
record that the set was emptied by this amendment and that any
future exception must be a deliberate, documented act. The probe
test `every_authz_rule_names_a_served_route` passes in the final
gate (suite total 9/0/0, as baseline): all 80 remaining rules in
`app::authz::ROUTES` name routes the router serves.

## 5. Task 4 — full gate, and two environment incidents

Environment: standard gate environment (`DATABASE_URL`,
`MEDIA_WORKER`, `MEDIA_DIR`, `BLOB_DIR`, disk-backed `TMPDIR`,
`NETTLE_PREGENERATED_BINDINGS=~/pgsys/nettle-bindings.rs`,
`PKG_CONFIG_PATH=~/pkgconfig`).

Incidents, for the record. (1) This session began on a replaced
VM: Postgres (binaries, data, the `pguser` account) was gone and
was re-provisioned per AGENTS.md before any work (Zonky binaries
from `~/pgsys` to `/tmp/pgx`, data `/tmp/pgdata`, port 5432,
`marketplace_dev` recreated, migrations 0001–0015, 38 tables).
(2) During the first full-gate attempt the VM was replaced
**again**: an initial foreground run was aborted, its background
rerun then lost Postgres mid-run — every database test after
that point failed with sqlx `PoolTimedOut`, `blind_direct_v1`
showed 35 spurious failures, and the run exited 101. That run is
**discarded in full**. Postgres was re-provisioned a second time
(same recipe; 38 tables) and the gate was rerun clean, alone,
to completion. Only that run's numbers follow.

### Final complete run — per-target results

`cargo test --workspace` (**exit 0**), then
`cargo test --manifest-path seller-helper/Cargo.toml` (exit 0):

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
| **blind_direct_v1** | **42** | **0** | **0** | **42** |
| **blind_stage1 (amended)** | **41** | **0** | **0** | **41** |
| blind_stage2 | 38 | 0 | 0 | 38 |
| blind_stage3 | 34 | 0 | 0 | 34 |
| blind_stage4 | 58 | 0 | 6 | 58/6 |
| blind_stage5 | 35 | 0 | 3 | 35/3 |
| blind_stage6 | 83 | 0 | 0 | 83 |
| blind_stage9 | 43 | 0 | 0 | 43 |
| blind_stage10 | 32 | 0 | 0 | 32 |
| (doc/empty targets) | 0 | 0 | 0 | — |
| **WORKSPACE TOTAL** | **585** | **0** | **9** | **585/0/9** |
| **seller-helper** | **18** | **0** | **0** | **18/18** |

Targeted pre/post checks around the edits agreed: `blind_stage1`
41/0/0, `modules_audit_fixes` 9/0/0, app lib 54/0/0, controls
`blind_stage4` 58/0/6 and `blind_direct_v1` 42/0/0.

**fmt / clippy — toolchain-generation drift, stated plainly.**
`cargo clippy --workspace --all-targets` exits 0. Two stricter
checks do **not** reproduce the BM/BL batch's clean results in
this VM generation, and the cause is pre-existing, verified
against a pristine `fcf57a6` worktree:

- `cargo fmt --all -- --check` (pinned toolchain 1.99.0) reports
  945 diff hunks on the **pristine** tree — this generation's
  rustfmt (1.10.0) wants every one-line struct literal expanded,
  tree-wide, including in locked files untouched for many batches
  (e.g. `blind_stage9.rs`). After this pass: 947 hunks — the +2
  net is hunk re-segmentation around the inserted comments
  (`blind_stage1.rs` 24 → 22 hunks, `modules_audit_fixes.rs`
  18 → 18, `authz.rs` 6 → 10, all of them pre-existing
  `RouteRule` lines; no hunk asks to reformat any line this pass
  wrote). Reformatting the tree to satisfy this generation's
  rustfmt would rewrite locked files and is out of scope.
- `cargo clippy --workspace --all-targets -- -D warnings
  -A dead_code -A clippy::too_many_arguments` fails on 18
  pre-existing lints in untouched files (`web.rs` ×8,
  `payments.rs` ×3, `moderation.rs` ×2, `disputes.rs`,
  `orders.rs`, `reputation.rs`, `passwords.rs`, `keys.rs` ×1 —
  `type_complexity`, redundant pattern matching, large `Err`
  variant, items-after-test-module). **Zero** clippy findings, in
  either run, touch `authz.rs`, `blind_stage1.rs`, or
  `modules_audit_fixes.rs`.

## 6. Locked-path manifests (SHA-256)

Scope: `marketplace/tests/security/**` (recursive) +
`marketplace/docs/invariants.md` — 17 files. The PRE manifest was
taken before any edit and matches the BM/BL batch's PRE manifest
exactly. The POST manifest was taken after the final gate. Full
contents are committed beside this report as
`BL1-AMENDMENT-LOCKED-MANIFEST-PRE-2026-10-19.txt` and
`BL1-AMENDMENT-LOCKED-MANIFEST-POST-2026-10-19.txt`.

Diff of the two manifests — exactly one line:

```
< 7282307b7ffab188ffcf08849281e53d693229266c0733fc03e18cb13a0beb91  marketplace/tests/security/blind_stage1.rs
> 702a23b531fdab59bf75b24fd3f8830c3fc2461ecef69bea072ee0a2b92e933e  marketplace/tests/security/blind_stage1.rs
```

Exactly **one** locked file differs — `blind_stage1.rs`, amended
under task 1. `blind_direct_v1.rs` is byte-identical
(`1f027a12219cad65a6b2aecf66f1d0a0a82ede31b6394f2f960e13d5519b389e`
in both manifests) because task 2 was stopped (§3). Every other
locked file, including `docs/invariants.md`, is byte-identical.

## 7. Full diffs of the amended locked files

### 7.1 `marketplace/tests/security/blind_stage1.rs` — the complete diff

(`git diff fcf57a6..6bcb413 -- marketplace/tests/security/blind_stage1.rs`)

```diff
diff --git a/marketplace/tests/security/blind_stage1.rs b/marketplace/tests/security/blind_stage1.rs
index 17f1634..c578d8a 100644
--- a/marketplace/tests/security/blind_stage1.rs
+++ b/marketplace/tests/security/blind_stage1.rs
@@ -291,6 +291,28 @@ enum Class {
 
 /// The route table, derived from spec §17's route list (path forms as
 /// written there) and classified by contract §7's authorization semantics.
+///
+/// AMENDMENT (owner decision 2026-10-19 — BL1 completion pass; the
+/// owner was asked whether to authorize the pass and delegated the
+/// decision with "do whatever you think is best"; the decision taken
+/// was YES): 13 rows were removed from this table, together with the
+/// rules they pinned in `app::authz::ROUTES`. Each removed row is
+/// kept visible below, commented out in place with a REMOVED marker.
+/// The rows named routes the router has never served in the Direct
+/// Payments build — leftovers of the retired invoice system and its
+/// contemporaries: the six `/invoices/*` routes, the two
+/// `/pools/{id}/statement.txt[.asc]` routes, the three
+/// `/seller/pools*` routes (pool management moved to
+/// `/seller/payment-batches`), `GET /messages/{id}/download`
+/// (superseded by `/conversations/{id}/messages/{mid}/download`) and
+/// `GET /security`. While the rows stood, the matching dead rules
+/// had to stay in the authorization table, where any future handler
+/// would silently inherit them. The plain-language assertion list
+/// at the top of this file (A1–A3) describes the table as
+/// originally locked and is kept verbatim for the record; the
+/// table below is the amended one. `POST /orders/{id}/invoice` is
+/// NOT among the removed rows: it matches the served
+/// `/orders/{id}/{action}` route pattern and stays.
 const ROUTES: &[(&str, &str, Class)] = &[
     // --- Public (spec §17 unauthenticated set; contract §7) ---
     ("GET", "/listings", Class::Public),
@@ -301,7 +323,8 @@ const ROUTES: &[(&str, &str, Class)] = &[
     ("POST", "/register", Class::Public),
     ("GET", "/login", Class::Public),
     ("POST", "/login", Class::Public),
-    ("GET", "/security", Class::Public),
+    // REMOVED 2026-10-19 (BL1 amendment, see the AMENDMENT note above):
+    // ("GET", "/security", Class::Public),
     ("GET", "/limitations", Class::Public),
     ("GET", "/policy", Class::Public),
     // --- Authenticated, any role (contract §7: account, security/keys,
@@ -347,37 +370,42 @@ const ROUTES: &[(&str, &str, Class)] = &[
     ("POST", "/orders/{id}/complete", Class::Authenticated),
     ("POST", "/orders/{id}/dispute", Class::Authenticated),
     ("POST", "/orders/{id}/invoice", Class::Authenticated),
-    ("GET", "/invoices/{id}", Class::Authenticated),
-    ("GET", "/invoices/{id}/qr.png", Class::Authenticated),
-    ("GET", "/invoices/{id}/statement.txt", Class::Authenticated),
-    ("GET", "/invoices/{id}/statement.txt.asc", Class::Authenticated),
+    // REMOVED 2026-10-19 (BL1 amendment, see the AMENDMENT note above):
+    // ("GET", "/invoices/{id}", Class::Authenticated),
+    // ("GET", "/invoices/{id}/qr.png", Class::Authenticated),
+    // ("GET", "/invoices/{id}/statement.txt", Class::Authenticated),
+    // ("GET", "/invoices/{id}/statement.txt.asc", Class::Authenticated),
     // DERIVATION-UNCERTAIN: POST /invoices/{id}/signature is performed by
     // the order's seller in the §11 flow, and evidence submission by the
     // buyer; contract §7 names only the seller dashboard and listing
     // creation as seller-only surfaces, so both are encoded as
     // any-authenticated at route level with the party check at object
     // level.
-    ("POST", "/invoices/{id}/signature", Class::Authenticated),
-    ("POST", "/invoices/{id}/evidence/{module}", Class::Authenticated),
+    // REMOVED 2026-10-19 (BL1 amendment, see the AMENDMENT note above):
+    // ("POST", "/invoices/{id}/signature", Class::Authenticated),
+    // ("POST", "/invoices/{id}/evidence/{module}", Class::Authenticated),
     // DERIVATION-UNCERTAIN: spec §17 adds "a pool statement is visible
     // only to its seller and to buyers holding an invoice from that
     // pool". That is an object-level visibility rule; at route level the
     // statement is not public, so anonymous -> LoginRequired and every
     // signed-in role -> Allow, with the pool-specific rule on top.
-    ("GET", "/pools/{id}/statement.txt", Class::Authenticated),
-    ("GET", "/pools/{id}/statement.txt.asc", Class::Authenticated),
+    // REMOVED 2026-10-19 (BL1 amendment, see the AMENDMENT note above):
+    // ("GET", "/pools/{id}/statement.txt", Class::Authenticated),
+    // ("GET", "/pools/{id}/statement.txt.asc", Class::Authenticated),
     ("GET", "/conversations/{id}", Class::Authenticated),
     ("POST", "/conversations/{id}/messages", Class::Authenticated),
-    ("GET", "/messages/{id}/download", Class::Authenticated),
+    // REMOVED 2026-10-19 (BL1 amendment, see the AMENDMENT note above):
+    // ("GET", "/messages/{id}/download", Class::Authenticated),
     ("GET", "/disputes/{id}", Class::Authenticated),
     ("POST", "/disputes/{id}/disclosures", Class::Authenticated),
     ("POST", "/reports", Class::Authenticated),
     // --- Seller surfaces (Seller or Admin; contract §7) ---
     ("GET", "/seller", Class::Seller),
     ("POST", "/seller/listings", Class::Seller),
-    ("GET", "/seller/pools", Class::Seller),
-    ("POST", "/seller/pools", Class::Seller),
-    ("POST", "/seller/pools/{id}/signature", Class::Seller),
+    // REMOVED 2026-10-19 (BL1 amendment, see the AMENDMENT note above):
+    // ("GET", "/seller/pools", Class::Seller),
+    // ("POST", "/seller/pools", Class::Seller),
+    // ("POST", "/seller/pools/{id}/signature", Class::Seller),
     // --- Moderation surfaces (Moderator or Admin; contract §7) ---
     ("GET", "/moderation", Class::Moderation),
     ("POST", "/disputes/{id}/resolve", Class::Moderation),
```

### 7.2 `marketplace/tests/security/blind_direct_v1.rs` — no diff

The file was **not amended**: SHA-256
`1f027a12219cad65a6b2aecf66f1d0a0a82ede31b6394f2f960e13d5519b389e`
before and after the pass, byte-identical to its state at every
prior gate. Its amendment was task 2's second half and fell with
the task (§3): amending its `accept_on_legacy_order_still_requires_invoice`
to assert the new behaviour is only meaningful together with the
guard removal that `blind_stage4.rs` blocks.

### 7.3 Appendix — the non-locked diffs, in full

(`git diff fcf57a6..6bcb413` for the two non-locked files changed
by tasks 1 and 3.)

```diff
diff --git a/marketplace/crates/app/src/authz.rs b/marketplace/crates/app/src/authz.rs
index e63bec0..748026e 100644
--- a/marketplace/crates/app/src/authz.rs
+++ b/marketplace/crates/app/src/authz.rs
@@ -16,7 +16,13 @@
 //! moderation queue pages, sanitized-media serving, profile and inbox
 //! actions). They are declared here with the class of their surface so
 //! the table stays complete for the running app; §17 remains the
-//! authority for the routes it does list. (History: §17 originally
+//! authority for the routes it does list. (BL1 amendment, 2026-10-19:
+//! 13 rows naming routes the router has never served in the Direct
+//! Payments build — the retired /invoices/* and pool-statement rows,
+//! /seller/pools*, /messages/{id}/download and /security — were
+//! removed from this table and from the locked blind_stage1 suite's
+//! expected table, so a future handler cannot silently inherit them;
+//! see the AMENDMENT note in that suite.) (History: §17 originally
 //! declared no GET /orders collection route, so `authorize` denied it
 //! while the Stage 4 draft web layer served the page — deviation
 //! recorded in RETROFIT-REPORT.md. Resolved by owner amendment
@@ -56,7 +62,13 @@ pub const ROUTES: &[RouteRule] = &[
     RouteRule { method: "POST", path: "/register", roles: PUBLIC, csrf: true },
     RouteRule { method: "GET", path: "/login", roles: PUBLIC, csrf: false },
     RouteRule { method: "POST", path: "/login", roles: PUBLIC, csrf: true },
-    RouteRule { method: "GET", path: "/security", roles: PUBLIC, csrf: false },
+    // BL1 amendment (2026-10-19): the §17-era "GET /security" row was
+    // removed — the router never served that path (the security
+    // guide lives at /security-guide, account security at
+    // /account/security), so the row only waited to be inherited by
+    // a future handler. Twelve further dead rows were removed the
+    // same day; see the notes at their sites below and the
+    // AMENDMENT note in tests/security/blind_stage1.rs.
     RouteRule { method: "GET", path: "/limitations", roles: PUBLIC, csrf: false },
     RouteRule { method: "GET", path: "/policy", roles: PUBLIC, csrf: false },
     // -- Authenticated, any role (§17 signed-in surfaces; contract §7) --
@@ -94,28 +106,28 @@ pub const ROUTES: &[RouteRule] = &[
     RouteRule { method: "POST", path: "/orders/{id}/manual-report", roles: AUTHENTICATED, csrf: true },
     RouteRule { method: "POST", path: "/orders/{id}/confirm-payment", roles: AUTHENTICATED, csrf: true },
     RouteRule { method: "POST", path: "/orders/{id}/declare-not-received", roles: AUTHENTICATED, csrf: true },
-    RouteRule { method: "GET", path: "/invoices/{id}", roles: AUTHENTICATED, csrf: false },
-    RouteRule { method: "GET", path: "/invoices/{id}/qr.png", roles: AUTHENTICATED, csrf: false },
-    RouteRule { method: "GET", path: "/invoices/{id}/statement.txt", roles: AUTHENTICATED, csrf: false },
-    RouteRule { method: "GET", path: "/invoices/{id}/statement.txt.asc", roles: AUTHENTICATED, csrf: false },
-    RouteRule { method: "POST", path: "/invoices/{id}/signature", roles: AUTHENTICATED, csrf: true },
-    RouteRule { method: "POST", path: "/invoices/{id}/evidence/{module}", roles: AUTHENTICATED, csrf: true },
-    RouteRule { method: "GET", path: "/pools/{id}/statement.txt", roles: AUTHENTICATED, csrf: false },
-    RouteRule { method: "GET", path: "/pools/{id}/statement.txt.asc", roles: AUTHENTICATED, csrf: false },
+    // BL1 amendment (2026-10-19): the six /invoices/* rows and the
+    // two /pools/{id}/statement.txt[.asc] rows were removed. Direct
+    // Payments retired the invoice system; the router serves none
+    // of these paths, and the rows only waited to be inherited by a
+    // future handler.
     RouteRule { method: "GET", path: "/conversations/{id}", roles: AUTHENTICATED, csrf: false },
     RouteRule { method: "POST", path: "/conversations/{id}/messages", roles: AUTHENTICATED, csrf: true },
     RouteRule { method: "POST", path: "/conversations/{id}/block", roles: AUTHENTICATED, csrf: true },
     RouteRule { method: "POST", path: "/conversations/blocks/{id}", roles: AUTHENTICATED, csrf: true },
-    RouteRule { method: "GET", path: "/messages/{id}/download", roles: AUTHENTICATED, csrf: false },
+    // BL1 amendment (2026-10-19): the "GET /messages/{id}/download"
+    // row was removed — superseded by the served
+    // /conversations/{id}/messages/{mid}/download route.
     RouteRule { method: "GET", path: "/disputes/{id}", roles: AUTHENTICATED, csrf: false },
     RouteRule { method: "POST", path: "/disputes/{id}/disclosures", roles: AUTHENTICATED, csrf: true },
     RouteRule { method: "POST", path: "/reports", roles: AUTHENTICATED, csrf: true },
     // -- Seller surfaces --
     RouteRule { method: "GET", path: "/seller", roles: SELLER, csrf: false },
     RouteRule { method: "POST", path: "/seller/listings", roles: SELLER, csrf: true },
-    RouteRule { method: "GET", path: "/seller/pools", roles: SELLER, csrf: false },
-    RouteRule { method: "POST", path: "/seller/pools", roles: SELLER, csrf: true },
-    RouteRule { method: "POST", path: "/seller/pools/{id}/signature", roles: SELLER, csrf: true },
+    // BL1 amendment (2026-10-19): the three /seller/pools* rows were
+    // removed — pool management moved to /seller/payment-identity
+    // and /seller/payment-batches in Direct Payments; the router
+    // serves none of the pool paths.
     // Direct Payments v1 (2026-10-15): payment identity + batch upload
     // live on the seller dashboard surface.
     RouteRule { method: "POST", path: "/seller/payment-identity", roles: SELLER, csrf: true },
diff --git a/marketplace/crates/app/tests/modules_audit_fixes.rs b/marketplace/crates/app/tests/modules_audit_fixes.rs
index f140a70..fec78bb 100644
--- a/marketplace/crates/app/tests/modules_audit_fixes.rs
+++ b/marketplace/crates/app/tests/modules_audit_fixes.rs
@@ -480,29 +480,19 @@ async fn publish_requires_payment_identity_and_unused_pool() {
     srv.stop();
 }
 
-/// The dead rules the LOCKED blind_stage1 suite pins: its expected
-/// authorize() table names each of these, so authorize() must keep
-/// answering Allow for them even though the router serves no such
-/// route. They cannot be removed without amending that locked
-/// suite (not authorized — see the batch report). This test pins
-/// the set: a NEW dead rule fails here, and if a pinned rule ever
-/// gains a route (or the locked suite is amended), the entry must
-/// be deliberately removed.
-const PINNED_DEAD_RULES: &[(&str, &str)] = &[
-    ("GET", "/invoices/{id}"),
-    ("GET", "/invoices/{id}/qr.png"),
-    ("GET", "/invoices/{id}/statement.txt"),
-    ("GET", "/invoices/{id}/statement.txt.asc"),
-    ("POST", "/invoices/{id}/signature"),
-    ("POST", "/invoices/{id}/evidence/{module}"),
-    ("GET", "/pools/{id}/statement.txt"),
-    ("GET", "/pools/{id}/statement.txt.asc"),
-    ("GET", "/seller/pools"),
-    ("POST", "/seller/pools"),
-    ("POST", "/seller/pools/{id}/signature"),
-    ("GET", "/messages/{id}/download"),
-    ("GET", "/security"),
-];
+/// The exception set is EMPTY since the BL1 amendment pass
+/// (2026-10-19): the locked blind_stage1 suite was amended to drop
+/// its 13 dead rows (the /invoices/*, pool-statement,
+/// /seller/pools*, /messages/{id}/download and /security rules),
+/// and the dead rules came out of `app::authz::ROUTES` with them.
+/// Before that amendment this list carried those 13 rules, because
+/// the locked suite pinned them in place. It is now kept as an
+/// empty set so this test fails on ANY authorization rule that
+/// names a route the router does not serve — a new dead rule, or
+/// a served route disappearing from under an existing rule. If a
+/// rule ever legitimately becomes an exception, re-adding it here
+/// must be a deliberate, documented act.
+const PINNED_DEAD_RULES: &[(&str, &str)] = &[];
 
 #[tokio::test]
 async fn every_authz_rule_names_a_served_route() {
@@ -548,8 +538,8 @@ async fn every_authz_rule_names_a_served_route() {
     assert_eq!(
         seen_dead, expected_dead,
         "the set of authorization rules naming unserved routes changed \
-         ({checked} rules probed): only the blind_stage1-pinned dead \
-         rules may be unserved"
+         ({checked} rules probed): since the BL1 amendment (2026-10-19) \
+         NO authorization rule may name an unserved route"
     );
     srv.stop();
 }
```

## 8. Commits and what remains

Commits (local only, branch `deployment-fix-batch`, NOT pushed):

- `6bcb413` — BL1 amendment (task 1+3): remove the 13 dead
  authorization rules (authz.rs, blind_stage1 amendment,
  PINNED_DEAD_RULES emptied).
- This report + the two manifest files.

**Task 2 remains open** and is the only incomplete item in this
pass. It needs one owner decision: extend the locked-amendment
authorization to `blind_stage4.rs`'s §C pin and
`c_accept_without_issued_invoice_yields_invoice_required`, and
confirm the intended end state for legacy unassigned orders
(§3, final paragraph). With that decision the remainder of BL1
is a small mechanical pass. BL1's other pieces from the BM/BL
batch (publish guard, dead form options, rule-to-route test)
were already complete; with tasks 1 and 3 here, the only
unretired piece of the invoice system left in the authorization
layer is the accept guard itself.
