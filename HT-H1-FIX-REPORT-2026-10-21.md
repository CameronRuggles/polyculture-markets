# Polyculture Markets — HT Stage H1 Audit Fix Report: Tasks 1 and 3

2026-10-21. Scope: fix brief tasks 1 (F2, CRLF in `terms_submit`) and
3 (F3, gate must not pass without a database + Dave fixture renewal)
from the H1 audit of `d21c523`. Three commits on top of the audited
commit, on branch `deployment-fix-batch`; nothing pushed:

- `d3a621f` — task 3a: renew the Dave fixture family
- `69a4b68` — task 1: normalise CRLF in `terms_submit` + new test
- `38918f4` — task 3b/3c: pool helpers panic without a DB; gate preflight

Not touched: locked suites' assertions, `docs/invariants.md`, and
the F1 marketplace-id code (task 2 waits on owner question 1, since
answered but not part of this batch).

Environment used for every run below: the system PostgreSQL 16
cluster (found stopped, started with `pg_ctlcluster`), database
`marketplace_dev` created fresh with all 16 migrations applied
(39 tables), `DATABASE_URL=postgres://postgres:dev@localhost:5432/marketplace_dev`,
`MEDIA_WORKER=<workspace>/target/debug/media-worker`,
`NETTLE_PREGENERATED_BINDINGS=$HOME/pgsys/nettle-bindings.rs`,
`PKG_CONFIG_PATH=$HOME/pkgconfig`.

## Task 1 (F2) — CRLF normalisation in `terms_submit`

`marketplace/crates/app/src/web.rs`: the handler now applies the
existing `normalize_crlf` to the form's `statement` and `signature`
before calling `lst::submit_terms`, matching the rotation handler.
What is stored is exactly what was verified.

New test `marketplace/crates/app/tests/ht_terms_web.rs`
(`terms_submit_accepts_browser_crlf`): builds a real seller key
(Sequoia), installs it through the app layer, creates a listing,
signs a valid v1 terms statement, and POSTs `/listings/{id}/terms`
through the real router over a socket with statement and signature
converted to CRLF line endings throughout. Asserts: 303 redirect to
`/seller?pmsg=terms_saved`; exactly one row in
`listing_terms_statements`; the stored statement is the normalised
LF text (no `\r`).

Acceptance evidence:
- With the fix: `cargo test -p app --test ht_terms_web` → 1 passed,
  exit 0.
- Negative control (fix stashed): the same test FAILS (the submit is
  rejected), exit 101. Restored afterwards.

Scoping (recorded in the commit and the test header): the F1 half of
the end-to-end path — a default instance hands this handler the v1
slug, which the `mkt_` rule refuses — is untouched, awaiting the
owner's decision. The test therefore configures its `AppState` with
a valid `mkt_` id (the same id blind_ht1's router uses), isolating
the CRLF behaviour.

## Task 3a (F3) — Dave fixture renewal

Applied from the prepared kit `fixture-regen-dave-2026-10-20/`
(three candidate certs, `DAVE_FPR`, fixtures README). Old-vs-new
diff summary, captured with `gpg --show-keys` before replacing:

- Fingerprint continuity: **none by key, by design.** The original
  family's private keys were discarded (fixtures README), so the
  old fingerprint cannot be extended or recreated. Renewal is a new
  key family with the same shape: RSA 2048 primary [SC], RSA 2048
  encryption subkey [E], UID `Fixture dave`; same three filenames.
- Old family: primary `61CD1CD1481CE46CF786B1A352DC295EC3B2A7A3`,
  created 2026-10-19T02:37:56Z. Short cert expired
  **2026-10-20T02:37:56Z** (1-day window). Extended and added-subkey
  certs expire 2028-10-18T02:37:57Z.
- New family: primary `5A37E91C3A9C8A8BAAEB9503DD38B3DF073E742C`,
  created 2026-10-20T18:30:38Z. Short cert expires
  **2027-10-20T18:30:38Z** (365 days — the one deliberate deviation:
  nothing in the suite asserts the duration, and a 1-day cert would
  restart the 24-hour clock). Extended expires 2028-10-19T18:30:39Z;
  added-subkey as extended plus a third subkey with no expiry.

Acceptance evidence: with Postgres running,
`cert_refresh_accepts_new_signatures_only` **passes** against the
renewed fixture (1 passed, exit 0); the whole messaging_audit file
passes 9/0 (see totals below, with the environment note there).

## Task 3b (F3) — pool helpers panic when the DB is set but unreachable

Every app-suite `pool()` helper converted its connect result with
`.ok()`, turning "DATABASE_URL set, database down" into the same
silent skip as "unset". All of them now `.expect("DATABASE_URL is
set but the database is unreachable")` in an `Some(...)` return;
unset still returns `None`. Per file:

- One-line form converted: `dispute_signature.rs`,
  `media_disputes_audit.rs`, `media_verification.rs`,
  `messaging_audit.rs`, `payments_db.rs`.
- Multi-line form converted: `account_security.rs`,
  `audit_fix_tasks.rs` (pool, 24 connections), `modules_audit_fixes.rs`,
  `stage1_db.rs`, `tx_proof_flow.rs`, `verification_fixes.rs`.
- `audit_fix_tasks.rs` `guard_pool()`: the admin connect, the
  existence check, the CREATE DATABASE, the scratch-pool connect and
  the setup DDL all swallowed errors with `.ok()?`; each now expects
  with a specific message.
- `media_serve_http.rs`: the inline `let Ok(pool) = ... else { return }`
  now panics on connect failure the same way (its separate
  `MEDIA_WORKER`-unset skip is unchanged — that is not a DB gate).
- The new `ht_terms_web.rs` helper is written to the new pattern.
- Blind suites (checked as the audit names them): `blind_stage1.rs`
  and `blind_stage3.rs` already panic on a set-but-unreachable
  DATABASE_URL (verified in the tree, unchanged). `blind_stage2.rs`'s
  `connect()` had the identical swallow and is fixed identically —
  the connect helper only; no assertion in any locked suite was
  touched. (`blind_ht1`, `blind_direct_v1`, `blind_stage4/6/9/10`
  already panic via `.expect(...)` connects.)

## Task 3c (F3) — gate preflight

New `run-gate.sh` at the repo root runs the recorded gate shape
(`cargo test --workspace`, then the seller-helper workspace) behind
a preflight: `DATABASE_URL` unset → exit 2 with the reason printed;
set but not answering `SELECT 1` via psql → exit 2. Evidence:
unset → exit 2; set with Postgres stopped → exit 2; both before any
compilation.

DB-stopped acceptance: with Postgres stopped and `DATABASE_URL`
set, `cargo test -p app --test messaging_audit
cert_refresh_accepts_new_signatures_only` exits **101** (the test
panics at the pool helper with the message above), and
`cargo test -p app --test ht_terms_web` exits **101**. A full
`cargo test -p app` in the stopped state was started and reached
the account_security binary (its non-DB tests are slow; the DB
tests fail fast on the panic) but was capped at 300 s before
finishing — it did not, and cannot, report success.

## Totals after the changes (ran, not counted)

App suite, per target (DB up, env as above; the one failure is
analysed below the table):

| Target | Result |
| --- | --- |
| app lib | 54 passed / 0 failed |
| account_security | 14 / 0 |
| audit_fix_tasks | 4 / 0 |
| dispute_signature | 1 / 0 |
| ht_terms_web (new) | 1 / 0 |
| media_disputes_audit | 9 / 0 |
| media_serve_http | 1 / 0 |
| media_verification | 6 / 0 |
| messaging_audit | 9 / 0 |
| modules_audit_fixes | 8 passed / **1 failed** |
| payments_db | 11 / 0 |
| stage1_db | 1 / 0 |
| tx_proof_flow | 20 / 0 |
| verification_fixes | 10 / 0 |

Integration total: 95 passed / 1 failed of 96 (the baseline files
account for 94 passed / 1 failed of 95 — matching the audit's
static count exactly — plus the 1 new test passing). With the app
lib's 54, the app package total is 149 passed / 1 failed of 150.

Also run: `cargo test -p domain` → 15/0, exit 0.
`cargo test -p security-tests --test blind_ht1` → 24/0, exit 0.
`cargo test -p security-tests --test blind_stage2` → 38/0, exit 0.

Environment note on messaging_audit: its test server puts BLOB_DIR
under `std::env::temp_dir()`. On this VM generation `/tmp` is a
512 MB tmpfs, and the V9 free-disk floor
(`MSG_DISK_FLOOR_DEFAULT` = 1 GiB) then refuses every message send
with StorageCeiling — 4 messaging tests fail for that reason alone
when TMPDIR points at the tmpfs. With `TMPDIR` on the real
filesystem (as in the runs above) the file passes 9/0. This is an
environment property, not a code regression: none of these commits
touch `messages.rs`, the floor, or BLOB_DIR handling — and it is
exactly the class of failure F3 hid, since the suite previously
"passed" without reaching the database at all.

## The one failure: pre-existing, not from this batch

`modules_audit_fixes::publish_requires_payment_identity_and_unused_pool`
fails: `assertion left == right failed: publish succeeds once the
seller can be paid — left: "/seller?pmsg=terms_required", right:
"/seller"`. The test (BM/BL era) sets up payment identity + pool and
publishes; since H1 the publish handler also requires pinned terms
(the gate at `web.rs` publish path), so the publish is refused.

Verified pre-existing: the same single test, run from a pristine
worktree of the audited commit `d21c523` against the live DB, fails
identically (exit 101, same `terms_required` redirect). None of
these commits touch the publish handler or that test's logic (only
its pool helper). It went unseen because, per F3, the app suite was
not reaching the database in the reported H1 gate. It belongs to
the fix brief's remaining work (task 4's clean full gate cannot be
green until this test is reconciled with the H1 terms gate — most
likely by pinning terms in its setup, which becomes possible end
to end once task 2 lands the `mkt_` id).
