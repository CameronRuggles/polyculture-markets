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

---

# Addendum — Tasks 2 and 4, and the BL1 publish-test reconciliation

2026-10-21 (later). Scope: fix brief task 2 (F1, a real `mkt_`
marketplace id — gated on owner question 1, answered: mint a
separate permanent id, do NOT relax the parser), the reconciliation
of the one failure recorded above, and fix brief task 4 (F15, run
and record the full gate). Three commits on top of `0d1ecc1`, same
branch; nothing pushed:

- `664cf63` — task 2: the per-instance `mkt_` id (F1)
- `eb30a7e` — reconciliation: the BL1 publish test completed for H1
- `7f6bf3a` — task 4: run-gate.sh executes the brief's gate shape

## Task 2 (F1) — a real `mkt_` marketplace id per instance

**Design.** `InstanceConfig` gains `ht_marketplace_id` beside the
v1 slug (`marketplace_id`, unchanged — it still feeds every
`xmr-direct-v1` message via the payments config). Resolution
(`config.rs`, still a pure function of the injected getter):

- `HT_MARKETPLACE_ID` set: the value must already satisfy the
  statement family's rule (`mkt_` + 32 lowercase hex, checked with
  `modules_api::validate_public_id`) or resolution fails closed
  with `InvalidValue` — the slug, a truncated id, uppercase hex,
  and the empty string are all refused at startup instead of by
  every statement parser forever.
- Unset: a fresh id is generated (`mkt_` + 16 random bytes, hex).

**Persistence.** `resolve` is stateless per process, so permanence
follows the codebase's one existing generated-once mechanism: the
key file's lifecycle (`keyfile.rs`, audit AL1). A new sibling
module `htid.rs` (`load_existing` / `load_or_generate`, file
created 0600 from creation) is wired into `main.rs` immediately
after the key-file load, before the pool opens: when
`HT_MARKETPLACE_ID` is not set, the resolved (fresh) value is
replaced by the persisted one from `HT_ID_FILE_PATH` (default
`marketplace.htid`) — generated and stored on first boot in the
Development profile; outside Development the file must already
exist, because silently minting a replacement would orphan every
pinned terms statement and every configured helper on the
instance, the AL1 failure class one level up. With the env
override set, the file is neither read nor written. The id is not
a secret (it is printed on the seller page); its integrity is
what the file protects.

**Use.** `terms_submit` now verifies against
`st.instance.ht_marketplace_id` (it previously passed the payments
slug — the F1 defect). The seller page displays the HT id in a new
"Signed terms (Hidden Trades)" block beside the terms forms,
labelled as the value the helper's `init` copies, and explicitly
as NOT the payments marketplace ID shown above it.

**Acceptance** (the brief's, verbatim in effect): new test
`marketplace/crates/app/tests/ht_terms_default_instance.rs` builds
its AppState from `InstanceConfig::resolve` defaults only — the
slug flows to payments untouched, no marketplace id value of
either family appears as a literal in the file — and pins terms
end to end through the POST route: (1) the minted id has the
family shape and differs from the slug; (2) a valid statement
naming the SLUG is refused (`terms_rejected`, zero rows) — the
direct F1 regression assertion; (3) the same statement naming the
minted id, submitted with CRLF line endings, is accepted
(`terms_saved`, exactly one row) and the stored bytes parse under
the HT id and not under the slug. Passes (1/0).

Supporting changes, recorded: four new unit tests (config ×2 —
default generation validity/distinctness, override strictness;
htid ×2 — lifecycle/mode, strict parsing; app lib 54 → 58). The
task-1 test `ht_terms_web.rs` had wired the fixture id through
`PaymentConfig`, which the handler no longer reads; its harness
now pins the resolved instance's `ht_marketplace_id` to the
fixture id instead. Its assertions are unchanged and it still
isolates the CRLF behaviour; its header's scope note was updated
to say so.

## Reconciliation — the BL1 publish test vs the H1 terms gate

`modules_audit_fixes::publish_requires_payment_identity_and_unused_pool`
(see "The one failure" above) is reconciled by completing its
setup, not by weakening anything: after the payment identity and
unused pool entry are in place and before the final publish
attempt, the seller installs a fresh identity key (app layer, the
established fixture pattern) and pins signed terms for the listing
through the real `POST /listings/{id}/terms` route, signed against
the test instance's minted HT id from task 2, asserting the
`terms_saved` redirect. The publish handler's gate order (payment
setup first, terms second) means the test's two refusal assertions
still exercise the payment gate exactly as before; its payment
assertions and the final success assertion are byte-for-byte
unchanged, and no app code was touched — the gate is not bypassed
anywhere. `TestServer` additionally carries the resolved
instance's HT id for signing. Result: the whole
`modules_audit_fixes` file passes 9/0 (was 8 passed / 1 failed).

## Task 4 (F15) — the full gate, run and recorded

`run-gate.sh` now executes the brief's shape exactly: preflight
(DATABASE_URL unset or unreachable → exit 2; psql required), rebuild
the database, `cargo test -p security-tests`, rebuild again,
`cargo test --workspace --exclude security-tests`, then the
seller-helper workspace. The rebuild drops and recreates the
database and applies all 16 migrations; it refuses any database
whose name does not contain `dev`, because the script drops a
database. The script runs under `set -eu`, so every cargo
invocation's own exit code gates the run: any non-zero aborts
before `gate: PASS`.

**A defect the first run exposed (recorded, then fixed).** The
first full run under the new shape (log `gate.log`, SHA-256
`5029876b3486d8157a9ea53a70321f8b1e828b1f7e249ea1f853d8796fcdac90`)
was green on the marketplace side (615/0/9, per-target identical
to the recorded run below) — but its helper step silently ran
only 17 of the helper workspace's 21 tests: seller-helper's root
manifest is a package as well as its workspace root, so the
script's bare `cargo test --manifest-path seller-helper/Cargo.toml`
tested the root package only and `helper-core`/`helper-cli` never
ran, while the script still printed PASS. That is F3's failure
class inside the gate script itself, and it is why the run below,
not the first, is the recorded gate. The step now passes
`--workspace` (commit `7f6bf3a`). The marketplace root is a virtual
manifest; its invocations never had this default.

**The recorded gate** — environment as for tasks 1+3, plus
`TMPDIR=$HOME/tmp-gate` on the real filesystem (the F3 report's
environment note). One run of `./run-gate.sh`; log at
`~/tmp-build/ht-h1-fix-gate/gate2.log`, **SHA-256
`69be7d80d522a38e24dfcd30c85d64851802d7161553aa4f959ebe64e0031371`**;
final lines `gate: PASS` and `GATE_EXIT_CODE=0`.

Correction (same day, on post-commit verification): this addendum
originally recorded SHA-256 `52fc7884…` for that log. That value
does not match the log preserved at the path above — no file in
the build directory hashes to it — so it was recorded in error and
is corrected here. The preserved log was re-verified in full after
the mismatch was found: its `test result` lines sum to exactly
636 passed / 0 failed / 9 ignored, its per-target counts are the
tables below (blind_stage5 35/0/3), it contains both database
rebuilds and no failure lines, and it ends `gate: PASS` /
`GATE_EXIT_CODE=0`. The commit message of `28ce3d0` still carries
the incorrect hash; this note is the correction of record, since
history is not rewritten.

Phase 1 — `cargo test -p security-tests` (fresh DB):

| Target | Passed / Failed / Ignored |
| --- | --- |
| security_tests lib | 0 / 0 / 0 |
| blind_direct_v1 | 42 / 0 / 0 |
| blind_ht1 | 24 / 0 / 0 |
| blind_stage1 | 41 / 0 / 0 |
| blind_stage10 | 32 / 0 / 0 |
| blind_stage2 | 38 / 0 / 0 |
| blind_stage3 | 34 / 0 / 0 |
| blind_stage4 | 58 / 0 / 6 |
| blind_stage6 | 83 / 0 / 0 |
| blind_stage9 | 43 / 0 / 0 |
| doc-tests | 0 / 0 / 0 |
| **Subtotal** | **395 / 0 / 6** |

Phase 2 — `cargo test --workspace --exclude security-tests`
(rebuilt DB):

| Target | Passed / Failed / Ignored |
| --- | --- |
| app lib | 58 / 0 / 0 |
| app main | 0 / 0 / 0 |
| account_security | 14 / 0 / 0 |
| audit_fix_tasks | 4 / 0 / 0 |
| dispute_signature | 1 / 0 / 0 |
| ht_terms_default_instance (task 2, new) | 1 / 0 / 0 |
| ht_terms_web (task 1) | 1 / 0 / 0 |
| media_disputes_audit | 9 / 0 / 0 |
| media_serve_http | 1 / 0 / 0 |
| media_verification | 6 / 0 / 0 |
| messaging_audit | 9 / 0 / 0 |
| modules_audit_fixes (reconciled) | 9 / 0 / 0 |
| payments_db | 11 / 0 / 0 |
| stage1_db | 1 / 0 / 0 |
| tx_proof_flow | 20 / 0 / 0 |
| verification_fixes | 10 / 0 / 0 |
| domain lib | 15 / 0 / 0 |
| envelope lib | 7 / 0 / 0 |
| blind_stage5 | **35 / 0 / 3** |
| media_worker main | 0 / 0 / 0 |
| modules_api lib | 8 / 0 / 0 |
| doc-tests (app, domain, envelope, modules_api) | 0 / 0 / 0 |
| **Subtotal** | **220 / 0 / 3** |

Phase 3 — `cargo test --manifest-path seller-helper/Cargo.toml
--workspace`:

| Target | Passed / Failed / Ignored |
| --- | --- |
| helper (bin) unittests | 0 / 0 / 0 |
| helper-cli tests/cli_init | 1 / 0 / 0 |
| helper_core lib | 3 / 0 / 0 |
| seller_helper lib | 17 / 0 / 0 |
| doc-tests | 0 / 0 / 0 |
| **Subtotal** | **21 / 0 / 0** |

**Totals and reconciliation.** Marketplace workspace:
**615 passed / 0 failed / 9 ignored**; seller-helper workspace:
**21 / 0 / 0**; grand total 636 / 0 / 9. Against the audit's
counting statement (the corrected post-H1 baseline at `d21c523`:
609/0/9 marketplace, 21/0/0 helper): 609 + 1 (task 1's
`ht_terms_web`) + 1 (task 2's `ht_terms_default_instance`) + 4
(task 2's unit tests: config ×2, htid ×2) = **615** exactly; the
ignored count is unchanged at 9 (blind_stage4's 6 + blind_stage5's
3); `blind_stage5` runs at the brief's named **35/0/3**; the
helper total matches the audit's static 21 with every member's
targets actually executed this time. No locked suite was edited;
no assertion anywhere was changed to reach green — the only test
modified in this addendum is the reconciled BL1 publish test,
whose setup grew and whose assertions did not move.

One operational footnote: `account_security`'s binary smoke test
executes the real app binary in the Development profile, and the
gate runs show task 2's persistence working as designed — it
minted `marketplace.htid` (0600, valid id) beside the crate
before serving. `marketplace.htid` is now gitignored beside
`marketplace.key` as a per-instance runtime file, and the stray
artifact was removed.
