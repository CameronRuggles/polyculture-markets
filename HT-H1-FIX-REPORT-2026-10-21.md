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

---

# Tasks 5–13 (second batch, 2026-10-21)

Executed under the brief with all five owner decisions in hand
(Q1–Q5, recorded with tasks 1–4). Commits on
`deployment-fix-batch`, new commits only, no history rewrite, no
push: `0ed7fd4` (task 11) · `f819cc4` + `1df6758` (task 13b,
domain half — the first was committed mid-pipeline with a
test-compile error that a piped `cargo test | tail` masked; the
second fixes it; both kept, append-only, recorded here rather
than hidden) · `40ac455` (tasks 6+7, task 8's core half) ·
`f8b32ee` (task 9) · `4acfa4b` (task 8, CLI tests) · `73e38ad`
(task 12) · `fa7526d` (task 5) · `7d5ca43` (task 10) · `9eaa05e`
(task 13a).

**Environment note.** The VM was replaced mid-session: the
PostgreSQL cluster was re-provisioned from the user-space
binaries (`~/pgsys`, port 5432, database `marketplace_dev`,
migrations re-applied) and, this generation having no psql
client at all, a minimal `sqlx`-backed psql stand-in was built
for the gate's preflight and rebuild steps (`~/pgbin/psql`; it
implements exactly the flags `run-gate.sh` and the migration
loop use). Nothing in the tree depends on it; it is recorded
here because the gate logs below were produced with it on PATH.

## Task 11 — terms version rule (F11) · `0ed7fd4`

`parse_terms_statement` now enforces spec §4 rule 5 (basis: the
in-tree locked test's comment naming the rule): an `lst_`
listing id requires version ≥ 1; an `off-platform` trade
requires version 0. New domain unit test
`terms_version_rule_scoped_by_destination` refuses both
mutations and accepts both legal forms. Domain lib 15 → 16 at
this commit.

## Task 13b — receipt-time fold and the overdue flag (F6/F18, Q2) · `f819cc4`, `1df6758`

The domain fold is now `fold_trade_timed(&[TimedEvent], now)`;
`fold_trade` delegates with no witnessed times and no clock, so
the locked `blind_ht1` behaviour is byte-identical (24/24 at the
close-out gate). `TimedEvent` pairs a statement with the time
the counterparty received it, when a witness recorded one.
Rules: the issue window's upper bound is the issue statement's
receipt when witnessed (else its signer date, as before); the
lower bound (an issue received before the shipment was received
cannot raise) applies only when **both** sides are
receipt-witnessed — a receipt time is never compared against a
mere signing date. `FoldedTrade.payment_overdue` is new:
payment method `on_receipt`, goods shipped, nothing accepted as
paid, and the caller-supplied `now` past the assignment's
`payment_due` (the date the assignment itself states — the
assignment's payment date, per Q2). Five domain unit tests
cover the receipt-governed window in both directions, the
signer-date fallback, the unwitnessed lower bound, and the
overdue flag (positive; not-yet-due negative; prepay negative).

The helper half (in `40ac455`): `EvidenceStore::admit_statement`
accepts an optional witnessed `received_at`, persisted as a
`<NN>-<kind>.received` sidecar (integer unix seconds; a
hand-edited sidecar is refused at load). `trade_status` folds
with the witnessed times and the wall clock, and both status
commands print `PAYMENT OVERDUE` when the flag is set.
`helper buyer verify` gained `--received-at <unix-seconds>` —
harness/conversation tooling passes the marketplace message's
receipt time; interactive use omits it.

**The Q2 gap, recorded precisely (no silent approximation).**
In H1 the only statement with an intake path is the assignment
(`buyer verify`). Shipped and issue statements have **no**
intake command yet — they arrive with H2's command set — so for
those two classes no receipt time exists for the fold to
consult today, and it falls back to signer dates exactly as
pre-fix. The fold's receipt path is unit-proven with witnessed
inputs; wiring it for shipped/issue is H2 work: each H2 intake
command must record the receipt time the same way (the store
machinery — admit parameter, sidecar, load — already carries
any kind). Similarly, `load_events` can currently only
reconstitute receipt times this helper itself recorded; a
receipt time witnessed by the *other* party's helper reaches
this fold only when an intake path carries it in.

## Tasks 6+7 — verified admission, durable ledger (F4/F5, with F9/F10/F13 and F16's line) · `40ac455`

**Held-set admission (F4).** `EvidenceStore::admit_statement`
replaces `save_statement`'s optional signature: it parses the
statement per kind, checks its trade id against the folder
(assignments by digest — an assignment's id is its content
digest; the existing H1 check), checks the signer's
fingerprint against the expected party for the kind, and
verifies the detached signature against the signer's pinned
certificate — all before any byte is written. Expected parties:
assignment/open/ack from the seller; shipped from the seller
on `on_ship` and from the buyer on the prepay paths (direction
decides — an assignment is required to know it, and its absence
is a refusal); issue and refund-to from the buyer; settle and
receipt from **either** party (deliberate: the protocol
exchanges these between the parties and only one signature is
held; a third party's is refused — pinned by test).
`load_events` re-verifies the whole held set on every read
(missing `.sig`, a foreign statement, a tampered byte are all
errors, never skipped) and returns the timed events.
`trade_status` now takes each trade's parties from *its own*
assignment (the previous single-seller assumption is gone),
folds per trade, and returns a `Result` per trade.

**Ledger durability (F5).** `PoolLedger::load` errors on an
unreadable `pool.json` (was: silent empty ledger). A new
`load_for_assign` refuses a *missing* ledger over a store that
holds any trade. `LedgerLock` (exclusive `.lock` file, bounded
wait, a clear stale-lock message) spans load → seed → mark →
save inside `seller assign`. `seed_from_batch_json` consults
the evidence store before inserting: an address present in any
stored assignment is never re-seeded, and if one is somehow
already in the ledger as unused it is healed to used.

**Helper correctness (F9/F10/F13, F16's line).** TOFU pinning of
`--seller-cert` happens only after the fingerprint matches the
assignment's `seller_fp` — a refused verify leaves no pin.
Status prints unreadable trades as `ERROR: <reason>` lines
instead of omitting them. `create_terms` and `create_assignment`
parse every statement back before signing, and the assignment is
parsed back again before its address is marked used. The
success line is now "Assignment checks passed (signature,
terms, destination, amount, expiry). Trade <id>".

Eight new helper-core store tests: admit/load round trip with
receipt times; refusals for a garbage signature, a buyer-signed
ack, and a foreign-trade ack; either-party settle acceptance
with third-party refusal; load refusals for a missing
signature, a tampered statement, and a foreign statement;
corrupt and missing ledger errors; seeding that never
resurrects and heals; and four concurrent assigns over one
store taking four distinct addresses under the lock.

## Task 9 — spike evidence (OutProofV2) · `f8b32ee`

**The checker port and the two transaction vectors could not
be recovered.** The H1 report quotes only truncated prefixes of
both txids/keys; the spike crate in-tree (`stage0-spike`) holds
the RPC *client*, not the verdict port; and a search of file
names and contents across the workspace, the build tree, and
all git history and branches found neither artefact. Per the
brief's fallback, the `proof.rs` construction is now behind
the non-default cargo feature `proof-construction` in
helper-core (the form checks stay default-on; no command
reaches construction either way, as before — `verify_payment`
still returns the explicit "lands in H2" error). Default and
feature builds both pass 11/11. The spike verdict is unchanged
and still limited: construction proven against a faithful port;
**binary acceptance on a real stagenet node remains an open
owner-side rig item**, and the tx-key proof path ships in no
command until it passes there.

## Task 8 — CLI integration tests · `4acfa4b`

New `helper-cli/tests/cli_ht.rs` drives the real binary end to
end: two inits, seller terms, a seller assign against a
batch-seeded pool, buyer pin, a fully accepted verify asserting
the new F16 line verbatim, and both status commands (buyer
shows the assignment; seller lists the address used). A refused
verify (wrong `--seller-cert`) leaves **no** pin, after which
the correct cert pins and verifies. Off-platform terms at
version 1 are refused by the CLI — the task-11 rule biting
end-to-end (F13 evidence). 2/2.

## Task 12 — wording and docs (F16/F17) · `73e38ad`

`SELLER-GUIDE.md` and `sh/src/config.rs` now use the real
command surface (`helper seller init|generate|check`); the
guide's stale build path is corrected to `target/release/helper`
(the only binary the workspace builds); the seller-helper
manifest comment scopes the "no hand-rolled cryptography" claim
to the v1 crate and names helper-core's tx-proof construction
as the audited exception. Acceptance greps over the seller-helper
tree return nothing for `seller-helper init|generate|check` or
"Assignment verified"; the same greps over marketplace sources
are also clean (historical report files quote the old strings
as record and are not edited).

## Task 5 — the three terms resources (F7) · `fa7526d`

The canonical terms text now comes from one function
(`listings::listing_terms_text_for`); the digest helper uses
it, so the served text is byte-identical to what the statement
digests. Three gated GET resources —
`/listings/{id}/terms/statement`, `/terms/signature`,
`/terms/text` — share the existing download's gate (exists →
owner-only while unpublished → current pin required) via
`terms_download_parts`; the combined `/terms` page is kept for
back-compat. New app suite `ht_terms_files` (helper-core added
as a test-only dev-dependency): downloads all three files for a
published listing, asserts the gating (draft not served,
owner-only until published, unpinned 404, unknown listing 404),
asserts the check-3 chain (text hashes to the statement's
stated digest; the statement parses; the signature verifies
against the seller's certificate), and runs the real
`helper_core::verify::verify_assignment` against an assignment
built on exactly those downloaded files. `helper buyer verify`
itself cannot be invoked from the marketplace workspace (it
lives in the separate helper workspace); the acceptance is
therefore evidenced as the app-side chain test here **plus**
task 8's CLI suite, where the same verify code accepts
end-to-end — the composition is the same code path the CLI
runs (`verify::verify_assignment` is helper-core, shared).

## Task 10 — publish-gate side doors (F14 + Q5) · `7d5ca43`

Moderator restore now re-checks `terms_match_listing` when the
pre-takedown status was `published`: a listing whose terms no
longer pin (or never pinned) is restored to **`paused`**, not
back to the shelf; the route's doc comment is updated to say
so. Migration `0017_ht_pause_unpinned_listings.sql` pauses
every currently-`published` listing with no current pin;
taken-down rows are untouched (restore re-checks them), as
are draft/paused rows. New suite `ht_publish_gate` (3/3):
restore-without-pin lands on `paused`; restore with a matching
pin (submitted through the real submit route) returns to
`published`; and a migration test that builds a scratch
database **from the migration files themselves**, seeds
pre-H1-shaped rows (published-unpinned, published-pinned,
removed, draft), applies only `0017`, and finds exactly the
unpinned published row paused. The two `media_disputes_audit`
assertions that encoded the old restore-to-published behaviour
for unpinned listings were updated with F14 comments in this
(non-locked) suite, assertions otherwise unchanged.

**⚠ Locked-suite collision — owner attention required.** The
LOCKED `blind_stage9` case
`listing_removal_hides_from_browse_and_restore_returns_it`
restores a published listing that has no terms pin and asserts
it returns to browse. That is irreconcilable with F14 + Q5 as
ratified: the fixture and a genuine pre-H1 listing are
observationally identical, so any rule that pauses the
pre-H1 listing pauses this one. The locked file was **not**
edited. At the close-out gate `blind_stage9` stands at
42 passed / 1 failed, failing at exactly that case's restore
assertion (line 1484) and nothing else in the tree. The fix is
process, not code: that one case needs blind re-authoring
under the Q3 protocol (below) so the suite encodes the
ratified behaviour (restore of an unpinned listing → paused,
off the shelf) before H2's gate can be full-green.

## Task 13a — invariant scoping (F8 + Q4) · `9eaa05e`

`docs/invariants.md` gains a **Scope** section directly under
its header: the amended (7)–(10) govern Hidden Trades; Direct
Payments v1 keeps the pre-amendment (7)–(10) — quoted in full
from the pre-amendment text — until v1's removal in stage H6;
(11) is marked v1-scoped, which is what reconciles it with the
amended (10) (they govern different coexisting systems). The
foot amendment paragraph now points to the scope.
`crates/domain/src/lib.rs`'s citation no longer states the v1
(10) as if it were the whole rule. New guard suite
`ht_invariants_scope` — brief-authored scaffolding under this
reviewed fix brief (named `ht_`, not `blind_`, per Q3), now
locked like every suite in that manifest — asserts the scope
text is present in the doc and, on a freshly migrated
database, that both systems' tables exist (v1
`destinations`/`orders`/`invoices` alongside
`listing_terms_statements`): the live-tree half that makes the
scope line load-bearing. 2/2.

## Q3 — process adoption for H2 (no code)

Ratified and recorded: **locked suites get a separate blind
author again.** The tasks-1–4 addendum's shortcut (no separate
blind author for `modules_audit_fixes`-class reconciliations)
is superseded for H2: every locked suite added or re-authored
in H2 — including the `blind_stage9` restore case above — is
written by a blind author from a plain-language assertion
list, and the implementer does not see the assertions before
the gate, exactly as in the stage protocol that produced the
existing suites.

## Close-out gate — tasks 5–13

`run-gate.sh` was run with the same env shape as task 4 (plus
the psql stand-in on PATH; see the environment note). Its
`set -e` halted after the security phase on the one known
failure, so the remaining phases were run with the script's
own commands unchanged, plus a `--no-fail-fast` security pass
so every security target is accounted on a freshly rebuilt
database. Logs: `~/tmp-build/ht-h1-fix-gate/gate3.log`
(SHA-256
`be7772a658eef0c4f7440bc4c17c5eaec0a1c443a6c5c52bc21088c3ab1855e9`)
and `~/tmp-build/ht-h1-fix-gate/gate3b.log` (SHA-256
`31823a760279e665d5ba89cc4e2404918ee2500d343541b7b989841827b68432`)
— **both hashes verified against the files on disk**
(`sha256sum -c`), per the task-4 lesson.

Phase 1 — security (fresh DB):

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
| blind_stage9 | **42 / 1 / 0** (the collision above) |
| ht_invariants_scope (task 13a, new) | 2 / 0 / 0 |
| **Subtotal** | **396 / 1 / 6** |

Phase 2 — workspace excluding security (rebuilt DB): **all
green**. Deltas against task 4's table: domain lib 15 → 21
(tasks 11, 13b); new `ht_terms_files` 2/0/0 (task 5); new
`ht_publish_gate` 3/0/0 (task 10); `media_disputes_audit` still
9/0/0 with the two F14 assertion updates; every other target
identical to the task-4 table, including `blind_stage5` at the
brief's named **35/0/3**. Subtotal **231 / 0 / 3**.

Phase 3 — seller-helper workspace: helper bin 0; `cli_ht`
(task 8, new) 2/0/0; `cli_init` 1/0/0; helper_core lib 3 → 11
(tasks 6+7's store tests); seller_helper lib 17/0/0. Subtotal
**31 / 0 / 0**.

**Totals and reconciliation.** Marketplace: **627 passed / 1
failed / 9 ignored**; seller-helper: **31 / 0 / 0**. Against
the task-4 close-out (615/0/9 and 21/0/0): the marketplace
gains 13 new tests (domain +6, `ht_terms_files` +2,
`ht_publish_gate` +3, `ht_invariants_scope` +2 — 615 + 13 =
628 tests run, 627 passing) and the helper gains 10
(helper-core +8, `cli_ht` +2 — 21 + 10 = 31), and there is
exactly one new failure, the locked
`blind_stage9` restore case, whose conflict with F14 + Q5 is
documented above and in commit `7d5ca43`. No locked suite's
assertions were edited anywhere in this batch; the only
existing tests modified are the two `media_disputes_audit`
(non-locked) restore assertions under F14, noted in task 10.

**Open items handed forward:** (1) blind re-authoring of the
one `blind_stage9` restore case under Q3; (2) H2 intake
commands must record receipt times for shipped/issue (the
fold machinery is ready); (3) the OutProofV2 binary-acceptance
rig re-run remains owner-side, and the checker port + vectors
remain unrecovered — if the rig session resurfaces them, they
should be committed as helper-core tests and the
`proof-construction` feature gate revisited; (4) settle/receipt
either-party signing is a recorded design choice in
`ExpectedSigners::for_kind` — if the spec intends a fixed
signer for either, it is a one-line change plus its test.

## Blind re-authoring of the `blind_stage9` restore case (Q3) — 2026-10-21

Open item (1) above is closed by this record. The locked case
`listing_removal_hides_from_browse_and_restore_returns_it`
predated F14 + Q5 and asserted the opposite of the ratified
policy, so it was re-authored under the Q3 protocol: a
separate blind author, briefed with the ratified policy only
((a) browsable only while published; (b) restore returns the
pre-takedown status ONLY IF signed terms are currently pinned
that match the listing, else the restore leaves it `paused`;
(c) both branches under test). The author was not shown the
implementation code, the old case's body, or this report.

Three authoring passes were needed; all are recorded, none
hidden:

1. **Rejected — fabricated harness.** The first pass produced
   a case against an HTTP harness that does not exist in
   `blind_stage9.rs` (invented helpers and endpoints —
   `spawn_with`, `common_listing`, `post_seller_terms`,
   `/admin/listings/remove` — none present in the file, whose
   harness is service-level throughout) and cited the case at
   the wrong line range. Rejected by the integrator after
   symbol-level verification against the file. Nothing was
   integrated.
2. **Rejected — grounded harness, guessed mechanics.** The
   second pass used the real service-level harness and
   honestly flagged its two undiscoverable unknowns, but
   guessed both wrong: `moderation::remove_listing` /
   `moderation::restore_listing` do not exist, and the
   `listing_term_pins` table it invented does not exist.
   Not integrated: replacing its placeholder pin with a real
   signed pin would have meant the integrator authoring the
   fixture, voiding the blindness the protocol exists for.
3. **Integrated.** The third pass was briefed with the policy,
   a grounding requirement (quote the exact signature line of
   every file helper used, with line numbers), a minimal
   API-contract fragment (the `set_listing_removed` /
   `browse` / `submit_terms` signatures — the restore entry
   point appears only inside the forbidden case, so it cannot
   be discovered from allowed reading), and permission to
   read the sibling locked suite `blind_ht1.rs`'s
   `TermsFixture` region for the pinning idiom only (stage9's
   file has no pinning idiom of its own). It read neither the
   old case's body nor any implementation.

The integrated case is ONE case under the same name, covering
both branches: a genuinely signed pin (real generated identity
key registered for the seller, statement built over the
listing's own stored fields, submitted through
`app::listings::submit_terms`) restores to `published` and
back to browse; the plain unpinned `make_listing` shape
restores to `paused` and stays out of browse. The integrator's
only act was the splice (old lines 1454–1485 replaced);
**no mechanical adjustments were needed** — the case compiled
as delivered and passed standalone before the gate re-run.
Locked-file diff: 1 file, 125 insertions / 21 deletions, a
single hunk inside the one function; no other case, helper,
or assertion in the suite was touched.

**The author's plain-language assertion list, verbatim:**

1. Pinning the valid signed terms to the first listing succeeds.
2. After pinning, the first listing's pinned terms match the listing.
3. Before takedown, the first listing's stored status is published.
4. Before takedown, the first listing appears in public browse.
5. Takedown of the first listing succeeds.
6. After takedown, the first listing does not appear in public browse.
7. Restore of the first listing succeeds.
8. After restore, the first listing's stored status is published, its pre-takedown status.
9. After restore, the first listing appears in public browse again.
10. Before takedown, the second listing has no pinned terms matching it.
11. Before takedown, the second listing's stored status is published.
12. Before takedown, the second listing appears in public browse.
13. Takedown of the second listing succeeds.
14. After takedown, the second listing does not appear in public browse.
15. Restore of the second listing succeeds.
16. After restore, the second listing's stored status is paused.
17. After restore, the second listing still does not appear in public browse.

## Close-out gate re-run — 2026-10-21

`./run-gate.sh`, unmodified, exit code 0 (`gate: PASS` printed
by the script itself under `set -e`; no phase needed altered
commands or a `--no-fail-fast` pass this time).

**Environment.** The VM was replaced again: PostgreSQL was
re-provisioned from the user-space binaries (`~/pgsys` copied
to `/home/pguser/pgsys`, server run as user `pguser` on
127.0.0.1:5432, trust auth), the `~/pgbin/psql` stand-in on
PATH, `DATABASE_URL=postgres://postgres:dev@localhost:5432/marketplace_dev`,
`MEDIA_WORKER=<workspace>/target/debug/media-worker` (built
fresh with `cargo build -p media-worker` first),
`TMPDIR` on the real filesystem (`~/gate-tmp` — `/tmp` is a
512 MiB tmpfs on this generation), nettle shim env as before.

**First attempt (recorded, not the gate).** Log
`~/tmp-build/ht-h1-fix-gate/gate4.log`, SHA-256
`c11a24ab6be1d133fa08d4c9a83e8054e0524a5d7b14b63111c61f22cf787339`.
It halted in the security phase at `blind_stage2` 36/2/0: the
two media PNG acceptance cases failed because this attempt
omitted `MEDIA_WORKER` from the recorded environment shape
(`MediaPipeline::from_env` defaults to a relative worker path
that does not resolve from the test package's working
directory). An environment omission by the integrator, not a
tree defect — under the recorded env shape `blind_stage2`
stands at 38/0/0 below. Per the task-4 lesson, the defect is
named here and the second run is the recorded gate.

**Recorded gate.** Log `~/tmp-build/ht-h1-fix-gate/gate5.log`,
SHA-256
`6ab1caa7d449276f0cce15f73743470b0bb88dd0636dbf0f5cf92375edb521ee`
— computed with `sha256sum` against the file on disk after the
run, per the task-4 lesson.

Phase 1 — security (fresh DB):

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
| blind_stage9 | **43 / 0 / 0** (the re-authored case passes) |
| ht_invariants_scope | 2 / 0 / 0 |
| **Subtotal** | **397 / 0 / 6** |

Phase 2 — workspace excluding security (rebuilt DB): **all
green**, subtotal **231 / 0 / 3**, every target identical to
the tasks 5–13 close-out table, including `blind_stage5` at
the brief's named **35 / 0 / 3** (app lib 58, domain lib 21,
envelope lib 7, modules-api lib 8, `ht_publish_gate` 3,
`ht_terms_files` 2, `ht_terms_web` 1,
`ht_terms_default_instance` 1, `media_disputes_audit` 9,
`modules_audit_fixes` 9, `messaging_audit` 9,
`account_security` 14, `payments_db` 11, `tx_proof_flow` 20,
`verification_fixes` 10, `media_verification` 6,
`audit_fix_tasks` 4, `dispute_signature` 1,
`media_serve_http` 1, `stage1_db` 1).

Phase 3 — seller-helper workspace: **31 / 0 / 0** (helper bin
0, helper-core lib 11, `cli_ht` 2, `cli_init` 1, seller-helper
lib 17).

**Totals and reconciliation.** Marketplace: **628 passed / 0
failed / 9 ignored**; seller-helper: **31 / 0 / 0**; combined
**659 / 0 / 9**. Against the tasks 5–13 close-out (627/1/9 and
31/0/0) the delta is exactly ONE test changing state,
explained test-by-test: `blind_stage9` goes 42/1/0 →
43/0/0 — the same 43 tests (one case replaced by one case of
the same name), with
`listing_removal_hides_from_browse_and_restore_returns_it`
flipping from the single recorded failure to a pass. No test
was added or removed anywhere; every other target is
numerically identical to the close-out table, and the ignored
count is unchanged at 9. The full gate is green for the first
time since the F14 + Q5 policy landed.

**Open items handed forward, updated:** item (1) is closed by
this record. Remaining: (2) H2 intake receipt times; (3) the
OutProofV2 rig re-run (owner-side); (4) the
`ExpectedSigners::for_kind` design note. H2 still waits on
the auditor's re-verification of this stack plus the spike
re-run.
