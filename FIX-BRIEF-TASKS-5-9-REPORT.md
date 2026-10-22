# Fix brief tasks 5–9 — completion report

Source: `Polyculture_Markets___Payment_Path_Audit_1_tlq1.md` (2026-10-18),
fix brief tasks 5–9 — the tasks that do **not** depend on the audit's
four open owner questions. Tasks 1–4 were not touched.

Method: test-first throughout. Every acceptance test below was written
first and observed failing against the pre-fix code (failure modes are
quoted per task), then the code was fixed and the test re-run green.
No existing test was modified or weakened; all locked/blind suites are
untouched and green (counts below).

Environment: PostgreSQL had not survived the VM replacement; it was
re-provisioned from the user-space Zonky binaries (`/tmp/pgsys`, data
in `/tmp/pgdata`, port 5432, trust auth), `marketplace_dev` recreated
and migrations 0001–0009 applied. Builds used
`NETTLE_PREGENERATED_BINDINGS=~/pgsys/nettle-bindings.rs` and
`PKG_CONFIG_PATH=~/pkgconfig` per AGENTS.md.

## Measured baselines (this machine, this environment)

| Suite | Before | After |
| --- | --- | --- |
| Marketplace workspace (`cargo test --workspace`, `MEDIA_WORKER` set) | 490 passed / 0 failed / 9 ignored | **494 passed / 0 failed / 9 ignored** |
| seller-helper | 13 passed / 0 failed | **17 passed / 0 failed** (16 unit + 1 CLI integration) |

(The brief's recorded workspace baseline was 489; the +1 difference
exists in the pre-change run here too — identical before/after
environment, so the delta attributable to this work is exactly the 4
new app tests and 4 new helper tests. Every previously green suite
kept its exact baseline count, including `blind_direct_v1` at 42.)

---

## Task 5 — Spend-key wording (M2) — DONE

**Failing tests written first**

- `crates/app/tests/audit_fix_tasks.rs::pay_template_requires_spend_key_signature_and_warns_about_feather`
  — asserts the pay template says the wallet must report a signature
  "made with the spend key" and warns that Feather cannot show which
  key signed. Failed pre-fix (strings absent).
- `seller-helper/src/lib.rs::generate_aborts_without_file_when_verify_reports_view_key`
  — a parameterised fake wallet (new test code) whose `verify` returns
  `good: true` with `signature_type: "view"`; `run_generate` must
  abort and write no batch file. Failed pre-fix: the batch was
  generated, because `verify` read only the `good` flag.

**Code changes**

- `marketplace/crates/app/templates/pay.html` — step 2 of "Verify
  before you pay" now reads: the wallet must report a good signature
  **made with the spend key**; view-key signatures also report as
  good but prove less (view keys are routinely copied to watch-only
  wallets/bookkeeping tools); and Feather shows only that a signature
  is valid — it does not show which key signed, so Feather cannot
  tell a spend-key signature from a view-key one. The locked
  `blind_direct_v1` template test still passes (no "verified" payment
  claim introduced; "seller confirmed payment" copy untouched).
- `seller-helper/src/rpc.rs` — `RpcClient::verify` now returns true
  only when the wallet reports `good == true` **and**
  `signature_type == "spend"`; a missing `signature_type` is not a
  spend signature. Its only caller is the self-verify in
  `run_generate`, so the helper now aborts any batch whose signatures
  the wallet attributes to the view key.

## Task 6 — Lock before counting (M4) — DONE

**Failing test written first**

- `audit_fix_tasks.rs::concurrent_creations_by_one_buyer_stop_at_the_open_unpaid_cap`
  — one buyer, 20 creations released simultaneously on a
  `tokio::sync::Barrier` (no sleeps anywhere) against a 25-address
  pool, default cap 3. Pre-fix result: **all 20 orders were created**
  (`left: 20, right: 3`) — every request counted 0 open orders before
  any insert committed.

**Code change**

- `marketplace/crates/app/src/orders.rs` (`create_order_with_config`)
  — the drain-defence counts and the insert/allocation now share one
  transaction that begins **before** counting. The transaction first
  takes `pg_advisory_xact_lock(buyer_id)` (the codebase's only
  advisory lock; key is the buyer account id), held to commit, so
  creations by one buyer serialize and the open-unpaid / hourly-rate
  counts observe every committed order of that buyer. The seller
  identity row lock and SKIP LOCKED allocation are unchanged, and
  lock order (buyer → seller identity) is consistent with every other
  path, so no lock-ordering cycle is introduced. Post-fix: exactly 3
  orders created, 17 × `OrderError::TooManyOpenUnpaid`, 22 pool
  entries remain. Test file run 5× consecutively: green every time.

## Task 7 — Upload tidy-ups (L1) — PARTIAL: cap re-check DONE, signature-shape check NOT DONE (blocked, see below)

**Failing test written first (cap half)**

- `audit_fix_tasks.rs::concurrent_uploads_cannot_overfill_the_pool`
  — two 60-entry uploads for one seller released on a barrier
  against the default 100-entry unused-pool cap. Pre-fix result:
  **both landed** (`Ok(60) / Ok(60)`, 120 entries stored).

**Code change (cap half)**

- `marketplace/crates/app/src/payments.rs` (`upload_batch`) — inside
  the insert transaction, the seller's identity row is taken
  `FOR UPDATE` (the same lock order creation and address changes
  already take), the unused count is re-read **inside** the
  transaction, and the cap is enforced there; the earlier outside
  check remains as a fast path. Post-fix: exactly one upload lands,
  the loser fails with `PaymentError::PoolFull`, 60 entries stored.

**Signature-shape half — NOT implemented (genuine conflict, stopped per instructions)**

The brief asks `upload_batch` to require `SigV2` + 88 base58 chars.
That rule is irreconcilable with the project's locked test contracts,
which this work is forbidden to modify:

- `tests/security/blind_direct_v1.rs`, documented assumption **A7**:
  with server-side signature checking off (the v1 default), the
  pinned contract enumerates `upload_batch`'s checks and a
  signature-format check is **not** among them — "If the
  implementation secretly format-checks signatures, the happy-path
  upload tests fail and that is an implementation deviation from the
  contract's enumerated check list." Its fixtures sign with strings
  like `SigBlind0001QWxhZGRpbj…=` (not `SigV2…`, contains `=`/`-`).
- `crates/app/tests/payments_db.rs` happy-path uploads use
  `"SigV2-byte-exact_CHECK.123"` and `"SigV2-assignment-primary"`,
  asserting byte-exact storage of arbitrary signature strings; its
  well-formed fixture `SIG` is 89 chars total, not the real-wallet
  93 (`SigV2` + 88).

Any `SigV2`+88 enforcement fails these suites. The audit itself
frames the shape check as the interim measure ("H2 replaces this"):
the durable fix is task 2's real signature verification, which is
owner-gated (open question 2: whether an offline verifier may run on
the server). Resolution paths for the owner: (a) amend the locked
contract A7 and the payments_db fixtures as part of the task-2 work,
then add the shape check (or verification) — recommended; (b) scope
a shape rule compatible with existing fixtures, which would be a
weaker check than the brief specifies and was not improvised here.
Nothing about the current behaviour changed: signatures remain
stored/served byte-exact with no format constraint.

## Task 8 — Network guard (L2) — DONE

**Failing test written first**

- `audit_fix_tasks.rs::network_guard_refuses_mismatched_stored_state`
  — failed pre-fix at compile time (`ensure_network_consistency` and
  `PaymentError::NetworkMismatch` did not exist). It runs against a
  scratch database (`marketplace_fix_guard`, created by the test)
  holding only the three tables the guard reads, so its
  whole-database counts cannot be poisoned by other suites'
  leftovers. Cases: empty state starts on either network; a stagenet
  identity alone refuses a mainnet start (`NetworkMismatch {
  identities: 1, unused_entries: 0 }`); an unused stagenet pool
  entry raises `unused_entries` to 1; aligning stored networks makes
  the mainnet config pass.

**Code changes**

- `marketplace/crates/app/src/payments.rs` — new
  `ensure_network_consistency(pool, cfg)`: counts
  `payment_identities` rows whose `network` differs from the
  instance's, plus unused `payment_pool_entries` whose batch's
  `network` differs; returns the new
  `PaymentError::NetworkMismatch { identities, unused_entries }`
  variant when either count is non-zero. New
  `PaymentError::NetworkMismatch` variant added (web.rs does not
  match `PaymentError` exhaustively; nothing else breaks).
- `marketplace/crates/app/src/main.rs` — immediately after the
  payment config is built (before key-file load or any background
  job spawns), the guard runs; on mismatch the process prints
  `configuration error: stored payment state does not match the
  instance network (…): N payment identit(y/ies) and M unused pool
  entr(y/ies) belong to another network. Refusing to start — …` and
  exits 2, the existing config-error convention.

**End-to-end smoke (real binary, dev database)**: seeded a stagenet
identity, started `marketplace-app` with
`DEPLOY_PROFILE=production INSTANCE_NETWORK=mainnet
MAINNET_CONFIRM="I ACCEPT MAINNET REAL FUNDS"` → exit 2 with the
message above (it counted all 36 stored stagenet identities). With
default (stagenet) config the same binary started and listened
normally. Seed rows removed afterwards.

## Task 9 — Helper hardening (L3, L4) — DONE

**Failing tests written first**

- `seller-helper/src/lib.rs::stored_account_index_with_wrong_label_falls_back_to_scan`
  — stored index 0 exists in the fake wallet but its index-0 label is
  "Primary account", not the dedicated label. Pre-fix,
  `run_generate` used account 0 (`account_index == 0`,
  `account_created == false`). Post-fix it falls back to the label
  scan, finds no dedicated account, and creates/labels one
  (`account_index == 1`, `account_created == true`).
- `seller-helper/src/lib.rs::write_atomic_creates_owner_only_file`
  (unix) — a file written through `write_atomic` must be mode 0600.
  Pre-fix it was 0660/0644 (default creation permissions; the chmod
  happened only later, on the config path, after the rename).
- `seller-helper/tests/cli_init.rs::init_refuses_rpc_password_flag`
  (new integration test) — runs the built binary: `init` with all
  flags including `--rpc-password` must exit non-zero, name the flag,
  and write no config. Verified against a scratch build with the
  pre-fix `main.rs` restored: the old binary **saved the config and
  exited 0** (test failed); post-fix it refuses.

**Code changes**

- `seller-helper/src/lib.rs` — `find_or_create_marketplace_account`:
  the stored index is now used only when the account exists **and**
  its index-0 label is still `xmr-direct-marketplace`; otherwise it
  falls through to the existing label scan / create path. Doc comment
  updated (the stored index is a hint, never proof).
- `seller-helper/src/lib.rs` — `write_atomic`: on unix the temp file
  is set to 0600 immediately after creation, before any bytes are
  written, so the rename lands an owner-only file. This closes the
  default-permissions window for the config (which carries the RPC
  login) — `save_config`'s post-rename chmod remains as a second
  layer. The batch file goes through the same path and is now also
  owner-only, which is harmless (the seller reads it themselves).
- `seller-helper/src/main.rs` — `init` no longer accepts
  `--rpc-password`: passing it is a hard error explaining why
  (shell history / process listings) and directing the user to the
  interactive prompt. The password is read by a new
  `prompt_password`, which disables terminal echo while reading
  (best-effort `stty -echo`, restored on drop, including on error)
  and requires an interactive terminal — non-interactive `init`
  without a prompt now fails with a clear message instead of ever
  taking the password from argv. USAGE text updated.
- `seller-helper/SELLER-GUIDE.md` — the `init` example no longer
  shows `--rpc-password yourrpcpassword`; it documents the prompt.

## Repetition / stability

- `audit_fix_tasks` (incl. both barrier concurrency tests): 5
  consecutive full-file runs, green every time; plus the runs inside
  the full workspace suite.
- seller-helper suite: 3 consecutive runs, green every time.
- Full workspace suite and seller-helper suite re-run after all
  changes: counts in the table above; all blind suites
  (blind_stage1/2/3/4/5/6/9/10 and blind_direct_v1) present and
  green at their baseline counts.

## Not done / notes

- **Task 7 signature-shape check — not implemented**, for the locked-
  contract conflict documented under task 7 above. This is the only
  incomplete item.

---

## Addendum 2026-10-19 — task 7 signature-shape half CLOSED (superseded)

The one incomplete item above is now closed, without code and
without any locked-suite amendment. The Fix Verification (Media,
Content, Disputes and Payment Tasks 5–9, 2026-10-19) reviewed the
partial and ruled on the shape check: the locked suites use
placeholder signatures it would reject, and real server-side
signature verification (owner decision 2) replaces it — "drop it
rather than amend the suites." The media verification fix batch
(2026-10-19) records the closure here per task 6 of that brief:
payment task 7 stands complete on its pool-cap-race half (already
shipped), and the signature-shape half is **closed as superseded by
decision 2**, not deferred and not pending a suite amendment. When
the payments redesign lands the verifier, signature validity is
checked for real, which is strictly stronger than the shape test
this half would have added.
- Tasks 1–4 untouched, as instructed. No migration was needed for
  any task (0008 already stores per-identity and per-batch network).
- The tree is not `rustfmt`-clean at HEAD and was left so; new code
  follows the surrounding style rather than reformatting files.
- Commits are on `main`, **not pushed** (parent agent pushes after
  review).
