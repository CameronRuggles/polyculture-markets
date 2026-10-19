# Media Verification Fix Batch — Completion Report

2026-10-19 · Base HEAD `0ef3b7a` · Brief: *Fix Verification: Media,
Content, Disputes and Payment Tasks 5–9* (2026-10-19), final section,
6 tasks.

**Result:** all 6 tasks complete. Final gate: **workspace 574 passed /
0 failed / 9 ignored** against the pre-batch baseline of 568 / 0 / 9 —
the +6 are this batch's new acceptance tests, exactly accounted.
**Seller-helper: 18 passed / 0 failed** against a baseline of 17 — the
+1 is task 5's new test. Every blind suite at baseline. **Zero locked
files changed** (proof in §8). Local commits only; nothing pushed.

Commits: `5ee5b4c` (task 1), `d65d75b` (task 2), `02897fe` (task 3),
`26ba2ea` (task 4), `43ae9e5` (task 5), `1e4ee36` (task 6 + threat
model), plus this report.

New acceptance suite: `marketplace/crates/app/tests/media_verification.rs`
(6 tests; the seller-helper test lives in `seller-helper/src/lib.rs`).
Tests were written first; pre-fix failures were captured for tasks
2, 3 and 4 (task 1's defect is deployment configuration, not code —
see its section; task 5's defect is a creation-instant window, proven
by the new test's control).

---

## 1. Turn the worker sandbox on where it ships (CM2)

**Changes.**
- `marketplace/deploy/env.demo.template`: the Media section now sets
  `MEDIA_WORKER_SANDBOX=bwrap`, with a comment stating what it does and
  that removing the line turns the sandbox off.
- `marketplace/deploy/deploy-demo.sh`:
  - Installs bubblewrap when missing (and dies with guidance if it
    cannot), and requires curl (already needed by the health check;
    the smoke probe uses it).
  - A **deploy-time smoke test** runs after the binaries and env file
    are installed, before PostgreSQL/service start, as the
    application user, with the same bwrap shape `media.rs` builds
    (`--unshare-net --die-with-parent --tmpfs /`, `/usr`, `/lib`,
    `--ro-bind-try /lib64`, `/dev`, worker at `/worker`, input at
    `/in`, job scratch bound at `/work`):
    (a) the real media-worker must sanitize a sample 1×1 PNG inside
    the sandbox and produce output; (b) a probe "worker" in the same
    shape must FAIL to read the key file (path taken from the
    effective env), FAIL to read a host file the app user can read
    outside the sandbox, and FAIL to open a network connection
    (curl to the service port). Either failure aborts the deploy —
    the deploy never silently ships the worker unconfined.
- `marketplace/crates/app/src/media.rs`: `/lib64` is now bound with
  `--ro-bind-try` instead of `--ro-bind`, per the brief (some
  distributions lack `/lib64`; a plain `--ro-bind` of a missing
  source fails the whole spawn).

**Evidence.**
- App-level acceptance tests (`media_verification.rs`):
  `sandbox_blocks_key_read_and_network_but_not_the_work` compiles a
  probe worker that tries to read a key file outside the sandbox and
  to connect to a live test listener; unconfined, it does both and
  refuses to produce output (positive control — the sanitize fails);
  with `MEDIA_WORKER_SANDBOX=bwrap` it can do neither, does its work,
  and the sanitize succeeds with the probe's "both-blocked" output.
  `sandboxed_real_worker_sanitizes_a_png` runs the real media-worker
  under bwrap on a genuine 1×1 PNG → Ok, 1×1, output stored.
- The deploy smoke test's exact command shape was executed locally
  against the locally built media-worker and the probe script: the
  worker printed `1x1` and wrote its output; the probe exited 0
  (key path, host file, network all unreachable inside).
- `sh -n` clean on the modified deploy script.

**Stated plainly — one part not executed here:** the script runs the
smoke test as the unprivileged application user. In THIS sandbox VM,
unprivileged user-namespace creation is blocked by the outer
container (`unshare -rn` fails writing `uid_map`), so bwrap cannot
run as a non-root user here at all; the local executions above ran
as root, where bwrap works. On a normal deploy host (the script's
target), the as-app-user smoke test is exactly what validates that
the shipped configuration works — and if it cannot, the deploy
fails by design. The app-level tests likewise ran as root here.

## 2. One scratch folder per job (CM2)

**Change** (`media.rs`): each sanitize job now creates a fresh
directory under the pipeline tmp dir (`tmp/<stem>/`, holding only
`in` and `out`), and the whole directory is deleted on every exit
path — success, rejection, worker failure, timeout, and output-parse
failure (the pre-fix code could leak the `.out` file on a parse
error). In the sandbox, that per-job directory alone is bound at
`/work` (previously the shared tmp dir was bound wholesale).

**Evidence:** `concurrent_jobs_cannot_see_each_others_files` — two
barrier-synchronized stub workers list their input's directory
mid-flight; each sees exactly one entry (its own input), and no
files remain in tmp afterwards. Pre-fix this failed: each job listed
both jobs' inputs in the shared tmp dir.

## 3. Bound the upload queue (CM2)

**Change** (`media.rs`, `web.rs`): admission to the pipeline is now
bounded and taken **before** any buffering-to-disk. A process-wide
admission semaphore holds `MAX_CONCURRENT_WORKERS (2) +
MAX_UPLOAD_QUEUE (4) = 6` permits; a job holds its permit for its
whole life (running or waiting for a worker slot). `sanitize` takes
admission with `try_acquire` before creating directories or writing
the upload body; past the bound it returns the new
`MediaError::Busy` at once. The HTTP handler (`listing_media`)
additionally probes `admission_saturated()` **before reading the
multipart body**, and maps `Busy` → **503** ("Media worker busy —
try again in a moment"). The unbounded in-memory pile-up the
verification found behind the worker semaphore is closed.

**Evidence:** two tests. Pipeline level
(`upload_burst_admits_at_most_six_and_refusals_write_nothing`): 30
barrier-synchronized uploads → exactly 6 admitted, 24 refused, and
zero files left in tmp (refused bodies never written; admitted jobs
cleaned up). HTTP level
(`upload_burst_over_http_answers_503_to_the_excess`): 30 parallel
multipart uploads against a slow stub worker → exactly 6 redirects
(success) and 24 × 503, no other statuses, nothing left on disk.
Pre-fix both failed the same way: all 30 uploads were admitted
(30 Ok / 30 redirects, 0 refusals).

## 4. Fix the resolve redirect (N1)

**Change** (`web.rs`): a refused TOTP code in `dispute_resolve` now
redirects to `/disputes/{id}?msg=mod_action_refused` (was
`/moderation/{id}` — a route that does not exist, so the moderator
got a bare 404). The `mod_action_refused` alert text no longer says
"Enroll in TOTP on your security page first"; it now reads:
*"Moderator action refused: the TOTP code was not accepted — it may
be wrong, already used, or code entry may be locked out after too
many failed attempts. Wait a few minutes and try again with a fresh
code; if you have not enrolled in TOTP yet, enroll on your security
page first."* (`mod_action_refused` is used only by this handler —
verified by grep.)

**Evidence:** `wrong_code_at_dispute_resolve_returns_to_the_dispute_page`
— a TOTP-enrolled moderator (enrolled via the library flow with the
server's keyfile) posts a wrong code to `/disputes/{id}/resolve`:
the response is a 303 to `/disputes/{id}?msg=mod_action_refused`;
following it renders the dispute page (200) showing the new refusal
text and not the old enroll-first wording; the dispute remains
`open`. Pre-fix the test captured the redirect to
`/moderation/5?msg=mod_action_refused` — the 404 target itself.

## 5. Helper temp file (payment task 9 nit)

**Change** (`seller-helper/src/lib.rs`): `write_atomic`'s temp file
is now created through `create_tmp_owner_only`, which opens it with
`OpenOptions::mode(0o600)` on Unix — owner-only **at the creation
instant**, not `File::create` at umask defaults narrowed a syscall
later. The subsequent `set_permissions(0o600)` is kept for the one
case create-mode cannot cover: a stale same-name temp file already
on disk (a create mode does not reset an existing file's mode).

**Evidence:** new test `temp_file_is_owner_only_at_the_creation_instant`
stats the temp file at the creation instant — it exists, nothing yet
written or chmod'ed — and asserts mode exactly 0600; a
`File::create` control in the same test proves the contrast is
observable under the process umask (0644 at umask 022). The existing
`write_atomic_creates_owner_only_file` end-to-end test still passes.

## 6. Drop the signature-shape half of payment task 7

Closed as superseded, exactly as the auditor ruled ("Real
verification (decision 2) replaces it, so drop it rather than amend
the suites"). **No code. No locked-suite amendment.** The closure is
recorded as a dated addendum in `FIX-BRIEF-TASKS-5-9-REPORT.md`
(commit `1e4ee36`): payment task 7 stands complete on its shipped
pool-cap-race half; the shape half is closed by supersession by
owner decision 2's server-side signature verification, not deferred.

The same commit updates threat model §T6 with a dated note so the
section again states exactly what is built and shipped: bounded
admission (2 running + 4 queued, 503 beyond, refused before
buffering), per-job scratch, and the shipped demo deployment
enabling the sandbox with the deploy-time smoke test.

---

## 7. Final verification

Environment for the gate: `DATABASE_URL` against the user-space
PostgreSQL (Zonky, port 5432, migrations 0001–0015), `MEDIA_WORKER`
pointing at the built media-worker, `MEDIA_DIR`/`BLOB_DIR` on the
disk-backed home filesystem (see §9 for why that matters), nettle
shims per AGENTS.md, bubblewrap 0.9.0 installed.

Because three VM replacements killed single `cargo test --workspace`
invocations mid-run (see §9), the final gate was executed as
per-target complete runs — every target below ran to completion
against the final tree, with the database's schema verified (38
tables) immediately before the run started. Per-suite results, all
at baseline except where noted:

| Suite | Result | Baseline |
|---|---|---|
| app lib | 52 / 0 / 0 | 52 |
| envelope (lib + suite) | 42 / 0 / 3 | (in baseline total) |
| domain + modules-api + media-worker | 8 / 0 / 0 | (in baseline total) |
| account_security | 14 / 0 / 0 | 14 |
| audit_fix_tasks | 4 / 0 / 0 | 4 |
| dispute_signature | 1 / 0 / 0 | 1 |
| media_disputes_audit | 9 / 0 / 0 | 9 |
| media_serve_http | 1 / 0 / 0 | 1 |
| **media_verification (new)** | **6 / 0 / 0** | — |
| messaging_audit | 9 / 0 / 0 | 9 |
| payments_db | 11 / 0 / 0 | 11 |
| stage1_db | 1 / 0 / 0 | 1 |
| tx_proof_flow | 20 / 0 / 0 | 20 |
| verification_fixes | 10 / 0 / 0 | 10 |
| blind_direct_v1 | 42 / 0 / 0 | 42 |
| blind_stage1 | 41 / 0 / 0 | 41 |
| blind_stage2 | 38 / 0 / 0 | 38 |
| blind_stage3 | 34 / 0 / 0 | 34 |
| blind_stage4 | 58 / 0 / 6 | 58 / 6 ignored |
| blind_stage6 | 83 / 0 / 0 | 83 |
| blind_stage9 (as amended 2026-10-19) | 43 / 0 / 0 | 43 |
| blind_stage10 | 32 / 0 / 0 | 32 |
| **Workspace total** | **574 / 0 / 9** | **568 / 0 / 9** |
| **seller-helper** | **18 / 0 / 0** | **17 / 0 / 0** |

Bookkeeping note: there is no `blind_stage5` target in this tree
(and none at base HEAD — the locked tree is byte-identical, §8);
the "35 passed / 3 ignored" that prior batch bookkeeping lists next
to that label is the envelope crate's own suite, counted in both
the baseline and this total.

## 8. Locked-file proof

No locked-suite amendments were authorized in this batch, and none
were made. Method note, stated plainly: the pre-batch SHA-256
manifest was written to `/tmp` and lost when the VM was replaced
mid-batch. The proof was therefore done against git, which is
equivalent-or-stronger for these paths: every locked file's working
-tree SHA-256 was compared against the SHA-256 of its blob at the
pre-batch HEAD `0ef3b7a` — **all 17 files identical** (16 under
`marketplace/tests/security/**` + `marketplace/docs/invariants.md`);
`git status`/`git diff` over those paths is likewise empty. The
post-batch manifest is saved beside this report as
`MEDIA-VERIFICATION-POST-MANIFEST-2026-10-19.txt`; its
`blind_stage9.rs` hash `2a98fa39…` matches the verification-fix
report's post-amendment hash exactly. The spec was not touched. The
untracked repo-root `OWNER-DECISIONS-2026-10-18-EVENING.md` was left
untracked and untouched.

## 9. Environment incidents (recorded honestly)

- **Three VM replacements** during the batch wiped `/tmp` (the
  user-space Postgres, the first gate run, the pre-manifest) and
  installed packages (bubblewrap, psql). Postgres was re-provisioned
  from `~/pgsys` each time (fresh cluster, `marketplace_dev`,
  migrations 0001–0015, 38 tables).
- **A poisoned gate run, discarded in full.** After one replacement,
  a resumable gate script's self-heal failed to recreate
  `marketplace_dev` (its `psql` was missing and the failure was
  silent). Most app suites then "passed" **vacuously** — this repo's
  DB suites return early when the pool can't connect
  (media_disputes_audit "passed" in 2.09s vs ~53s of real work),
  account_security's `production_profile_fails_closed` failed because
  the spawned binary could not reach the missing database, and the
  blind suites (which panic on connect failure) reported
  `database "marketplace_dev" does not exist`. That entire run was
  thrown away; the final gate above ran only after a hard pre-check
  verified the schema (38 tables) and with per-suite durations at
  real-work scale. The one account_security failure belonged to the
  poisoned run; in the real gate it passes 14/14.
- **Disk floor vs tmpfs.** The first full-gate attempt put
  `MEDIA_DIR`/`BLOB_DIR` under `/tmp` (a 512 MB tmpfs); three
  verification_fixes tests then failed with `StorageCeiling` — the
  V9 free-disk floor (1 GiB, statvfs on the blob filesystem) can
  never be met there. Environmental, not a regression: with the
  directories on the disk-backed home filesystem the suite passes
  10/10 and the full gate is green. Deployments should likewise not
  point `BLOB_DIR` at a sub-1-GiB filesystem.
- Nothing was deployed to the real demo, and nothing was pushed
  (push remains blocked on the gh workflow-scope refresh, handled
  outside this batch).
