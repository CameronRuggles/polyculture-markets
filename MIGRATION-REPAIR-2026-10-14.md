# Migration repair — STOPPED, NOT performed (2026-10-14)

**Outcome: no repair was executed.** The repair specification in the
task brief (attributed to STAGE6-REPORT.md §8) does not match the
actual tree in at least seven material ways. Per the task's own stop
rule ("if anything in §8 proves wrong against the actual tree — file
names, columns, which code writes which shape — STOP, do not improvise
a different repair, and report the discrepancy"), nothing was renamed,
created, edited, or backed up. This file is the discrepancy report.

A tree-verified repair plan already exists in this folder and should
be the basis of any re-issued task:
**`MIGRATION-0006-REPAIR-DRAFT-2026-10-14.md`, Option A** (independently
confirmed as the pending repair by `STAGE7-PREFLIGHT.md`, "Hard blocker
before any Stage 7 migration").

## What the brief specified vs. what the tree contains

| # | Brief / §8-as-relayed | Actual tree (verified 2026-10-14) |
|---|---|---|
| 1 | §8 of STAGE6-REPORT.md specifies the repair | The on-disk `STAGE6-REPORT.md` (8,129 bytes, 158 lines) **ends mid-§6**. §§7–8 were never written to disk; the report references a §8 that does not exist in the file. The repair text survives only as relayed summaries, which disagree with the tree and partly with each other. |
| 2 | Duplicate pair: `0006_conversation_key_sightings.sql` + `0006_key_currency_backfill.sql` | Duplicate pair: `0006_conversation_key_sightings.sql` + **`0006_conversations.sql`**. No `0006_key_currency_backfill.sql` exists anywhere in the project. |
| 3 | Conversations shape created by `0008_conversations.sql` | No `0008` exists. The conversations shape is created by `0006_conversations.sql` itself (which, despite its name, creates no `conversations` table — that is in `0001_initial.sql`). |
| 4 | Key shape marked by columns `participant_a`/`participant_b`; conversations shape by `first_seen_order` | Neither marker exists anywhere in the project. Key shape: `id, conversation_id, account_id, fingerprint, key_id, shown_to, shown_at`. Conversations shape: `id, conversation_id, key_owner_id, fingerprint, shown_to_id, created_at`. A conditional repair keyed on the brief's marker columns would mis-detect every real database. |
| 5 | Renumber to `0011_…`, append `0012_…` (presupposes migrations through 0010) | Migrations run **0001–0006 only**. There are no 0007–0010 files; renumbering to 0011 would open an unexplained version gap and contradict the tree-verified draft, which appends `0007_unify_key_sightings.sql`. |
| 6 | `deploy/dev-setup.sh` hand-creates the union table; must be fixed to end "MIGRATION-DEFERRED" (inline tables, no sightings table, no `_sqlx_migrations` inserts) | `dev-setup.sh` creates **no tables at all**. It loops `psql -f` over `migrations/*.sql` in glob order with `ON_ERROR_STOP=1`. There is no union-table code to remove, and no "MIGRATION-DEFERRED" state anywhere in the project's sources, docs, migrations, or deploy files (the literal string surfaces only inside stale compiled artifacts under `marketplace/target/` — build outputs, not a tree concept). The union table exists only inside the current dev DB, built ad hoc during the Stage 6 gate. Corollary: a truly fresh dev-setup run applies the key shape first, then **fails** on the second 0006's duplicate `CREATE TABLE` — a different failure mode than "one shape wins arbitrarily." |
| 7 | "sqlx records version 0006 once; fresh-DB migration order is filename-dependent" | The application contains **no `sqlx::migrate!` / `Migrator` usage** — migrations are applied by `dev-setup.sh` via psql. No `_sqlx_migrations` bookkeeping exists in the dev path. |
| 8 | Proof requires a `git status`/diff summary | The project is **not a git repository** (`git status` → "not a git repository"). Proof would need a hash manifest instead. |

## What the brief got right

- The defect is real: two version-0006 files create
  `conversation_key_sightings` in two incompatible shapes.
- Write-path attribution: `crates/app/src/keys.rs:283` writes the key
  shape `(conversation_id, account_id, fingerprint, key_id, shown_to)`;
  `crates/app/src/messages.rs:35` writes the conversations shape
  `(conversation_id, key_owner_id, fingerprint, shown_to_id)`.
- The dev DB's table is a hand-built union present in no migration file.

## Why the brief's repair would have been wrong even if its files existed

The brief's end state — final KEY shape reached by conditional DDL
while both code write paths stay as they are — is the union approach
the tree-verified draft records as **Option B (rejected)**: it leaves
two insert shapes, two unique constraints, and two names for the same
facts forever. In the actual tree, "final shape = key shape" is
impossible as a migration-only repair, because `messages.rs` is a live
writer (and the Q16 validator a live reader) of the other shape.
Option A resolves this correctly: delete `0006_conversations.sql`,
keep `0006_conversation_key_sightings.sql` as the sole 0006 (the
keys.rs schema is the richer one and is **pinned by the locked
blind_stage3 suite**), patch `messages.rs::record_sightings()` to call
`keys::record_key_sighting()` (key_id = last 16 hex chars of the
fingerprint, matching the locked suite's `key_id_of()` definition),
and append `0007_unify_key_sightings.sql` to migrate the existing dev
DB. None of that matches the brief's renumber/append pair (0011/0012),
its marker columns, or its dev-setup.sh rewrite.

## Environment notes (for whoever re-runs this)

- PostgreSQL was **not running** in this environment (port 5432
  closed); the psql client is not on PATH. Zonky binaries exist under
  `~/pgsys`. No backup was taken, because the repair was stopped
  before step 1 and there was nothing to back up *for*.
- Baseline to beat when the real repair is verified (per the draft):
  fresh DB from migrations in order → both write paths execute →
  workspace **327 passed / 0 failed** → Q16 probe (blind_stage5) green.

## Recommendation

Re-issue this task against `MIGRATION-0006-REPAIR-DRAFT-2026-10-14.md`
Option A, with the proof adapted to a non-git tree (sha256 manifest of
migrations/ before and after instead of `git status`). Separately,
note the documentation defect: `STAGE6-REPORT.md` on disk is truncated
mid-§6 — its §§7–8 (crypto-guard detail and the original defect
write-up) never landed in the file, which is how a garbled repair spec
could circulate detached from the tree in the first place.


---

# Migration repair — EXECUTED, Option A (2026-10-14, owner-approved)

The repair recommended above was re-issued against
`MIGRATION-0006-REPAIR-DRAFT-2026-10-14.md` **Option A** and executed
the same day, after the owner's go-ahead ("Repair the migration defect
now", 2026-10-14). The draft was verified against the tree at every
step before acting; it matched everywhere material. **Result: repair
complete, all four verifications green, full suite at the 327/0
baseline.**

## Step 1 — backup: NOT APPLICABLE (documented, not skipped)

The brief's step 1 assumed a live dev DB holding the hand-built union
table. It no longer exists: the user-space PostgreSQL data directory
lives in `/tmp`, which did not survive the VM replacement that
preceded this run (verified exhaustively: no server on 5432, no
pgdata anywhere under `~`, no postgres processes). There was nothing
to back up — but also nothing to lose: the marketplace has never been
deployed, and the only copy of the union shape was the draft's own
description, from which a faithful replica was rebuilt for testing
(below). The PostgreSQL environment was re-provisioned per AGENTS.md
(Zonky 16.4.0 user-space server, `/tmp/pgdata`, port 5432, trust auth)
and the dev DB was rebuilt from the repaired migrations after the
fix. No data was lost *by* the repair.

## Changes made

1. **Deleted** `migrations/0006_conversations.sql`.
   `migrations/0006_conversation_key_sightings.sql` is now the sole
   0006; its contents are byte-identical (sha256 unchanged, see
   manifests).
2. **Patched `crates/app/src/messages.rs::record_sightings()`** — its
   bespoke INSERT into the Stage-5 shape is gone; it now derives
   `key_id` as the last 16 hex chars of the fingerprint (exactly the
   locked blind_stage3 suite's `key_id_of`) and calls the existing
   `crate::keys::record_key_sighting()`. `keys.rs` is untouched (its
   signature/shape stay pinned by the locked suite); no locked test
   was touched.
3. **Added `migrations/0007_unify_key_sightings.sql`** — a single
   atomic `DO` block for existing (union-shaped) databases only:
   no-ops when the Stage-5 columns are absent (fresh installs);
   RAISEs and rolls back untouched if any row is unmappable; deletes
   Stage-5 rows whose mapped form already exists as a canonical row
   (exact duplicates only — the sighting survives in the canonical
   row); backfills the rest (`key_owner_id`→`account_id`,
   `shown_to_id`→`shown_to`, `key_id`=`right(fingerprint,16)`,
   `shown_at` from `created_at`); then drops the Stage-5 columns and
   the non-canonical unique constraint and restores canonical
   nullability/index. Two defects were caught by the union-replica
   test and fixed before this file was final: the backfill must not
   precede duplicate handling (canonical UNIQUE fires mid-update),
   and the constraint column-set comparison needs a `name[]`→`text[]`
   cast.

## sha256 manifests (change evidence; project is not a git repo)

Full files: `migrations-sha256-BEFORE.txt` / `migrations-sha256-AFTER.txt`
in this folder.

| File | Before | After |
|---|---|---|
| 0001–0005 | (unchanged) | identical hashes |
| `0006_conversation_key_sightings.sql` | `dfca6513…` | `dfca6513…` (untouched) |
| `0006_conversations.sql` | `a1920f75…` | **deleted** |
| `0007_unify_key_sightings.sql` | — | `ac6ffab7…` (new) |

Code: `messages.rs` after = `7bfdf8a1…`; `keys.rs` after =
`97287d4b…` (`code-sha256-AFTER.txt`).

## Verification (all four required checks + the 0007 transform)

- **0007 transform (union replica):** a faithful replica of the
  hand-built union table (both column sets, both unique constraints)
  was seeded with 4 sightings — each of two sightings recorded in
  both shapes. After 0007: **2 rows**, Stage-5 columns gone, mapped
  values exact (`key_id` = right(fingerprint,16)), canonical UNIQUE
  present, NOT NULLs restored. Abort path: adding an unmappable row
  (fingerprint with no matching `identity_keys` entry) makes 0007
  raise and leave all 5 rows and all 3 Stage-5 columns untouched.
- **(a) Fresh install:** new database, migrations 0001→0007 applied
  in glob order, no hand-built tables. `conversation_key_sightings`
  is exactly the canonical shape (7 columns, correct nullability,
  `shown_at DEFAULT now()`); 0007 no-ops cleanly.
- **(b) Both write paths on the fresh DB:** keys.rs path —
  blind_stage3's DB section calls `record_key_sighting()` +
  `key_shown_in_conversation()` against the fresh DB (suite 34/34;
  it cleans up its rows, hence 0 leftover sightings). messages.rs
  path — no locked suite calls `record_sightings()` directly, so a
  temporary harness test (created under `crates/app/tests/`, run,
  then deleted — not part of the tree) proved it: two sightings in
  canonical shape with `key_id` = last 16 hex chars, idempotent on a
  second call. 1/1.
- **(c) Full workspace suite:** dev DB rebuilt from the repaired
  migrations, `cargo test --workspace` → **327 passed / 0 failed /
  9 ignored** — the Stage 6 baseline exactly. (A first run without
  `MEDIA_WORKER` set showed 325/2: the two blind_stage2 PNG tests
  shell out to `target/debug/media-worker` via a CWD-relative default
  path. With `MEDIA_WORKER` pointed at the built binary, stage2 is
  38/38 and the workspace is 327/0. Invocation environment, not code.)
- **(d) Q16 probe:** `retired_key_not_shown_is_wrong_recipient_leak_probe`
  in the locked blind_stage5 suite (envelope crate) re-run by name:
  **ok**. (Full stage5 suite: 35 passed, 3 pre-existing ignores — the
  RFC 9580 v6 hand-built PKESK cases.)

## Environment restored along the way (this VM generation)

This generation lacked the Nettle/GMP dev files the build needs; the
Stage 6 generation's fixes had lived in `/usr`, which does not
persist. Restored: dev symlinks `libnettle.so`/`libhogweed.so`/
`libgmp.so`; real `nettle-dev` + `libgmp-dev` headers/.pc files and
`libclang-18` + `libLLVM 18` extracted from the Ubuntu 24.04 archive
(apt is broken in this generation). Cargo invocations that rebuild
nettle-sys need `LIBCLANG_PATH=/usr/lib/llvm-18/lib` and
`BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/13/include`.

## Consequence for Stage 7

The duplicate-0006 blocker named in `STAGE7-PREFLIGHT.md` is cleared:
a fresh install now produces exactly one `conversation_key_sightings`
shape, and both live writers use it.
