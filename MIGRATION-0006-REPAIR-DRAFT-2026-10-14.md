# DRAFT — Migration 0006 repair plan (prepared 2026-10-14, NOT applied)

Status: awaiting Cameron's go-ahead. No migration file, code file, or
database was changed in preparing this draft. Verified against the tree
on 2026-10-14 ~16:25 MDT.

## The defect (verified in the tree)

Two files share version 0006 and each creates the SAME table with a
DIFFERENT schema. sqlx records version 0006 once, so on a fresh
database only one file's shape is created and the other live write
path breaks. The dev DB works only because it holds a hand-built
union of both shapes.

Files (marketplace/migrations/):
- `0006_conversation_key_sightings.sql` (retrofit, 2026-10-14 04:20)
  Columns: id (identity), conversation_id, **account_id**, fingerprint,
  **key_id NOT NULL**, **shown_to**, shown_at
  Unique: (conversation_id, account_id, fingerprint, key_id, shown_to)
- `0006_conversations.sql` (Stage 5, 2026-10-14 16:03 — the filename is
  misleading; it does NOT create `conversations`, that table is in 0001)
  Columns: id (bigserial), conversation_id, **key_owner_id**, fingerprint,
  **shown_to_id**, created_at
  Unique: (conversation_id, fingerprint, shown_to_id)

## The two live write paths (verified)

1. `crates/app/src/keys.rs:283` — `record_key_sighting()` inserts
   (conversation_id, account_id, fingerprint, key_id, shown_to) with
   `ON CONFLICT (conversation_id, account_id, fingerprint, key_id, shown_to)`.
   This function is exercised by the LOCKED blind_stage3 suite
   (tests/security/blind_stage3.rs:1172), so its signature/shape is
   pinned by a locked test — do not change it.
2. `crates/app/src/messages.rs:35` — `record_sightings()` inserts
   (conversation_id, key_owner_id, fingerprint, shown_to_id) with
   `ON CONFLICT DO NOTHING`. Called from messages.rs:98 and web.rs:1291.
   No locked test pins this insert's column names.

Reads: keys.rs:319 (`key_shown_in_conversation`) uses the first shape's
names; messages.rs:206 (`retired_shown`) uses only conversation_id +
fingerprint, which are common to both.

## Recommended repair (Option A — unify on the keys.rs schema)

The keys.rs schema is the richer one (it records key_id, which the
Q16 RecipientKeyRetired decision needs) and is the one a locked suite
pins. Unify on it:

1. **Delete** `migrations/0006_conversations.sql` (its only statement
   is the duplicate CREATE TABLE) and **keep**
   `0006_conversation_key_sightings.sql` as the sole 0006.
2. **Patch `messages.rs::record_sightings()`** to call the existing
   `crate::keys::record_key_sighting()` instead of its own INSERT.
   One wrinkle: record_sightings currently only has the fingerprint
   from `current_key()` (which returns fpr/cert/version, no key_id).
   The key_id is derivable from the fingerprint alone — the locked
   blind_stage3 suite defines `key_id_of()` as the last 16 hex chars
   of the fingerprint (tests/security/blind_stage3.rs, "OpenPGP key
   ID = low 64 bits of the fingerprint"), and envelope::KeyRef has no
   key_id getter (its handles set is private, matches() only), so use
   that same last-16 derivation for consistency with the locked test.
3. **Add migration `0007_unify_key_sightings.sql`** for the EXISTING
   dev database only (fresh installs never need it): backfill/drop
   the Stage-5-only columns (key_owner_id, shown_to_id, created_at)
   after copying any rows that exist only in that shape into the
   canonical columns (key_owner_id→account_id, shown_to_id→shown_to,
   key_id backfilled from identity_keys where derivable, else the
   row is a duplicate of a canonical-shape sighting in practice —
   verify row counts before/after in the run, and abort if a row
   cannot be mapped).
4. **Verify:** fresh-database install from migrations 0001→0007 in a
   scratch DB, then (a) both write paths execute, (b) full workspace
   suite re-run — baseline to beat is Stage 6's 327 passed / 0 failed,
   (c) the Q16 probe in blind_stage5 still passes.

## Option B (rejected in this draft, kept for the record)

Keep a permanent union table (all columns from both shapes, the
non-canonical ones nullable) via a final deduplicating migration.
This is the repair sketched in the Stage 6 report summary. It touches
no code, but it leaves two insert shapes, two unique constraints and
two names for the same facts forever, and every future reader has to
guess which shape a row used. Option A costs one small code patch
now, while the only databases in existence are disposable dev ones.

## Why now

Nothing public is deployed, so today's blast radius is zero. Every
day this waits, more dev databases (and eventually a stagenet MVP
install) inherit the broken fresh-install path. The Stage 6 report
§5/§8 flagged this as an owner-visible decision and the coordinator's
recommendation was to fix it now; this draft is the concrete patch
shape behind that recommendation.
