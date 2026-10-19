# Dispute Page Signed-Signature Fix — Completion Report

**Date:** 2026-10-19 · **Repo:** monero-marketplace-v2, branch `main`
**Base:** 2cce90f (media/content/disputes batch at 6ceb8e8, plus the
deployment batch) · **Fix commit:** 8222588 (local only, not pushed)
**Investigation:** `DISPUTE-SIGNATURE-GAP-2026-10-18.md`

## Landing conditions (checked this run)

- HEAD had advanced beyond f7bda16 with the media/content/disputes
  batch committed (6ceb8e8) and its report present
  (`MEDIA-DISPUTES-FIX-REPORT.md`: 553 passed / 0 failed / 9 ignored).
- Working tree clean except the untracked
  `OWNER-DECISIONS-2026-10-18-EVENING.md` in the repo root, which does
  not block per the job definition.

## The fix

Moderators and dispute participants could not verify the seller's
payment-address ownership from the dispute page: the handler already
fetched the assignment's signature, but the template rendered neither
it nor the seller's primary address.

1. `marketplace/crates/app/src/web.rs` — `DisputeTpl` gains
   `signed_primary_address: Option<String>`, populated as
   `assignment.as_ref().map(|a| a.primary_address.clone())` next to
   the existing `signed_message` / `signed_signature` population.
   (`signed_signature` was already populated; it was simply never
   rendered.)
2. `marketplace/crates/app/templates/dispute.html` — in "What
   moderators can see", after the signed_message line, the primary
   address and the signature now render as copyable readonly
   textareas matching pay.html's presentation.
3. `marketplace/crates/app/tests/dispute_signature.rs` (new, app
   crate's own tests) — regression test: builds an order with a
   payment assignment (distinctive primary address, signed message,
   and signature), requests the dispute page as buyer and as seller,
   and asserts the signature, the primary address, and the signed
   message all appear in the rendered page.

## Gate

Environment per AGENTS.md: `~/.cargo/bin` on PATH,
`NETTLE_PREGENERATED_BINDINGS=~/pgsys/nettle-bindings.rs`,
`PKG_CONFIG_PATH=~/pkgconfig`, `MEDIA_WORKER`/`MEDIA_DIR` set,
`TMPDIR` on a disk-backed dir, user-space Postgres on port 5432.

- `cargo check --workspace --all-targets`: clean (pre-existing
  warnings only).
- **Complete workspace run (final): 554 passed / 0 failed /
  9 ignored** — baseline 553 (media batch) + 1 new regression test.
  Every locked blind suite at baseline: blind_direct_v1 42/42,
  blind_stage1 41, blind_stage2 38, blind_stage3 34,
  blind_stage4 58 passed / 6 ignored, blind_stage5 35 / 3,
  blind_stage6 83, blind_stage9 43/43, blind_stage10 32/32;
  account_security 14/14, messaging_audit 9/9,
  media_disputes_audit 9/9.
- **Zero files under `marketplace/tests/security/`,
  `docs/invariants.md`, or the spec were modified.**

### Gate honesty note — one transient failure in the first run

The first complete run finished 553 passed / 1 failed / 9 ignored:
one `blind_stage4` test failed (57 passed in that suite). The failing
test could not be identified from that run's log (the log file was
found truncated afterward), so the suite was re-run standalone:
**58 passed / 0 failed / 6 ignored in 3.0s**, and the second complete
workspace run (reported above) passed blind_stage4 58/58 in 2.0s.
Evidence the failure was environmental, not caused by this change:
no security test references `DisputeTpl`, `signed_signature`, or the
dispute template (verified by grep; blind_stage4 exercises the order
state machine at library level), and this VM generation was heavily
loaded during the runs (the account_security suite alone took 467s
in the second run; two of its tests exceeded 60s each). Reported
here rather than hidden, per this repo's convention.

### Environment note

Mid-run, the sandbox VM was replaced: the user-space Postgres, its
`/tmp` data dir, and the apt psql client vanished (the AGENTS.md
failure mode). Postgres was re-provisioned from the Zonky binaries
in `~/pgsys` (extracted to `/tmp/pgx`, cluster in `/tmp/pgdata`,
port 5432, trust auth), and `marketplace_dev` was recreated fresh
with migrations 0001–0013 applied via a small sqlx runner (no psql
client exists on this generation; single-user mode cannot apply
multi-line migration files). Final schema: 38 tables, matching the
deployment batch's count. The server was left running.

## Files changed (commit 8222588)

- `marketplace/crates/app/src/web.rs` (+2 lines)
- `marketplace/crates/app/templates/dispute.html` (+2 lines)
- `marketplace/crates/app/tests/dispute_signature.rs` (new)

Nothing pushed.
