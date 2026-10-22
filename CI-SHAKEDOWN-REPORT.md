# CI Shakedown Report — PR #1, first live CI run

Date: 2026-10-19. Branch `deployment-fix-batch`. Fix commit: `6b3197a`.
(Preceded by `0bdbdf6`, which fixed the workflow's startup validation
failure — `${{ runner.temp }}` is not an allowed context in job-level
`env:`; that one never created jobs at all.)

## Symptom

With the workflow finally starting, the `marketplace test suite
(Postgres)` job failed on both the push and PR runs: 11 of 14 tests
in `crates/app/tests/account_security.rs` failed — most panicking
with Postgres error 42P01 (`relation "accounts" does not exist` at
account_security.rs:160, `relation "payment_declarations" does not
exist` at :81), plus `production_profile_fails_closed` ("the
development profile must start").

Because `cargo test` stops at the first failing test binary, no
later suite ran in that job at all — the failure looked
account-security-specific but wasn't.

## Root cause (single)

The CI Postgres service starts **empty**, and nothing applied the
schema:

- The app never runs migrations on boot (by design).
- No test suite creates the schema; every DB suite assumes the
  database at `DATABASE_URL` is already migrated.
- Production gets its schema from `deploy/deploy-demo.sh`, which
  applies `marketplace/migrations/*.sql` in filename order with
  `schema_migrations` bookkeeping.
- Locally the dev database is long-lived and pre-migrated, so this
  was invisible in every local run.

`production_profile_fails_closed` was the same cause, not a second
one: its development-profile control spawns the app against the
test database, and the app exits at startup when its boot queries
hit missing tables.

## Reproduction (local, before the fix)

Stood up a fresh empty database (`marketplace_ci_repro`, 0 tables)
on the local Postgres and ran the suite against it:

- Empty DB: **10 failed / 4 passed**, with the exact CI signatures
  (42P01 "accounts" at :160, "payment_declarations" at :81, and
  `production_profile_fails_closed` in the failure list). CI showed
  11 failures; the one-test difference is environment noise between
  the shared local box and the runner — the failure class is
  identical.
- Applied the 13 migrations deploy-style (schema_migrations table +
  each `migrations/*.sql` in order → 39 public tables), same fresh
  DB: **14 passed / 0 failed**.

## Fix

Workflow-only change in `.github/workflows/ci.yml` (commit
`6b3197a`); no code and no test files touched:

- The test job installs `postgresql-client` and gains an **"Apply
  migrations"** step before "Full test suite", mirroring
  `deploy-demo.sh`: create `schema_migrations`, apply each
  `migrations/*.sql` in filename order with `ON_ERROR_STOP=1`,
  record each version. CI connects as the service superuser, so
  the deploy script's migrator-role separation doesn't apply —
  the bookkeeping shape is kept so the CI database looks like a
  production one.
- The workflow header comment documents why the step exists.

## Evidence after the fix

- **CI, commit `6b3197a`** — all jobs green on both the push run
  (39235995936) and the PR run (39236000518):
  - `marketplace test suite (Postgres)`: **pass** (8m13s push /
    4m57s PR). The migration step completes and the full suite —
    every binary, not just account_security — runs green.
  - `audit / deny / crypto guard / clippy`: pass.
  - `seller-helper build + tests`: pass.
  - `fuzz smoke` (advisory): pass (10m15s / 10m19s).
- **Local, long-lived dev DB** — full workspace run at this branch
  state (`~/buildtmp/baseline.log`): **554 passed / 0 failed / 9
  ignored** (553 deployment-batch baseline + 1 test from the
  signed_signature fix commits `8222588`/`0935cc2`).
- **Local, fresh DB** — account_security 14/14 after migration
  application (above).
- Nothing under `marketplace/tests/security/` was modified; no
  assertion was weakened and no test was removed.

## Notes

- The local full-suite baseline was produced by a concurrent
  verification run on this box rather than by this fix's own run,
  and the fresh-DB local repro ran 10 failures where CI showed 11;
  both are stated plainly rather than smoothed over. The CI result
  at the fixed commit — the environment that actually failed — is
  unambiguous: every job green, twice.
