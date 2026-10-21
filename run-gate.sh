#!/bin/sh
# The project gate: the full marketplace workspace suite plus the
# seller-helper workspace suite, against a real PostgreSQL.
#
# HT H1 audit fix task 3 (finding F3) adds the preflight below: the
# gate must be UNABLE to pass without a database. Before this, the
# app suites' pool() helpers returned None when the database was
# unreachable and every DB test returned early — a "green" gate run
# could silently contain no database coverage at all, and did (the
# expired Dave fixture passed a suite it would have failed). The
# helpers now panic when DATABASE_URL is set but unreachable, and
# this preflight fails the gate when DATABASE_URL is unset, so
# neither silent-skip mode can produce a green run.
#
# HT H1 audit fix task 4 (finding F15) fixes the gate's SHAPE to
# the audit brief's: the database is REBUILT (dropped, recreated,
# all migrations applied) before the security suites and again
# before the rest of the workspace, so no suite's verdict can
# depend on rows another suite left behind, and the locked
# envelope suite (blind_stage5) — silently omitted by the H1
# report's ad-hoc invocations — is always inside the run. The
# rebuild refuses any database whose name does not contain "dev":
# this script drops a database, and that must never be aimable at
# anything but a development database.
#
# Usage:  DATABASE_URL=postgres://postgres:dev@localhost:5432/marketplace_dev ./run-gate.sh
set -eu

cd "$(dirname "$0")"

if [ -z "${DATABASE_URL:-}" ]; then
    echo "gate preflight: DATABASE_URL is unset — refusing to run." >&2
    echo "A gate run without a database proves nothing (audit F3)." >&2
    echo "Set DATABASE_URL (see marketplace/deploy/dev-setup.sh) and re-run." >&2
    exit 2
fi

if ! command -v psql >/dev/null 2>&1; then
    echo "gate preflight: psql is required (reachability check + database rebuild)." >&2
    exit 2
fi

if ! psql "$DATABASE_URL" -tAc 'SELECT 1' >/dev/null 2>&1; then
    echo "gate preflight: DATABASE_URL is set but the database is unreachable:" >&2
    echo "  $DATABASE_URL" >&2
    exit 2
fi

DB_NAME=$(printf '%s' "$DATABASE_URL" | sed 's|.*/||; s|?.*||')
case "$DB_NAME" in
    *dev*) ;;
    *)
        echo "gate preflight: refusing to rebuild database '$DB_NAME':" >&2
        echo "the gate drops and recreates its database, and only rebuilds" >&2
        echo "databases with 'dev' in the name." >&2
        exit 2
        ;;
esac
MAINT_URL=$(printf '%s' "$DATABASE_URL" | sed 's|/[^/]*$|/postgres|')

rebuild_db() {
    echo "gate: rebuilding database $DB_NAME"
    psql "$MAINT_URL" -v ON_ERROR_STOP=1 -q \
        -c "DROP DATABASE IF EXISTS \"$DB_NAME\" WITH (FORCE)" \
        -c "CREATE DATABASE \"$DB_NAME\""
    for m in marketplace/migrations/*.sql; do
        psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$m" >/dev/null
    done
}

echo "gate preflight: DATABASE_URL set, database reachable."

rebuild_db
cd marketplace
cargo test -p security-tests
cd ..

rebuild_db
cd marketplace
cargo test --workspace --exclude security-tests
cd ..

# --workspace matters here: seller-helper's root manifest is a
# package AND its workspace root, so a bare `cargo test` against
# it tests only the root package and silently skips helper-core
# and helper-cli (found by fix task 4's per-target accounting:
# 17 of the workspace's 21 tests ran). The marketplace workspace
# root is a virtual manifest and has no such default.
cargo test --manifest-path seller-helper/Cargo.toml --workspace

echo "gate: PASS"
