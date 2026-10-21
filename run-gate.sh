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
# Usage:  DATABASE_URL=postgres://postgres:dev@localhost:5432/marketplace_dev ./run-gate.sh
# The database must exist with marketplace/migrations/*.sql applied
# (marketplace/deploy/dev-setup.sh provisions both).
set -eu

cd "$(dirname "$0")"

if [ -z "${DATABASE_URL:-}" ]; then
    echo "gate preflight: DATABASE_URL is unset — refusing to run." >&2
    echo "A gate run without a database proves nothing (audit F3)." >&2
    echo "Set DATABASE_URL (see marketplace/deploy/dev-setup.sh) and re-run." >&2
    exit 2
fi

if command -v psql >/dev/null 2>&1; then
    if ! psql "$DATABASE_URL" -tAc 'SELECT 1' >/dev/null 2>&1; then
        echo "gate preflight: DATABASE_URL is set but the database is unreachable:" >&2
        echo "  $DATABASE_URL" >&2
        exit 2
    fi
fi

echo "gate preflight: DATABASE_URL set, database reachable."

cd marketplace
cargo test --workspace
cd ..
cargo test --manifest-path seller-helper/Cargo.toml

echo "gate: PASS"
