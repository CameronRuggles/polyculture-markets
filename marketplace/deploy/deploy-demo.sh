#!/bin/sh
# deploy-demo.sh — idempotent deploy of the marketplace DEMO profile
# (stagenet) to a single small VM. See DEPLOY-DEMO-RUNBOOK.md for the
# full walkthrough this script belongs to.
#
# What it does, in order, every run:
#   1. Refuses to run if the env file selects mainnet (the demo
#      tooling is stagenet-only; the binary independently refuses
#      mainnet in the demo profile too — defense in depth).
#   2. Builds the release binaries (marketplace-app, media-worker).
#   3. Creates the marketplace system user and directories.
#   4. Installs binaries to /usr/local/bin and the systemd unit.
#   5. Installs the env file from env.demo.template ONLY IF ABSENT —
#      an existing /etc/marketplace/marketplace.env is never
#      overwritten (it holds the operator's filled-in secrets).
#   6. Provisions the PostgreSQL role + database (idempotent).
#   7. Applies migrations in glob order (each migration is applied
#      at most once; a marker table records what ran).
#   8. Restarts the unit and health-checks http://127.0.0.1:8080/
#      until it answers, then prints the binary SHA-256.
#
# Re-running this script is the upgrade path: new binaries, pending
# migrations, restart, health check. Nothing is ever downgraded and
# the database is never dropped.
#
# Required env (operator-provided, never committed):
#   MARKETPLACE_DB_PASSWORD — password for the PostgreSQL role the
#   script creates/updates; must match DATABASE_URL in the env file.
#
# Run as root on the target VM, from anywhere:
#   sudo MARKETPLACE_DB_PASSWORD='...' sh deploy/deploy-demo.sh [SRC_DIR]
# SRC_DIR defaults to the parent of this script's directory.

set -eu

SRC_DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
ENV_FILE="/etc/marketplace/marketplace.env"
ENV_TEMPLATE="$SRC_DIR/deploy/env.demo.template"
UNIT_FILE="$SRC_DIR/deploy/marketplace-demo.service"
APP_USER="marketplace"
STATE_DIR="/var/lib/marketplace"

say() { printf '%s\n' "deploy-demo: $*"; }
die() { printf '%s\n' "deploy-demo: ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root (sudo)."
[ -n "${MARKETPLACE_DB_PASSWORD:-}" ] || die "MARKETPLACE_DB_PASSWORD is not set (see runbook)."
[ -f "$ENV_TEMPLATE" ] || die "env template not found at $ENV_TEMPLATE"
[ -f "$UNIT_FILE" ] || die "unit file not found at $UNIT_FILE"

# --- 1. Stagenet-only guard ------------------------------------------------
# Check the EFFECTIVE env file (the installed one if present, else
# the template) before doing anything at all.
EFFECTIVE_ENV="$ENV_FILE"
[ -f "$EFFECTIVE_ENV" ] || EFFECTIVE_ENV="$ENV_TEMPLATE"
if grep -Eq '^[[:space:]]*INSTANCE_NETWORK[[:space:]]*=[[:space:]]*mainnet' "$EFFECTIVE_ENV"; then
    die "the env file selects mainnet. The demo deploy tooling is stagenet-only; refusing."
fi
if grep -Eq '^[[:space:]]*DEPLOY_PROFILE[[:space:]]*=[[:space:]]*production' "$EFFECTIVE_ENV"; then
    die "the env file selects the production profile. This script deploys the demo profile only; refusing."
fi

# --- 2. Build ----------------------------------------------------------------
export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH (install the pinned Rust toolchain first — see runbook)."
say "building release binaries from $SRC_DIR ..."
(cd "$SRC_DIR" && cargo build --release --locked -p app -p media-worker)
APP_BIN="$SRC_DIR/target/release/marketplace-app"
WORKER_BIN="$SRC_DIR/target/release/media-worker"
[ -x "$APP_BIN" ] || die "release binary missing after build: $APP_BIN"
[ -x "$WORKER_BIN" ] || die "release binary missing after build: $WORKER_BIN"

# --- 3. User + directories -----------------------------------------------------
if ! id "$APP_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$APP_USER"
    say "created system user $APP_USER"
fi
mkdir -p "$STATE_DIR/media" /etc/marketplace
chown -R "$APP_USER:$APP_USER" "$STATE_DIR"
chmod 750 "$STATE_DIR"

# --- 4. Binaries + unit ----------------------------------------------------------
install -m 0755 "$APP_BIN" /usr/local/bin/marketplace-app
install -m 0755 "$WORKER_BIN" /usr/local/bin/media-worker
install -m 0644 "$UNIT_FILE" /etc/systemd/system/marketplace-demo.service
say "installed binaries and systemd unit"

# --- 5. Env file (never overwrite) ------------------------------------------------
if [ -f "$ENV_FILE" ]; then
    say "env file $ENV_FILE already exists — left untouched"
else
    install -m 0600 "$ENV_TEMPLATE" "$ENV_FILE"
    # Fill the database password placeholder from the operator env.
    sed -i "s/CHANGE-ME/$MARKETPLACE_DB_PASSWORD/" "$ENV_FILE"
    chown root:root "$ENV_FILE"
    say "installed env file from template (fill in anything else marked CHANGE-ME, then re-run)"
fi

# --- 6. PostgreSQL role + database --------------------------------------------------
DB_NAME="marketplace_demo"
if su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname = 'marketplace'\"" | grep -q 1; then
    su postgres -c "psql -v ON_ERROR_STOP=1 -c \"ALTER ROLE marketplace WITH PASSWORD '$MARKETPLACE_DB_PASSWORD'\""
else
    su postgres -c "psql -v ON_ERROR_STOP=1 -c \"CREATE ROLE marketplace LOGIN PASSWORD '$MARKETPLACE_DB_PASSWORD'\""
fi
if ! su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'\"" | grep -q 1; then
    su postgres -c "createdb -O marketplace $DB_NAME"
    say "created database $DB_NAME"
fi

# --- 7. Migrations (glob order, each at most once) ----------------------------------
su postgres -c "psql -d $DB_NAME -v ON_ERROR_STOP=1 -c \"
  CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());\"" >/dev/null
for f in "$SRC_DIR"/migrations/*.sql; do
    v="$(basename "$f")"
    applied="$(su postgres -c "psql -d $DB_NAME -tAc \"SELECT 1 FROM schema_migrations WHERE version = '$v'\"")"
    if [ "$applied" = "1" ]; then
        say "migration $v already applied — skipping"
    else
        say "applying migration $v"
        su postgres -c "psql -d $DB_NAME -v ON_ERROR_STOP=1 -q -f '$f'"
        su postgres -c "psql -d $DB_NAME -v ON_ERROR_STOP=1 -q -c \"INSERT INTO schema_migrations (version) VALUES ('$v')\"" >/dev/null
    fi
done
# The app connects as the marketplace role; own what the migrations made.
su postgres -c "psql -d $DB_NAME -v ON_ERROR_STOP=1 -q -c \"
  GRANT ALL ON ALL TABLES IN SCHEMA public TO marketplace;
  GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO marketplace;\"" >/dev/null

# --- 8. Start + health check -------------------------------------------------------------
systemctl daemon-reload
systemctl enable --now marketplace-demo.service >/dev/null 2>&1 || true
systemctl restart marketplace-demo.service
say "waiting for the app to answer on http://127.0.0.1:8080/ ..."
i=0
while [ "$i" -lt 30 ]; do
    if curl -fsS -o /dev/null http://127.0.0.1:8080/ 2>/dev/null; then
        say "healthy: http://127.0.0.1:8080/ answers"
        break
    fi
    i=$((i + 1))
    sleep 2
done
[ "$i" -lt 30 ] || die "health check failed after 60s — inspect: journalctl -u marketplace-demo -n 100"

SHA="$(sha256sum /usr/local/bin/marketplace-app | awk '{print $1}')"
say "deployed marketplace-app sha256: $SHA"
say "done. Reach the demo through an SSH tunnel: ssh -L 8080:127.0.0.1:8080 <user>@<vm>"
