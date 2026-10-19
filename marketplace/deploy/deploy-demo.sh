#!/bin/sh
# deploy-demo.sh — build (unprivileged), install, and (re)start the
# Polyculture Markets DEMO deployment (Stage 10 §18 profile tooling).
#
# DEMO / STAGENET ONLY. This script refuses to run against a
# mainnet or production-profile environment — see the guard below.
# Production deployment is a separate, reviewed procedure (§19).
#
# Run as root (sudo). Everything that must be root (installing
# binaries, the env file, systemd, PostgreSQL role/database
# administration) is root; everything that must NOT be root is not:
#
#   * The Rust build never runs as root (deployment audit DM3:
#     cargo executes every dependency's build script; ~500 crates'
#     worth of arbitrary code must not run with the key file and the
#     database in reach). Builds happen as an unprivileged user in a
#     throwaway copy of the source tree, or not at all: set
#     MARKETPLACE_BIN_DIR to install prebuilt binaries instead.
#   * Database migrations never run as the PostgreSQL superuser.
#     They run as the dedicated role `marketplace_migrator`, which
#     owns the demo database and its objects. The superuser is used
#     only to create roles/the database and to hand over ownership.
#   * The database password is read from a file
#     (MARKETPLACE_DB_PASSWORD_FILE, mode 0600 recommended) and is
#     passed to psql as a variable (:'pw'), never interpolated into
#     SQL text and never placed on any command line (audit DL1: a
#     password containing ' " $ / & broke the old sed/SQL
#     interpolation, and the value was visible in the process
#     list). MARKETPLACE_DB_PASSWORD remains as a fallback for
#     callers that cannot use a file.
#
# Layout installed:
#   /usr/local/bin/marketplace-app, /usr/local/bin/media-worker
#   /etc/systemd/system/marketplace-demo.service
#   /etc/marketplace/marketplace.env   (0600, created once, never
#                                       overwritten afterwards)
#   /var/lib/marketplace/              (runtime state: key file,
#                                       media/, blobs/)
#
# Usage:  sudo MARKETPLACE_DB_PASSWORD_FILE=/root/marketplace-db-password \
#           MARKETPLACE_BUILD_USER=<your normal account> \
#           deploy/deploy-demo.sh [path-to-marketplace-tree]
#         sudo MARKETPLACE_DB_PASSWORD_FILE=... \
#           MARKETPLACE_BIN_DIR=/path/to/prebuilt-binaries \
#           deploy/deploy-demo.sh [path-to-marketplace-tree]
set -eu

SRC_DIR="${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
ENV_FILE="/etc/marketplace/marketplace.env"
ENV_TEMPLATE="$SRC_DIR/deploy/env.demo.template"
UNIT_SRC="$SRC_DIR/deploy/marketplace-demo.service"
APP_USER="marketplace"
DB_NAME="marketplace_demo"
MIGRATOR_ROLE="marketplace_migrator"
STATE_DIR="/var/lib/marketplace"
BIN_DIR="${MARKETPLACE_BIN_DIR:-}"
BUILD_USER="${MARKETPLACE_BUILD_USER:-${SUDO_USER:-}}"
BUILD_WORK=""
SQL_TMP=""

say() { printf '%s\n' "deploy-demo: $*"; }
die() { printf '%s\n' "deploy-demo: ERROR: $*" >&2; exit 1; }
cleanup() {
    if [ -n "$BUILD_WORK" ]; then rm -rf "$BUILD_WORK"; fi
    if [ -n "$SQL_TMP" ]; then rm -f "$SQL_TMP"; fi
}
trap cleanup EXIT INT TERM

[ "$(id -u)" = "0" ] || die "run as root (sudo) — this installs system files and a systemd unit."

# --- Database password: from a file, never interpolated -------------
PW_FILE="${MARKETPLACE_DB_PASSWORD_FILE:-}"
if [ -n "$PW_FILE" ]; then
    [ -f "$PW_FILE" ] || die "MARKETPLACE_DB_PASSWORD_FILE=$PW_FILE does not exist."
    DB_PASSWORD="$(cat "$PW_FILE")"
    [ -n "$DB_PASSWORD" ] || die "password file $PW_FILE is empty."
elif [ -n "${MARKETPLACE_DB_PASSWORD:-}" ]; then
    DB_PASSWORD="$MARKETPLACE_DB_PASSWORD"
    say "warning: password taken from the MARKETPLACE_DB_PASSWORD environment variable;"
    say "         prefer MARKETPLACE_DB_PASSWORD_FILE so the secret never enters a process environment."
else
    die "set MARKETPLACE_DB_PASSWORD_FILE (preferred) or MARKETPLACE_DB_PASSWORD (see runbook)."
fi

[ -f "$ENV_TEMPLATE" ] || die "env template not found at $ENV_TEMPLATE"
[ -f "$UNIT_SRC" ] || die "unit file not found at $UNIT_SRC"

# --- Demo-only guard --------------------------------------------------
# A filled-in env file (once installed) wins over the template: never
# let a stray template edit re-arm a production-configured host.
EFFECTIVE_ENV="$ENV_TEMPLATE"
[ -f "$ENV_FILE" ] && EFFECTIVE_ENV="$ENV_FILE"
if grep -Eq '^[[:space:]]*INSTANCE_NETWORK[[:space:]]*=[[:space:]]*mainnet' "$EFFECTIVE_ENV"; then
    die "effective env ($EFFECTIVE_ENV) is MAINNET — this script deploys the stagenet demo only."
fi
if grep -Eq '^[[:space:]]*DEPLOY_PROFILE[[:space:]]*=[[:space:]]*production' "$EFFECTIVE_ENV"; then
    die "effective env ($EFFECTIVE_ENV) uses the production profile — this script deploys the demo only."
fi

APP_BIN=""; WORKER_BIN=""
if [ -n "$BIN_DIR" ]; then
    # --- Prebuilt binaries: no build on this host at all --------------
    APP_BIN="$BIN_DIR/marketplace-app"
    WORKER_BIN="$BIN_DIR/media-worker"
    [ -x "$APP_BIN" ] || die "prebuilt marketplace-app not found/executable in MARKETPLACE_BIN_DIR=$BIN_DIR"
    [ -x "$WORKER_BIN" ] || die "prebuilt media-worker not found/executable in MARKETPLACE_BIN_DIR=$BIN_DIR"
    say "using prebuilt binaries from $BIN_DIR (no build on this host)"
else
    # --- Build as an unprivileged user in a throwaway tree copy -----
    # cargo is NEVER run as root (DM3). The default build user is the
    # account that invoked sudo (the one whose ~/.cargo holds the
    # toolchain); override with MARKETPLACE_BUILD_USER.
    [ -n "$BUILD_USER" ] || die "refusing to run cargo as root: set MARKETPLACE_BUILD_USER=<unprivileged account> (default: \$SUDO_USER), or MARKETPLACE_BIN_DIR=<dir> to install prebuilt binaries instead."
    [ "$BUILD_USER" != "root" ] || die "MARKETPLACE_BUILD_USER must not be root (the build never runs as root)."
    id "$BUILD_USER" >/dev/null 2>&1 || die "build user '$BUILD_USER' does not exist on this host."
    BUILD_WORK="$(mktemp -d /tmp/marketplace-build.XXXXXX)"
    BUILD_SRC="$BUILD_WORK/src"
    mkdir -p "$BUILD_SRC"
    (cd "$SRC_DIR" && tar cf - --exclude=./target --exclude=./.git .) | (cd "$BUILD_SRC" && tar xf -)
    chown -R "$BUILD_USER" "$BUILD_WORK"
    say "building release binaries as $BUILD_USER in a throwaway copy of $SRC_DIR ..."
    su "$BUILD_USER" -c "cd '$BUILD_SRC' && export PATH=\"\$HOME/.cargo/bin:\$PATH\" && { command -v cargo >/dev/null 2>&1 || { echo 'deploy-demo: ERROR: cargo not found for build user $BUILD_USER (runbook §2 installs it as that user)' >&2; exit 1; }; } && cargo build --release --locked -p app -p media-worker"
    APP_BIN="$BUILD_SRC/target/release/marketplace-app"
    WORKER_BIN="$BUILD_SRC/target/release/media-worker"
    [ -x "$APP_BIN" ] && [ -x "$WORKER_BIN" ] || die "build finished but binaries are missing under $BUILD_SRC/target/release"
fi

# --- System user + dirs ------------------------------------------------
if ! id "$APP_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$APP_USER" 2>/dev/null \
        || useradd --system --home-dir "$STATE_DIR" --shell /bin/false "$APP_USER"
fi
mkdir -p "$STATE_DIR/media" "$STATE_DIR/blobs" /etc/marketplace
chown -R "$APP_USER:$APP_USER" "$STATE_DIR"
chmod 750 "$STATE_DIR"

# --- Install binaries + unit -------------------------------------------
install -o root -g root -m 0755 "$APP_BIN" /usr/local/bin/marketplace-app
install -o root -g root -m 0755 "$WORKER_BIN" /usr/local/bin/media-worker
install -o root -g root -m 0644 "$UNIT_SRC" /etc/systemd/system/marketplace-demo.service
say "installed binaries and systemd unit"

# --- Env file (created once; never overwrite a filled-in env) ----------
# The DATABASE_URL line is produced by splicing the template line with
# awk: the password is percent-encoded for the URL userinfo, so a
# password containing ' " $ / & \ (or anything else) round-trips
# byte-exact and never appears in plaintext in the env file.
url_encode_pw() (
    LC_ALL=C; export LC_ALL
    _rest="$DB_PASSWORD"; _out=""
    while [ -n "$_rest" ]; do
        _c=$(printf '%s' "$_rest" | dd bs=1 count=1 2>/dev/null)
        _rest=$(printf '%s' "$_rest" | dd bs=1 skip=1 2>/dev/null)
        case "$_c" in
            [A-Za-z0-9._~-]) _out="$_out$_c" ;;
            *) _out="$_out$(printf '%%%02X' "'$_c")" ;;
        esac
    done
    printf '%s' "$_out"
)
if [ ! -f "$ENV_FILE" ]; then
    PW_ENC="$(url_encode_pw)"
    install -o root -g root -m 0600 /dev/null "$ENV_FILE.tmp"
    awk -v "repl=DATABASE_URL=postgres://marketplace:${PW_ENC}@127.0.0.1:5432/${DB_NAME}" \
        '/^DATABASE_URL=/ { print repl; next } { print }' \
        "$ENV_TEMPLATE" > "$ENV_FILE.tmp"
    mv "$ENV_FILE.tmp" "$ENV_FILE"
    say "env file written to $ENV_FILE (0600) — review before first start if you need changes"
else
    say "env file $ENV_FILE already exists — left untouched"
fi

# --- PostgreSQL: roles, database, migrations ---------------------------
# The postgres superuser is used only to create the two roles and the
# database and to hand ownership to the migrator role. Everything
# after that runs AS the migrator (SET ROLE), which owns the database
# objects; schema changes never execute with superuser rights (DM3).
#
# The application role's password is set from a psql variable: the
# value travels on psql's stdin from a mode-0600 temporary SQL file,
# so it never appears in a command line, an SQL string literal, or
# the process list (DL1). \set quoting rule: backslash escapes the
# next character inside the single-quoted value.
sql_escape() { printf '%s' "$1" | awk '{ gsub(/\\/, "\\\\"); gsub(/'"'"'/, "\\'"'"'"); print }'; }
SQL_TMP="$(mktemp)"; chmod 600 "$SQL_TMP"   # removed by the exit trap as well
{
    printf "\\set pw '%s'\n" "$(sql_escape "$DB_PASSWORD")"
    if [ "$(su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='$APP_USER'\"")" = "1" ]; then
        echo "ALTER ROLE $APP_USER WITH LOGIN PASSWORD :'pw';"
    else
        echo "CREATE ROLE $APP_USER LOGIN PASSWORD :'pw';"
    fi
} > "$SQL_TMP"
if [ "$(su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='$MIGRATOR_ROLE'\"")" != "1" ]; then
    su postgres -c "psql -q -c \"CREATE ROLE $MIGRATOR_ROLE NOLOGIN\""
    say "created migration role $MIGRATOR_ROLE"
fi
su postgres -c "psql -v ON_ERROR_STOP=1 -q -f '$SQL_TMP'"
rm -f "$SQL_TMP"; SQL_TMP=""
say "application role '$APP_USER' password set (via psql variable, from ${PW_FILE:-the environment})"

if [ "$(su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='$DB_NAME'\"")" != "1" ]; then
    su postgres -c "createdb -O $MIGRATOR_ROLE $DB_NAME"
    say "created database $DB_NAME (owner: $MIGRATOR_ROLE)"
else
    su postgres -c "psql -q -c \"ALTER DATABASE $DB_NAME OWNER TO $MIGRATOR_ROLE\""
fi
# Databases created by earlier versions of this script have their
# tables owned by the postgres superuser; hand them to the migrator
# so migrations run unprivileged there too (no-op on fresh installs).
LEGACY_OWNED=$(su postgres -c "psql -d $DB_NAME -tAc \"SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tableowner = 'postgres'\"")
if [ "$LEGACY_OWNED" != "0" ]; then
    su postgres -c "psql -d $DB_NAME -q -c \"REASSIGN OWNED BY postgres TO $MIGRATOR_ROLE\""
    say "handed $LEGACY_OWNED legacy superuser-owned table(s) to $MIGRATOR_ROLE"
fi

AS_MIGRATOR="SET ROLE $MIGRATOR_ROLE"
su postgres -c "psql -d $DB_NAME -v ON_ERROR_STOP=1 -q -c \"$AS_MIGRATOR\" -c \"CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())\""
APPLIED=0; SKIPPED=0
for f in "$SRC_DIR"/migrations/*.sql; do
    v=$(basename "$f")
    if [ "$(su postgres -c "psql -d $DB_NAME -tAq -c \"$AS_MIGRATOR\" -c \"SELECT 1 FROM schema_migrations WHERE version = '$v'\"" | grep -c '^1$')" = "1" ]; then
        SKIPPED=$((SKIPPED+1)); continue
    fi
    su postgres -c "psql -d $DB_NAME -v ON_ERROR_STOP=1 -q -c \"$AS_MIGRATOR\" -f '$f'"
    su postgres -c "psql -d $DB_NAME -q -c \"$AS_MIGRATOR\" -c \"INSERT INTO schema_migrations (version) VALUES ('$v')\""
    APPLIED=$((APPLIED+1))
done
# Application-role DML on everything the migrator owns (re-runnable).
su postgres -c "psql -d $DB_NAME -q -c \"$AS_MIGRATOR\" -c \"GRANT ALL ON ALL TABLES IN SCHEMA public TO $APP_USER\" -c \"GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO $APP_USER\""
say "migrations: $APPLIED applied, $SKIPPED already present (as role $MIGRATOR_ROLE, never superuser)"

# --- Start / restart ----------------------------------------------------
systemctl daemon-reload
systemctl enable marketplace-demo.service >/dev/null 2>&1 || true
systemctl restart marketplace-demo.service

# --- Health check ---------------------------------------------------------
HEALTHY=""
for i in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:8080/" >/dev/null 2>&1; then HEALTHY=1; break; fi
    sleep 2
done
if [ -n "$HEALTHY" ]; then
    say "demo is up: http://127.0.0.1:8080/ (bind is loopback-only; front it per the runbook)"
else
    say "WARNING: service did not answer on :8080 within 60s — check: journalctl -u marketplace-demo -n 50" >&2
    exit 1
fi

say "deployed binary sha256:"
sha256sum /usr/local/bin/marketplace-app
say "SOURCE_URL and /source: the env template points at the public repo;"
say "if this instance serves other people, that line is your AGPL source offer — keep it set."
