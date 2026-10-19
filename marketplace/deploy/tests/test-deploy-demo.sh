#!/bin/sh
# Guard/behaviour tests for deploy-demo.sh (deployment audit DM3 + DL1).
#
# These tests run the deploy script WITHOUT deploying anything real:
# every privileged helper it calls (cargo, psql, createdb, systemctl,
# curl, useradd, su-to-postgres) is a stub on PATH that logs its
# invocation, and the source tree is a scratch copy. They prove:
#
#   T1  a mainnet/production effective env is refused before anything
#       is built or installed (pre-existing safety property, kept);
#   T2  as root with no build user and no prebuilt binaries, the
#       script REFUSES to run cargo as root (DM3) and builds nothing;
#   T3  with prebuilt binaries, a full run succeeds; the installed
#       env's DATABASE_URL carries a hostile password (' " $ / & \)
#       percent-encoded and byte-exact after decoding; the password
#       never appears in any psql argv; the role SQL passes it via a
#       psql variable (:'pw'); cargo is never invoked (DL1 + DM3);
#   T4  with a build user, cargo runs under THAT user's uid, never 0;
#   T5  an existing filled env file is never overwritten.
#
# SANDBOX ONLY: the script's install paths are absolute
# (/etc/marketplace, /var/lib/marketplace, /usr/local/bin), so this
# harness refuses to start if /etc/marketplace/marketplace.env
# already exists — it is for a disposable dev box/CI container with
# the stubs on PATH, never for a host running a real instance.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCRIPT="$HERE/../deploy-demo.sh"
ENV_FILE=/etc/marketplace/marketplace.env
PW='p'"'"'a"s$/\&x'          # ' " $ / & \ — the DL1 hostile set
TMP=$(mktemp -d)
LOGS="$TMP/logs"; BIN="$TMP/stubbin"; SRC="$TMP/src"
mkdir -p "$LOGS" "$BIN" "$SRC/deploy" "$SRC/migrations" "$TMP/prebuilt"
chmod 755 "$TMP" "$BIN"   # the build user (T4) must traverse these
chmod 777 "$LOGS"         # ...and must be able to create its log there
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
note() { echo "note: $1"; }

if [ -e "$ENV_FILE" ]; then
    echo "refusing to run: $ENV_FILE already exists (sandbox-only harness)" >&2
    exit 2
fi
command -v python3 >/dev/null || { echo "python3 required for URL decoding" >&2; exit 2; }
id pguser >/dev/null 2>&1 || { echo "a non-root 'pguser' account is required for T4" >&2; exit 2; }

# --- scratch source tree -------------------------------------------------
cp "$HERE/../env.demo.template" "$SRC/deploy/env.demo.template"
cp "$HERE/../marketplace-demo.service" "$SRC/deploy/marketplace-demo.service"
printf -- '-- stub migration\nCREATE TABLE IF NOT EXISTS stub_t (id int);\n' > "$SRC/migrations/0001_stub.sql"

# --- stubs ---------------------------------------------------------------
cat > "$BIN/cargo" <<'EOF'
#!/bin/sh
echo "cargo uid=$(id -u) args=$*" >> "__LOGS__/cargo.log"
mkdir -p target/release 2>/dev/null
for b in marketplace-app media-worker; do
    printf '#!/bin/sh\nexit 0\n' > "target/release/$b" 2>/dev/null
    chmod +x "target/release/$b" 2>/dev/null
done
exit 0
EOF
cat > "$BIN/psql" <<'EOF'
#!/bin/sh
echo "psql argv: $*" >> "__LOGS__/psql-argv.log"
prev=""
for a in "$@"; do
    if [ "$prev" = "-f" ]; then
        { echo "--- file: $a"; cat "$a"; } >> "__LOGS__/psql-files.log" 2>/dev/null
    fi
    prev="$a"
done
case "$*" in
    *pg_roles*migrator*) : ;;
    *pg_roles*) [ "${STUB_APP_ROLE:-0}" = "1" ] && echo 1 ;;
    *pg_database*) : ;;
    *schema_migrations*SELECT*) : ;;
    *pg_tables*tableowner*) echo 0 ;;
esac
exit 0
EOF
cat > "$BIN/su" <<'EOF'
#!/bin/sh
echo "su user=$1" >> "__LOGS__/su.log"
if [ "$1" = "postgres" ]; then
    shift; [ "${1:-}" = "-c" ] && shift
    sh -c "$1"
else
    exec /usr/bin/su "$@"
fi
EOF
cat > "$BIN/id" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-u" ]; then exec /usr/bin/id -u; fi
exit 0
EOF
cat > "$BIN/chown" <<'EOF'
#!/bin/sh
echo "chown $*" >> "__LOGS__/chown.log"
/usr/bin/chown "$@" 2>/dev/null || true
exit 0
EOF
for c in createdb systemctl curl useradd; do
    printf '#!/bin/sh\necho "%s $*" >> "__LOGS__/misc.log"\nexit 0\n' "$c" > "$BIN/$c"
done
sed -i "s|__LOGS__|$LOGS|g" "$BIN"/*
chmod 755 "$BIN"/*   # explicit modes: a 0007 umask makes `chmod +x` give 770, unreadable to the build user
printf '#!/bin/sh\nexit 0\n' > "$TMP/prebuilt/marketplace-app"
printf '#!/bin/sh\nexit 0\n' > "$TMP/prebuilt/media-worker"
chmod 755 "$TMP/prebuilt"/*
printf '%s\n' "$PW" > "$TMP/pwfile"; chmod 600 "$TMP/pwfile"

export TEST_LOG_DIR="$LOGS"
BASE_PATH="$BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
run_script() {
    # extra env assignments are passed as arguments: VAR=val ...
    # MARKETPLACE_DB_PASSWORD is always supplied as well: it was the
    # pre-restructure interface (and remains the documented fallback),
    # so both interfaces are exercised on every run.
    env -i PATH="$BASE_PATH" TEST_LOG_DIR="$LOGS" HOME=/root MARKETPLACE_DB_PASSWORD="$PW" "$@" "$SCRIPT" "$SRC"
}
reset_logs() { rm -f "$LOGS"/*.log; }

echo "== T1: mainnet effective env refused before any build/install"
reset_logs
cp "$SRC/deploy/env.demo.template" "$TMP/template.bak"
sed 's/INSTANCE_NETWORK=stagenet/INSTANCE_NETWORK=mainnet/' "$TMP/template.bak" > "$SRC/deploy/env.demo.template"
if run_script MARKETPLACE_BIN_DIR="$TMP/prebuilt" MARKETPLACE_DB_PASSWORD_FILE="$TMP/pwfile" > "$TMP/t1.out" 2>&1; then
    bad "T1 script exited 0 on a mainnet template"
else
    grep -qi "mainnet" "$TMP/t1.out" && ok "T1 refused with a mainnet message" || bad "T1 refused but message unclear: $(cat "$TMP/t1.out")"
fi
[ ! -s "$LOGS/cargo.log" ] && ok "T1 cargo never ran" || bad "T1 cargo ran before the guard"
cp "$TMP/template.bak" "$SRC/deploy/env.demo.template"

echo "== T2: root with no build user and no binaries refuses to run cargo"
reset_logs
if run_script MARKETPLACE_BUILD_USER= SUDO_USER= MARKETPLACE_BIN_DIR= MARKETPLACE_DB_PASSWORD_FILE="$TMP/pwfile" > "$TMP/t2.out" 2>&1; then
    bad "T2 script exited 0 (it must refuse or build unprivileged)"
else
    ok "T2 script refused"
fi
if [ -s "$LOGS/cargo.log" ]; then
    grep -q "uid=0" "$LOGS/cargo.log" && bad "T2 cargo ran AS ROOT" || note "T2 cargo ran unprivileged (acceptable shape)"
else
    grep -qi "refusing to run cargo as root\|refuses to build as root\|will not build as root" "$TMP/t2.out" \
        && ok "T2 refusal names the root-build problem" || note "T2 refusal message: $(head -2 "$TMP/t2.out")"
fi
rm -f "$ENV_FILE"   # a pre-restructure script may have installed one; start T3 clean

echo "== T3: prebuilt run; hostile password round-trips; psql argv stays clean"
reset_logs
if run_script MARKETPLACE_BIN_DIR="$TMP/prebuilt" MARKETPLACE_DB_PASSWORD_FILE="$TMP/pwfile" > "$TMP/t3.out" 2>&1; then
    ok "T3 prebuilt run succeeded"
else
    bad "T3 prebuilt run failed: $(tail -3 "$TMP/t3.out")"
fi
[ ! -s "$LOGS/cargo.log" ] && ok "T3 cargo never invoked in prebuilt mode" || bad "T3 cargo invoked in prebuilt mode"
if [ -f "$ENV_FILE" ]; then
    [ "$(stat -c %a "$ENV_FILE")" = "600" ] && ok "T3 env file is 0600" || bad "T3 env file mode is $(stat -c %a "$ENV_FILE")"
    if grep -qF "$PW" "$ENV_FILE"; then bad "T3 env file contains the RAW password"; else ok "T3 env file has no raw password"; fi
    DECODED=$(python3 - "$ENV_FILE" <<'PYEOF'
import sys, urllib.parse
for line in open(sys.argv[1]):
    if line.startswith("DATABASE_URL="):
        url = line.strip()[len("DATABASE_URL="):]
        userinfo = url.split("://", 1)[1].split("@", 1)[0]
        print(urllib.parse.unquote(userinfo.split(":", 1)[1]))
        break
PYEOF
)
    [ "$DECODED" = "$PW" ] && ok "T3 DATABASE_URL password decodes byte-exact" || bad "T3 decoded password mismatch: [$DECODED] != [$PW]"
else
    bad "T3 env file was not installed"
fi
if grep -qF "$PW" "$LOGS/psql-argv.log" 2>/dev/null; then bad "T3 password appears in psql argv (process list)"; else ok "T3 password absent from psql argv"; fi
grep -q ":'pw'" "$LOGS/psql-files.log" 2>/dev/null && ok "T3 role SQL uses the :'pw' psql variable" || bad "T3 no :'pw' variable mechanism found in psql input"
if grep -qF "PASSWORD '$PW'" "$LOGS/psql-files.log" "$LOGS/psql-argv.log" 2>/dev/null; then bad "T3 password interpolated literally into SQL"; else ok "T3 no literal password interpolation in SQL"; fi

echo "== T4: build mode runs cargo as the build user, never root"
reset_logs
if run_script MARKETPLACE_BUILD_USER=pguser MARKETPLACE_BIN_DIR= MARKETPLACE_DB_PASSWORD_FILE="$TMP/pwfile" > "$TMP/t4.out" 2>&1; then
    ok "T4 build-mode run succeeded"
else
    bad "T4 build-mode run failed: $(tail -3 "$TMP/t4.out")"
fi
if [ -s "$LOGS/cargo.log" ]; then
    grep -q "uid=0" "$LOGS/cargo.log" && bad "T4 cargo ran as root" || ok "T4 cargo uid != 0 ($(head -1 "$LOGS/cargo.log"))"
else
    bad "T4 cargo never ran in build mode"
fi

echo "== T5: existing env file is never overwritten"
BEFORE=$(sha256sum "$ENV_FILE" 2>/dev/null | cut -d' ' -f1)
run_script MARKETPLACE_BIN_DIR="$TMP/prebuilt" MARKETPLACE_DB_PASSWORD_FILE="$TMP/pwfile" > "$TMP/t5.out" 2>&1
AFTER=$(sha256sum "$ENV_FILE" 2>/dev/null | cut -d' ' -f1)
if [ -n "$BEFORE" ] && [ "$BEFORE" = "$AFTER" ]; then ok "T5 env file untouched on re-run"; else bad "T5 env file changed on re-run"; fi

echo
echo "passed: $PASS  failed: $FAIL"
if [ -n "${KEEP_TMP:-}" ]; then echo "scratch kept at: $TMP"; else rm -rf "$TMP"; fi
[ "$FAIL" = "0" ]
