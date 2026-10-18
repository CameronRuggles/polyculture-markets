#!/bin/sh
# Q8 guard (decision log Q8, spec amendments §22): every build — dev, CI,
# production — uses Sequoia's Nettle backend. A build in which the
# experimental / variable-time RustCrypto backend is enabled must FAIL:
# algorithm support differs by backend, so a key verifying under one must
# verify under the other, and variable-time crypto is not accepted anywhere.
# Exits 0 only if crypto-nettle is resolved and no forbidden feature is.
set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

tree="$(cargo tree -e features -i sequoia-openpgp 2>/dev/null)"
if ! printf '%s' "$tree" | grep -q 'crypto-nettle'; then
  echo "FAIL: sequoia-openpgp is not built with crypto-nettle" >&2
  exit 1
fi
if printf '%s' "$tree" | grep -qE 'allow-experimental-crypto|allow-variable-time-crypto|crypto-rust'; then
  echo "FAIL: experimental/variable-time RustCrypto backend feature is enabled" >&2
  exit 1
fi
echo "OK: sequoia-openpgp resolves to the Nettle backend; no RustCrypto backend features enabled"
