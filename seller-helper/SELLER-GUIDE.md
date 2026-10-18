# Seller Guide — xmr-direct helper tool

## What this tool is

The marketplace pays you **directly**: buyers send Monero from their
own wallet straight to yours. The marketplace never holds money, keys
or payment data — so it needs a set of your payment addresses in
advance, and buyers need a way to be sure an address they are shown
really is yours.

This helper tool creates that set, on **your** machine, inside **your**
wallet:

1. It creates subaddresses in a dedicated account in your wallet.
2. For each one, it builds a one-line message
   (`xmr-direct-v1|<marketplace>|<network>|<your seller ID>|<your primary address>|<subaddress>`)
   and asks your wallet to sign it with your primary address key.
3. It checks every signature itself, then writes a **batch file**.
   You upload that file in your seller dashboard. Each subaddress is
   used for exactly one order.

A buyer can paste the message, your primary address and the signature
into their own wallet's "verify message" feature and confirm the
payment address is genuinely yours — even if the marketplace server
were compromised.

**Safety properties, by design:**

- The tool only talks to a wallet RPC on **127.0.0.1** (this computer).
  It refuses any other address, in code. It has no other network
  access: no telemetry, no update checks, no uploads.
- It can only call 8 wallet RPC methods, enforced by an allowlist in
  the code: `get_version`, `get_address`, `create_account`,
  `create_address`, `label_address`, `get_address_index`, `sign`,
  `verify`. It cannot send funds, read your keys, or open/close
  wallets — those methods are refused before any network call.
- It **never asks for your seed, your wallet password, or any key**,
  and it never sees them. Signing happens inside your wallet.
- The marketplace never sees your keys either: it only stores the
  subaddresses, messages and signatures from the batch file.

## What you need

- Your Monero wallet, restored/openable by `monero-wallet-rpc`
  (from the official Monero release, v0.18.x).
- This tool, built from source:

```sh
cd seller-helper
cargo build --release
# binary: target/release/seller-helper
```

## Step 0 — start your wallet RPC (local only)

Start `monero-wallet-rpc` bound to 127.0.0.1 with an RPC login. Pick
any username/password for the login — it only protects the wallet RPC
on your own machine, and the helper needs it in its config (below).

Stagenet (for testing):

```sh
monero-wallet-rpc \
  --stagenet \
  --rpc-bind-ip 127.0.0.1 \
  --rpc-bind-port 28088 \
  --rpc-login yourname:yourrpcpassword \
  --daemon-address 127.0.0.1:38089 \
  --wallet-dir /path/to/your/wallets
```

Mainnet:

```sh
monero-wallet-rpc \
  --rpc-bind-ip 127.0.0.1 \
  --rpc-bind-port 18088 \
  --rpc-login yourname:yourrpcpassword \
  --daemon-address 127.0.0.1:18089 \
  --wallet-dir /path/to/your/wallets
```

Notes:

- `--daemon-address` should point at **your own node** (the examples
  above assume a local `monerod`: stagenet p2p/RPC on 38089, mainnet
  on 18089). Address generation and signing don't need the daemon to
  be synced, but keep your normal node setup.
- Open your wallet in the RPC (with `monero-wallet-cli`, the GUI, or
  the RPC's own open command) before running `generate`, and leave the
  RPC running while you use the helper.
- Never bind the wallet RPC to anything but 127.0.0.1, and never share
  the RPC login. The helper refuses non-local addresses anyway.

## The three-step routine

### 1. One-time setup: `init`

Copy `marketplace_id`, `network` and your `seller_id` **exactly** from
your seller dashboard — they are baked into every signed message, and
a mismatch means the marketplace will reject your batch.

```sh
seller-helper init \
  --marketplace-id <from dashboard> \
  --network stagenet \
  --seller-id <your seller id> \
  --rpc-url http://127.0.0.1:28088/json_rpc \
  --rpc-user yourname \
  --rpc-password yourrpcpassword
```

(With no flags, it prompts for each value instead. Use `--network
mainnet` and port 18088 when you go live.)

This saves `~/.config/xmr-direct-helper/config.json` with owner-only
permissions (0600). It contains the RPC login for your **local** RPC —
that login never leaves your machine and is never sent to the
marketplace. The config contains no seed and no wallet password.

### 2. Generate a batch and upload it: `generate`

With your wallet open in the local RPC:

```sh
seller-helper generate --count 20
```

This writes `xmr-direct-batch-<your seller id>.json` in the current
directory (use `--out some/path.json` to change that). Upload that
file in your seller dashboard. Your listings can take orders until
the pool runs low — when the marketplace warns you the pool is low,
run `generate` again and upload the new batch.

What the tool does during `generate`:

- Checks the wallet's primary address is on the configured network;
  if not, it **aborts before creating anything**.
- Creates the subaddresses in a dedicated wallet account labelled
  **xmr-direct-marketplace** (created and labelled on first run, then
  remembered), and labels each new subaddress.
- Signs each message and **verifies each signature**; if any check
  fails, the whole batch is aborted and **no file is written**.

### 3. Spot-check a live order: `check`

Open one of your listings' payment pages (a test order is ideal),
copy the payment subaddress shown, and run:

```sh
seller-helper check <the address from the payment page>
```

It prints whether the address belongs to your wallet, and which
account/index it is (exit code 0), or "not in this wallet" (exit code
1). If a payment page ever shows an address that is not in your
wallet, do not accept payment there — report it.

## ⚠️ Restore warning (read this once)

When `generate` finishes it prints the **highest subaddress index**
used in the marketplace account. Write that number down with your
wallet records.

A wallet restored from its seed phrase only scans a limited number of
subaddresses ahead by default (monero-wallet v0.18 scans **200**
subaddresses ahead per account). If your marketplace account ever
grows past that — or you just want to be safe — raise the wallet's
subaddress lookahead to **at least the highest index the tool
printed** *before* restoring from seed (the `--subaddress-lookahead`
option of `monero-wallet-rpc`/`monero-wallet-cli`, or the equivalent
wallet setting). Otherwise a restored wallet may not see payments
sent to high-index marketplace subaddresses until the lookahead is
raised and the wallet is rescanned.

## Rules to keep

- The tool never asks for your seed or wallet password. If anything
  ever does — a web page, an email, a "new version" of this tool —
  stop: it's not this tool. Build the tool from source (or verify the
  checksum of a published build) and keep your seed offline as usual.
- Your RPC login stays on your machine. The marketplace never needs
  it, your wallet password, or any key — anyone asking doesn't get it.
- Keep your primary address stable. Changing it is treated as a new
  payment identity: your unused subaddresses are retired and your
  listings show a change warning. Generate a fresh batch after any
  deliberate change.
- Amounts and refunds: buyers pay the exact order amount to the
  subaddress. If something goes wrong, refunds are between you and
  the buyer, from your wallet — the marketplace cannot move your
  money.
