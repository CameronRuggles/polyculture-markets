# seller-helper

Standalone seller tool for **Direct Monero Payments v1**. It runs on
the seller's own machine, talks only to their local `monero-wallet-rpc`
on 127.0.0.1, pre-generates signed subaddresses in a dedicated wallet
account, self-verifies every signature, and writes a batch file
(`xmr-direct-batch-v1`) that the seller uploads to the marketplace.

This crate is intentionally **not** part of the marketplace workspace
(its `Cargo.toml` carries its own `[workspace]`), so it builds and
ships on its own:

```sh
cargo build --release   # binary: target/release/seller-helper
cargo test
```

Commands: `init`, `generate --count N`, `check <address>`.
Sellers: read [SELLER-GUIDE.md](SELLER-GUIDE.md).

Pinned for Monero wallet **v0.18.4.3** RPC shapes and the `monero`
crate **0.22** (same major as the marketplace). Exact dependency
versions are locked in `Cargo.lock`.
