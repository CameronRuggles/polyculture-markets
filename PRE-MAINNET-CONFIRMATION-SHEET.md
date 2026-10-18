# Pre-mainnet confirmation sheet — Direct Payments v1

Status: **PARTLY confirmed.** Prepared 2026-10-15 (America/Denver) so the
stagenet → mainnet flip, when Cameron chooses it, is a single sign-off
instead of a scavenger hunt. Nothing on this sheet changes any running
config; every value below is the current stagenet default, verified
against `marketplace/crates/app/src/payments.rs` (`PaymentConfig::defaults`)
on 2026-10-15.

Owner decision 2026-10-16: Cameron delegated the handoff settings to
Muse ("do whatever handoff settings you think is best"). Sections 2–3
are therefore accepted with the current defaults below. Section 1 — the
actual network flip to mainnet — remains a separate launch decision and
has NOT been executed by this delegation.

Confirming this sheet means: "these are the production values."

## 1. The switch itself

- [ ] **Network: stagenet → mainnet** (`INSTANCE_NETWORK`). Once flipped,
  sellers' signed batches bind to mainnet addresses and the
  `vespiary-market` marketplace_id is baked into real payment messages.

## 2. Capacity and anti-abuse knobs (env config, adjustable live, low stakes)

| Setting | Env var | Current default |
|---|---|---|
| Max batch size per upload | `PAYMENTS_MAX_BATCH` | 100 subaddresses |
| Max unused pool per seller | `PAYMENTS_MAX_UNUSED_POOL` | 100 |
| Low-pool alert to seller | `PAYMENTS_LOW_POOL_THRESHOLD` | at 10 left |
| Unpaid orders expire after | `PAYMENTS_UNPAID_EXPIRY_HOURS` | 48 hours (address retires with the order) |
| Open unpaid orders per buyer | `PAYMENTS_OPEN_UNPAID_CAP` | 3 max |
| Order creation rate | `PAYMENTS_ORDER_RATE_PER_HOUR` | 10 per hour per buyer |
| Address-change warning banner | `PAYMENTS_RESET_WARNING_DAYS` | 30 days |
| Expiry sweep interval | `PAYMENTS_SWEEP_INTERVAL_SECS` | 900 s (15 min) — internal, was not in the chat summary |

## 3. Two design-flavored items

- [x] **Server-side signature check: OFF** (`PAYMENTS_SERVER_SIGNATURE_CHECK`).
  Accepted 2026-10-16 under Cameron's delegation. The server never
  verifies sellers' wallet signatures at upload; the buyer's wallet is
  the only check. Note from the code: in v1 there is no verifier —
  turning this flag on does not add checking, it *rejects uploads*.
  Enabling real server-side verification is a separate build (isolated
  offline wallet or a vetted signature crate), not a toggle.
- [x] **Pinned versions accepted for launch:** wallet RPC **0.18.4.3**
  and the current address-parsing crate. Accepted 2026-10-16 under
  Cameron's delegation.

## 4. Owner-owes before mainnet (from DIRECT-PAYMENTS-V1-REPORT.md)

- [ ] Parked, not a current pre-mainnet blocker: re-run the
  address/signature acceptance tests on the **FCMP++ fork build** only
  if/when FCMP++ gets a real activation path (no mainnet date for
  FCMP++ as of Oct 2026). Cameron's call 2026-10-16: FCMP isn't live,
  so it doesn't matter for the current launch path.
- [ ] Publish **distribution checksums** for the `seller-helper` tool when
  it is distributed. (A sandbox release binary exists in
  `seller-helper/target/release/` — its hash is *not* recorded here,
  because that build is not necessarily the distributable artifact;
  checksums must be computed on the actual release build at release time.)
- [ ] Deferred acceptance checks from the v1 gate, if wanted before
  mainnet: verification in Monero GUI / Feather and the literal
  Tor Browser copy test (neither exists in the dev sandbox; a second
  wallet-RPC instance stood in at gate time).

## Sign-off

- [x] Sections 2–3 confirmed as production values under Cameron's
  2026-10-16 delegation to Muse. Date: 2026-10-16
- [ ] Section 1 (stagenet → mainnet flip) remains a separate launch
  decision. Date: ____________

Everything not listed here can be tuned live after launch.
