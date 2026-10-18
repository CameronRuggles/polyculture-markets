# Direct Monero Payments v1 — Release Report

Date: 2026-10-15 · Governing design: `Direct_Monero_Payments_v1___Muse.AI_Handoff`
(2026-10-15), mapping: `DIRECT-PAYMENTS-V1-PLAN.md` (owner-approved
2026-10-15, incl. disposition 4 softening). Built under hybrid §22
gate discipline.

## Verdict: PASS

The release is complete and gated. Buyers pay sellers directly,
wallet to wallet; the server stores signed subaddresses, assigns
exactly one per order at creation, and never touches keys, funds,
txids or received amounts. No escrow, no tx-proof, no fees, no
server-side node/wallet — none built, stubbed or scaffolded.

**Final totals (counted line-by-line from the actual run output —
see §7): workspace 386 passed / 0 failed / 9 ignored; seller-helper
standalone crate 13/13; live acceptance 37 case checks passed, 2
environment-deferred (named in §6).**

## 1. What was built

**Server (`marketplace/`)**
- Migration `0008_direct_payments_v1.sql` — additive schema (§5).
- `crates/app/src/payments.rs` — `PaymentConfig` (all handoff settings
  from env), seller payment identity (set/change/reset), batch upload,
  assignment queries, `mark_paid`, 48h expiry sweep, and `DirectV1`:
  the compiled-in strategy module implementing the modules-api
  `DestinationProvider` + `PaymentEvidenceProvider` traits (Q9 seam —
  no runtime plugins). Seller mark-paid proposes
  `EvidenceClaim::SellerAttestation { amount_atomic: None }`; Core
  remains the only writer of the Paid transition; the domain state
  machine was **not** changed.
- `modules-api`: `validate_standard_address` (same pinned check order
  as `Subaddress::validate`; everything through the vetted `monero`
  crate 0.22.0 — no hand-rolled crypto anywhere).
- Routes: `GET /orders/{id}/pay`, `GET /orders/{id}/pay/qr.png`,
  `POST /orders/{id}/mark-paid` (via the order-action dispatch),
  `POST /seller/payment-identity`, `POST /seller/payment-batches`.
  Allocation happens inside order creation (row-locked
  take-oldest-unused, per-seller identity row lock).
- Buyer payment page (server-rendered, no JS): exact amount from
  atomic units (Stage 6 core formatting), subaddress, seller primary
  in full + unchanged-since / change notice, signed message and
  signature in separate copy boxes, the handoff's verification steps
  (Monero GUI, Feather, monero-wallet-cli named; no invented menu
  paths), the handoff disclosure verbatim, QR + `monero:` URI from
  the Stage 6 library. Paid state reads **"Seller confirmed
  payment"**; the pre-existing tx-proof evidence label was also
  reworded so no surface calls a payment "verified".
- Expiry sweep: minimal in-process interval task (default 15 min);
  the general scheduler remains Stage 10, as documented in code.
- Config: `MARKETPLACE_ID` (default now **`vespiary-market`** — the
  zero dev default is gone; env override kept), `INSTANCE_NETWORK`
  (default `stagenet`), `PAYMENTS_MAX_BATCH`=100,
  `PAYMENTS_MAX_UNUSED_POOL`=100, `PAYMENTS_LOW_POOL_THRESHOLD`=10,
  `PAYMENTS_UNPAID_EXPIRY_HOURS`=48, `PAYMENTS_OPEN_UNPAID_CAP`=3,
  `PAYMENTS_ORDER_RATE_PER_HOUR`=10, `PAYMENTS_RESET_WARNING_DAYS`=30,
  `PAYMENTS_SERVER_SIGNATURE_CHECK`=off, `PAYMENTS_SWEEP_INTERVAL_SECS`=900.

**Seller helper (`seller-helper/` — standalone crate, own workspace)**
- `init` / `generate --count N` / `check <address>` against the
  seller's local monero-wallet-rpc. Single allowlist choke point
  (`RpcClient::call`) admits exactly {get_version, get_address,
  create_account, create_address, label_address, get_address_index,
  sign, verify} and refuses everything else **before any socket is
  opened** (unit-tested against a dead port). Loopback-only RPC URLs
  enforced in config validation. Dedicated labelled wallet account,
  per-subaddress labels, self-verify of every signature with
  whole-batch abort, atomic file write, restore-lookahead warning
  printing the highest subaddress index used.
- Transport is hand-rolled HTTP over TcpStream with MD5 Digest auth —
  forced by a real epee behaviour found in testing: **the digest
  nonce is bound to the TCP connection**, so the whole handshake must
  complete on one connection (recorded in code comments).
- `seller-helper/SELLER-GUIDE.md`: wallet-RPC startup on 127.0.0.1
  with `--rpc-login`, the three-step routine, the restore warning,
  safety rules. Distribution checksums are a release step and were
  **not** produced in this build.

**Amendments** — `SPEC-V2-AMENDMENTS.md` gained a dated 2026-10-15
section: (a) wallet signatures (`xmr-direct-v1`) supersede §10 PGP
statements for the payment path (PGP stays for rotation/terms);
(b) Stage 8 scope shrink — tx-proof deferred indefinitely,
attestation ships here, no "verified" payment label may render;
(c) assignment at order creation for the direct strategy;
(d) primary-address change = presentation reset (30-day banner +
pool retirement), history never erased; (e) the no-payment-identity
compatibility rule + assignment-scoped drain defences; (f) payment
seller_id rendered `acct-<32 hex>`.

## 2. Spike record (step 1 — pinned wallet v0.18.4.3)

Proven against `monero-wallet-rpc` 0.18.4.3 ("Fluorine Fermi") with
the Stage 0 stagenet fixture wallet (restored from its committed
seed; empty; reserved for this):
- Offline start works with a dead `--daemon-address` for
  address/sign/verify operations. `--wallet-dir` required. Auth is
  HTTP Digest.
- `get_version` → `{"release": true, "version": 65565}`.
- `restore_deterministic_wallet {filename, password, seed,
  language: "German", restore_height}` → restored primary matches
  the fixture record exactly.
- `create_address {account_index, count}` →
  `{address, address_index, address_indices, addresses: [plain
  strings]}`.
- `sign {data}` → 93-char signature starting `SigV2`;
  `verify {data, address, signature}` → `{good, old,
  signature_type: "spend", version: 2}`; works in a wallet that does
  not own the key; tampered message and wrong signer both give
  `good: false`.
- `get_address_index` returns only `{"index": {"major", "minor"}}`;
  a foreign address returns error **-2** ("Address doesn't belong
  to the wallet").

## 3. §22 gate — blind suite

`marketplace/tests/security/blind_direct_v1.rs` — 42 tests, authored
from the handoff + amendments + a written API/route contract only;
the author never read the implementation (18 contract ambiguities
recorded in the suite header, A1–A18).

First run: **41 passed / 1 failed**. The failure was a real
implementation violation of the pinned contract: `set_primary_address`
returned `changed=true` on *first* set. **Fixed in code** (first set →
`false`; `changed_at` stays NULL; banner semantics were already
correct), never in the test. The coordinator also fixed a second,
unpinned defect the author surfaced (A18): `assignment_for_order`
served the seller's *current* primary address, so after a mid-order
identity change the payment page would show a primary whose key did
not make the assignment's signature — wallet verification against
the pasted address would fail. It now serves the primary bound in
the entry's signed message. Pinned by a new implementer test.

Final: **blind_direct_v1 42/42**, with all prior locked suites
unmodified and green (41 + 38 + 34 + 58 + 83).

Q7a note: no blind-suite file was changed by anyone after authoring.
One fixture-hygiene fix WAS made in the *implementer's own* suite
(`crates/app/tests/payments_db.rs`, not locked): it now pre-purges
its POOL200 fixture addresses and serializes on a fixture lock,
because the blind suite (by its own design) pre-cleans slices but
leaves final state in the shared dev DB — without this, the app
suite was not re-runnable after a blind run. No assertions changed.

## 4. cargo-mutants

`cargo mutants -p app --file crates/app/src/payments.rs`
(TMPDIR on the home filesystem): **79 mutants — 52 caught, 15
missed, 12 unviable** (outputs preserved in
`mutants-runs/direct-v1-payments/`). Triage of the 15 missed:
- 6 are scope artifacts: mutants ran only the app package's tests,
  while the behaviours (same-address no-op in `set_primary_address`,
  pool-full boundary equality in `upload_batch`) are pinned by the
  locked blind suite, which lives in the security-tests package.
- 5 are `PaymentConfig::from_env` string-parsing edges (network
  names, flag parsing) — startup-only config with tested defaults;
  accepted as a documented gap.
- 3 are the insert-time unique-violation classification fallback
  (`is_unique_violation`): unreachable in tests because the
  pre-checks catch duplicates first; it is a defence-in-depth second
  layer. Accepted, documented here.
- 1 (`DirectV1::capabilities` returning empty) is module metadata
  with no v1 consumer.
- 1 was real: deleting `!` in the message-primary extraction (the
  A18 fix) survived — a new implementer test now pins it
  (`assignment_primary_comes_from_the_signed_message`).

## 5. Schema design choices

- **Additive only.** New tables: `payment_identities`,
  `payment_batches`, `payment_pool_entries`, `payment_attestations`.
  Every pool address is also inserted into the existing global
  `destinations` table (source `'pool'`), so the pre-existing global
  UNIQUE constraint — never the application code alone — guarantees
  no address is ever handed out twice, across all sellers and states.
- **No rows in `invoices`.** Its `statement` column is the §10 PGP
  statement contract; writing wallet-message bytes there would fake
  the type. The direct strategy's assignment lives in
  `payment_pool_entries` (address/message/signature stored as
  byte-exact TEXT). `address_pools` (PGP) untouched.
- **`payment_attestations`, not `payment_evidence`**:
  `payment_evidence.invoice_id` is NOT NULL and direct orders have
  no invoice; the new table records order, entry, submitter,
  claim kind, and `amount_atomic` — always NULL by construction
  (blind suite asserts this at DB level).
- **seller_id**: accounts carry `acct_<hex>`; the handoff's message
  charset is `[a-z0-9-]`, so the payment seller_id is `acct-<hex>`
  from one derivation function shared by dashboard, validation and
  message rebuild.

## 6. Stagenet acceptance (real wallets)

Environment: monero-wallet-rpc **v0.18.4.3** (two instances: the
restored fixture wallet as seller; a fresh wallet as independent
verifier), marketplace app from this tree, PostgreSQL 16.4,
stagenet throughout. The seller's batch was produced by the actual
`seller-helper` binary against the fixture wallet and uploaded
through the real dashboard.

| Handoff case | Result |
|---|---|
| Helper generates batch vs real stagenet wallet; signatures verify in a second tool | **Ran.** Batch of 5 generated (dedicated account created + labelled); entry signatures verified `good: true, spend, v2` in the second RPC instance. Monero GUI / Feather are not installed in this sandbox — the second-RPC-instance substitute was used; GUI/Feather verification is **environment-deferred** |
| Wallet on wrong network aborts before creating any subaddress | **Ran.** mainnet config vs stagenet wallet: exit 1, explicit message, no file, no account created |
| Non-allowlisted RPC method refused, unit test | **Ran.** Helper unit tests (13/13) refuse transfer/query_key/sweep_all/get_balance etc. before any network I/O |
| One signature fails self-verify → no file | **Ran at unit level** (in-process fake wallet in the helper suite: abort, no file). Not separately staged against the real wallet |
| Upload: wrong seller_id / network / marketplace_id / primary | **Ran** (blind suite + implementer DB tests, all-or-nothing asserted); a live 1-byte-tampered batch was also rejected whole over HTTP |
| Upload: message off by one byte | **Ran** (suites + live) |
| Upload: duplicate (same/other seller, in-batch) | **Ran** (suites) |
| Upload: standard/integrated where subaddress belongs | **Ran** (suites) |
| Two orders at the same moment → two subaddresses | **Ran** (implementer + blind concurrency tests against the real DB); live orders also all distinct |
| Cancel, then new order → fresh address, old retired | **Ran live** + suites |
| Pool empty → listing stops, seller notified | **Ran live**: pool of 5 drained, next order refused, listing shows the seller-needs-addresses state, `payment_pool_low` notification present |
| Buyer past rate limit refused, pool not drained | **Ran** in suites (open-unpaid cap 3 and 10/hour, scoped to assigned orders). Live drain hit pool-empty first |
| Payment page copy → wallet verify, no hand edits | **Ran** via the rendered HTML page (values extracted byte-for
...[truncated 2774 chars]