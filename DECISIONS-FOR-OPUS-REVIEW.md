# Decision Pack for Claude Opus — Privacy-First Noncustodial Marketplace, Spec v2

**How to use this document:** Paste it whole into Claude Opus. It is
self-contained: context, verified ground facts from a completed feasibility
spike, then 12 numbered decisions. Each decision gives the options, the
implementer's recommendation, and what it blocks. Opus: answer every
numbered question using the response template at the end. Challenge the
recommendations wherever you disagree — but do not re-litigate the ground
facts in Part 2; they were established by running code, and the test
results are stated there.

---

## Part 0 — Instructions to the reviewer

1. For each question: give a verdict (one of the options, or a better one),
   one paragraph of reasoning, and — if you reject the recommendation —
   a concrete scenario showing how the recommended option goes wrong.
2. Abstract objections ("this could be insecure") don't count. Name the
   mechanism: who does what, to whom, with what result.
3. The project owner (Cameron) makes the final call on Q9 and Q10. Advise
   on those; decide-with-reasons on Q1–Q8 and Q11–Q12.
4. End with the "Missing questions" section (Part 4): decisions that are
   NOT on this list but will bite later if left implicit.

## Part 1 — The project in brief

A self-hosted, AGPL-3.0-or-later marketplace for lawful goods, where
pseudonymous buyers pay sellers **directly in Monero**. The software never
holds funds: no spending keys, no balances, no escrow in v2 (multisig
settlement is explicitly deferred to a future major version). Key design
commitments:

- Rust (Axum) + PostgreSQL, server-rendered HTML, **no client-side
  JavaScript at all**, designed to work in Tor Browser at Safest level,
  including as an onion service.
- Payments: sellers sign batches of subaddresses ("address pools") or
  individual invoices with their OpenPGP key; the server only ever hands
  out signature-verified destinations. Payment evidence is tiered:
  buyer report (never sufficient) < seller attestation < on-chain
  tx-proof verified via the operator's own `monerod`/`monero-wallet-rpc`.
- Messaging is ciphertext-only: users encrypt locally with OpenPGP; the
  server validates the packet envelope (recipients, integrity protection)
  without ever seeing plaintext or private keys.
- Extensibility is compiled-in Rust strategy modules behind fixed traits
  (modules propose; the core verifies, records, renders). Runtime
  third-party plugins are out of scope for v2.
- Development process (§22 of the spec): the security test suite is
  written FIRST by a separate author working only from the spec, locked
  against implementer changes, with a human review gate per stage and an
  independent security review required before any real funds.

An earlier, different design (tiny core + WASM plugin economy, multisig
escrow as the centrepiece) was explored in October and set aside; spec v2
supersedes it if Q9 is answered yes.

Implementation stages: 0 = threat model, module API, schema, locked
security suite. 1–10 = MVP (accounts → catalogue → keys → orders →
messaging → invoices → address pools → payment evidence → reputation/
disputes → retention/deployment). 11–13 = extensions, hardening,
view-only-wallet evidence module.

## Part 2 — Ground facts (established by the Stage 0 feasibility spike, 2026-10-13)

A spike implementation was built and tested (Rust 1.99; `monero` crate
0.22; `sequoia-openpgp` 2.4.1; GnuPG 2.4.4 as the fixture tool). Results:

1. **Monero address validation works as the spec assumes.** The `monero`
   crate parses address type + network and verifies checksum/key
   validity. Subaddress-only acceptance, primary/integrated rejection,
   wrong-network rejection all behave per spec §3.7 — verified against
   externally published addresses (official Monero docs, Moneropedia),
   not only self-generated ones.
2. **Canonical signed statements work.** Byte-exact serialize/parse per
   spec §10, including the rule that a parser must reject anything whose
   re-serialization is not byte-identical. Detached OpenPGP signature
   verification via Sequoia works; a one-byte tamper fails.
3. **Envelope validation works** (packet-level, via Sequoia): accepts
   messages encrypted to the recipient (optionally also to the sender);
   rejects plaintext, symmetric-only (SKESK) messages, wrong/stranger
   recipients, hidden (`--throw-keyids`) recipients, and inputs over the
   64 KiB cap before parsing.
4. **Tx-proof API shape confirmed** against official wallet-RPC docs:
   `check_tx_proof(txid, address, message, signature)` returns
   `{good, received, confirmations, in_pool, untrusted}`. A client was
   built and tested against a mock server. The cryptographic check itself
   happens inside the real wallet and has NOT been exercised — that needs
   a synced stagenet node and a real stagenet payment (Stage 8).
5. **GnuPG 2.4.4 emits the LibrePGP AEAD packet (tag 20) by default** —
   not RFC 9580 SEIPD v2 (tag 18) and not SEIPD v1/MDC. Verified with
   `gpg --list-packets`. It also **silently ignores `--disable-mdc`** in
   every mode tried (default, `--openpgp`, `--rfc2440`, RSA parameter
   keys): a legacy no-integrity packet could not be produced with it at
   all. Sequoia 2.4 parses tag 20 as an unknown packet type (it knows the
   tag, has no AEAD packet implementation).
6. **Sequoia's pure-Rust crypto backend is upstream-flagged** "not
   considered production ready" and not constant-time; it sits behind two
   explicit opt-in cargo features. Sequoia's production-recommended
   backend is Nettle (C library, needs system nettle + clang to build).
   This project's Sequoia usage never touches secret keys: it parses
   packets and verifies signatures with public keys only.
7. **The blind-test process works.** A separate agent session, given only
   the spec and an API contract (never the implementation), wrote 47
   tests: address 16/16 pass, statements 19/19, envelope 10/12. Both
   envelope failures were proven to be test-fixture failures, not
   implementation failures (fact 5 above; and a test whose 72 KiB
   plaintext of one repeated byte compressed to near-nothing, so the
   encrypted message never exceeded the size cap it was testing). The
   blind author also recorded 11 spec/contract ambiguities, which are
   the source of Q2–Q7 below. Per the process rules, the blind tests
   were not modified.

**Spike verdict: GO** — no assumption in the spec was falsified. Three
clarifications and a handful of rulings are needed before the locked
test suite is finalized.

## Part 3 — The decisions

### Blocking finalization of the locked security suite (Stage 0)

**Q1 — Does the AEAD packet (tag 20) count as "integrity protected" under §14?**
Spec §14 accepts "SEIPD v1 with MDC, or v2 AEAD", and its encryption
guide tells users to run plain `gpg --armor --sign --encrypt` — which on
current GnuPG produces tag-20 AED (ground fact 5). Options:
- **A (recommended):** Amend §14 to explicitly accept three integrity-
  protected forms: SEIPD v1 (MDC), RFC 9580 SEIP v2, and LibrePGP AED
  (tag 20). Rationale: AED genuinely is AEAD integrity protection; the
  packet's inner content is never trusted by the server (it cannot
  decrypt); rejecting what the world's most common tool emits by default
  would make the marketplace's own documented workflow fail.
- **B:** SEIP-only. Change the guide's commands to force SEIPD v1
  (`--openpgp --force-mdc` works today). Costs: user friction, fragile
  against future GnuPG defaults.
- **C:** Accept tag 20 but display a warning. Costs: warning fatigue for
  the normal case; no security gain identified.
If you pick B, state what attack A enables that B prevents, concretely.

**Q2 — Rejection precedence for addresses that fail two checks.**
A stagenet *primary* address checked on a mainnet instance is both
wrong-network and not-a-subaddress; the spec doesn't order the checks,
so locked tests can't assert a specific error. Implementation currently
checks network first. Options: **A (recommended)** network → kind →
(otherwise tests assert only "rejected"); **B** kind → network;
**C** leave unspecified permanently, tests assert rejection only.
This is minor but must be pinned for the locked suite to be precise.

**Q3 — Are leading-zero amounts ("amount-atomic: 007") rejected?**
No §10 rule says so literally; rejection follows from "re-serialization
must be byte-identical" + `u64` parsing. Options: **A (recommended)**
keep the rejection and write the rule into §10 explicitly ("amounts are
decimal, no leading zeros, no sign"); **B** accept and canonicalize —
contradicts the byte-identity rule everything else relies on.

**Q4 — How deep does statement-parser validation go?** Three sub-calls:
- S1: Must `parse_invoice` also validate that `destination` is a real
  Monero subaddress matching the `network:` field? **Recommended: yes**
  for the invoice path — defense in depth at the one place money moves.
  Cost: the statements crate gains a dependency on the Monero crate.
  Alternative: parse stays format-only; destination validation stays
  solely in the core's allocation path (§11), and a test asserts the
  core rejects a well-formed statement carrying a bad destination.
- S3: Must timestamps be semantically valid (month ≤ 12, day valid for
  month), or is RFC 3339 shape enough? **Recommended: semantic** — a
  hand-rolled date check is ~30 lines and removes a class of nonsense
  expiries. Alternative: shape-only + expiry comparisons happen on parsed
  values elsewhere.
- S4: Must the parser reject `network:` values outside the three known
  strings? **Recommended: yes**, closed set, same as other enums in the
  design.

**Q5 — What does the 64 KiB message cap measure?**
§14.1 says "messages up to 64 KiB armored"; a binary submission has no
armor. Options: **A (recommended)** the cap is on the submitted bytes,
armored or binary, checked before any decoding — simplest, and it is
what "size first, before parsing" means operationally; **B** cap on
decoded bytes (requires decoding before the check — the thing the rule
exists to avoid); **C** both caps (submitted ≤ 64 KiB AND decoded
≤ 64 KiB). 

**Q6 — Packet-count and nesting limits (§14.1: "at most 32 packets,
bounded nesting").**
The spike enforces ≤32 *top-level* packets. Packets nested inside the
encrypted container are cryptographically invisible to the server — no
envelope validator can count them without decrypting, which the design
forbids. Options: **A (recommended)** spec amended to say the limit
applies to the top-level packet sequence (the only thing the server can
see), nesting limit applies to container packets outside the encrypted
payload (compressed/literal wrappers are rejected anyway); **B** drop
the count/depth language from §14 as unenforceable. If you see a way to
enforce more without decryption, describe it.

**Q7 — Rulings on the blind test suite itself (process §22: locked tests
change only with human approval).**
- (a) Two envelope tests fail for fixture reasons (ground fact 7). May
  the *test constructions* be fixed — `--compress-algo none` for the
  oversize test; a legacy no-integrity fixture built with a packet-level
  tool or older GnuPG in a container for the legacy test — with
  assertions unchanged? **Recommended: yes**, constructions only, diff
  shown to the owner.
- (b) The blind author's stagenet/testnet subaddress fixtures were
  *constructed* (published wallet keys re-encoded under subaddress
  prefix bytes with recomputed checksums, independently verified) since
  no published examples exist. Acceptable for the locked suite, or must
  fixtures come from a real wallet? **Recommended: acceptable now**,
  replace with real-wallet fixtures when the Stage 8 stagenet wallet
  exists anyway.

### Blocking the production build (decide in Stage 0)

**Q8 — Sequoia crypto backend for production.**
Options: **A (recommended)** Nettle backend for production builds
(upstream's production choice, constant-time); RustCrypto backend
acceptable for development/spike only. Cost: build/deployment gains a
system dependency (nettle, clang) — the deployment profiles must carry
it. **B:** RustCrypto everywhere, justified in writing: the server
never holds OpenPGP secret keys or decrypts; all operations are
parsing + public-key verification, where variable-time behaviour has
no secret to leak. If you pick B, state precisely which operation in
this design could leak what. **C:** Reconsider library choice entirely
(name the alternative and what it does better at packet level).

### Owner decisions (advise; Cameron decides)

**Q9 — Adopt spec v2 as the build basis?**
This retires the earlier October model (multisig-escrow-first, WASM
plugin economy) for v2: direct noncustodial payment, compiled-in
modules, escrow deferred to a future major version, AGPL-3.0-or-later.
Advise: is anything in the retired model worth pulling forward into v2
despite the spec's scoping, and is AGPL the right licence for a
self-hosted marketplace whose operators the spec expects to modify it?

**Q10 — Sequencing and the human review gate.**
Remaining Stage 0 work is ~1–2 focused days (threat model, module API
crate, schema, repo layout with locked tests). The full MVP (stages
1–10) was estimated at 5–8 weeks of implementer time if prioritized.
But §22 requires a human review of the diff at every stage gate, and
the owner also has a separate business launch checkpoint on Nov 15.
Options: **A** finish Stage 0 now, then park until after Nov 15;
**B** proceed straight through stages as the main project; **C**
proceed, but make the stage-gate review a Claude-Opus review pack like
this one (owner reads Opus's verdict + spot-checks) instead of the
owner reading every diff — state honestly whether C weakens the gate
§22 intends, and if so, for which stages it is and isn't acceptable.

### Advisory (can be answered briefly)

**Q11 — Carrying unverified paths.** Three paths are currently
claimed-but-untested and would sit in `docs/unverified.md`: RFC 9580
SEIP v2 acceptance (no tool here emits it), the legacy-packet reject
path (Q7a fixes its fixture), and real stagenet tx-proof verification
(Stage 8). Is carrying them as disclosed-unverified until their stages
acceptable process, or should any one block Stage 1 from starting?

**Q12 — Dependency posture.** The spike pins `monero` 0.22 and
`sequoia-openpgp` 2.4 — both young major versions of security-critical
libraries. Any posture you would impose beyond `Cargo.lock` pinning +
`cargo audit`/`cargo deny` in CI (e.g. vendor the two crates, delay
major upgrades by policy, add a second address-parser cross-check)?

## Part 4 — Missing questions (required)

List any decision a reasonable spec owner will face before or during
stages 1–10 that this document does not raise, one line each, with the
stage by which it must be answered. Include at least a check on:
operator legal exposure for running a public instance, and what
"independent security review" can realistically mean for a solo
project (who, paid how, reviewing what scope).

## Response template (please use it)

```
Q1: <option> — <reasoning; if rejecting recommendation: concrete failure scenario>
Q2: ...
...
Missing questions:
- <question> (needed by stage N)
```
