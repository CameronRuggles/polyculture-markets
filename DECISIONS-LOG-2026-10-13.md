# Decisions Log — Marketplace Spec v2, Stage 0

Source: `DECISIONS-FOR-OPUS-REVIEW.md` (Q1–Q12) + `DECISIONS-ADDENDUM-UNSCOVERED-AMBIGUITIES.md`
(Q13–Q17), reviewed by Claude Opus 5.5 extra; review uploaded by Cameron 2026-10-13
(`~/workspace/user/files/Decision_Review_Marketplace_Spec_v2_0_lyjx.md`).

Status key: **RATIFIED** = decided in the review per the pack's process (Q1–Q8, Q11–Q17).
**ADVISORY → CONFIRMED** = Q9 and Q10: Cameron confirmed both on 2026-10-13
("adopt v2, Stage 0 now then park"). Two post-review corrections from the reviewer
were also accepted the same day: the Q14 locked-fixture retention (see Q14) and the
Q16 `RecipientKeyRetired` leak fix (see Q16).
Implementer verification notes are marked ◆ — facts checked against library source or
spike evidence after the review arrived, so the build doesn't inherit an unchecked claim.

## Q1 — AED tag 20: ACCEPT, with conditions (extended)
- Amend §14 to name tag-20 AED explicitly; special-case tag 20 **by name** (never
  "unknown packet in container position" — that would admit tags 22–39 unreviewed).
- Hand-check the AED fixed header: version 1, cipher AES-128/192/256, AEAD mode OCB or
  EAX, sane chunk-size octet (~15 lines, format check only).
- Enforce PKESK/SEIP version pairing: v3 PKESKs → SEIPD v1 or tag 20; v6 PKESKs → SEIPD
  v2 only (RFC 9580 MUST); reject mixed sequences.
- No encryption-guide change needed.

## Q2 — Address error precedence: decode/checksum → network → kind (extended)
Pin in §3.7; locked tests may assert exact error codes. (Spike implementation already
checks network before kind; add decode-first is inherent — parse precedes both.)

## Q3 — Integer fields: strict canonical form everywhere (extended)
All signed-statement integers: ASCII digits only, no sign/whitespace/leading zeros, fits
u64; then range checks (amount > 0 and ≤ configured max; address-count 1–200; quantity ≥ 1).
Write the rule into §10 explicitly.

## Q4 — Statement-parser depth (extended; S3 changed)
- S1 **Yes, by type**: introduce a `Subaddress` newtype in the API that only the
  validation function can construct; `InvoiceStatement.destination` and
  `PoolStatement.addresses` use it. Parser checks each address's network against the
  statement's `network:` line. (Pools included — they are the default path.)
- S3 **Semantic via the `time` crate**: parse RFC 3339 with `time`, re-format canonically,
  require byte-identity; explicitly reject leap seconds (`:60`). NOT hand-rolled.
- S4 **Yes**: closed set of three network values in the parser; the core additionally
  rejects statements whose network ≠ the instance's configured network.

## Q5 — 64 KiB cap measures submitted bytes (held)
Enforce as a per-route HTTP body limit, before multipart parsing or armor decoding.

## Q6 — Packet limits, concrete (held)
Configure Sequoia's parser to never descend into containers; enforce on the visible
top-level sequence: 1–8 PKESKs; exactly one encrypted container, nothing after it; no
top-level SKESK/marker/compressed/literal/signature packets; no trailing bytes after the
armor footer; reject Padding (tag 21) until a real client emits it.
◆ Spike currently allows up to 32 top-level packets incl. any PKESK count — tighten to
this rule in Stage 5.

## Q7 — Blind-suite fixtures (changed)
- (a) Construction fixes APPROVED, assertions unchanged, owner sees the list: legacy
  fixture = **synthetic tag-9 packet of random bytes appended to a valid PKESK** (the
  validator rejects on tag alone — no old-GnuPG container needed); oversize fixture =
  `--compress-algo none` + random plaintext.
- (b) Constructed stagenet/testnet subaddress fixtures stand **only until the suite
  locks**; before locking, generate real fixtures with `monero-wallet-cli --stagenet
  --offline` (`address new` needs no daemon) and commit the valueless stagenet seed for
  reuse in Stage 8.

## Q8 — Sequoia backend: Nettle everywhere, dev and CI too (changed)
- Production, dev, and CI all build against Nettle. (Backend differences change
  algorithm support; a key verifying in CI must verify in production.)
- CI fails any release build enabling `allow-experimental-crypto` /
  `allow-variable-time-crypto`.
- ◆ Sandbox caveat: this dev VM could not install nettle/clang when tried during the
  spike (apt lock). Stage 0 proper must stand up the containerised dev environment with
  Nettle and re-run the spike suite under it — that re-run is the proof for Q8.

## Q11 — Unverified paths (held, with homework)
- SEIPD v2: close with the **RFC 9580 Appendix A test vectors** (A.3 sample v6 cert,
  A.8 X25519 AEAD-OCB message) + a derived hidden-recipient v6 variant. Independent
  vectors, not self-generated.
- Legacy reject: closed by Q7(a).
- Tx-proof: carry as unverified; **hard gate** — no "verified" label may render anywhere
  until real stagenet verification is proven (Stage 8).

## Q12 — Dependency posture (extended)
Lockfile + `cargo audit` + `cargo deny`, plus: (1) `cargo vet` — recorded audit required
for every version bump of `monero`, `sequoia-openpgp`, Nettle bindings; CI fails on
unaudited versions. (2) Upgrade policy: security fixes within days; other bumps of those
crates only as a planned task re-running the full locked suite, never bundled with
feature work. (3) **Second-parser cross-check at destination submission only**: verify
pool/invoice uploads also via `validate_address` on the verify-only wallet RPC (the
reference C++ implementation); disagreement ⇒ reject + security event. (4)
`rust-toolchain.toml` pin. Vendoring skipped deliberately.

## Addendum rulings

### Q13 — Address normalization: TRIM ONCE AT THE FORM LAYER (overruled)
- One function, `form::destinations_input`: split pasted input on line breaks, strip ASCII
  whitespace (space/tab/CR/LF) from line ends, drop empty lines. Same function normalizes
  tx-proof `txid`/`proof` fields. Rationale: browsers submit textarea newlines as CRLF —
  strict-at-every-layer rejects every pasted pool (verified reasoning: HTML form newline
  normalization is real).
- Non-ASCII whitespace/invisibles (NBSP, zero-width space, BOM) are REJECTED with a
  specific "contains invisible characters" error — never silently stripped.
- Nothing below the form layer trims: not `Subaddress::parse`, not the statements
  parser, not the DB, not URI/QR generation. Sellers sign server-generated pool bytes
  built from already-normalized strings, so there is no second path.

### Q14 — Curve-point validity: TORSION CHECK REQUIRED (overruled, with a correction)
- ◆ VERIFIED against monero 0.22 source: `PublicKey::from_slice` already decompresses
  each key and rejects if re-compression isn't byte-identical (`util/key.rs` 287–305) —
  Opus's non-canonical-encoding scenario is **already stopped by the library**.
- The genuinely additive part stands: after parsing, require both keys torsion-free and
  not identity (`curve25519-dalek` `is_torsion_free` / `is_small_order` on the crate's
  decompressed point accessor). A small-order view key would make payments linkable and
  amounts decryptable to any observer. Add fixtures for both bad cases.
- **Post-review correction (accepted 2026-10-13):** keep a locked fixture for the
  non-canonical-encoding case ANYWAY, even though the current crate rejects it. If a
  future `monero` version drops the round-trip check, CI fails instead of the hole
  quietly reopening — this fixture is exactly what the Q12 `cargo vet` gate exists to
  catch regressions through.
- Net build rule: canonical round-trip = library (cite it, don't reimplement);
  torsion/identity check = ours, in the `Subaddress` validation function (Q4).

### Q15 — Statement ID patterns: fixed 32-hex (held; spec inconsistency fixed)
§16 promises 128-bit public IDs but §10's examples show 48-bit IDs. Pin:
`mkt_` / `inv_` / `ord_` / `pool_` / `acct_` + `[0-9a-f]{32}`, enforced at parse time.
Rationale includes a real workflow fact: buyers pass invoice-id as the message argument
to `get_tx_proof` on a command line — whitespace/metacharacters in an ID break proof
verification for a correct buyer. §10 examples must be regenerated at the pinned length.

### Q16 — Envelope errors: reclassified taxonomy (changed)
No registered-vs-unknown recipient split — distinguishing them is a membership oracle
(someone can probe whether a keyserver key has an account here). Evaluation order,
first failure wins:
1. `Empty` (form layer) 2. `NotEncrypted` (not saved; plaintext never echoed back into
the form, never logged) 3. `Malformed` 4. `UnsupportedPacket` (SKESK, literal, legacy
SED, unknown tag) 5. `HiddenRecipient` 6. `RecipientKeyRetired` ("re-encrypt to their
new key") 7.
`WrongRecipient` (no PKESK matches recipient's current key, whoever owns the others)
8. `ExtraRecipient` (recipient matched + an unrelated PKESK; show key ID only, never an
owner — a stray `encrypt-to` in a user's gpg.conf is the common cause).
- **Post-review LEAK FIX (2026-10-13, reviewer's own correction — accepted):** the
  original rationale for #6 ("rotation state is public profile data") holds only for
  SELLERS; buyers have no public profile. A PKESK key ID is sender-chosen bytes the
  server cannot verify, so an unconditioned `RecipientKeyRetired` lets any
  counterparty probe "was key X ever this buyer's key?" using key IDs harvested from
  keyservers — the same membership oracle Q16 exists to close, aimed at one buyer.
  **Rule: return `RecipientKeyRetired` only when the matched key was the recipient's
  current key at some point during THIS conversation (i.e. the sender was already
  shown it). Otherwise return `WrongRecipient`.** Locked test required: probe a
  buyer's retired key in a conversation that never saw it → expect `WrongRecipient`.
◆ This replaces the spike contract's variant set (`UnknownRecipient` deleted). API
contract must be revised before the locked suite is authored against it.

### Q17 — `kind` field: REMOVED from the success type (extended)
With the `Subaddress` newtype (Q4), kind on a validated value is redundant-or-wrong.
Kind survives only inside the rejection: `WrongKind { found: AddressKind }`,
`AddressKind` a closed enum {Standard, Integrated, Subaddress}; network likewise a
closed enum. (Spike contract's `DestinationInfo.kind: String` is deleted.)

## Advisory — pending Cameron's confirmation

### Q9 — Adopt spec v2 (Opus advises: adopt)
- Adopt v2; retire the Oct model (escrow-first/WASM economy) as reference material for §21.
- Carry forward ONE thing: a `settlement` field on orders (always `direct` in v2) + room
  in the state machine for a future escrow state — cheap now, painful migration later.
- AGPL confirmed as fitting; make compliance automatic: the footer Source link serves the
  running build's exact source tarball from the instance itself (works over onion too).
- Disclosed trade-off: operators can't keep modified anti-abuse heuristics private.

### Q10 — Sequencing + review gate (Opus advises: A now, then C within limits)
- **SUPERSEDED IN PART 2026-10-13:** Cameron lifted the park the same day —
  "since you're doing all the work on this, just continue with it." The build
  proceeds through the stages now; Nov 15 remains a WorldExpanders checkpoint
  but no longer gates marketplace work. The review-gate limits below still apply.
- Finish Stage 0 now (~1–2 days), then **park until after the Nov 15** WorldExpanders
  checkpoint. *(original advice, park portion superseded above)*
- Stage gates for stages 1–10 may use Opus-style review packs (option C) ONLY if: different
  model or fresh context given spec+diff only; file:line evidence per invariant; paired
  `cargo-mutants` runs. C acceptable only while stagenet/no public users, with the external
  audit as backstop.
- C is NEVER acceptable for: changes to locked tests or invariants (Cameron reads those as
  plain-language assertion lists himself) or the go-live gate (human audit, no substitute).

## Missing-questions register (Opus Part 4 — adopted as open items)

| By stage | Question |
|---|---|
| 0 | `marketplace-id` generation; must survive onion/domain migration (every signed statement binds it) |
| 1 | Admin/moderator security: TOTP (no-JS-compatible) + separate admin listener |
| 2 | Listing-image illegal-content reporting workflow (NCMEC obligations for US providers) |
| 4 | Key-file lifecycle: generation, backup, rotation, loss consequences (buyer tokens, pending proofs, disclosures) |
| 4/10 | Clock source with §19's no-outbound rule (NTP path or Tor-based time) |
| 6 | Independent review funding: apply early — Monero CCS, OTF Red Team Lab, NLnet (audit pairing); budget by Stage 10 |
| 8 | Tx-proof flags policy: `untrusted: true`, `in_pool: true`, reorg below min confirmations — none may yield ProofVerified |
| 8 | FCMP++/Carrot protocol upgrade: effect on subaddresses/tx-proofs and whether the `monero` crate tracks it |
| 9 | Legal review before ANY public instance: operator liability, marketplace-facilitator sales-tax status, money transmission (FinCEN 2019 noncustodial guidance), DMCA agent |
| 9 | Seller exit/re-entry: account deletion to shed reputation; retired-fingerprint blocklist |
| 9 | GPG usability test with non-experts before launch |
| 10 | Release integrity: signed releases + reproducible builds (AGPL Source link trustworthiness) |

*Next step on Cameron's word: fold RATIFIED items into the spec as amendments, revise
API-CONTRACT.md (Q16/Q17), then Stage 0 proper (threat model, modules-api, schema,
locked-suite scaffolding, Nettle container re-run of the spike).*

## Gate pace — Cameron's ruling (2026-10-13, late)
RETROFIT stages 1–3 first, then gate-as-we-go from Stage 4: no stage starts until the previous one passes its gate. Retrofit order: (1) fold ratified amendments into the spec + revise API contract for Q16/Q17 first (blind authors work from the spec); (2) blind suites for stages 1–3, starting with Stage 1's route-by-role authorization matrix; (3) fix failures in code, never in tests; (4) cargo-mutants on the auth and key crates + one review pack per stage. Specific check queued: whether Stage 3 stores the key history Q16 requires (when each key was current, which conversations saw it) — small change now vs migration at Stage 8.

## Owner rulings during the Stage 4 gate (Cameron, 2026-10-14)
- Description size bound RATIFIED: 20,000 characters. Pin in the spec amendments; the Stage 2 blind oversize test activates unchanged (remove its #[ignore] per the author's design) and the Stage 2 suite re-runs to confirm.
- GET /orders: AMEND §17 to declare the orders collection route (login-required; object-level filtering in the handler) rather than moving the page. authorize() gains the declared route. This is an owner spec amendment mid-gate: the blind suite's §17 assertions follow the AMENDED spec, and the change + its timing must be documented in GATE4-REPORT.md (not a test edit to make code pass — an upstream owner ruling).
