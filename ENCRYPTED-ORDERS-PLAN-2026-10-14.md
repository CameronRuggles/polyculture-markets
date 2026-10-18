# Encrypted-orders plan (post-review synthesis, 2026-10-14)

Status: DRAFT for Cameron's ratification. Sources: Cameron's design
direction 2026-10-14; external review
`encrypted-orders-design-review.md` (R1–R11). The second announced
review (ChatGPT/Claude pair) has not yet arrived; this plan proceeds on
the received review unless the second materially contradicts it.

## The architecture (what we're building)

1. **Listings stay public**, signed and versioned by the seller.
2. **Address assignment is authenticated.** Seller uploads a signed
   pool manifest; the core reserves one address atomically and issues
   a signed reservation certificate (marketplace id, random order id,
   buyer + seller fingerprints, listing-version digest, address,
   network, time). Exposed addresses are never recycled.
3. **The buyer composes the order locally** from the listing snapshot:
   items, quantities, total (atomic units), deadlines, terms — and a
   **buyer-designated refund address**, inside the committed order so
   it cannot be substituted later by either side.
4. **Randomized commitments.** C_terms and C_shipping are hashed with
   independent 256-bit random secrets; C_order binds them. Terms and
   shipping are committed separately so a dispute can reveal one
   without the other. Buyer signs the proposal, encrypts it to the
   seller, submits ciphertext + signed commitment. Core stores the
   commitment immutably, returns a signed submission receipt.
5. **Seller acceptance BEFORE payment** (the review's principal
   addition). Seller decrypts, recomputes the commitments, checks
   address/version/amount/deadlines, and signs an acceptance binding
   C_order + reservation + both identities, returned encrypted. The
   buyer pays only after verifying acceptance. Without this, a dispute
   proves only what the buyer wrote — never what the seller agreed to.
6. **Happy path is fully private.** Payment acks, shipping info, and
   completion messages stay inside encrypted messages. The core's
   order lifecycle is only: reserved → ciphertext routed →
   retained/expired. Dispute and enforcement lifecycles are separate.
   The platform has no happy-path sales ledger.

## Disputes (where the evidence machinery lives)

1. Buyer submits to the restricted dispute service: allegation,
   receipts, terms + commitment secret, seller acceptance, signed
   communications. Shipping stays sealed unless the allegation
   requires it.
2. Operator verifies in order: signatures under historical keys →
   receipt authenticity → commitment opening → acceptance of that same
   commitment → address/network → deadlines/obligation.
3. Payment evidence last: buyer generates a tx proof bound to a fresh
   case challenge; verifier checks cryptographic validity, exact
   destination, amount vs obligation, chain inclusion/confirmations
   via remote nodes. **Spendability caveat (§5 of the review):**
   `good = true` ≠ adequate settlement; unresolved anomalies produce
   an *inconclusive* outcome, never an auto-sustained finding.
4. Seller gets the evidence and a bounded response window. The seller
   may **refund to the order's committed refund address** and present
   a refund tx proof, verified the same way.
   **Refunds resolve the buyer's loss. They count for nothing as
   trust** (Cameron's ruling, 2026-10-14): refunding under pressure is
   gameable, wash cycles are free, and a refund does not erase an
   independently established deception finding. The seller record
   stores adjudicated findings and remediation — never a refund-based
   score.
5. Outcomes (review §4.7): Dismissed / Inconclusive / Resolved
   mistake / Sustained service breach / Sustained deliberate
   deception / Procedural noncooperation. Signed, reasoned decisions;
   appeal route; only minimal redacted outcomes published (no txids,
   amounts, addresses, buyer identities).

## Trust posture (what we will and will not claim)

- No percentages, no "verified sales," no fulfilment scores — the
  denominator is impossible under the constraints (indistinguishability
  result), and refunds/receipts are attestations at best.
- Sellers get a **risk dossier**: platform-observed continuity
  (first-seen, listing availability, key continuity), scoped signed
  endorsements, adjudicated findings/remediation history,
  new/unestablished status, and a standing warning that direct
  payments have no platform-enforced recovery.
- Enforcement is severity-based and human-reviewed: one proven
  deliberate, material deception can justify removal; a service breach
  is not fraud; no automatic strike counters.

## Consequences for the build

- Stage 4's server-side plaintext order model is superseded. Its
  terms encoding/digest machinery survives as the local commitment
  encoding + authenticated listing snapshots. Dev data is disposable;
  no production migration exists.
- Core functions that die (§7.4): order arithmetic validation,
  inventory reservation, paid/shipped/completed transitions,
  commissions, revenue analytics. Inventory becomes seller-local.
- Remaining stages re-plan against this: messaging (§14) unchanged in
  spirit; pools gain reservation certificates + wallet
  restoration/lookahead tests; payment evidence becomes the
  dispute-time proof-verification service (remote-node chain status);
  reputation becomes dossier + findings. R11 security gates added:
  proof-spendability, active key/address substitution, pool
  restoration/lookahead, dispute-data isolation, post-ban evidence
  preservation.
- **Gate before re-planning (review's condition):** the manual
  order workflow (compose → encrypt → commit → accept → pay on
  stagenet → dispute reveal) is tested with representative users.
  GPG competence is not assumed.

## Ratification table (from the review; Cameron rules per line)

R1 adopt-with-changes · R2 adopt-with-changes · R3 adopt ·
R4 reject · R5 adopt · R6 reject · R7 adopt · R8 adopt-with-limitations ·
R9 reject · R10 reject · R11 adopt.
Plus Cameron's additions 2026-10-14: refund address committed inside
the order; refund proof = loss resolution only, never trust currency.

## Local helper (added 2026-10-14, Cameron's question + Muse's recommendation)

The manual workflow (hand-composing canonical order bytes, generating
commitment secrets, signing/encrypting, verifying acceptance,
preserving the evidence bundle, generating a proof with the case
challenge as its message) is too much to ask of ordinary users — and
its worst failure is silent: a canonicalization slip voids dispute
protection invisibly until dispute day.

So the plan includes a standalone client-side helper, CLI first:
open-source, offline-capable, reproducible signed releases. It builds
the order deterministically from the listing snapshot + reservation
certificate, generates the secrets, computes the commitments, signs
and encrypts via the user's own GPG keyring, and outputs a submission
package the user pastes/uploads (the helper itself submits nothing).
It verifies seller acceptance and displays the exact pay-to address
and amount, keeps the evidence bundle locally encrypted to the user's
key, and assembles the reveal package + proof walkthrough in a
dispute. The user reviews the human-readable order before anything is
signed.

Safety property of the protocol: errors surface BEFORE payment — the
seller recomputes the commitments before accepting, and the buyer
verifies acceptance before paying — so a helper bug costs a rejected
order, not a lost dispute.

The protocol itself stays tool-agnostic (public canonical spec;
anyone can hand-roll or build a rival tool). The helper is an aid,
never a gatekeeper — that is also what keeps it honest. It is a real
second component to build and audit; the representative-user workflow
test (the review's gate) should test the helper path as primary and
the manual path as the expert fallback.

## Amendment to §5 of the protocol sketch — standing acceptance (2026-10-14)

Cameron's objection: per-order interactive seller acceptance makes
checkout a two-party round-trip — the buyer cannot pay until the
seller comes online, decrypts, validates, and signs. On an async
marketplace that strangles the flow the design exists to make easy.

Resolution: **standing acceptance** for standard orders. The seller's
signed, versioned listing (price, shipping charges, deadlines, refund
terms) plus their signed pool manifest plus the core's signed
reservation certificate together constitute the seller's pre-signed
acceptance of any order that conforms to that listing version and
uses the reserved address. The buyer composes → commits → pays in one
sitting; no round-trip. The helper builds the order FROM the listing
snapshot, so conformance is mechanical on the helper path.

Dispute evidence chain is preserved: committed order + reservation
certificate + signed listing. Adjudication checks conformance
deterministically — an order whose committed total/terms deviate from
the signed listing creates NO seller obligation at those terms; the
buyer's own commitment proves the deviation. Deviation voids the
buyer's protection, so gaming it is self-defeating.

Explicit interactive acceptance (the review's Phase 3) remains for
NON-standard orders only: negotiated price, special deadlines,
anything not fully expressed in the listing terms.

Costs accepted: listing terms must be complete and structured (they
largely are already); sellers carry stock-accuracy risk, bounded by
their own signed refund remedy in the listing terms (inability to
fulfil + prompt refund = resolved mistake / service breach, not
deception). Deviation from the review's letter, recorded openly: the
review required authenticated seller agreement to the exact terms;
standing acceptance provides it via prior signature + reservation
binding rather than a per-order signature.

## Owner ruling — the listing is the contract (Cameron, 2026-10-14)

The seller's listing IS the contract. Any order placed against a
listing is held to that listing's terms. Consequences locked in:

- The order's job is to INVOKE the listing: items, quantities,
  shipping destination, refund address. It introduces no terms of its
  own; anything in an order that conflicts with the listing does not
  bind — the listing prevails.
- Adjudication simplifies to two checks: does the revealed order
  conform to the listing version it cites, and was the reserved
  address paid per that listing's terms.
- Version discipline is load-bearing: edits create a new signed
  listing version; an order binds to the version current at
  reservation; superseded versions are retained (signed, cheap to
  keep) for dispute lookback.

## Owner ruling — refund address is outer metadata (Cameron, 2026-10-14)

The buyer-designated refund address is NOT inside the encrypted order.
It travels in the signed outer submission: the buyer's signature
covers (commitment, refund address, reservation) together, and the
core's submission receipt binds all three at submission time — so it
cannot be substituted later, by either side, once a dispute exists.

Why it's safe: a published Monero address exposes nothing on-chain
(outputs land at one-time stealth addresses; the chain cannot be
searched by address). The only real risk is off-chain correlation if
a buyer reuses an address across orders — mitigated by the helper
issuing a FRESH refund subaddress per order as the default.

What it buys (Cameron's point): disputes can settle at the refund
layer without opening the order at all. The operator verifies the
seller's refund proof against the recorded address; in a cooperative
resolution the buyer's claimed amount + the seller's matching refund
are self-consistent. The order reveal remains the fallback for when
the seller contests the amount or the facts — staged disclosure, as
the review required. It also means a refund can still reach a buyer
who lost their copy of the order.

## Addendum — fixes from the two follow-up reviews (2026-10-14, pending ratification)

Sources: DESIGN-REVIEW-SETTLEMENT-FOCUS-2026-10-14.md and
DESIGN-REVIEW-WALKTHROUGH-CRITIQUE-2026-10-14.md. Both accept the
architecture; these close the holes they found in the walkthrough.

- **F1 — Standing offer must be explicit.** A signed listing binds the
  seller only if the listing itself carries the authorization clause
  (marketplace may issue reservations under stated limits; a conforming
  order submitted and paid within the deadlines binds the seller
  without further acceptance) and defines eligibility, price
  calculation (atomic units, rounding, shipping, exchange-rate expiry),
  capacity, the binding event, expiry/withdrawal effects on outstanding
  reservations, and the conformance rule. The seller authorizes the
  reservation mechanism explicitly, not merely the pool. Listings that
  cannot support a precise standing offer keep interactive acceptance.
- **F2 — Inventory trilemma acknowledged.** Hidden quantities + exact
  core-enforced stock + no seller involvement: pick two. Default:
  bounded orders / reservation-slot limits / seller-managed
  availability; residual overselling risk is the seller's, remedied
  via their signed refund terms.
- **F3 — Refund-first becomes settlement-by-agreement.** The walkthrough's
  step 12 had a real hole (whose claimed amount?). Closure of an
  unopened dispute requires a BUYER-SIGNED settlement authorization
  (case ID, commitment, recorded refund address, exact amount in
  atomic units, deadline, settlement scope). The operator verifies the
  refund proof against that authorization. No buyer agreement → case
  proceeds to selective disclosure. Settlement closes the monetary
  claim only; it is not exoneration and buys no immunity from evidence
  already establishing deception. (Supersedes the plan's simpler
  refund-layer wording.)
- **F4 — Refund address binding completed.** The signed submission and
  the marketplace receipt bind refund address + reservation ID +
  commitment + network + ciphertext digest. Changes require a
  separately authenticated amendment with a precedence rule; no silent
  substitution by operator or seller. The core's retention of a
  buyer-associated destination gets an explicit retention policy.
  Losing the order bundle ≠ losing the refund wallet's keys — separate
  failure modes, helper preserves refund-wallet recovery info.
- **F5 — Reservation certificate drops the listing version.** The core
  does not need to know which listing a buyer is buying (price leaks
  roughly the amount). The listing binding lives in the committed
  order and the seller-signed listing itself; dispute conformance
  checks work unchanged.
- **F6 — Seller defense against mismatched ciphertext.** If the
  submitted ciphertext doesn't open to content matching the filed
  hash, the seller may reveal that message's session key; the operator
  decrypts the CORE-STORED copy and checks it against the hash,
  proving buyer-side mismatch rather than seller non-performance.
  Requires ciphertext retention through the dispute window and the
  seller's helper checking hash-vs-plaintext at first open, before
  shipping.
- **F7 — Evidence bundle includes the tx key.** At payment time the
  helper records txid + tx private key (a seed-restored wallet loses
  tx keys; without it no proof can be generated). Bundle may be backed
  up server-side encrypted to the buyer's own key (buyer may decline);
  loss mode shrinks to "lost PGP key."
- **F8 — Private refunds:reservations ratio.** The core keeps, per
  seller, refunds ÷ reservations (reservations are core-issued, an
  exact internal count) for operator triage and tier throttles ONLY —
  never published, never a score. Bounded use noted by Muse:
  denominator inflation via sockpuppet reservations is possible but
  costly and pattern-visible, and F9 caps blunt it.
- **F9 — Pool exhaustion defenses.** Caps on unpaid reservations per
  buyer (lower for new accounts), short reservation expiry, low-pool
  alerts to sellers, and the seller helper records the highest pool
  index issued (wallet lookahead after seed restore).
- **F10 — Proof qualification everywhere.** Guarantee wording corrected:
  proofs are verified against authenticated instructions with
  destination/amount/inclusion/reorg/abnormal-output checks, timing
  and prior-use checks, and dedup against prior settlement claims.
  "Can't fake a refund" is retired as a claim.
- **S1 — Late payment.** A payment landing after reservation expiry is
  still a payment: fulfil or refund. Expiry ends routing privileges,
  not obligations.
- **S2 — Fiat-priced listings.** The committed terms fix the XMR
  amount via an exchange rate with an expiry, inside the commitment.
- **S3 — Phishing root confirmed present.** The helper pins the
  marketplace operator's key; seller keys are certified via the
  authenticated key-transition history (Stage 3 key records). Signed
  artifacts are only as good as this root.
- **S4 — "Deliberate deception" gets evidentiary definitions** (e.g.,
  provably false tracking data, the seller's own signed statements
  contradicted by verified evidence) — not an operator label.
- Wording discipline from both reviews is adopted for all future
  claims: a submission is a proposal, not a sale; the happy path
  "produces no core-visible payment or completion confirmation";
  guarantees use the reviewers' revised set.

## Invariant — refunds are case events, never currency (Cameron's attack, 2026-10-14)

Refunds are trivially cheap for a seller to fake as a signal (refund a
sockpuppet buyer; the money circles home minus fees). Therefore:
- A refund's ONLY effect is inside its own case: verified against the
  recorded address and the buyer-signed settlement amount, it closes
  that monetary claim. It cannot be redirected (address pre-recorded)
  and cannot settle anyone else's claim.
- Settled/dismissed cases are recorded NEUTRALLY — never as positive
  reputation, never as mitigation credit by count. (Review 1's rule:
  dismissed ≠ successful sale.)
- The general invariant Cameron's attacks have converged on: EVERY
  positive metric in this system is manufacturable (receipts, ratios,
  refund counts); only NEGATIVE evidence from independent
  counterparties is expensive to fake. So seller records are purely
  subtractive: they start clean and accumulate findings; there are no
  points to earn. The only positive-flavoured datum is
  platform-OBSERVED continuity (time active with zero sustained
  findings), which nobody submits.
- Corollary: a seller who refunds every genuine complainant accrues
  no findings — that is the system working (victims made whole), not
  gaming. Residual leak: victims who never complain; bounded by
  dispute visibility and buyer education, not by metrics.

## Addition — paid account activation (Cameron's proposal, 2026-10-14)

Charge a small one-time XMR fee to activate an account for
TRANSACTING (reserving/ordering/disputing). Browsing and reading stay
free. Rationale and placement:

- It is the missing RE-ENTRY COST. Review 1's weakness — "nuking is
  weak without re-entry cost" — is directly answered: a banned
  scammer pays again for every new identity, and a Sybil farm pays
  per account, linearly, forever. A genuine buyer pays once, ever.
  (Precedent: paid-registration communities; a one-time fee is
  trivial for a person and a recurring tax on a farm.)
- It prices the residual Sybil-powered attacks that survive the
  no-positive-metrics invariant: reservation churn / pool exhaustion
  (F9) and dispute flooding against human review.
- Mechanics: operator issues a per-registration address from its own
  pool machinery; the account activates when the fee confirms. The
  fee is the operator's service revenue (not trade custody — the
  noncustodial trade posture is untouched) and is forfeit on a fraud
  ban. Sellers pay too (same or higher tier), complementing
  activation delay / probation (R8).
- Costs stated honestly: signup friction (mitigated by charging at
  first transaction, not at registration) and a one-time link between
  the account and a funding transaction (mitigated: buyer may fund
  from any wallet; the operator learns a payment happened, nothing
  about trades).
- Calibration: small enough to be a non-event for a person (order of
  a few dollars in XMR), large enough that a thousand-account farm
  feels it every time it is burned.

## Pack Review 1 — required changes (2026-10-14; source: DESIGN-REVIEW-PACK-RESPONSE-1-2026-10-14.md; pending ratification)

Verdict: adopt the architecture with changes; NOT yet ratifiable as an
implementable protocol. Changes Muse accepts on the merits:

- **Offer lifecycle (biggest catch):** a signed listing proves contents,
  not applicability. Standing-offer listings use seller-signed FIXED
  VALIDITY INTERVALS with stated reservation-qualification windows and
  submission/payment grace periods; no retroactive withdrawal within
  an interval; edits bind later intervals only. Eligibility must be
  objective or the listing uses explicit acceptance.
- **T3 ratio REMOVED entirely** (not demoted): queue order is an
  operational consequence, so an attacker-controlled denominator
  suppresses review of genuine complaints. Review priority = severity,
  evidence sufficiency, age, urgency of ADMITTED complaints. G3
  amended: no routine volume-based mitigation; moderators weigh
  uncertainty/incident context (severity, duration, common cause,
  remediation, recurrence) without a volume rule.
- **Dispute admission before duties:** Layer 1 is an optional
  settlement invitation; mandatory response duties (and any
  noncooperation finding) attach only to ADMITTED cases meeting
  defined criteria, with notice + outage tolerance. Kills manufactured
  noncooperation (attack A).
- **U3 struck as written:** seller checks happen AFTER payment. Bounded
  claim only: pre-payment checks enumerated (helper conformity,
  receipt verified before payment instruction shown, wallet-evidence
  capability checked pre-payment); the rest are seller-side/dispute-time.
- **Endorsements REMOVED from the v1 dossier** (contradicted G2 in
  practice). Dossier wording fixed: "No sustained findings recorded.
  Sales volume and successful fulfilment are not verified. Absence of
  findings is not evidence of successful trading." First-seen and
  last-observed shown separately, never collapsed into "active for N".
- **Proofs:** drop mandatory fresh-challenge regeneration at dispute
  time — the durable proof saved at rehearsal is presented bound by
  the party's signed case submission; credit allocation is per
  destination/output allocation (not blanket txid dedup); "already
  spent" ≠ invalid; deadlines defined by qualifying inclusion + grace,
  not wall-clock broadcast time; P13 becomes a pinned implementation
  with an operator-controlled, independently validated chain source and
  a failure taxonomy (invalid / unsupported / unavailable / adverse).
- **Usability corrections:** the user task is "Save payment evidence"
  with a persistent visible "Payment evidence not saved" state;
  helper MAY submit on explicit user click (manual copying was never
  a confidentiality boundary); seller checks collapse into ONE summary
  with exceptions; user-test scenarios must include retry, lost key,
  wallet restore, malformed order, late payment, refund recovery, and
  clean-device backup RESTORATION.
- **P11 narrowed:** session-key defense establishes mismatch ONLY on a
  successful authenticated opening of the exact receipted ciphertext;
  failed openings prove nothing (classify as unresolved technical
  failure). Commercial/shipping compartments get SEPARATE encryption
  keys; session keys never reused across orders/compartments (RFC 9580
  profile); keys never pasted into case threads/logs.
- **P14 corrections:** pilot-only; delete "forfeit" (fee is
  nonrefundable revenue); delete "a person pays once ever" (no
  personhood; account sale/key loss exist) → "each activated account
  has an acquisition cost; bans can impose replacement cost"; bans
  must NOT cut off existing orders, evidence retrieval, disputes, or
  appeals, and erroneous bans are remedied without a new fee;
  operator-incentive checks (published fee policy, no ban quotas,
  aggregate enforcement stats).
- **Smaller accepted fixes:** P1 constrained PGP profile + no
  real-name UIDs; P3 softened claim + manifest validation rules; P4
  cert binds marketplace ID/protocol/policy versions + pool-manifest
  identity, helper verifies seller pool authorization; P5 caps =
  outstanding/unexpired reservations + issuance rate, pool recovery
  preserves full index/scan info, late payment preserves
  fulfil-or-refund claim but not original price terms (expired FX
  quote doesn't bind forever); P6 ONE canonical machine-readable
  format shared by buyer helper/seller helper/moderator, summary
  rendered from committed bytes; P7 payload must include openings for
  the seller; P9 idempotent one-submission-per-reservation machine,
  receipt verified BEFORE payment instruction; P10 enumerated
  settlement scopes + revision freezing + "amount evidenced at the
  designated destination" wording; P12 admission criteria + burdens,
  buyer access preserved after ban, outcome definitions fenced; T1
  incident dedup (one outage = one root incident) + separately
  labelled precautionary restrictions; T2 falsity ≠ intent — deception
  needs knowledge/intent evidence within the statement's proposition
  scope (attack E); T5 address match = lead/conflict only, never
  attribution (poisoning, attack B); operator-signature claims
  downgraded — pinning proves channel, not honesty; timestamps are
  operator assertions (attack C); redacted outcomes are operator
  decisions, not publicly verifiable proof (attack G); address-privacy
  sentence replaced with the qualified version (Janus/active-linkage
  noted); Carrot/FCMP++ treated as a separate future migration profile
  (legacy claims labelled legacy); retention table adopted (bounded
  dispute horizon per listing within a platform max); pack errata —
  activation cross-references P12→P14, §8 "auto-sustained" struck
  (findings are human; the gate is that qualification TESTS exist).
- **Six ratification gates (reviewer's):** (1) authenticated offer
  applicability + deadline semantics; (2) canonical format + state
  machine; (3) P11 success/failure tests incl. compartment leakage;
  (4) pinned proof implementation + adversarial qualification tests;
  (5) ratio removed + dispute admission defined; (6) unaided user
  tests incl. evidence export + backup recovery.

## Pack Review 2 + reconciliation (2026-10-14; source: DESIGN-REVIEW-PACK-RESPONSE-2-2026-10-14.md; pending ratification)

Verdict: adopt with changes; 7 of 25 items adopt as written, 18 adopt
with changes, NONE rejected.

**Convergent with Pack Review 1 (treat as settled ground):**
endorsements OUT of v1; fresh-challenge proof regeneration DROPPED by
both (durable tx-key evidence, one order per transaction, presentation
bound by signed case submission); canonical single pricing format;
helper submission on user action / file-based handoffs; activation fee
= anti-griefing/re-entry pricing, NOT scam deterrence; Carrot/FCMP++
as a separate future migration profile; dossier honesty language;
deception requires intent-grade evidence.

**New catches unique to Review 2 (Muse accepts on the merits):**
- **A1 (strongest in either review): server address substitution.** As
  packed, the server picks the pool address and signs the cert — a
  compromised/exiting operator redirects payments AND the evidence
  convicts honest sellers. Fix: seller signs a MERKLE ROOT over the
  pool; each reservation cert carries the address's inclusion proof;
  the helper verifies it against the seller's key; seller keys
  certified by an offline root; Layer 2 checks inclusion too.
- **A3: listing recovery via C_order.** With C_terms/C_shipping filed,
  the only unknown in C_order was the public listing digest —
  dictionary attack recovers the listing, undoing P4's omission. Fix:
  listing digest moves INSIDE the terms, under secret1.
- **A2: probable-sales metadata.** Seller helper acknowledges EVERY
  submission on arrival (fixed content), ciphertexts padded to size
  buckets, reservation rows + thread metadata purged at window close;
  copy corrected to "no confirmation of sale; timing can still suggest
  which orders were paid."
- **New-seller reservation cap** (platform-set weekly cap rising with
  continuity) — bounds buyer exposure without any positive signal.
- **Unique-item mode (opt-in):** certificate names the listing, only
  one open reservation; seller accepts the listing-visibility cost.
- **UX-1:** before the address is shown, the helper asks "paying from
  your own wallet, one that shows a transaction key?" — swap-service /
  exchange payments silently destroy Layer 2 evidence; rehearsal
  turns red if destination/amount mismatch (also UX-3 short-payment
  "short by X" at once). Order-kit FILES in/out replace paste
  shuttling (UX-2). Buyer's own per-seller history (helper-local,
  unsubmittable) joins the dossier.
- **Two-decryptions rule (P11):** AEAD is not key-committing; a
  buyer-signed ciphertext that decrypts validly under two session
  keys is itself proof of buyer manipulation. Compartments become
  SEPARATE MESSAGES. Mismatch ends in refund, no resubmission path.
- **Burn claims:** Inconclusive unless the seller identifies the
  duplicate output (chain-wide lookup); timelock checks stay but are
  near-extinct post-relay-rule/deprecation.
- **P10 deltas:** settlement authorization irrevocable until its
  deadline (≤72h); amount = what the buyer RECEIVES, fee on top;
  partial settlements state the remaining claim or default to closing
  the whole money claim; operator never re-prices a lapsed
  authorization (buyer re-signs).

**DECISIONS FOR CAMERON (the two reviews diverge):**
- **D1 — T3 ratio:** Review 1 says REMOVE entirely; Review 2 says keep
  one-way (may raise review priority, never lower it below the floor
  set by findings/open disputes). Muse's analysis: the one-way floor
  does defeat Review 1's suppression attack (inflation can't push
  priority below baseline), but the marginal signal over Review 1's
  own priority criteria (severity/evidence/age/open disputes) is
  small. Muse leans REMOVE for v1 (simpler, one less
  attacker-touchable input); one-way variant documented as fallback.
- **D2 — Settlement vs conduct:** Review 2 lets the buyer reveal for
  DECEPTION even after settling the money claim; Review 1 implies
  settlement closes the case absent already-established misconduct.
  Muse leans ADOPT Review 2 with Review 1's fencing: post-settlement
  reveal must pass dispute admission, and never reopens the money
  claim. (Otherwise settle-everything is a findings escape hatch, A6.)

**Merged without conflict:** ban-fee handling = Review 1's structural
checks PLUS Review 2's public donation of post-ban re-activation fees
with proof; late payment = seller's choice, fulfil or full refund;
refund-address amendments = pre-dispute only, identity-signed, seller
acknowledged, exact revision named in settlements, addresses deleted
at window close; offer applicability = Review 1's signed validity
intervals (Review 2's "withdrawal stops new reservations" is the same
rule operationally); P2 fallback replaced by an unlisted single-buyer
listing version (one protocol path).

## Residual-risk annex — Muse's post-reconciliation pass (2026-10-14)

Asked by Cameron for remaining exploits/game-theoretic holes in the
current iteration. None found that break the design; four are bounded
residuals/understatements to record, two are tuning items:

1. **Reservation-cap DoS (new interplay, from Review 2's cap):** the
   new-seller weekly cap and the unique-item single-slot mode can be
   squatted — attacker reserves (never pays), genuine buyers are
   turned away. Bounded by activation fee per identity + short expiry
   freeing quota, but the cap formula must assume hostile squatting,
   not just organic demand.
2. **Refund-or-finding extortion (buyer-side abuse is thinner than
   seller-side in the design):** a buyer can file to pressure an
   honest seller into refunding a delivered order. Bounded: settlement
   creates NO finding (neutral), admission filters weak cases, and
   findings are judgment not filings. Gap: repeat-filer abuse records
   deserve the same subtractive treatment as seller records.
3. **Quality/substitution fraud flies at breach altitude:** the design
   catches non-delivery structurally; deliberate mis-delivery rarely
   produces intent-grade evidence and can persist as "breaches."
   Mitigation is accumulation + graduated sanctions only. Known and
   inherent (no inspection exists), stated so copy never implies
   delivery-quality verification.
4. **Operator availability trust:** post-A1, a malicious operator can
   no longer steal payments or frame sellers — but CAN quietly censor
   or delay reservations/disputes, undetectably in v1 (no
   transparency log). v1 states this as an operator trust assumption,
   like first-contact key trust.
5. **Helper monoculture / WYSIWYS:** all guarantees compress into one
   client artifact. Mitigations are implementation discipline:
   summary rendered from the exact committed bytes, reproducible
   signed releases, tool-agnostic spec. Top implementation risk.
6. **Tuning items:** (a) the cap-rise curve IS the bound on a sleeper
   seller's exit harvest (cap × avg order value × detection latency)
   — set it consciously; (b) "made whole" is denominated in XMR —
   under fiat-priced listings a refund restores the XMR amount, not
   the fiat value; adjudication copy must say so.
