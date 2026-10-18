# Design review request — encrypted orders and the seller-trust signal problem

**For:** Claude Opus (external reviewer), fresh context.
**From:** the marketplace build (spec v2, Rust/Axum/PostgreSQL, AGPL-3.0,
no-JS, noncustodial Monero marketplace; stages 1–4 built and
security-gated as of 2026-10-14).
**What we need:** a worked-through verdict on a proposed design change
that deepens the marketplace's privacy model, and a solution — or an
honest impossibility result — for the trust-signal problem it creates.
Please argue with us where we are wrong.

---

## 1. Settled ground (do not relitigate; these are constraints)

- **Noncustodial, always.** No escrow, no multisig in v2. The
  marketplace never holds funds or spend keys. Payments are direct,
  buyer wallet → seller wallet.
- **No JavaScript.** Server-rendered HTML only. Buyers and sellers do
  their cryptography (PGP, Monero wallets) in their own local tools.
- **Identity = PGP keys.** Every account has a PGP identity key
  (built, Stage 3). Messaging is already ciphertext-only: the core
  validates and routes PGP envelopes, stores ciphertext, never sees
  plaintext (§14 of the spec).
- **Subaddress pools.** Sellers generate subaddresses locally in their
  own wallets and upload a signed pool. Subaddresses cannot be derived
  from a public view key; derivation needs the *private* view key,
  which the marketplace must never hold (it would link all of a
  seller's sales and expose their incoming payments). One fresh pool
  subaddress is assigned per order/invoice.
- **Payment evidence = Monero tx proofs.** A buyer's wallet can produce
  a proof that transaction X paid amount Y to address Z. Verification
  is cryptographic and local (view-only wallet RPC `check_tx_proof`);
  chain status (existence, confirmations) can come from remote nodes —
  no local chain sync is needed, because each check is a single-tx
  lookup and proof checks are stateless. Payments into fresh
  subaddresses do not change this: the marketplace never scans anything.
- **Direct-payment reality.** A seller sees incoming payments in their
  own wallet, against the assigned subaddress, without the marketplace
  being involved at all.

## 2. The proposed change (owner's direction, 2026-10-14 — NOT yet ratified)

The current spec has a server-side order model: the core sees orders,
quantities, totals, generates canonical terms files, and tx proofs are
verified routinely to advance order state. The owner proposes to push
the ciphertext-only principle from messages through to orders
themselves, in two steps:

**Step A — verification becomes dispute-triggered only.**
The marketplace does not routinely verify payments. An order's paid
state is the seller's own confirmation (they saw it in their wallet).
A buyer submits a tx proof only when contesting ("I paid, and I'm
contesting it"). The marketplace then verifies the proof. Consequence:
**the marketplace does not know whether sales happen at all.**

**Step B — orders are encrypted end-to-end.**
The buyer composes the order from the public listing (items,
quantities, shipping details, terms as displayed), encrypts it to the
seller's PGP key, and submits ciphertext, which the marketplace routes
and stores like a message. At submission the buyer also posts a
**hash commitment** of the order. Only the seller can read the order.
In a dispute, the buyer reveals the order; the marketplace checks it
against the pre-committed hash (terms cannot have been rewritten after
the fact) and checks the tx proof against the subaddress named in the
order. On that evidence the operator judges honest mistake vs scam and
can close ("nuke") a scam seller's account.

What the core would then know: accounts, public listings, pool
addresses, that ciphertext threads exist, hash commitments, and
dispute outcomes. What it would never know: order contents, shipping
details, sales, totals, revenue.

## 3. Why we want it

- Privacy is the product. A breached, seized, or subpoenaed server
  yields listings, usernames, and ciphertext — no sales ledger exists.
- Payments get *easier*, not harder: nothing to validate in the happy
  path; the seller's own wallet is the settlement layer.
- The one strong signal survives: a provable "I paid, here is the
  committed order, here is the proof" contest is very hard to fake.
- It plausibly softens operator-liability exposure (facilitator /
  money-transmission questions are already on our open register).

## 4. The problem we cannot yet solve — the seller-trust signal

**The risk in this system is the seller scamming, not the buyer.**
Buyers risk money on every order; sellers risk little. The platform's
protective functions are (a) guiding buyers *before* they pay, and
(b) removing scam sellers *after* evidence accumulates. Both need a
trust signal. But:

- **The denominator problem (owner's formulation).** Under Step B the
  platform sees complaints/findings only. A seller with 10 bad outcomes
  might be 10/10 (a pure scammer) or 10/10,000 (an excellent seller at
  volume). The platform sees the same thing. Complaint counts without
  sales volume cannot express a *rate*, and nuking on raw counts
  eventually executes the platform's best sellers.
- **Nuking is weak without re-entry cost.** Accounts are free.
  A nuked scammer returns under a new name and key unless something
  makes re-entry expensive or links the new identity to the old.
- **Pre-purchase guidance is what actually protects buyers.** Post-hoc
  removal caps the damage per identity but every fresh identity gets a
  fresh set of victims. Is any honest pre-purchase signal possible when
  the platform cannot see sales?

Candidate mechanisms we have sketched — please evaluate, combine, or
replace them:

1. **Sustained-findings threshold.** A complaint only "lands" with a
   revealed, hash-verified order + a verified tx proof to the seller's
   assigned subaddress. Faking one requires a real payment and a
   pre-committed order, so honest sellers should essentially never
   accrue *proven* scams. Nuke on N sustained findings, no denominator
   needed for the fraud question (quality ≠ fraud). Does this hold up?
   What is N, and what about a scammer who stays just under it?
2. **Countersigned completion receipts.** On happy completion, buyer
   and seller both sign the order hash; the platform counts receipts
   per seller as a soft denominator. Sybil buyers can inflate it
   (buyer accounts are free; a seller can manufacture orders to
   themselves). Is it useful anyway in bulk / from aged accounts only?
3. **Blind-signed completion tokens.** At order-commit time the core
   issues a blind-signed token (Chaum-style) unlinkable to the order;
   on completion the buyer returns it and the platform counts valid,
   unlinked completions. Sellers cannot mint them. Does this give a
   genuinely hard-to-fake denominator without leaking which orders
   completed? What stops token farming (seller as their own buyer),
   and what does issuance-count metadata leak (pad with decoy issuance?
   issue per thread, not per order)?
4. **Costly identity signals.** Account age, key continuity, listing
   longevity. A seller "bond" as a timelocked-to-self on-chain
   transaction (provable locked capital — but it cannot be slashed
   without custody, so it is pure costly signalling). Vouching:
   established sellers stake their own standing on newcomers.
   Which of these actually raise scammer cost more than honest-seller
   cost?
5. **Buyer-side standing.** Weight findings by the complaining buyer's
   account age/history, and let failed (unproven) complaints count
   against the complainer. Does this change the economics enough?

## 5. Other issues we already see (please confirm, extend, or dismiss)

- **Delivery is unprovable.** Payment is provable; a parcel's arrival
  is testimony. Disputes can prove order + payment, not non-delivery.
  Sellers can offer tracking numbers inside encrypted replies, but the
  platform cannot verify them. How should adjudication treat this
  honestly?
- **Non-delivery vs wrong goods vs quality.** The hash proves the
  terms; "goods were junk" is not cryptographically decidable. Scope
  the dispute system to what evidence can settle?
- **User data burden.** Lose your keys or your copy of the order and
  you have no dispute. GPG usability for non-experts becomes
  load-bearing (already on our open register).
- **Metadata remains.** Even with ciphertext orders, the core sees who
  threads with whom, about which listing, and when. Thread existence
  partially implies order intent. How bad is this, and is cover traffic
  or thread/order decoupling worth anything here?
- **Buyer griefing.** Fake orders cost sellers attention and pool
  addresses; no payment, no recourse. Does anything need to price
  order placement (e.g., nothing, small proof-of-work, account age)?
- **Listings stay public.** Illegal-listing moderation and reporting
  obligations are unaffected by order privacy and remain the
  operator's problem. (Noted, out of scope for this review.)
- **Build cost.** Step B supersedes part of the just-gated Stage 4
  server-side order work and reshapes stages 5–9 (messaging, invoices,
  pools, payment evidence, reputation/disputes). We accept this if the
  design wins; name anything else it breaks (e.g., the order state
  machine's core-visible transitions, retention rules, the terms-file
  digest machinery surviving as buyer-side commitments).

## 6. What we are asking you for

1. A verdict on Step A and Step B separately: adopt, adopt with
   changes, or reject — with the strongest counterargument you can
   make against each.
2. A solution to the seller-trust signal problem (§4): the best
   mechanism stack you can construct **within the §1 constraints**
   (noncustodial, no-JS, no sales visibility), each mechanism rated for
   fake-resistance, privacy cost, and implementation cost. If you
   conclude no adequate pre-purchase signal exists under these
   constraints, say so plainly and define the best achievable posture
   (e.g., post-hoc-only enforcement + buyer education + what else).
3. A precise dispute protocol sketch: what is committed, revealed,
   verified, in what order, by whom; what outcomes exist (finding
   sustained / dismissed / honest-mistake), and what each does to the
   seller's signal.
4. The three most likely ways this design fails in the real world that
   we have not listed.
5. Anything in §1 you believe makes the whole direction unsound —
   say it now, before we re-plan stages around it.

Plain-language where possible; precise where it counts. We will
ratify or reject each recommendation explicitly, as with prior
reviews.
