# Multisig design exploration — commissioning brief (AWAITING Cameron's go)

Prepared 2026-10-17, after Cameron asked whether now is a good time to
explore improving Polyculture Markets' Monero transactions with
different multisig designs, and how plugin-style modification should
be navigated. The main chat's answer: yes for paper exploration, not
yet for building; multisig designs would arrive through the existing
plugin seam. **This brief is the prepared commission. No exploration
has been run and no code is to change until Cameron says go.**

## What the exploration is

A paper survey — a design memo with a recommendation — not a build.
Deliverable: one document scoring each candidate design against the
settled invariants (below), naming what each would cost in code,
audit surface, and user friction, and recommending one design (or
"none yet") for a later, separate build decision.

## Designs to survey

1. **2-of-3 with arbiter** — buyer, seller, and a dispute arbiter as
   third key; funds move on any two signatures.
2. **2-of-2 with timelocked refund** — buyer+seller must cooperate;
   a pre-signed refund path unlocks after a deadline.
3. **Optional-mediator escrow** — direct payment stays the default
   (v1 behaviour); buyer/seller may opt into a mediated multisig
   order at creation.
4. **Double-deposit / MAD (Particl-style)** — both parties post a
   bond into multisig; honesty is enforced by mutual loss, no arbiter.
5. **Status quo as the control** — Direct Payments v1 (no escrow,
   seller attestation) scored on the same axes, so any change has to
   beat the shipped design, not a strawman.

## Settled invariants every design is scored against

- **Noncustodial always** — the server never holds keys, funds,
  txids, or amounts (Direct Payments v1 property; a design that
  breaks this is disqualified, not traded off).
- **No JavaScript; server stays blind** (ciphertext-only PGP
  messaging; coordination data the design forces the server to see
  must be listed explicitly — it counts against the design).
- **The trait seam is the delivery route** — spec v2 excluded
  *runtime* (WASM) plugins, not extension itself: payment strategies
  are compile-time modules behind Rust traits, chosen by the instance
  operator. A multisig design must be expressible as such a module;
  operator consent is the trust point, stated plainly, no sandbox
  theatre. (This is also the answer to the plugin question: channel
  modification through a versioned, documented seam and the Manioc
  Server signed-recipe pipe; AGPL keeps forks open; the name
  "Polyculture Markets" is the trademark lever against pass-offs.)
- **Monero's multisig maturity is a constraint, not a detail** — its
  multisig is the least mature part of the wallet stack (setup
  ceremonies, no FCMP++ yet — FCMP++ retest stays parked). Each design
  must state its wallet-side ceremony in full: rounds of info
  exchange, what happens when a party abandons mid-ceremony, and
  what a non-technical seller on Manioc Server can actually complete.
- **Account closure remains the only moderation mechanism** — no
  design may smuggle in banning/suspension via the arbiter role.
- Prior art on record: Neveko (Rust/I2P, multisig escrow, archived),
  Haveno (Java, multisig-based), Particl (double-deposit MAD), and
  tor-marketplace (charges 4% on its escrow basis) — from the
  2026-10-16 comparable-software research.

## Questions the memo must answer

1. Which designs preserve the server-blind property end-to-end, and
   which quietly require the server (or arbiter) to learn amounts,
   addresses, or timing it currently never sees?
2. Failure theatre: buyer ghosts after funding; seller ghosts after
   shipment; arbiter unavailable for a month. Walk each design
   through all three, with the exact recovery path and its deadline.
3. **The fee question** (parked since October): escrow is what makes
   a percentage fee collectible at all. For each viable design, state
   whether a fee becomes technically collectible, and who would set
   it — without recommending a business model; that stays Cameron's.
4. Audit cost: how much new trusted code does each design add, and
   can it be gated as its own stage with locked tests, the way
   Direct Payments v1 was?
5. Sequencing check: confirm the memo's recommendation respects the
   standing order — frozen v1 gets its multi-AI audit pass FIRST
   (blocked only on Cameron's GitHub sign-in); any multisig build is
   a post-audit stage of its own.

## Out of scope

No code, no spec amendment, no change to the frozen/gated v1 tree,
no change to the demo. If the memo recommends a design, building it
is a separate Cameron decision with its own stage brief and gate.
