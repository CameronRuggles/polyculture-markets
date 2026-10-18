# Locked security tests (spec §22)

This directory is **locked**: implementing agents may not modify it. Changes
require the owner's review — for test changes, the owner reviews a
plain-language list of the assertions added/removed/changed, not just a diff
(decision log Q10).

## Process

1. Tests here are authored from the spec alone, by an author who has not seen
   the implementation under test.
2. If a test looks wrong, the implementer stops and writes a note for human
   review. Never weaken a test to make code pass.
3. Fixture *constructions* may change only with the owner's sight of the diff;
   assertions never (Q7a).

## Stage 0 seed suite

The feasibility spike's blind suite lives at
`../../stage0-spike/tests-blind/` (47 tests: address 16, statement 19,
envelope 12) and is the seed for this directory. Before it is copied in and
locked:

- [ ] Address fixtures replaced with real `monero-wallet-cli --stagenet
      --offline` outputs (Q7b); the valueless stagenet seed committed alongside.
- [ ] Envelope fixtures fixed per Q7a (synthetic tag-9 legacy packet;
      `--compress-algo none` oversize fixture).
- [ ] Envelope tests updated to the Q16 taxonomy (incl. the conversation-
      scoped `RecipientKeyRetired` probe test from the 2026-10-13 leak fix).
- [ ] Address tests updated to the newtype API (Q17: no `kind` on success;
      `WrongKind { found }` on rejection) and Q14 fixtures (non-canonical
      encoding — permanent regression guard; small-order view key).
- [ ] SEIPD v2 acceptance tested against the RFC 9580 Appendix A vectors (Q11).
- [ ] Suite re-run green against the Nettle Sequoia backend (Q8).

## Assertion list (plain language, Stage 0 seed)

Addresses: a real subaddress is accepted on its own network; primary and
integrated addresses are refused; a subaddress from another network is refused;
damaged or made-up strings are refused; an address whose key encoding is
non-canonical is refused; an address with a small-order key is refused.

Statements: a correct invoice statement is accepted and reproduces byte-for-
byte; any change to spacing, line endings, letter case of fingerprints/digests,
key order, or integer spelling (leading zeros) is refused; a signature over
different bytes is refused.

Envelopes: a message encrypted to the recipient (optionally also to the
sender) is accepted; plaintext, password-only encryption, strangers' keys,
hidden recipients, retired keys the sender never saw, and oversized messages
are each refused with the specific error the spec names — and the refusal
never reveals whether an unknown key belongs to some other account.
