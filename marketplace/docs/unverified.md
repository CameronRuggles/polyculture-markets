# Unverified properties (spec §22.4)

Security properties claimed by the design but **not yet tested**. This file is
reviewed at every stage gate; anything still open here must be disclosed on the
instance Limitations page before launch.

| # | Property | Status / closing stage |
|---|---|---|
| 1 | Real stagenet tx-proof verification (crypto happens in the wallet against a synced node) | Open — Stage 8. Hard gate: no "verified" label renders until closed |
| 2 | RFC 9580 SEIP v2 envelope acceptance | **CLOSED 2026-10-13** — RFC 9580 A.8 vector accepted by the validator (fixtures in stage0-spike/fixtures-rfc9580); v6 hidden-recipient variant still open → item 2a |
| 3 | Legacy SED (tag 9) rejection against a real packet | **CLOSED 2026-10-14** — synthetic tag-9 fixture (Q7a) rejected as UnsupportedPacket in the blind Stage 5 suite (`legacy_sed_container_is_unsupported`) |
| 4 | Sequoia Nettle backend parity with the spike suite | **CLOSED 2026-10-13** — spike suite 19/19 under the Nettle backend (Q8 discharged for the spike; production crates use Nettle from the start) |
| 5 | Tor Browser Safest behaviour incl. `__Host-` cookies on onion (§18) | Open — pre-launch checklist |
| 6 | Envelope packet limits as amended (1–8 PKESK, no Padding tag 21, no trailing bytes) vs spike's simpler 32-packet cap | **CLOSED 2026-10-14** — amended rule implemented in `crates/envelope` (hand-rolled top-level scanner, never descends); locked cases green in the blind Stage 5 suite (35 passed) |
| 7 | `RecipientKeyRetired` conversation-scoping (Q16 leak fix) | **CLOSED 2026-10-14** — sightings + validity-overlap implemented (Stage 5); blind probe tests pass both directions (shown retired → RecipientKeyRetired; unshown retired → WrongRecipient) |
| 8 | Small-order/torsion destination rejection (Q14) | Implemented in `modules-api` Stage 0; locked fixtures land with the suite |
| 9 | Argon2 parameters benchmarked on target hardware | Open — Stage 1 |
| 10 | Clock source under the no-outbound deployment rule | **ADDRESSED 2026-10-16 (Stage 10)** — every retention/expiry cutoff is computed database-side (`now()`), so one clock governs all data decisions; host clock sync (NTP/NTS) on an onion-only host remains an operator duty, documented in docs/operations.md §4 |
| 11 | Remainder of §20 retention: order/invoice/terms purge at terminal + 180 days with tombstones, report windows, backup-copy completion | Open — Stage 10 automated notifications/sessions/security-events/disclosures (retention.rs); the message-payload window (rows past their 90-day `expires_at`, with blob unlinking and orphan-blob reconciliation) was added by Code Audit 2 item 3, 2026-10-24. The rest interacts with reputation facts and counterparty history and is disclosed as not-implemented on the Limitations page, per the Stage 10 brief |
| 12 | Signed releases and reproducible builds (spec §25 deliverable) | Open — the demo deploy script prints the built binary's SHA-256, but no signing key, signed-release pipeline, or reproducibility proof exists yet. Nothing public may claim signed releases until this closes |
| 2a | v6 hidden-recipient (zero-length fingerprint PKESK) rejection | Open — derived fixture still to build; v3 wildcard path is tested |
