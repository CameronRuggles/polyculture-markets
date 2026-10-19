# Threat Model — Privacy-First Noncustodial Marketplace

Stage 0 deliverable (spec §24). Companion to `docs/invariants.md` and the spec's
§2; amendments in `../../SPEC-V2-AMENDMENTS.md` win on conflict.

## 1. What the system is

A self-hosted web application (Rust/Axum, PostgreSQL, no client-side JavaScript)
where pseudonymous buyers pay sellers directly in Monero. The server stores
listings, orders, signed statements, ciphertext messages, and reputation facts.
It never holds funds, spending keys, or message plaintext.

## 2. Assets, ranked by harm if compromised

1. **Buyer/seller funds in flight** — protected structurally: the server cannot
   redirect a payment without forging a seller signature (see T2).
2. **The external key file** — encrypts pending tx proofs, dispute disclosures,
   optional view keys; keys the buyer-token HMAC. Theft of DB + key file together
   is the worst realistic server-side event (see T1). Lifecycle (generation,
   separate backup, rotation, loss consequences) is a Stage 4 design item; loss
   means: pending proofs/disclosures unreadable, buyer tokens rotate (distinct-
   buyer counts reset), view-key watching stops.
3. **Message metadata graph** — who messaged whom, when, how large; order graph
   with timestamps. The DB is this graph; retention (§20) is the mitigation.
4. **Identity keys' continuity** — a hijacked account + rotated key can impersonate
   a seller to future buyers. Mitigated by rotation rules (§8) and pinning.
5. **Session tokens / account credentials** — Argon2id, hashed tokens, throttles.
6. **Reputation integrity** — farming raises fraud losses for buyers; weighted
   model raises cost, does not eliminate.

## 3. Actors

- **Malicious/compromised operator or server intruder** — the design's central
  adversary for funds and message content; a *trusted* party for metadata and
  availability (disclosed in §2 of the spec and the Limitations page).
- **Malicious seller** — non-delivery, bait listings, reputation farming,
  destination substitution attempts via social engineering.
- **Malicious buyer** — false payment reports, dispute abuse, envelope probing
  (T5), review extortion.
- **External attacker** — credential stuffing, DoS (Argon2 exhaustion, slow
  requests), upload attacks, XSS/markup injection via listings.
- **Network observer** — sees onion-service metadata only if Tor is used as
  intended; clearnet HTTPS profile leaks more (IP, timing). Out of scope beyond
  Tor's own guarantees.
- **State-level adversary** — traffic correlation is explicitly NOT defended
  (spec §2). Operator legal exposure is a separate, pre-launch item (Stage 9).

## 4. Threats and controls

**T1 — Database/key-file theft.** Controls: no plaintext messages, shipping
details, spending keys, or raw session tokens at rest; secrets that must exist are
encrypted under the external key file; key file stored outside the DB and backed
up separately; retention jobs delete on schedule (§20). Residual: metadata graph
and ciphertext remain exposed; disclosed honestly.

**T2 — Operator/intruder substitutes a payment destination.** Controls: every
destination arrives inside a seller-signed pool or invoice statement; core verifies
the signature against the key pinned on the order; destinations are unique
forever (global table) and validated as torsion-free subaddresses on the right
network by the in-process address parser. NOT built: a wallet-RPC
`validate_address` cross-check — the server runs no wallet (an earlier draft of
this document claimed one; messaging audit ML2). Residual: a buyer who never verifies locally against their own pinned
key trusts the server's display — mitigated by downloads + guide, not eliminated.

**T3 — Account takeover.** Controls: Argon2id + global hashing semaphore (503
before exhaustion), per-username exponential delay (never lockout), session
rotation on login/privilege change, `__Host-` cookies, CSRF synchronizer tokens,
recovery codes that revoke all sessions and publicly mark the profile 30 days.
Admin/moderator accounts: TOTP at login and as a fresh step-up for moderator
actions and disclosure reads (built, account security audit). PLANNED, not
built: a separate listener for admin/moderator surfaces — today they ride the
same listener as the public pages. Residual:
passphrase quality is the user's.

**T4 — Seller non-delivery / fraud.** No escrow in v2 — this risk is *accepted
and disclosed*, priced into design via reputation (weighted model, raw facts
always shown), disputes with signed-message evidence only, and the invoice-page
risk notice. The marketplace cannot recover funds; nothing in the UI may imply
otherwise (locked wording tests).

**T5 — Envelope probing / membership oracles.** PKESK key IDs are
attacker-chosen bytes. Controls: envelope errors follow the Q16 ordered taxonomy;
no registered-vs-unknown recipient distinction; `RecipientKeyRetired` returned
only for keys the sender was already shown in this conversation; ciphertext
downloads restricted to participants; rejected plaintext never echoed or logged.

**T6 — Malicious uploads.** Images are decoded/re-encoded by a separate
media-worker process and metadata is stripped; JPEG/PNG only. Attachments are
opaque, download-only, never rendered inline. Worker containment, stated
exactly as built (corrected 2026-10-19 — an earlier version of this section
claimed isolation the code did not have): IN CODE, the worker child is
killed when its timeout expires (`kill_on_drop`; a runaway decoder cannot
outlive the request), and at most two workers run concurrently
process-wide, so decoder resource use is bounded in count as well as
time. WHERE THE DEPLOYMENT PROVIDES bubblewrap, the worker additionally
runs sandboxed (`MEDIA_WORKER_SANDBOX=bwrap`): no network namespace, a
read-only root containing only the worker binary, the single input file,
and a scratch directory — off by default because bubblewrap is a
deployment dependency, not something this code can assume. Per-worker
MEMORY caps are a deployment measure (systemd `MemoryMax=` on the app
unit), not something the application enforces on its child. There is no
seccomp profile; the worker is a separate minimal binary that only
reads one file and writes one file, and the claim ends there.

**T7 — DoS.** Per-account throttles (built: a per-account request throttle on
signed-in POSTs, plus messaging-layer limits — 60 messages/minute per account,
a 16 MiB rolling daily byte budget per account, and per-conversation caps).
Storage-exhaustion bounds (built 2026-10-19, fix verification V9): per-account
budgets cannot bound total storage while accounts are free to create, so the
messaging layer also enforces an instance-wide daily storage ceiling
(default 256 MiB of message ciphertext per 24h, operator-settable) and a
free-disk floor on the blob volume (default 1 GiB) past which message storage
is refused with a 503 rather than filling the disk; accounts less than a day
old, or with no completed order, get a smaller 1 MiB daily budget. A global
registration cap is built and operator-settable from the environment
(`ACCOUNT_CAP` in the instance configuration); it ships unset — no cap — by
default, so whether the instance accepts unlimited accounts is the operator's
stated choice, not a hard-wired one. Also built: Argon2 semaphore, body-size
limits before parsing, header/idle timeouts.
PLANNED, not built in code: Tor proof-of-work defenses on the onion profile —
an operator-side Tor configuration choice, not an application control.
Residual: a determined attacker can degrade a
small instance; no funds or data loss results.

**T8 — Module misbehaviour.** Modules propose; the core verifies, records,
renders. Closed evidence enums; capability handles granted per module; no module
I/O by default; reputation models pure. A buggy/malicious module cannot write a
destination, a state, or markup (locked module-boundary tests, §23).

**T9 — Supply chain.** `cargo vet` audits for crypto-critical crates, lockfile
pinning, toolchain pin, Nettle-only Sequoia builds enforced in CI, signed
releases + reproducible builds as a Stage 10 item. A locked regression fixture
(non-canonical address encoding) guards against a future crate version weakening
a check the design relies on.

**T10 — Time manipulation.** Expiries, sessions, retention, and reputation months
all trust the host clock; §19 denies general outbound traffic, so the clock
source (NTP allowance or Tor-based sync) must be specified by Stage 10 and the
instance must fail loudly on gross clock skew rather than silently mis-expiring.

## 5. Explicitly out of scope (spec §2 restated)

Compromised user devices; traffic correlation; a malicious server on a buyer's
very first visit (before any key is pinned); users skipping verification;
information a buyer voluntarily discloses for delivery; seller non-delivery
beyond the reputation/dispute mitigations in T4.

## 6. Open items (from the decision review's missing questions)

marketplace-id generation + persistence across onion/domain migration (Stage 0 —
decided in `modules-api`: generated once at instance init, stored outside the DB
with the key file, never changes for the life of the instance's signed-statement
history); admin TOTP (Stage 1); listing-image illegal-content reporting workflow
(Stage 2); key-file lifecycle (Stage 4); clock source (Stage 4/10); review funding
applications (Stage 6); tx-proof flag policy (Stage 8); FCMP++/Carrot watch
(Stage 8); operator legal review (Stage 9, before any public instance); seller
exit/re-entry and retired-fingerprint blocklist (Stage 9); non-expert GPG
usability test (Stage 9); signed releases/reproducible builds (Stage 10).
