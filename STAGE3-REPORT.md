# Stage 3 — Completion Report (identity keys and rotation)

Date: 2026-10-13 · Spec §24 Stage 3 (§8, §10 rotation statement)

## What exists

- **Certificate validation** (`app::keys`, Sequoia on the Nettle backend):
  parses the uploaded cert, requires validity under Sequoia's standard
  policy (not expired/revoked), an encryption-capable subkey, and a
  signing-capable key (§8). The primary fingerprint is the identity.
- **Upload warnings:** every user ID that will become public is examined;
  IDs that look like an email address or a real name produce explicit
  warnings on the result page (§8).
- **Key registration:** first key installs as `current` (fingerprint is
  globally unique); a second upload is refused — replacement only via
  rotation.
- **Certified rotation:** the `marketplace-key-rotation-v1` statement is
  parsed strictly (fixed field order, pinned 128-bit account/marketplace
  ID patterns per amendment Q15, uppercase fingerprints, canonical
  timestamp, byte-level ASCII/LF rules) and must be detached-signed by
  **both** the old and the new key; both signatures are verified against
  the exact statement bytes, and the statement must name this account,
  the current fingerprint, and the new cert's fingerprint.
- **Uncertified rotation:** explicit "I lost my old key" path; recorded
  with `certified = false`; the seller profile shows the spec's
  continuity warning for 90 days (SQL-windowed).
- **Key history:** `identity_keys` versions + `key_rotations` rows; the
  profile shows every version with status and dates.
- **Seller profile** (`/sellers/{public_id}`): pseudonym, role, current
  fingerprint, key download (`key.asc`), the verify-locally note (§8's
  TOFU wording), recovered-account marker (30 days, §7), uncertified-
  rotation warning, plain-text profile field (links never become anchors),
  and the seller's published listings.
- **Account security page:** key registration/rotation forms, session
  list with per-session revoke (§7's list-and-revoke, a Stage 1 leftover),
  and the profile-text editor.

## Evidence

- Unit: keys 3/3 (both fixture certs validate with correct fingerprints;
  email user ID produces the public-warning; garbage rejected; rotation
  statement parser rejects lowercase fingerprints, wrong marketplace ID,
  and a missing trailing LF). Workspace total now 25/25 + 1 integration.
- Live smoke: register → upload key A (warning shown for its email ID) →
  build a real rotation statement → sign with **both** GnuPG keys →
  rotate → profile shows the new fingerprint, v1 retired / v2 current
  history, `key_rotations.certified = true`, and `key.asc` serves the
  new certificate.

## Honest gaps

- The full canonical-statement library (serializer + all statement types)
  is Stage 6; rotation parsing here is a strict local implementation of
  the one format Stage 3 needs.
- Uncertified-rotation side effects on open orders and pools (reconfirm
  before invoicing, retire old-key pools) arrive with orders (Stage 4)
  and pools (Stage 7) — the data (rotation type + date) is recorded now.
- v6/RFC 9580 certs are accepted to the extent Sequoia 2.4 supports them;
  the RFC's A.3 v6 sample validates through the same code path used by
  the envelope work.
