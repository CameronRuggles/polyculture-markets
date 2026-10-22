# GnuPG fixtures for the messaging-audit fix (2026-10-19)

Generated with **GnuPG 2.4.4** in throwaway GNUPGHOMEs (batch mode,
`--pinentry-mode loopback`, `%no-protection` test keys). Only public
certificates and ciphertexts live here — **no private key material is
in the repository**; the private keys stayed in the scratch keyrings
and were discarded with them.

Keys (RSA 2048 sign primary + RSA 2048 encryption subkey, no expiry
unless noted):

| Cert | Primary fingerprint | Notes |
| --- | --- | --- |
| `cert-alice.asc` | `698C2CE6489C747F1458C2BF35C511FEAF38F328` | sender in the message fixtures |
| `cert-bob.asc` | `54C8A581E49106123FB5CCBACED0A0143425A8E0` | recipient; signer of the disclosure message |
| `cert-carol-v1.asc` | `346F063FB3DB1FB8EDB9F17D4065C0B2115BED30` | two encryption subkeys, both valid |
| `cert-carol-v2-revoked-subkey.asc` | same primary | subkey `E82C05E4…E2632C4` revoked via `gpg --edit-key` → `revkey`; subkey `614E4F52…6E87C970` still valid |
| `cert-dave-short-expiry.asc` | `5A37E91C3A9C8A8BAAEB9503DD38B3DF073E742C` | whole cert expires 365 days after creation (2027-10-20) — renewed family, see below |
| `cert-dave-extended.asc` | same primary | expiry extended to 2028-10-19 (signatures only, no new key material) |
| `cert-dave-added-subkey.asc` | same primary | third key added (new key material) |

The Dave family was renewed on 2026-10-21 (HT H1 audit fix task 3):
the original family (`61CD1CD1…C3B2A7A3`, created 2026-10-19) had a
1-day short cert that expired 2026-10-20, and its private keys were
discarded by design, so renewal meant a new key family with the same
shape (RSA 2048 primary [SC], RSA 2048 subkey [E], UID `Fixture dave`).
The "short" window is now 365 days rather than 1 day: nothing in the
suite asserts the duration, and a 1-day cert puts the suite back on a
24-hour clock. Regeneration kit: `fixture-regen-dave-2026-10-20/` in
the project root.

Messages (alice → bob, also encrypted to alice; plaintexts are
seeded-random base64 text at ~300 B / ~2 KB / ~40 KB so compression
cannot shrink them — with repetitive plaintext GnuPG's compression
hides the very packet forms these fixtures exist to exercise):

- `msg-{300,2k,40k}-unsigned.asc` — `gpg --armor --encrypt`
- `msg-{300,2k,40k}-signed.asc` — `gpg --armor --sign --encrypt`
- `msg-2k-signed.gpg` — the 2 KB signed message, binary (unarmed)

GnuPG 2.4.4 writes the encrypted-data packet of the signed messages
(and the 2 KB unsigned one) with **partial body lengths** at every
size (`gpg --list-packets` shows `partial` on tag 20); the 300 B
unsigned message uses a definite length. That split is the point:
before the MH2 fix only the last of these was accepted.

Disclosure fixtures (bob → alice, plaintext: "Bob here: your widget
shipped today, tracking is in the next message."):

- `msg-disclose-bob-to-alice.asc` — `gpg --armor --sign --encrypt`
- `unwrap-bob-signed.asc` — `gpg --unwrap --armor` of the above:
  compressed wrapper around one-pass-sig + literal + signature;
  `gpg --verify` reports a good signature from bob's key
- `unwrap-bob-unsigned.asc` — `--unwrap` of an unsigned encryption
  of the same text: literal data only, no signature

Key-matching fixture:

- `msg-to-carol-subkey1.asc` — encrypted to carol's first encryption
  subkey ONLY (`--recipient <subkey-fpr>!`), made while that subkey
  was valid. Against `cert-carol-v1.asc` it must be accepted; against
  the refreshed `cert-carol-v2-revoked-subkey.asc` it must be refused
  as WrongRecipient (MM3).
