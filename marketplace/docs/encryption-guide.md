# Encryption guide

How messaging and signed statements work here, in plain language.
Everything on this page happens **on your own computer**. The site
never sees your private key, your passphrase, or the readable text of
any message.

The marketplace is ciphertext-only: the server stores encrypted
messages and can check that each one is properly encrypted to the
right person, but it cannot read them. You do the encrypting and
decrypting locally with GnuPG (`gpg`). The commands below are the
ones the site itself suggests (§10 and §14 of the spec).

## 1. Make a dedicated key for this marketplace

Do not reuse a key that carries your real name or your everyday
email address. When you register a key, **every user ID on it becomes
public** — the site shows them to you before you confirm, and warns
you if one looks like a real name or an email address — and your
fingerprint is printed on your profile, your listings, and every
order you take part in.

Create a key that belongs to this account and nothing else:

```
gpg --full-generate-key
```

- Choose a key type with both signing and encryption capability
  (the default "RSA and RSA" is fine). The certificate must have an
  encryption-capable subkey and a signing-capable key, and it must
  not be expired or revoked, or the site will refuse it.
- For the name, use your marketplace username or another pseudonym —
  at least five characters, no real name. You may leave the email
  field empty.
- Set an expiry you can live with (you can extend it later) and a
  strong passphrase you store somewhere safe.

Find the fingerprint (you will use it everywhere below):

```
gpg --fingerprint <YOUR_USERNAME>
```

Export the **public** key — this, and only this, is what you upload
when you register the key on your account:

```
gpg --armor --export <YOUR_FPR>
```

Never upload, paste, or send your private key anywhere. No page on
this site will ever ask for it.

Back the private key up offline. Account recovery on this site
restores your login only — **it never restores or changes identity
keys**. If you lose your private key, the replacement is an
uncertified rotation, and your profile, open orders, and invoices
will carry an "identity continuity could not be verified" warning
for 90 days.

## 2. Get the other person's key — and pin it locally

Trust lives in your own keyring, not on this website. A fingerprint
shown on a page is a convenience; only a key you pinned locally
protects you if the site itself is ever compromised or malicious.

1. Download the seller's key from their profile
   (`/sellers/{id}/key.asc`) and import it:

   ```
   gpg --import key.asc
   gpg --fingerprint <THEIR_FPR>
   ```

2. Check that the fingerprint GnuPG shows matches the fingerprint
   on the profile — and, better, a copy of the fingerprint the
   seller publishes somewhere else (sellers may list other places
   their fingerprint appears, in their profile).
3. From then on, verify everything against your local copy, never
   against a fingerprint freshly read off a page.

Every order also pins the seller's fingerprint at the moment the
order is created, so a later key change cannot quietly rewrite who
you agreed to pay.

## 3. Send a message: sign, then encrypt, locally

There is no plaintext composer on this site, on purpose. Write your
message in a plain text file, then run the command the compose page
suggests:

```
gpg --armor --sign --encrypt --recipient <THEIR_FPR> --recipient <YOUR_FPR> message.txt
```

Then paste the armored output (`message.txt.asc`) into the compose
box, or upload the file.

Why each part matters:

- **Encrypt to yourself as well** (`--recipient <YOUR_FPR>`).
  Without it, you cannot re-read what you sent.
- **Sign before encrypting** (`--sign`). The server cannot require
  a signature — it sits inside the encryption, where the server
  cannot see it. Signing makes the message usable as evidence in a
  dispute: only messages carrying a valid signature from the other
  party's pinned key count as evidence; unsigned material is shown
  to moderators as an "unverified claim".
- **The trade-off, plainly:** a signed message cannot be denied
  later — by you, to anyone the recipient chooses to share it with.
  If you do not want that for a particular message, leave `--sign`
  out, and accept that it also cannot prove anything in a dispute.

Put shipping details **only** inside encrypted messages like this
one. There is no other private channel on the site.

### What the server checks — and what it rejects

Before storing a message, the server opens only the envelope
(packet structure — never the contents) and checks:

- Size first: at most **64 KiB** of submitted (armored or binary)
  bytes per message. The file-upload form takes the same messages
  under the same 64 KiB cap — there is no separate, larger
  attachment allowance.
- The message is encrypted to the recipient's **current** registered
  key. Any extra recipient must be one of your own registered keys
  (that is the encrypt-to-yourself copy above) — anything else is
  rejected, and only the offending key ID is shown.
- The form is integrity-protected: SEIPD v1 (MDC), RFC 9580 SEIP v2,
  or the LibrePGP AEAD form (tag 20) that current GnuPG versions
  produce are accepted.
- Password-encrypted messages (a symmetric/session-key packet
  instead of public-key encryption) are rejected — always encrypt
  to keys.
- Hidden ("wildcard") recipients are rejected — do not use
  `--throw-keyids` or similar options. The recipient must be named
  in the envelope so the server can confirm you encrypted to the
  right key.

If the recipient has rotated keys since you last wrote, the
conversation shows a rotation banner and new messages must be
encrypted to the **new** key; re-check the fingerprint in your
keyring before sending anything sensitive.

## 4. Read a message

Download the ciphertext from the conversation (downloads are always
attachments, never displayed in the page) and decrypt it locally:

```
gpg --decrypt message.txt.asc
```

or, to save the readable copy to a file:

```
gpg --output message.txt --decrypt message.txt.asc
```

If you signed-and-encrypted as above, GnuPG also reports whether
the signature inside is valid and which key made it — check that it
is the other party's pinned key before treating the contents as
theirs.

Treat decrypted files from strangers as dangerous to open, exactly
as you would an unexpected email attachment: read plain text, and be
wary of anything that asks your computer to run or render more than
that.

## 5. Verify a signed invoice, pool, and terms file

Payment destinations arrive as statements the seller signed with
the key your order pinned. Verify them locally before paying —
this is the check that stops anyone, including a malicious
operator, from swapping the destination:

```
# seller signs (for reference — sellers run this, buyers verify)
gpg --armor --detach-sign --local-user <FPR> invoice.txt

# buyer verifies an invoice and its terms
gpg --verify invoice.txt.asc invoice.txt
sha256sum terms.txt

# buyer verifies a pool entry
gpg --verify pool.txt.asc pool.txt
grep -x "address: <destination>" pool.txt
```

- `gpg --verify` must report a good signature from the **pinned**
  fingerprint — the one from your local keyring (§2), not a
  fingerprint the invoice page happens to display.
- `sha256sum terms.txt` must match the hash recorded for your
  order. The terms file is stored byte-for-byte and never
  regenerated, so a mismatch means you are not looking at the
  terms you agreed to.
- For a pool, the `grep` confirms the exact destination you are
  about to pay actually appears in the signed pool statement.

## 6. What validation cannot check

Stated plainly, because the site will not pretend otherwise:

- Envelope validation **cannot** check the plaintext, any signature
  inside the encryption, or whether the content means anything. It
  proves a message was encrypted to the right key in an accepted,
  integrity-protected form — nothing more.
- Encrypted messages are **not anonymous**: the server necessarily
  sees the conversation, its participants, the message size, and
  when it arrived.
- A good signature proves the pinned key signed those bytes. It
  does not prove the statements in them are true.
- There is no escrow. A verified payment goes directly to the
  seller, and the marketplace cannot recover it.
