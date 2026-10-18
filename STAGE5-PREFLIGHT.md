# Stage 5 — Pre-flight brief (ciphertext messaging + envelope validation)

Prepared 2026-10-13 (background research, after Stage 4 completed and
screenshots were sent). Stage 5 is the first stage under **full §22 gate
discipline** (hybrid-mode decision, Stage 4 report) — so the fixtures and
locked tests below are gate inputs, not nice-to-haves. Nothing here is a
decision; items marked DECISION are Cameron's as spec owner.

## Scope (spec §24 stage 5 = §14)

Compose page (recipient name + fingerprint, key download, local-encryption
instructions, armored paste box + file upload, **no plaintext composer**);
envelope validation at packet level via Sequoia; storage = ciphertext +
minimal metadata only (conversation, sender, recipient, recipient key
version, received time, byte length, expiry); participant-only download
with `application/octet-stream` + attachment + `nosniff` + `no-store`,
ciphertext never rendered inline; conversations attach to an order or are
pre-order inquiries (count toward new-account limits); rotation banner
when the recipient's key changes; shipping details only inside messages.

## Read the amendments, not raw §14 — three places they diverge

`SPEC-V2-AMENDMENTS.md` §14 (Q1, Q5, Q6, Q16) overrides the spec text:

1. **Packet cap:** spec §14 says "at most 32 packets." Amended rule:
   parser never descends into containers; on the visible top-level
   sequence — **1–8 PKESKs, exactly one encrypted container, nothing
   after it**; no top-level SKESK/marker/compressed/literal/signature;
   no trailing bytes after the armor footer; **Padding tag 21 rejected**
   until a real client emits it.
2. **Accepted containers:** SEIPD v1 (MDC), RFC 9580 SEIP v2, **and**
   LibrePGP AED tag 20 — tag 20 special-cased by name with a hand-check
   of its fixed header (v1; AES-128/192/256; OCB or EAX; sane chunk-size
   octet). PKESK/SEIP pairing enforced: v3 PKESKs → SEIPD v1 or tag 20;
   v6 PKESKs → SEIPD v2 only; mixed sequences rejected.
3. **Size cap:** 64 KiB measures **submitted bytes** (armored or binary),
   enforced as a per-route body limit *before* multipart parsing or
   armor decoding (Q5). Attachments 10 MiB, same treatment.

Error taxonomy is ordered, first failure wins: `Empty`, `NotEncrypted`,
`Malformed`, `UnsupportedPacket`, `HiddenRecipient`,
`RecipientKeyRetired`, `WrongRecipient`, `ExtraRecipient`. No
registered-vs-unknown recipient distinction (membership oracle).
Rejected plaintext is never echoed into a form and never logged.
`ExtraRecipient` shows the offending key ID only, never an owner.

## Fixtures / locked tests owed before or with this stage

From `marketplace/docs/unverified.md` (items that close or land at Stage 5):

- **#6** — amended packet limits above vs the spike's simpler 32-packet
  cap: Stage 5 implements the amended rule; needs locked cases for
  9 PKESKs, a Padding tag 21, and trailing bytes after the armor footer.
- **#7 / Q16 leak fix** — `RecipientKeyRetired` is **conversation-scoped
  only**: return it only when the matched key was the recipient's current
  key at some point during THIS conversation; otherwise `WrongRecipient`.
  Locked probe test required: probe a buyer's retired key in a
  conversation that never exposed it → must get `WrongRecipient`.
- **#2a** — v6 hidden-recipient (zero-length fingerprint PKESK) derived
  fixture **still to build** (v3 wildcard path is already tested).
- **#3** — legacy SED tag-9 rejection: synthetic tag-9 fixture approved
  (Q7a), lands with the locked suite.

Plus the seed-suite checklist still open in
`marketplace/tests/security/README.md` insofar as it touches envelopes:
envelope fixtures fixed per Q7a (synthetic tag-9; `--compress-algo none`
oversize fixture) and envelope tests updated to the Q16 taxonomy
including the probe test above.

## Missing deliverable spotted

Spec §14 names `docs/encryption-guide.md` as the place that states what
validation **cannot** check (plaintext, inner signature, meaning).
Checked 2026-10-13: `marketplace/docs/` contains only `invariants.md`,
`threat-model.md`, `unverified.md` — **no encryption-guide.md exists
yet**. Stage 5's compose page links the guide's content (gpg command,
"encrypt to yourself as well" copy), so the guide should be written as
part of this stage, not left to Stage 10 docs.

## Suggested build order inside the stage

1. Locked envelope fixtures + Q16 taxonomy tests first (gate discipline:
   tests authored from spec + amendments, not from the implementation).
2. Validator implementing the amended packet rules + pairing + taxonomy.
3. Storage/retrieval + download headers + rotation banner.
4. Compose page + `docs/encryption-guide.md`.
5. Live smoke mirroring Stage 4's pattern: valid message accepted and
   downloadable byte-exact; each taxonomy error produced live at least
   once; probe test for the Q16 leak fix green.

## DECISION items for Cameron (none blocking the brief)

- None new. Q1/Q5/Q6/Q16 are already decided and logged; this brief only
  collects their consequences in one place. If the 1–8 PKESK range or
  the tag-21 rejection should change, that is a spec-amendment call
  before fixtures lock, not during implementation.
