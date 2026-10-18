# API Contract — Privacy-First Noncustodial Marketplace, Spec v2

**Status:** canonical, revised 2026-10-13 for the Stage 1–3 gate retrofit.
This document is the interface contract blind test authors work from,
together with the spec (`Privacy-First Noncustodial Marketplace — Spec v2`)
and `SPEC-V2-AMENDMENTS.md` (amendments win over spec text). It describes
public interfaces and their semantics — never implementation internals.

It supersedes `stage0-spike/API-CONTRACT.md`, which described the spike
crate only. Differences that matter (decision log Q16/Q17): the spike
contract's `DestinationInfo { kind: String }` is deleted, and its envelope
reject set (`UnknownRecipient`, …) is replaced by the Q16 taxonomy in §5
below. The code form of this contract lives in `crates/modules-api` (types
and traits) and the public modules of `crates/app` and `crates/domain`;
where code and this document disagree, that is a defect to report, not a
choice to resolve silently.

Conventions: `Result<T, E>` errors are exhaustive enums. Unless stated,
string inputs are used exactly as given — no layer below §3 trims,
case-folds, or otherwise normalizes its input.

## 1. Networks, address kinds, destinations (§3.7; Q2, Q14, Q17)

```rust
pub enum Network { Mainnet, Stagenet, Testnet }        // closed, Copy
pub enum AddressKind { Standard, Integrated, Subaddress } // closed, Copy
pub enum DestinationError {
    Parse,                              // undecodable, bad checksum, non-canonical key encoding
    WrongNetwork,                       // valid address, wrong network
    WrongKind { found: AddressKind },   // right network, not a subaddress
    SmallOrderKey,                      // a public key is identity / not torsion-free
}
pub struct Subaddress { /* opaque */ }
impl Subaddress {
    pub fn validate(input: &str, expected: Network) -> Result<Subaddress, DestinationError>;
    pub fn network(&self) -> Network;
    pub fn as_str(&self) -> String;    // canonical re-encoding of the validated address
}
```

Validation order is pinned (Q2): **decode/checksum → network → kind →
key sanity**. A `Subaddress` value is proof of validation: it is always a
subaddress, on the network it reports, with both embedded public keys
torsion-free and not the identity (Q14). There is no `kind` field on the
success type (Q17). `validate` never trims its input: a valid address
wrapped in whitespace fails (which check fires is unspecified beyond
rejection; tests assert rejection, not a specific variant, for wrapped
input).

## 2. Public IDs and canonical integers (Q3, Q15)

```rust
pub fn validate_public_id(s: &str, prefix: &str) -> bool;
pub fn parse_canonical_u64(s: &str) -> Option<u64>;
```

Public IDs are `<prefix>_` + exactly 32 lowercase hex characters
(prefixes: `mkt_`, `inv_`, `ord_`, `pool_`, `acct_`). Canonical integers:
ASCII digits only, no sign, no whitespace, no leading zeros (`"0"` itself
is allowed), must fit in u64. Field-level range rules (amount > 0,
address-count 1–200, quantity ≥ 1) are enforced by each field's own
validation, not by `parse_canonical_u64`.

## 3. Form-layer input normalization (Q13)

```rust
pub enum FormInputError { InvisibleCharacters }
pub fn normalize_form_lines(input: &str) -> Result<Vec<String>, FormInputError>;
```

The ONLY normalization in the system. Splits pasted multi-line input into
lines, strips ASCII whitespace (space, tab, CR, LF) from line ends, drops
empty lines. Any non-ASCII whitespace or invisible/format character
(NBSP, zero-width space, BOM, …) anywhere in the input ⇒
`InvisibleCharacters`; such characters are never silently stripped.

## 4. Canonical statements (§10; Q3, Q4, Q15)

Every statement: printable ASCII (0x20–0x7E) + LF only; one `key: value`
per line, single space after the colon; keys lowercase, fixed order; no
blank lines or trailing spaces; exactly one final LF; line 1 is
`statement-format: …`, line 2 `marketplace-id: …`. A parser must reject
any input whose re-serialization is not byte-identical to the input.
Timestamps are RFC 3339 UTC seconds with `Z`, parsed semantically
(month/day valid, leap seconds rejected) and re-formatted canonically.
Fingerprints are uppercase hex (40 or 64). Digests are lowercase hex (64).
`network:` takes exactly three values (`monero-mainnet`,
`monero-stagenet`, `monero-testnet`); statement destinations are
validated through §1 and must match the statement's own network line.

```rust
// domain crate
pub fn validate_canonical_timestamp(s: &str) -> bool;
pub fn statement_network_matches(statement_network: &str, instance: Network) -> bool;
```

## 5. Envelope validation (§14; Q1, Q5, Q6, Q16)

```rust
pub enum EnvelopeError {
    Empty,              // empty submission (form layer)
    NotEncrypted,       // not an encrypted OpenPGP message at all
    Malformed,          // OpenPGP, but structurally invalid
    UnsupportedPacket,  // SKESK, literal data, legacy SED, unknown packet tag
    HiddenRecipient,    // wildcard (hidden) recipient key ID present
    RecipientKeyRetired,// a PKESK matches a recipient key the sender was
                        // already shown in THIS conversation, since retired
    WrongRecipient,     // no PKESK matches the recipient's current key
    ExtraRecipient,     // recipient matched, plus a PKESK belonging to neither party
}
```

Evaluation order is the enum order above; first failure wins. There is
deliberately **no** registered-vs-unknown recipient distinction: the
result must never reveal whether an unrecognized key belongs to some
other account (membership oracle). `RecipientKeyRetired` is
conversation-scoped (Q16 leak fix): it is returned only when the matched
key was shown to this sender in this conversation (a recorded key
sighting, or the key's validity interval overlapping this conversation —
see §8); in every other case a non-current recipient key yields
`WrongRecipient`. Rejected plaintext is never echoed into a form and
never logged. `ExtraRecipient` reporting shows the offending key ID only,
never an owner.

Accepted structure (visible top level; the validator never descends into
the encrypted container): 1–8 PKESK packets, then exactly one
integrity-protected container — SEIPD v1 (MDC), RFC 9580 SEIP v2, or
LibrePGP AED (tag 20, special-cased by name with its fixed header
checked: version 1, cipher AES-128/192/256, AEAD mode OCB or EAX) — and
nothing after it. PKESK/SEIP version pairing is enforced (v3 PKESKs →
SEIPD v1 or tag 20; v6 PKESKs → SEIPD v2 only). No top-level SKESK,
marker, compressed, literal, or signature packets; no trailing bytes
after the armor footer; Padding (tag 21) is rejected. The 64 KiB cap
measures submitted bytes (armored or binary) and is enforced before any
decoding.

(The validator itself is Stage 5 work; this section is the contract the
Stage 3 key storage in §8 exists to serve, and the taxonomy types are
already part of the API.)

## 6. Module traits (§4)

Modules propose; the core verifies, records, renders. Modules receive
only the data their interface defines — never spending keys, message
payloads, session tokens, or raw request bodies (invariant 17).

```rust
pub trait Module { fn id(&self) -> ModuleId; fn version(&self) -> semver::Version;
                   fn capabilities(&self) -> &[Capability]; }
pub trait DestinationProvider: Module {
    fn allocate(&self, cx: &AllocateCx) -> Result<DestinationProposal, ModuleError>; }
pub trait PaymentEvidenceProvider: Module {
    fn claim(&self, cx: &EvidenceCx, input: &FormInput) -> Result<EvidenceClaim, ModuleError>; }
pub trait ReputationModel: Module {
    fn summarize(&self, facts: &[ReputationFact]) -> ReputationSummary; }
pub trait PricingSource: Module {
    fn quote(&self, cx: &QuoteCx) -> Result<u64, ModuleError>; }
pub trait AdmissionPolicy: Module {
    fn admit(&self, cx: &AdmissionCx, input: &FormInput) -> Result<Admission, ModuleError>; }
pub trait NotificationChannel: Module {
    fn deliver(&self, cx: &NotifyCx, n: &Notification) -> Result<(), ModuleError>; }
pub enum Admission { Admitted, PendingApproval, Rejected }
```

Payment evidence claims are the closed enum `EvidenceClaim`
(`BuyerReport`, `SellerAttestation`, `TxProof`, `WalletObservation`).
Destination evidence is the closed enum `DestinationEvidence`
(`SignedInvoice`, `SignedPoolEntry`). A buyer's report alone can never
move an order to Paid (invariant 11).

## 7. Stage 1 surface — accounts, sessions, authorization (§7, §17)

```rust
// usernames
pub fn fold_username(input: &str) -> String;          // Unicode case-fold + trim for identity comparison
pub fn validate_username(folded: &str) -> bool;       // 3–24 chars, [a-z0-9_-] after folding
// passwords
pub struct HashGuard { /* global Argon2id semaphore */ }
pub enum HashError { Busy, Invalid }
impl HashGuard {
    pub fn new(permits: usize) -> Self;
    pub async fn hash(&self, password: &str) -> Result<String, HashError>;   // Busy on saturation — never queues unboundedly
    pub async fn verify(&self, password: &str, stored: &str) -> Result<bool, HashError>;
}
pub fn is_common_password(pw: &str) -> bool;
// sessions
pub const IDLE_TIMEOUT: Duration = Duration::hours(12);
pub const ABSOLUTE_TIMEOUT: Duration = Duration::days(7);
pub fn new_token() -> String;                          // 256 random bits, hex
pub fn hash_token(token: &str) -> [u8; 32];            // only this hash is ever stored
pub struct Session { pub account_id: i64, pub created_at, pub last_seen_at, pub revoked: bool }
impl Session { pub fn fresh(account_id: i64, now) -> Session; pub fn is_valid(&self, now) -> bool; pub fn touch(&mut self, now); }
pub fn csrf_matches(stored_secret: &str, presented: &str) -> bool;  // constant-time
// recovery
pub fn new_recovery_code() -> String;                  // ≥100 bits, unambiguous alphabet
pub fn hash_code(code: &str) -> [u8; 32];
// throttles
pub struct TokenBucket { pub fn new(capacity: f64, refill_per_min: f64, now) -> Self; pub fn allow(&mut self, now) -> bool }
pub struct Throttles { pub fn allow_request(&self, account_id: i64, now) -> bool;
                       pub fn record_login_failure(&self, username_folded: &str) -> Duration;  // grows exponentially, capped; keyed by submitted name, account or not
                       pub fn clear_login_failures(&self, username_folded: &str); }
// authorization
pub enum Role { Buyer, Seller, Moderator, Admin }
pub enum Decision { Allow, Deny, LoginRequired }
pub fn authorize(method: &str, path: &str, role: Option<Role>) -> Decision;
pub fn route_requires_csrf(method: &str, path: &str) -> bool;
```

Authorization semantics (§17, the contract the route-by-role matrix is
derived from):

- One route table declares every route's roles; `authorize` is the only
  enforcement entry point; anything undeclared is denied — including for
  Admin, and including unknown methods on known paths.
- Public routes (spec §17's unauthenticated set: catalogue, seller
  profiles and `key.asc`, register/login pages and their POSTs, account
  recovery POST, the static information pages) allow every actor,
  including anonymous.
- Authenticated routes with no role restriction allow any signed-in
  account and return `LoginRequired` (not `Deny`) for anonymous actors —
  the two results are distinguishable by design at this layer; object
  endpoints must additionally make "exists but not yours"
  indistinguishable from "does not exist" (§9 below).
- A role not listed for a route is `Deny`, for every method.
- Every state-changing route (all POSTs) requires CSRF; no GET route
  requires CSRF, and GET never changes state.
- Seller-only surfaces: the seller dashboard and listing creation.
  Moderation surfaces: Moderator or Admin. `/admin`: Admin only.
  Account, security/keys, orders, and inbox surfaces: any authenticated
  account (object-level rules then apply per §9).
- Admission: buyer registration runs the admission trait (§6) — the
  default open policy admits under a feature flag and a global account
  cap (`!registrations_open` or count ≥ cap ⇒ not `Admitted`); seller
  admission's default is `admin-approval` (§7 table, Stage 2 surface §8).

Storage semantics (PostgreSQL, §16): only token *hashes* are stored for
sessions and recovery codes; consuming a recovery code succeeds exactly
once, revokes **all** of the account's sessions, and marks the profile
recovered — in one transaction; an unknown username and a wrong code
produce the same outcome (no account oracle). Passwords are stored only
as Argon2id hashes (≥ OWASP parameters).

## 8. Stage 2 surface — listings, markup, media (§9, §15, §18)

```rust
// domain
pub struct Atomic(pub u64);
impl Atomic { pub fn parse_decimal(s: &str) -> Option<Atomic>;  // exact decimal XMR → atomic units
              pub fn format_decimal(&self) -> String; }          // canonical round-trip
pub fn render_listing_markup(input: &str) -> String;             // domain::markup
// app::listings
pub const CATEGORIES: &[&str];                                    // fixed operator set
pub const DESTINATION_MODULES: &[&str] = &["signed-address-pool", "signed-invoice"];
pub enum ListingError { Title, Description, Price, Category, DestinationModule, AutoInvoiceNeedsPool, /* … */ }
pub fn validate_listing(title, description, price_atomic: u64, category, destination_module, auto_invoice) -> Result<(), ListingError>;
// app::media — the app-side door to the media worker
pub enum MediaError { /* Unsupported, TooLarge, Worker, … */ }
pub struct MediaPipeline { pub async fn sanitize(&self, bytes: &[u8]) -> Result<(String, i32, i32), MediaError>; }
```

Markup contract: the renderer escapes **all** input first; the only
markup is paragraphs, `- ` bullet lists, and `**bold**`. No input can
produce a tag, attribute, link, or image the renderer did not generate;
URLs remain plain text; unmatched `**` stays literal text.

Listing validation: title non-empty without angle brackets; description
within the size bound; price an exact decimal amount, > 0 atomic units;
category in the fixed set; destination module one of the two declared;
**auto-invoice requires the `signed-address-pool` module**. Unpublished
or removed listings are visible only to their seller — to everyone else
they are indistinguishable from nonexistent (404, invariant: no oracle).

Media contract: the worker accepts bytes and returns a stored reference
plus dimensions, or an error. Only JPEG/PNG **by content sniffing** are
accepted; inputs > 5 MiB, any side > 4096 px, or > 24 megapixels are
rejected (dimension limits enforced from the header, before full
decode). Output is re-encoded from decoded pixels, so all metadata
(EXIF, text chunks) is stripped; the original upload is never stored or
served, and no failure mode serves the original bytes. The worker is a
separate process invoked with a cleared environment and a timeout; it
takes no caller-chosen paths.

Seller admission flow: `apply_for_seller` records a pending application
(re-applying while pending is idempotent); `decide_seller_application`
by a moderator/admin flips the account role to Seller in the same
transaction as the decision record — no partial grants (invariant:
admission decisions are atomic). A non-privileged actor cannot decide
any application, including their own.

## 9. Stage 3 surface — identity keys (§8, §10, §16; Q16 storage)

```rust
pub enum KeyError { Malformed, PolicyInvalid, NoEncryptionSubkey, NoSigningKey }
pub struct CertInfo { pub fingerprint: String, pub user_ids: Vec<String>, pub warnings: Vec<String> }
pub fn validate_cert(bytes: &[u8]) -> Result<CertInfo, KeyError>;      // app::keys
pub fn verify_detached(cert_bytes: &[u8], message: &[u8], sig_armored: &[u8]) -> bool;
pub struct RotationStatement { pub account_id: String, pub old_fingerprint: String,
                               pub new_fingerprint: String, pub rotated_at: String }
pub fn parse_rotation_statement(text: &str, marketplace_id: &str) -> Option<RotationStatement>;
```

Certificate rules (§8): the cert must parse and be valid under Sequoia's
standard policy (not expired, not revoked), with an encryption-capable
subkey and a signing-capable key. `fingerprint` is the primary key's,
uppercase hex. Every user ID is surfaced in `user_ids`; a user ID that
looks like an email address or a real name produces a warning (the ID
will be public). Validation runs on the Nettle backend (Q8) — the same
backend in dev, CI, and production.

Rotation statement rules: the §4 canonical rules, with the fixed field
order `statement-format, marketplace-id, account-id, old-fingerprint,
new-fingerprint, rotated-at`; `marketplace-id` must equal this instance's
ID; `account-id` must match the §2 ID pattern; fingerprints uppercase
hex (40 or 64); `rotated-at` a canonical timestamp. Certified rotation
additionally requires `verify_detached` to succeed for **both** the old
and the new cert over the exact statement bytes, and the statement to
name the account, its current fingerprint, and the new cert's
fingerprint. An uncertified (lost-key) rotation is a distinct recorded
state and must never be presentable as certified.

Key storage contract (§16, Q16): installing a key retires the previous
current key in the same transaction — the old row's `retired_at` is set,
the rotation is recorded in `key_rotations` (with `certified` true only
for the dual-signed path), and the new key becomes the single `current`
row with the next version number. At most one key per account is
`current` at any time. Key history (every version, status, and its
validity interval) remains queryable afterwards — Stage 5's
`RecipientKeyRetired` decision depends on these intervals.

Conversation key sightings (Q16 storage, added 2026-10-13):

```rust
pub async fn record_key_sighting(pool, conversation_id: i64, account_id: i64,
                                 fingerprint: &str, key_id: &str, shown_to: i64) -> Result<(), sqlx::Error>;
pub async fn key_shown_in_conversation(pool, conversation_id: i64, account_id: i64,
                                       fingerprint: &str) -> Result<bool, sqlx::Error>;
```

Whenever the server presents a participant's key inside a conversation
(compose page, key download in conversation context), a sighting is
recorded. `key_shown_in_conversation` answers the Q16 question — "was
this key already shown to the other party in THIS conversation?" — from
sightings, or from the key's validity interval overlapping the
conversation's lifetime. It must never answer from key history on other
conversations, and never reveal anything about keys belonging to
non-participants.

## 10. Order and invoice state machines (§9) — for reference

Stages 1–3 do not build orders, but the domain tables are Stage 0/2
contract surface and later stages build on them:

```rust
pub enum OrderState { /* §9 table */ }
pub enum Actor { Buyer, Seller, Core, Moderator }
pub enum EvidenceLevel { None, BuyerReported, SellerAttested, ProofVerified, WalletObserved }
pub fn order_can_transition(from: OrderState, to: OrderState, actor: Actor, evidence: EvidenceLevel) -> bool;
pub fn invoice_can_transition(from: InvoiceState, to: InvoiceState) -> bool;
```

No transition lets a buyer's report (or any non-core actor) move an
order to Paid; `settlement` is `direct` throughout v2 (Q9).

## 11. Stage 4 surface — orders, terms files, inbox (§9, §10, §15, §17)

```rust
// orders (crates/app, orders module). orders.state is written ONLY here,
// and only through the domain transition table (§10 of this contract).
pub struct Order {
    pub id: i64, pub public_id: String,           // ord_ + 32 hex (Q15)
    pub buyer_id: i64, pub seller_id: i64, pub listing_id: i64,
    pub listing_title: String,
    pub state: String,                            // OrderState name
    pub settlement: String,                       // "direct" throughout v2 (Q9)
    pub seller_fpr_pinned: String,                // seller's key fingerprint at creation
    pub terms_sha256: String,                     // digest of the stored terms bytes
    pub total_atomic: i64,
    pub evidence_level: String,                   // EvidenceLevel name
    pub created_at: String,                       // canonical timestamp
}
pub enum OrderError {
    ListingNotAvailable,   // unknown or not-published listing
    OwnListing,            // buyer == seller
    NoSellerKey,           // seller has no current identity key to pin
    BadQuantity,           // quantity 0 or above the bound
    NewAccountLimit,       // §7: accounts < 24 h old hold at most 3 orders
    NotFound,
    TransitionDenied,      // state machine or actor check failed
    InvoiceRequired,       // accept before an invoice has been issued (§9)
}
pub async fn create_order(pool, marketplace_id: &str, buyer_id: i64,
    listing_public_id: &str, quantity: u32, idempotency_key: &str)
    -> Result<(Order, bool), OrderError>;   // bool = newly created
pub async fn order_by_public_id(pool, public_id: &str) -> Option<Order>;
pub async fn orders_for(pool, account_id: i64) -> Vec<Order>;  // buyer or seller only
pub async fn terms_bytes(pool, order_id: i64) -> Option<Vec<u8>>;
pub async fn apply_action(pool, order: &Order, action: &str, actor_id: i64)
    -> Result<OrderState, OrderError>;
// terms builder (pure): the exact bytes stored at creation
pub fn build_terms(marketplace_id, order_id, listing_id, buyer_account,
    seller_account, seller_key_fingerprint, quantity, total_atomic,
    pricing_module, created_at, title, description, delivery_terms,
    refund_terms) -> Vec<u8>;
// inbox (§15)
pub async fn notify(pool, account_id: i64, event_type: &str, object_ref: &str);
pub async fn inbox(pool, account_id: i64)
    -> Vec<(i64, String, String, String, bool)>;  // (id, event, ref, time, read), newest first
pub async fn unread_count(pool, account_id: i64) -> i64;
pub async fn mark_all_read(pool, account_id: i64);
```

Order semantics (§9):

- Creation requires a **published** listing, buyer ≠ seller, quantity
  ≥ 1 (implementation bound 10,000), and total = unit price × quantity
  in checked u64 arithmetic — overflow is an error, never a wrap.
  The seller's **current** key fingerprint is pinned into the order at
  creation; a seller with no current key cannot be ordered from.
- **Idempotency (§9):** a repeated submission with the same
  (buyer, idempotency key) returns the original order with
  `created = false` and creates nothing — no second order, invoice, or
  evidence record. A different key is a new order.
- **Terms (§10):** at creation the core builds the terms file once —
  `marketplace-terms-v1` header (marketplace-id, order-id, listing-id,
  buyer-account, seller-account, seller-key-fingerprint, quantity,
  total-atomic, pricing-module, created-at), one blank line, then
  Title / Description / Delivery terms / Refund terms sections — UTF-8
  NFC, LF endings. The exact bytes and their SHA-256 are stored and
  **never regenerated**; editing the listing afterwards never touches
  an existing order's terms. Buyers verify by hashing the download.
- **Transitions:** the action strings are `accept`, `decline`,
  `cancel`, `fulfil`, `complete`, `dispute`. The actor is derived from
  the caller's relation to the order (buyer / seller); anyone else is
  `TransitionDenied`, as is any (state, action) pair the domain table
  (§10) refuses for that actor. Two guards sit above the pure table:
  `accept` additionally requires an issued invoice (`InvoiceRequired`
  — until the payment stages, accept is always refused with that
  reason), and `dispute` from AwaitingPayment enforces §9's 72-hour
  buyer-report guard. A buyer's report alone never moves an order to
  Paid (invariant: only the core raises evidence, and the Paid
  transition is Core-only per §10).
- **Routes (§17, as amended 2026-10-14):** `POST /orders`,
  `GET /orders`, `GET /orders/{id}`, `GET /orders/{id}/terms.txt`,
  and the six action POSTs are any-authenticated routes: anonymous
  actors get `LoginRequired`; every signed-in role passes the route
  layer and object-level rules then apply — a non-participant's view
  of an order (or its terms) is indistinguishable from nonexistent.
  `GET /orders` lists only the caller's own orders (buyer or seller).
  (`POST /orders/{id}/invoice` is the Stage 6 signed-invoice surface.)

Inbox semantics (§15): a notification is stored per order event for
the counterparty (order requested → seller; declined / cancelled /
fulfilled / completed / dispute opened → the other party), carrying
only the event type, the object reference, and the time. The inbox
lists newest first with read markers; `unread_count` backs the §15
header counts; notifications are deleted 30 days after being read
(retention mechanics land with Stage 10; the stored fields are fixed
now).

## 12. Stage 6 core surface — statement library, payment URI/QR, xmr-only pricing (§10, §11, §24 stage 6)

Added 2026-10-14 for the Stage 6 core build. This section is the library
only: it parses and serializes the §10 seller-signed statement types, and
derives the payment URI / QR from an already-validated invoice statement.
It does no I/O and verifies no signatures (detached-signature verification
is §9's `verify_detached`; statement upload flows, the invoice page, and
order wiring are separate surface, built later). The terms-file builder
stays where §11 put it (Stage 4, `app::orders`).

```rust
// domain crate, `statements` module
pub struct InvoiceStatement {
    pub marketplace_id: String,          // mkt_ + 32 hex (Q15)
    pub invoice_id: String,              // inv_ + 32 hex
    pub order_id: String,                // ord_ + 32 hex
    pub seller_key_fingerprint: String,  // uppercase hex, 40 or 64 chars
    pub network: Network,                // closed enum (Q17) — never a string
    pub destination: Subaddress,         // validated newtype (§1)
    pub amount_atomic: u64,
    pub expires_at: String,              // canonical RFC 3339 (§4)
    pub terms_sha256: String,            // exactly 64 lowercase hex chars
}
pub struct PoolStatement {
    pub marketplace_id: String,          // mkt_ + 32 hex
    pub pool_id: String,                 // pool_ + 32 hex
    pub seller_key_fingerprint: String,  // uppercase hex, 40 or 64 chars
    pub network: Network,                // closed enum (Q17)
    pub created_at: String,              // canonical RFC 3339 (§4)
    pub addresses: Vec<Subaddress>,      // 1..=200 entries
}
impl InvoiceStatement { pub fn to_bytes(&self) -> Vec<u8>; }
impl PoolStatement { pub fn to_bytes(&self) -> Vec<u8>; }
pub fn parse_invoice_statement(text: &str, marketplace_id: &str,
    instance_network: Network, max_amount_atomic: u64) -> Option<InvoiceStatement>;
pub fn parse_pool_statement(text: &str, marketplace_id: &str,
    instance_network: Network) -> Option<PoolStatement>;
pub fn payment_uri(invoice: &InvoiceStatement) -> String;
pub fn payment_qr_png(invoice: &InvoiceStatement) -> Vec<u8>;
// domain crate root, next to Atomic (§8): the sole pricing mode until Stage 11
pub const PRICING_MODULE_XMR_ONLY: &str = "xmr-only";
pub fn xmr_only_total(unit_price_atomic: u64, quantity: u64) -> Option<u64>;
```

Statement rules (a parser returns `None` on ANY violation; §10 as amended):

- The §4 canonical byte rules, enforced by re-serialization: parse the
  fields, re-serialize, reject unless byte-identical to the input. Field
  order is the §10 layout order — invoice: `statement-format`,
  `marketplace-id`, `invoice-id`, `order-id`, `seller-key-fingerprint`,
  `network`, `destination`, `amount-atomic`, `expires-at`,
  `terms-sha256`; pool: `statement-format`, `marketplace-id`, `pool-id`,
  `seller-key-fingerprint`, `network`, `created-at`, `address-count`,
  then the `address` lines last.
- `statement-format` is exactly `marketplace-invoice-v1` /
  `marketplace-address-pool-v1`. `marketplace-id` must equal the
  instance's ID passed in and match the `mkt_` pattern (§2).
- IDs match their field's §2 pattern with the matching prefix.
  Fingerprints are uppercase hex (40 or 64). `terms-sha256` is exactly
  64 lowercase hex characters.
- `network:` is the closed three-value set and must equal
  `instance_network` (the amendment's core rule). The destination (and
  every pool address) is validated through §1 against the statement's
  own network line — a destination on any other network, or of any
  other kind, rejects the whole statement.
- Integers are canonical (Q3, §2). `amount-atomic` must additionally be
  > 0 and ≤ `max_amount_atomic`. `address-count` must be 1–200 and
  exactly the number of `address` lines. Duplicate address lines within
  one pool statement are rejected (an entry index must identify one
  address, §11).
- Timestamps pass §4 canonical validation (semantic RFC 3339, leap
  seconds rejected, byte-identical re-format).
- Nothing in this library trims or normalizes (Q13): stray whitespace,
  CRs, or case drift fail byte-identity. `normalize_form_lines` (§3)
  remains the only normalization in the system, upstream of this library.

`payment_uri`: `monero:` + the destination's canonical string (§1
`as_str`) + `?tx_amount=` + the amount rendered by `Atomic::format_decimal`
(§8) — no other parameters, no label or description (§11). Same
statement ⇒ same string, always.

`payment_qr_png`: the QR encoding of the `payment_uri` bytes, rendered
black modules on white with a 4-module quiet zone at 8 px per module,
PNG-encoded. Same statement ⇒ identical PNG bytes.

`xmr_only_total`: unit price × quantity in checked u64 arithmetic;
`None` on overflow. It is the only total computation in v2 —
`seller-quoted-rate` and every other pricing mode do not exist until
Stage 11 (§24). (Quantity ≥ 1 is the order layer's rule, §11; this
helper is the pure arithmetic.)

Regenerated §10 examples (Q15 — every §10 example at the pinned 32-hex
ID length; address / fingerprint / digest remain placeholders as in the
spec, real fixtures are generated per Q7b):

```
statement-format: marketplace-invoice-v1
marketplace-id: mkt_4f9c2a7e1b3d5f60718293a4b5c6d7e8
invoice-id: inv_8d1e5b0c3a7f2b4d6f8091a3b5c7d9e0
order-id: ord_2b6a9e4d1c083f5a7c9e1b2d4f607182
seller-key-fingerprint: <40 or 64 hex>
network: monero-mainnet
destination: <subaddress>
amount-atomic: 1250000000000
expires-at: 2026-10-16T17:00:00Z
terms-sha256: <64 hex>
```

```
statement-format: marketplace-address-pool-v1
marketplace-id: mkt_4f9c2a7e1b3d5f60718293a4b5c6d7e8
pool-id: pool_6c0e3f9a5b7d9f1a2c4e6a8b0d2f4a6b
seller-key-fingerprint: <40 or 64 hex>
network: monero-mainnet
created-at: 2026-10-13T16:00:00Z
address-count: 100
address: <subaddress>
```
