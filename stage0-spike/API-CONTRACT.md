# Stage 0 Spike — Public API Contract (interface only, no implementation)

> **SUPERSEDED (2026-10-13)** as the contract for the production build.
> This document described the spike crate only. The canonical contract is
> now `marketplace/docs/api-contract.md` (code form: `crates/modules-api`
> plus the public modules of `crates/app` / `crates/domain`). Material
> differences: `DestinationInfo.kind: String` is deleted (Q17 — kind and
> network exist only inside rejection types, as closed enums), and the
> envelope reject set below (`UnknownRecipient`, …) is replaced by the
> Q16 taxonomy (`Empty`, `NotEncrypted`, `Malformed`, `UnsupportedPacket`,
> `HiddenRecipient`, `RecipientKeyRetired` — conversation-scoped,
> `WrongRecipient`, `ExtraRecipient`), which has no registered-vs-unknown
> recipient distinction. Kept unchanged below as the spike's record.

Crate name: `stage0_spike` (lib). Integration tests import `stage0_spike::...`.

## address module (`stage0_spike::address`)
```rust
pub enum Network { Mainnet, Stagenet, Testnet }   // derive Debug, Clone, Copy, PartialEq, Eq
pub struct DestinationInfo { pub network: Network, pub kind: String } // kind == "subaddress"
pub enum Reject { Parse, WrongNetwork, NotSubaddress } // derive Debug, PartialEq, Eq
pub fn validate_destination(address: &str, expected: Network) -> Result<DestinationInfo, Reject>
```
Rules (spec s3 #7, s9, s23): only a Monero *subaddress* on the expected network is accepted.
Primary/standard addresses => Err(NotSubaddress). Integrated addresses => Err(NotSubaddress).
Wrong network => Err(WrongNetwork). Unparseable/bad checksum => Err(Parse).

## statement module (`stage0_spike::statement`)
```rust
pub struct Invoice {
  pub marketplace_id: String, pub invoice_id: String, pub order_id: String,
  pub seller_fingerprint: String, pub network: String, // "monero-mainnet" | "monero-stagenet" | "monero-testnet"
  pub destination: String, pub amount_atomic: u64,
  pub expires_at: String, pub terms_sha256: String,
}
pub fn serialize_invoice(inv: &Invoice) -> Vec<u8>
pub fn parse_invoice(bytes: &[u8]) -> Result<Invoice, String>
```
Canonical rules (spec s10): printable ASCII 0x20-0x7E + LF only; no CR/tab; one `key: value` per line,
single space after colon; keys lowercase, fixed order as in the spec's invoice example, line 1 is
`statement-format: marketplace-invoice-v1`, line 2 `marketplace-id: ...`; no blank lines, no trailing
spaces, exactly one final LF. Fingerprints uppercase hex (40 or 64). Digests lowercase hex (64).
Timestamps RFC3339 UTC seconds with `Z`. parse_invoice MUST reject any input whose re-serialization
is not byte-identical to the input.

## envelope module (`stage0_spike::envelope`)
```rust
pub enum EnvelopeReject { TooLarge, NotArmoredOrBinary, Plaintext, SymmetricSessionKey,
  LegacyNoIntegrity, WildcardRecipient, WrongRecipient, UnknownRecipient, Malformed }
pub fn validate_envelope(msg: &[u8], recipient_cert_armored: &[u8], sender_cert_armored: &[u8])
  -> Result<(), EnvelopeReject>
```
Rules (spec s14): input is an OpenPGP message (armored or binary). Accept only: one or more PKESK
packets followed by exactly one integrity-protected data packet (SEIPD v1/MDC or v2 AEAD).
Every PKESK recipient must be an encryption subkey of the recipient cert or of the sender cert;
at least one must be the recipient's. Reject: SKESK anywhere, top-level literal/compressed data,
packets without integrity protection, wildcard (hidden) recipient key IDs, recipients belonging
to neither cert. Size cap checked before parsing: 64 KiB.

## txproof module (`stage0_spike::txproof`)
```rust
pub struct CheckTxProof { pub good: bool, pub received_atomic: u64, pub confirmations: u64, pub in_pool: bool }
pub fn check_tx_proof(endpoint: &str, txid_hex: &str, address: &str, message: &str, signature: &str)
  -> Result<CheckTxProof, String>
```
Calls monero-wallet-rpc JSON-RPC method `check_tx_proof` at `endpoint` (e.g. http://127.0.0.1:18088/json_rpc)
with params {txid, address, message, signature}; parses result {good, received, confirmations, in_pool}.
