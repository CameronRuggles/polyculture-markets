//! Monero transaction proofs (§5/§7/§14).
//!
//! Two separate things live here:
//!
//! 1. **Form checks.** The helper has no node (§14), so for proofs a
//!    user hands it, it checks FORM only: the `OutProofV2` prefix,
//!    the exact message naming this trade, the txid shape. Form is
//!    not truth — a form-valid proof can still be worthless, and
//!    every surface that shows one says so.
//!
//! 2. **Construction from the transaction key** — the H1 spike's
//!    subject. `build_out_proof_v2` builds an OutProofV2 from
//!    (txid, transaction key(s), address, message) alone, with no
//!    wallet file and no node, following the reference wallet's
//!    construction exactly (Monero `wallet2::get_tx_proof` +
//!    `crypto::generate_tx_proof`, v2): the proof is one
//!    *(shared secret, signature)* pair per transaction key, where
//!    the shared secret is `key · view-pub`, and the signature is
//!    the Schnorr proof of knowledge of the key against
//!    `R = key · G` (standard address) or `R = key · spend-pub`
//!    (subaddress). Whether this construction is accepted by a real
//!    `check_tx_proof` is the spike's verdict, recorded in the H1
//!    report; this code is the thing the spike tests.
//!
//!    The construction is behind the non-default cargo feature
//!    `proof-construction` (HT H1 audit fix, task 9): the spike's
//!    checker port and its two stagenet transaction vectors were
//!    rig-side scratch and are not recoverable from the repository,
//!    and binary acceptance on a real stagenet node is still an
//!    open owner item — so the construction does not compile into
//!    default builds and no command can reach it.

#[cfg(feature = "proof-construction")]
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "proof-construction")]
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
#[cfg(feature = "proof-construction")]
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use sha3::Digest as _;
#[cfg(feature = "proof-construction")]
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Keccak-256 (Monero's cn_fast_hash) and hash-to-scalar.

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = sha3::Keccak256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(feature = "proof-construction")]
fn hash_to_scalar(data: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order(keccak256(data))
}

#[cfg(feature = "proof-construction")]
fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ---------------------------------------------------------------------------
// Monero base58 (block form: 8-byte blocks → 11 chars, tail per the
// size table). The same encoding the reference wallet uses for
// addresses and proof strings.
//
// This module originally carried a hand-rolled codec that read
// each block as a LITTLE-endian u64. Monero's encoding is
// BIG-endian per block, so the old codec byte-swapped every block:
// `build_out_proof_v2` emitted proof strings no real node would
// accept, and `parse_out_proof_v2` mis-decoded genuine ones —
// while round-tripping happily against itself and against the
// spike's equally hand-rolled checker port, which is very likely
// why binary acceptance on a real stagenet node was never obtained
// in the H1 spike (Code Audit 2, M3/R1). The codec is now the
// `base58-monero` crate — the same implementation the `monero`
// crate uses — cross-checked in the tests below against a real
// stagenet subaddress and the `monero` crate's own address parse.

pub fn base58_encode(data: &[u8]) -> String {
    // base58-monero's encode is total over byte strings: every
    // length decomposes into 8-byte blocks plus a tabled tail.
    base58_monero::encode(data).expect("base58-monero encodes any byte string")
}

pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    base58_monero::decode(s).ok()
}

// ---------------------------------------------------------------------------
// Proof form (§14): prefix, segment count, decodability, txid and
// message binding. A proof string is `OutProofV2` followed by one
// (32-byte shared secret, 64-byte signature) base58 pair per
// transaction key in the transaction.

pub const OUT_PROOF_V2_PREFIX: &str = "OutProofV2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSegment {
    pub shared_secret: [u8; 32],
    pub signature: [u8; 64],
}

/// Parse a proof string's form. `None` = not a well-formed
/// OutProofV2 string at all.
pub fn parse_out_proof_v2(proof: &str) -> Option<Vec<ProofSegment>> {
    let body = proof.strip_prefix(OUT_PROOF_V2_PREFIX)?;
    // 32 bytes encode to 44 chars; 64 bytes to 88 chars.
    if body.is_empty() || body.len() % 132 != 0 {
        return None;
    }
    let mut segments = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let pk = base58_decode(&body[offset..offset + 44])?;
        let sig = base58_decode(&body[offset + 44..offset + 132])?;
        if pk.len() != 32 || sig.len() != 64 {
            return None;
        }
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&pk);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig);
        segments.push(ProofSegment {
            shared_secret,
            signature,
        });
        offset += 132;
    }
    Some(segments)
}

pub fn proof_form_ok(proof: &str) -> bool {
    parse_out_proof_v2(proof).is_some()
}

// ---------------------------------------------------------------------------
// Construction (the spike's subject) — feature-gated, see the
// module docs. Nothing below this line compiles into a default
// build.

#[cfg(feature = "proof-construction")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    BadTxid,
    BadTxKey,
    BadAddress,
    BadPoint,
}

#[cfg(feature = "proof-construction")]
fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(feature = "proof-construction")]
fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*bytes).decompress()
}

/// The v2 signature (`crypto::generate_tx_proof`): prove knowledge
/// of `secret` such that `R = secret·G` (or `secret·B` when a spend
/// key `b` is given) and `d = secret·A`, committing to
/// `prefix_hash`. Returns (c, r) as 64 signature bytes.
#[cfg(feature = "proof-construction")]
fn generate_tx_proof(
    prefix_hash: &[u8; 32],
    r_point: &EdwardsPoint,
    a_view: &EdwardsPoint,
    b_spend: Option<&EdwardsPoint>,
    d_shared: &EdwardsPoint,
    secret: &Scalar,
) -> [u8; 64] {
    let k = random_scalar();
    let x = match b_spend {
        Some(b) => k * b,
        None => k * ED25519_BASEPOINT_POINT,
    };
    let y = k * a_view;
    let sep = keccak256(b"TXPROOF_V2");
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(prefix_hash);
    buf.extend_from_slice(d_shared.compress().as_bytes());
    buf.extend_from_slice(x.compress().as_bytes());
    buf.extend_from_slice(y.compress().as_bytes());
    buf.extend_from_slice(&sep);
    buf.extend_from_slice(r_point.compress().as_bytes());
    buf.extend_from_slice(a_view.compress().as_bytes());
    match b_spend {
        Some(b) => buf.extend_from_slice(b.compress().as_bytes()),
        None => buf.extend_from_slice(&[0u8; 32]),
    }
    let c = hash_to_scalar(&buf);
    let r = k - c * secret;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(c.as_bytes());
    sig[32..].copy_from_slice(r.as_bytes());
    sig
}

/// Build an OutProofV2 for a payment, from the transaction key(s)
/// alone — no wallet, no node, no transaction body. `tx_keys_hex`
/// is the main transaction key first, then any additional
/// transaction keys in order; a plain single-recipient payment has
/// exactly one. The message is the exact proof message (§5:
/// `marketplace-pay-v1|<trade-id>`).
///
/// SPIKE STATUS (H1, spec §16.1): the construction follows Monero
/// 0.18.3.4's `generate_tx_proof` exactly and verifies against a
/// faithful port of the reference `check_tx_proof` + wallet2 output
/// scan (see HT-H1-REPORT-2026-10-20.md). Acceptance by the
/// reference wallet BINARY could not be obtained in the build
/// sandbox (its daemon/wallet pair fails its own proof path on
/// every transaction). Per the gate, no H1 command exposes this
/// path; it must not be wired into a user command until binary
/// acceptance is recorded on a real stagenet node. It compiles
/// only under the non-default `proof-construction` feature.
#[cfg(feature = "proof-construction")]
pub fn build_out_proof_v2(
    txid_hex: &str,
    tx_keys_hex: &[&str],
    address: &str,
    message: &str,
) -> Result<String, ProofError> {
    if tx_keys_hex.is_empty() {
        return Err(ProofError::BadTxKey);
    }
    let txid = hex32(txid_hex).ok_or(ProofError::BadTxid)?;
    let parsed = monero::Address::from_str(address).map_err(|_| ProofError::BadAddress)?;
    let is_subaddress = parsed.addr_type == monero::AddressType::SubAddress;
    let mut spend_bytes = [0u8; 32];
    spend_bytes.copy_from_slice(parsed.public_spend.as_bytes());
    let mut view_bytes = [0u8; 32];
    view_bytes.copy_from_slice(parsed.public_view.as_bytes());
    let spend = decompress(&spend_bytes).ok_or(ProofError::BadPoint)?;
    let view = decompress(&view_bytes).ok_or(ProofError::BadPoint)?;

    // prefix_hash = Keccak256(txid || message)
    let mut prefix_data = Vec::with_capacity(32 + message.len());
    prefix_data.extend_from_slice(&txid);
    prefix_data.extend_from_slice(message.as_bytes());
    let prefix_hash = keccak256(&prefix_data);

    let mut out = String::from(OUT_PROOF_V2_PREFIX);
    for key_hex in tx_keys_hex {
        let key_bytes = hex32(key_hex).ok_or(ProofError::BadTxKey)?;
        let secret = Scalar::from_bytes_mod_order(key_bytes);
        let shared = secret * view;
        let r_point = if is_subaddress {
            secret * spend
        } else {
            secret * ED25519_BASEPOINT_POINT
        };
        let sig = generate_tx_proof(
            &prefix_hash,
            &r_point,
            &view,
            if is_subaddress { Some(&spend) } else { None },
            &shared,
            &secret,
        );
        out.push_str(&base58_encode(shared.compress().as_bytes()));
        out.push_str(&base58_encode(&sig));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trips() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0u8; 32],
            vec![7u8; 32],
            vec![255u8; 64],
            vec![1, 2, 3, 4, 5],
            vec![42],
        ];
        for raw in &cases {
            let enc = base58_encode(raw);
            assert_eq!(base58_decode(&enc).as_deref(), Some(raw.as_slice()), "round trip {enc}");
        }
        // A 32-byte block encodes to exactly 44 chars; 64 to 88.
        assert_eq!(base58_encode(&[0u8; 32]).len(), 44);
        assert_eq!(base58_encode(&[0u8; 64]).len(), 88);
        assert_eq!(base58_decode("0"), None); // '0' is not in the alphabet
        assert_eq!(base58_decode(""), None);
        // 13 chars = one full block (8 bytes) + a 2-char tail (1 byte).
        assert_eq!(base58_decode("1111111111111"), Some(vec![0u8; 9]));
        // 12 chars would need a 1-char tail, which no byte count makes.
        assert_eq!(base58_decode("111111111111"), None);
    }

    #[test]
    fn base58_cross_checked_against_monero_crates() {
        use std::str::FromStr as _;
        // A real stagenet subaddress (the store suite's SUB_B
        // fixture). Our codec must decode it to the 69 raw bytes
        // (prefix ‖ spend ‖ view ‖ checksum) and re-encode it
        // byte-for-byte — the old little-endian codec did neither.
        const ADDR: &str =
            "72GeiPtUwSSSsbBtk7SgYGebrQYiDZZYvGa7Y5Z5AAi2M5Cpp38sCU8DjQtcCVJPTxUjua8ekmSuRhzNSz6gFcfFErM7Jqm";
        let raw = base58_decode(ADDR).expect("a real address decodes");
        assert_eq!(raw.len(), 69);
        assert_eq!(base58_encode(&raw), ADDR, "re-encode is byte-exact");
        // Cross-check 1: base58-monero's checked decode validates
        // the 4-byte Keccak checksum and strips it.
        let payload = base58_monero::decode_check(ADDR).expect("checksum validates");
        assert_eq!(payload.as_slice(), &raw[..65]);
        // Cross-check 2: the `monero` crate's own address parser
        // recovers the same spend/view keys from the same string.
        let parsed = monero::Address::from_str(ADDR).expect("monero parses it");
        assert_eq!(parsed.addr_type, monero::AddressType::SubAddress);
        assert_eq!(&raw[1..33], &parsed.public_spend.as_bytes()[..]);
        assert_eq!(&raw[33..65], &parsed.public_view.as_bytes()[..]);
        // Asymmetric blocks must agree with the crate's big-endian
        // reading (under the old codec [1,0,…] and […,0,1] swapped).
        let a = [1u8, 0, 0, 0, 0, 0, 0, 0, 9, 8, 7];
        assert_eq!(base58_encode(&a), base58_monero::encode(&a).unwrap());
        assert_eq!(
            base58_decode(&base58_monero::encode(&a).unwrap()).as_deref(),
            Some(&a[..])
        );
    }

    #[test]
    fn proof_form_parses_and_rejects() {
        let seg_pk = base58_encode(&[3u8; 32]);
        let seg_sig = base58_encode(&[4u8; 64]);
        let good = format!("OutProofV2{seg_pk}{seg_sig}");
        assert!(proof_form_ok(&good));
        let parsed = parse_out_proof_v2(&good).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].shared_secret, [3u8; 32]);
        assert!(!proof_form_ok("OutProofV1anything"));
        assert!(!proof_form_ok("OutProofV2"));
        assert!(!proof_form_ok(&format!("OutProofV2{seg_pk}")));
        assert!(!proof_form_ok(&format!("InProofV2{seg_pk}{seg_sig}")));
    }

    #[test]
    fn keccak_known_vector() {
        // Keccak-256("") — the well-known value (NOT SHA3-256).
        let h = keccak256(b"");
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
