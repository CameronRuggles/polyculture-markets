//! Envelope validation — amended spec §14.
//!
//! Packet-level inspection only; this code never decrypts and never sees
//! a private key. Amended rules implemented (SPEC-V2-AMENDMENTS §14):
//! Q1 AED tag-20 special case + PKESK/SEIP pairing, Q5 64 KiB submitted-
//! bytes cap, Q6 concrete packet limits, Q16 ordered error taxonomy with
//! the conversation-scoped `RecipientKeyRetired` leak fix.

pub use modules_api::EnvelopeError;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Cert;
use std::collections::HashSet;

pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// A reference to one party's key. Built from a full certificate when
/// available (matching is certificate-level: any key in the cert), or
/// from a bare primary fingerprint (matching limited to it + its key ID).
#[derive(Clone, Debug)]
pub struct KeyRef {
    fingerprint: String,
    handles: HashSet<String>, // uppercase hex fingerprints + key IDs of all keys in the cert
}

impl KeyRef {
    pub fn from_cert(cert_bytes: &[u8]) -> Option<KeyRef> {
        let cert = Cert::from_bytes(cert_bytes).ok()?;
        let mut handles = HashSet::new();
        let mut primary = String::new();
        for (i, k) in cert.keys().enumerate() {
            let key = k.key();
            let fpr = format!("{:X}", key.fingerprint());
            if i == 0 {
                primary = fpr.clone();
            }
            handles.insert(fpr);
            handles.insert(format!("{:X}", key.keyid()));
        }
        if primary.is_empty() {
            return None;
        }
        Some(KeyRef {
            fingerprint: primary,
            handles,
        })
    }

    pub fn from_fingerprint(fingerprint: &str) -> KeyRef {
        let fpr = fingerprint.to_uppercase();
        let mut handles = HashSet::new();
        handles.insert(fpr.clone());
        if fpr.len() >= 16 {
            // The key-ID suffix is the last 16 BYTES, but slicing there
            // panics if the offset falls inside a multi-byte character
            // (found by the 2026-10-17 deterministic-tools pass: a
            // fingerprint of six '€' chars — 18 bytes — panicked).
            // Real fingerprints are ASCII hex, where the offset is
            // always a boundary; for anything else, derive no key-ID
            // handle instead of panicking.
            let start = fpr.len() - 16;
            if fpr.is_char_boundary(start) {
                handles.insert(fpr[start..].to_string());
            }
        }
        KeyRef {
            fingerprint: fpr,
            handles,
        }
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    fn matches(&self, handle_hex: &str) -> bool {
        // Exact membership only. The handle set already contains every
        // fingerprint and key ID of the cert (from_cert) or the primary
        // fingerprint + its key ID (from_fingerprint). Suffix-alias
        // matching was removed at the Stage 5 gate: it let malformed
        // handles match by containment, and no real packet form needs it
        // (v3 PKESKs name key IDs, v6 PKESKs name full fingerprints).
        self.handles.contains(handle_hex)
    }
}

pub struct EnvelopeContext {
    /// The sender's current key.
    pub sender: KeyRef,
    /// The recipient's current key.
    pub recipient: KeyRef,
    /// The recipient's retired keys that were shown to the sender inside
    /// THIS conversation (sightings / validity overlap). Leak fix: a
    /// retired key outside this list yields WrongRecipient, never
    /// RecipientKeyRetired.
    pub recipient_retired_shown: Vec<KeyRef>,
}

pub struct EnvelopeInfo {
    /// Primary fingerprints of the parties whose keys were matched.
    pub recipient_fingerprints: Vec<String>,
}

fn is_hidden(handle_hex: &str) -> bool {
    handle_hex.chars().all(|c| c == '0')
}

/// One pass over the envelope collecting PKESK recipients and the
/// container descriptor; shared by validate + the key-ID helper.
struct Scan {
    pkesk_recipients: Vec<Option<String>>, // None = hidden/wildcard
    pkesk_versions: Vec<u8>,
    container: Container,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Container {
    SeipV1,
    SeipV2,
    Aed,
    None,
}

// The packet walk is a hand-rolled top-level header scanner, NOT a
// general OpenPGP parser: the amended rules require that the parser
// never descend into containers (Q6), and general parsers fail whole
// messages on container contents they try to interpret (a compressed
// packet's deflate stream, an SEIPD's inner MDC). The scanner reads
// packet headers and lengths only; bodies are opaque except the fixed
// prefixes the rules name (PKESK version/recipient, SEIP version, the
// AED fixed header). Envelope validation is structural by design — the
// recipient's client performs the cryptography.

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut nbits = 0;
    for c in text.bytes() {
        if c == b'=' {
            break;
        }
        let v = b64_val(c)?;
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// Resolve the submission to raw packet bytes, applying the armor rules:
/// clearsign is plaintext (NotEncrypted); broken armor is Malformed;
/// unarmored readable text is NotEncrypted; anything else is raw binary.
fn packet_bytes(bytes: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let text = std::str::from_utf8(bytes).unwrap_or("");
    if text.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
        return Err(EnvelopeError::NotEncrypted);
    }
    if let Some(start) = text.find("-----BEGIN PGP MESSAGE-----") {
        let rest = &text[start + "-----BEGIN PGP MESSAGE-----".len()..];
        // Optional armor headers end at the first blank line.
        let body_start = rest.find("\n\n").map(|i| i + 2).ok_or(EnvelopeError::Malformed)?;
        let body = &rest[body_start..];
        let end = body
            .find("-----END PGP MESSAGE-----")
            .ok_or(EnvelopeError::Malformed)?;
        let tail = &body[end + "-----END PGP MESSAGE-----".len()..];
        if !tail.trim().is_empty() {
            return Err(EnvelopeError::Malformed); // trailing bytes (Q6)
        }
        let mut b64 = String::new();
        for line in body[..end].lines() {
            let line = line.trim();
            if line.starts_with('=') {
                break; // CRC line
            }
            b64.push_str(line);
        }
        return b64_decode(&b64).ok_or(EnvelopeError::Malformed);
    }
    if text.contains("-----BEGIN PGP") {
        return Err(EnvelopeError::Malformed); // some other armor type
    }
    let texty = bytes
        .iter()
        .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace());
    if texty && !bytes.is_empty() {
        return Err(EnvelopeError::NotEncrypted);
    }
    Ok(bytes.to_vec())
}

struct RawPacket {
    tag: u8,
    body: Vec<u8>,
}

fn split_packets(bin: &[u8]) -> Result<Vec<RawPacket>, EnvelopeError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bin.len() {
        let b0 = bin[i];
        if b0 & 0x80 == 0 {
            return Err(EnvelopeError::Malformed);
        }
        let (tag, hdr) = if b0 & 0x40 != 0 {
            // New format.
            if i + 1 >= bin.len() {
                return Err(EnvelopeError::Malformed);
            }
            let l = bin[i + 1];
            match l {
                0..=191 => (b0 & 0x3F, (2usize, l as usize)),
                192..=223 => {
                    if i + 2 >= bin.len() {
                        return Err(EnvelopeError::Malformed);
                    }
                    (
                        b0 & 0x3F,
                        (3usize, 192 + (((l as usize) - 192) << 8) + bin[i + 2] as usize),
                    )
                }
                224..=254 => return Err(EnvelopeError::Malformed), // partial lengths: not for complete messages
                255 => {
                    if i + 5 >= bin.len() {
                        return Err(EnvelopeError::Malformed);
                    }
                    (
                        b0 & 0x3F,
                        (
                            6usize,
                            u32::from_be_bytes([bin[i + 2], bin[i + 3], bin[i + 4], bin[i + 5]])
                                as usize,
                        ),
                    )
                }
            }
        } else {
            // Old format: tag in bits 5..2, length type in bits 1..0.
            let tag = (b0 >> 2) & 0xF;
            match b0 & 0x3 {
                0 => {
                    if i + 1 >= bin.len() {
                        return Err(EnvelopeError::Malformed);
                    }
                    (tag, (2usize, bin[i + 1] as usize))
                }
                1 => {
                    if i + 2 >= bin.len() {
                        return Err(EnvelopeError::Malformed);
                    }
                    (
                        tag,
                        (3usize, u16::from_be_bytes([bin[i + 1], bin[i + 2]]) as usize),
                    )
                }
                2 => {
                    if i + 4 >= bin.len() {
                        return Err(EnvelopeError::Malformed);
                    }
                    (
                        tag,
                        (
                            5usize,
                            u32::from_be_bytes([bin[i + 1], bin[i + 2], bin[i + 3], bin[i + 4]])
                                as usize,
                        ),
                    )
                }
                _ => return Err(EnvelopeError::Malformed), // indeterminate length
            }
        };
        let (tag, (hlen, blen)) = (tag, hdr);
        if i + hlen + blen > bin.len() {
            return Err(EnvelopeError::Malformed);
        }
        out.push(RawPacket {
            tag,
            body: bin[i + hlen..i + hlen + blen].to_vec(),
        });
        i += hlen + blen;
    }
    Ok(out)
}

const TAG_SIGNATURE: u8 = 2;
const TAG_PKESK: u8 = 1;
const TAG_LITERAL: u8 = 11;
const TAG_SEIP: u8 = 18;
const TAG_AED: u8 = 20;

fn scan(bytes: &[u8]) -> Result<Scan, EnvelopeError> {
    let bin = packet_bytes(bytes)?;
    let packets = split_packets(&bin)?;
    if packets.is_empty() {
        return Err(EnvelopeError::Malformed);
    }
    // Plaintext structures first (taxonomy order): an unencrypted
    // message whose first packet is literal data or a signature.
    if packets[0].tag == TAG_LITERAL || packets[0].tag == TAG_SIGNATURE {
        return Err(EnvelopeError::NotEncrypted);
    }
    let mut scan = Scan {
        pkesk_recipients: Vec::new(),
        pkesk_versions: Vec::new(),
        container: Container::None,
    };
    for p in &packets {
        match p.tag {
            TAG_PKESK => {
                if scan.container != Container::None {
                    return Err(EnvelopeError::UnsupportedPacket); // PKESK after container
                }
                if p.body.is_empty() {
                    return Err(EnvelopeError::Malformed);
                }
                let version = p.body[0];
                let recipient = match version {
                    3 => {
                        if p.body.len() < 10 {
                            return Err(EnvelopeError::Malformed);
                        }
                        let hex: String = p.body[1..9].iter().map(|b| format!("{b:02X}")).collect();
                        if is_hidden(&hex) {
                            None
                        } else {
                            Some(hex)
                        }
                    }
                    6 => {
                        if p.body.len() < 2 {
                            return Err(EnvelopeError::Malformed);
                        }
                        let n = p.body[1] as usize;
                        if n == 0 || p.body.len() < 2 + n {
                            None // zero-length fingerprint = hidden (RFC 9580)
                        } else {
                            let hex: String =
                                p.body[2..2 + n].iter().map(|b| format!("{b:02X}")).collect();
                            if is_hidden(&hex) {
                                None
                            } else {
                                Some(hex)
                            }
                        }
                    }
                    _ => return Err(EnvelopeError::UnsupportedPacket),
                };
                scan.pkesk_versions.push(version);
                scan.pkesk_recipients.push(recipient);
            }
            TAG_SEIP => {
                if scan.container != Container::None || scan.pkesk_recipients.is_empty() {
                    return Err(EnvelopeError::UnsupportedPacket);
                }
                if p.body.is_empty() {
                    return Err(EnvelopeError::Malformed);
                }
                scan.container = match p.body[0] {
                    1 => Container::SeipV1,
                    2 => Container::SeipV2,
                    _ => return Err(EnvelopeError::UnsupportedPacket),
                };
            }
            TAG_AED => {
                if scan.container != Container::None || scan.pkesk_recipients.is_empty() {
                    return Err(EnvelopeError::UnsupportedPacket);
                }
                check_aed_header(&p.body)?;
                scan.container = Container::Aed;
            }
            // SKESK (3), marker (10), compressed (8), literal (11),
            // signature (2), SED (9), padding (21), and every other tag
            // have no place at the top level (Q6).
            _ => return Err(EnvelopeError::UnsupportedPacket),
        }
    }
    if scan.pkesk_recipients.is_empty() {
        return Err(EnvelopeError::Malformed);
    }
    if scan.pkesk_recipients.len() > 8 {
        // Q6 packet-count limit: a packet-form violation, not corruption.
        return Err(EnvelopeError::UnsupportedPacket);
    }
    if scan.container == Container::None {
        return Err(EnvelopeError::Malformed); // session keys but no message
    }
    // Pairing (Q1): homogeneous PKESK versions; v3 -> SEIPD v1 or AED;
    // v6 -> SEIPD v2 only.
    let v = scan.pkesk_versions[0];
    if scan.pkesk_versions.iter().any(|x| *x != v) {
        return Err(EnvelopeError::UnsupportedPacket);
    }
    let pairing_ok = matches!(
        (v, scan.container),
        (3, Container::SeipV1) | (3, Container::Aed) | (6, Container::SeipV2)
    );
    if !pairing_ok {
        return Err(EnvelopeError::UnsupportedPacket);
    }
    Ok(scan)
}

/// Q1 hand-check of the AED (tag 20) fixed header: version 1, AES cipher
/// (7/8/9), AEAD mode EAX (1) or OCB (2), sane chunk-size octet, and the
/// 32-byte salt must be present.
fn check_aed_header(body: &[u8]) -> Result<(), EnvelopeError> {
    if body.len() < 4 + 32 {
        return Err(EnvelopeError::UnsupportedPacket);
    }
    let (version, cipher, aead, chunk) = (body[0], body[1], body[2], body[3]);
    if version != 1 || !matches!(cipher, 7..=9) || !matches!(aead, 1 | 2) || chunk > 16 {
        return Err(EnvelopeError::UnsupportedPacket);
    }
    Ok(())
}

pub fn validate_envelope(bytes: &[u8], ctx: &EnvelopeContext) -> Result<EnvelopeInfo, EnvelopeError> {
    if bytes.is_empty() {
        return Err(EnvelopeError::Empty);
    }
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(EnvelopeError::Malformed);
    }
    let scan = scan(bytes)?;
    // Hidden recipients outrank recipient matching (taxonomy order).
    if scan.pkesk_recipients.iter().any(|r| r.is_none()) {
        return Err(EnvelopeError::HiddenRecipient);
    }
    let handles: Vec<&str> = scan
        .pkesk_recipients
        .iter()
        .map(|r| r.as_deref().unwrap())
        .collect();
    let recipient_hit = handles.iter().any(|h| ctx.recipient.matches(h));
    if !recipient_hit {
        let retired_hit = handles.iter().any(|h| {
            ctx.recipient_retired_shown.iter().any(|k| k.matches(h))
        });
        if retired_hit {
            return Err(EnvelopeError::RecipientKeyRetired);
        }
        return Err(EnvelopeError::WrongRecipient);
    }
    // Extra recipients: any PKESK matching neither party (a retired-shown
    // key of the recipient is tolerated — it is one of the parties' keys).
    for h in &handles {
        let known = ctx.sender.matches(h)
            || ctx.recipient.matches(h)
            || ctx.recipient_retired_shown.iter().any(|k| k.matches(h));
        if !known {
            return Err(EnvelopeError::ExtraRecipient);
        }
    }
    let mut fps = vec![ctx.recipient.fingerprint().to_string()];
    if handles.iter().any(|h| ctx.sender.matches(h)) {
        fps.push(ctx.sender.fingerprint().to_string());
    }
    Ok(EnvelopeInfo {
        recipient_fingerprints: fps,
    })
}

/// For the UI on ExtraRecipient: the offending key ID only (never an
/// owner). Key IDs are the last 16 hex of a v4 fingerprint handle.
pub fn extra_recipient_key_id(bytes: &[u8], ctx: &EnvelopeContext) -> Option<String> {
    let scan = scan(bytes).ok()?;
    for r in scan.pkesk_recipients.iter().flatten() {
        let known = ctx.sender.matches(r)
            || ctx.recipient.matches(r)
            || ctx.recipient_retired_shown.iter().any(|k| k.matches(r));
        if !known {
            return Some(if r.len() > 16 {
                r[r.len() - 16..].to_string()
            } else {
                r.clone()
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_fingerprint_short_input_never_panics_and_never_matches() {
        // Pins the len>=16 guard (a cargo-mutants survivor at the Stage 5
        // gate): short garbage fingerprints get no key-ID handle.
        let k = KeyRef::from_fingerprint("AB12");
        assert_eq!(k.fingerprint(), "AB12");
        // No key-ID handle is derived from a short fingerprint (the guard
        // exists so the suffix slice can never underflow).
        assert_eq!(k.handles.len(), 1);
        let k2 = KeyRef::from_fingerprint("0123456789abcde"); // 15 chars
        assert_eq!(k2.handles.len(), 1);
        let k3 = KeyRef::from_fingerprint("0123456789abcdef"); // exactly 16
        assert_eq!(k3.handles.len(), 1); // fpr == its own key ID: one entry
    }

    #[test]
    fn from_fingerprint_non_ascii_never_panics() {
        // Regression (2026-10-17 tools pass): six '€' = 18 bytes; the
        // len-16 offset (byte 2) is inside the first character and the
        // old suffix slice panicked. No key-ID handle is derived, and
        // the (uppercased) fingerprint itself is still the sole handle.
        let k = KeyRef::from_fingerprint("€€€€€€");
        assert_eq!(k.handles.len(), 1);
        assert!(k.matches("€€€€€€"));
        // Mixed widths where the offset IS a boundary still derive.
        let k2 = KeyRef::from_fingerprint("0123456789abcdef€"); // 19 bytes, offset 3 is a boundary
        assert_eq!(k2.handles.len(), 2);
    }

    #[test]
    fn from_fingerprint_matches_own_key_id() {
        let f = "0123456789ABCDEF0123456789ABCDEF01234567";
        let k = KeyRef::from_fingerprint(f);
        assert!(k.matches(f));
        assert!(k.matches("89ABCDEF01234567")); // last 16 = v4 key ID
        assert!(!k.matches("0123456789ABCDEF")); // first 16 is NOT a v4 key ID
    }
}

#[cfg(test)]
mod packet_tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02X}")).collect()
    }

    #[test]
    fn split_parses_old_and_new_format_headers() {
        // Old-format PKESK: 0x85 = tag 1, two-byte length; body 3 bytes.
        let old = [0x85u8, 0x00, 0x03, 3, 0xAA, 0xBB];
        let ps = split_packets(&old).unwrap();
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].tag, 1);
        assert_eq!(ps[0].body.len(), 3);
        // New-format: 0xC0|tag, one-byte length.
        let new = [0xC0u8 | 18, 0x02, 1, 0x00];
        let ps = split_packets(&new).unwrap();
        assert_eq!(ps[0].tag, 18);
        assert_eq!(hex(&ps[0].body), "0100");
        // New-format two-octet length (192..=223).
        let mut v = vec![0xC0u8 | 20, 192 + 1, 44]; // len = 192 + 256 + 44 = 492? no: 192+((1)<<8)+44 = 492
        v.extend(std::iter::repeat_n(0u8, 492));
        let ps = split_packets(&v).unwrap();
        assert_eq!(ps[0].body.len(), 492);
        // Old-format one-byte and four-byte lengths.
        let old1 = [0x80u8 | (11 << 2), 0x01, 0xFF];
        assert_eq!(split_packets(&old1).unwrap()[0].tag, 11);
        let mut old4 = vec![0x80u8 | (3 << 2) | 2, 0, 0, 0, 2, 9, 9];
        let ps = split_packets(&old4).unwrap();
        assert_eq!(ps[0].tag, 3);
        assert_eq!(ps[0].body.len(), 2);
        old4.clear();
    }

    #[test]
    fn split_rejects_partial_indeterminate_and_truncated() {
        // New-format partial body length (224) is refused.
        assert!(split_packets(&[0xC0u8 | 18, 224, 1]).is_err());
        // Old-format indeterminate length (type 3) is refused.
        assert!(split_packets(&[0x80u8 | (1 << 2) | 3, 1, 2]).is_err());
        // Declared length beyond the buffer is refused.
        assert!(split_packets(&[0xC0u8 | 18, 50, 1]).is_err());
        // A packet header byte without the always-1 bit is refused.
        assert!(split_packets(&[0x12u8, 0x00]).is_err());
    }
}
