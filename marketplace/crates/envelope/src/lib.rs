//! Envelope validation — amended spec §14.
//!
//! Packet-level inspection only; this code never decrypts and never sees
//! a private key. Amended rules implemented (SPEC-V2-AMENDMENTS §14):
//! Q1 AED tag-20 special case + PKESK/SEIP pairing, Q5 64 KiB submitted-
//! bytes cap, Q6 concrete packet limits, Q16 ordered error taxonomy with
//! the conversation-scoped `RecipientKeyRetired` leak fix.

pub use modules_api::EnvelopeError;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::RevocationStatus;
use sequoia_openpgp::Cert;
use std::collections::HashSet;

pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// A reference to one party's key. Built from a full certificate when
/// available, or from a bare primary fingerprint (matching limited to
/// it + its key ID). Certificate matching covers only the keys a
/// sender can usefully encrypt to RIGHT NOW: alive,
/// encryption-capable subkeys (messaging audit MM3 — a certificate
/// can carry revoked, expired, signing-only and certification keys,
/// and none of those may vouch for a recipient match).
#[derive(Clone, Debug)]
pub struct KeyRef {
    fingerprint: String,
    handles: HashSet<String>, // uppercase hex fingerprints + key IDs of the matchable keys
}

impl KeyRef {
    /// Strict matching (MM3): only subkeys that are alive (not
    /// expired), not revoked, and encryption-capable under the
    /// standard policy count as recipient handles — the same policy
    /// work `keys::validate_cert` does at upload. A certificate that
    /// fails policy validation as a whole (revoked/expired primary)
    /// matches nothing, but still yields its primary fingerprint so
    /// callers can name the key.
    pub fn from_cert(cert_bytes: &[u8]) -> Option<KeyRef> {
        let cert = Cert::from_bytes(cert_bytes).ok()?;
        let primary = format!("{:X}", cert.fingerprint());
        let mut handles = HashSet::new();
        if let Ok(valid) = cert.with_policy(&StandardPolicy::new(), None) {
            for ka in valid.keys().subkeys() {
                if !(ka.for_storage_encryption() || ka.for_transport_encryption()) {
                    continue;
                }
                if ka.alive().is_err() {
                    continue;
                }
                if matches!(ka.revocation_status(), RevocationStatus::Revoked(_)) {
                    continue;
                }
                let key = ka.key();
                handles.insert(format!("{:X}", key.fingerprint()));
                handles.insert(format!("{:X}", key.keyid()));
            }
        }
        Some(KeyRef {
            fingerprint: primary,
            handles,
        })
    }

    /// Unfiltered matching: EVERY key in the certificate, alive or
    /// not, encryption-capable or not. Used ONLY for retired-key
    /// recognition (the RecipientKeyRetired path): a message encrypted
    /// to a key the recipient has since rotated away from — including
    /// one whose certificate later expired or whose subkey was
    /// revoked in a refresh — must still be recognised as "encrypted
    /// to a shown retired key", never silently reclassified.
    pub fn from_cert_unfiltered(cert_bytes: &[u8]) -> Option<KeyRef> {
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
        // Optional armor headers end at the first blank line. Lines
        // may end in LF or CRLF: browsers submit textarea content
        // with CRLF line endings (messaging audit MH1), and a CRLF
        // text contains no "\n\n", so the blank line is found by
        // walking lines rather than searching for a byte pair. The
        // first piece is the remainder of the BEGIN line itself.
        let mut body_start = None;
        let mut offset = 0usize;
        for (n, line) in rest.split_inclusive('\n').enumerate() {
            let content = line.trim_end_matches(['\n', '\r']);
            if content.is_empty() {
                if n > 0 {
                    body_start = Some(offset + line.len());
                    break;
                }
            } else if n == 0 || !content.contains(':') {
                // Junk on the BEGIN line, or a non-header line before
                // the blank separator: not well-formed armor.
                return Err(EnvelopeError::Malformed);
            }
            offset += line.len();
        }
        let body_start = body_start.ok_or(EnvelopeError::Malformed)?;
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

enum LenKind {
    Definite(usize),
    Partial(usize),
}

/// Read one new-format length field at `i` (RFC 9580 §4.2.2):
/// returns the kind and the number of octets consumed. Partial body
/// lengths decode to their chunk size, `1 << (octet - 224)` (the
/// RFC's own worked example: 0xEA → 1024).
fn read_new_length(bin: &[u8], i: usize) -> Result<(LenKind, usize), EnvelopeError> {
    if i >= bin.len() {
        return Err(EnvelopeError::Malformed);
    }
    let l = bin[i];
    match l {
        0..=191 => Ok((LenKind::Definite(l as usize), 1)),
        192..=223 => {
            if i + 1 >= bin.len() {
                return Err(EnvelopeError::Malformed);
            }
            Ok((
                LenKind::Definite(192 + (((l as usize) - 192) << 8) + bin[i + 1] as usize),
                2,
            ))
        }
        224..=254 => Ok((LenKind::Partial(1usize << (l - 224)), 1)),
        255 => {
            if i + 4 >= bin.len() {
                return Err(EnvelopeError::Malformed);
            }
            Ok((
                LenKind::Definite(
                    u32::from_be_bytes([bin[i + 1], bin[i + 2], bin[i + 3], bin[i + 4]]) as usize,
                ),
                5,
            ))
        }
    }
}

fn split_packets(bin: &[u8]) -> Result<Vec<RawPacket>, EnvelopeError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bin.len() {
        let b0 = bin[i];
        if b0 & 0x80 == 0 {
            return Err(EnvelopeError::Malformed);
        }
        if b0 & 0x40 == 0 {
            // Old format: tag in bits 5..2, length type in bits 1..0.
            let tag = (b0 >> 2) & 0xF;
            let (hlen, blen) = match b0 & 0x3 {
                0 => {
                    if i + 1 >= bin.len() {
                        return Err(EnvelopeError::Malformed);
                    }
                    (2usize, bin[i + 1] as usize)
                }
                1 => {
                    if i + 2 >= bin.len() {
                        return Err(EnvelopeError::Malformed);
                    }
                    (3usize, u16::from_be_bytes([bin[i + 1], bin[i + 2]]) as usize)
                }
                2 => {
                    if i + 4 >= bin.len() {
                        return Err(EnvelopeError::Malformed);
                    }
                    (
                        5usize,
                        u32::from_be_bytes([bin[i + 1], bin[i + 2], bin[i + 3], bin[i + 4]])
                            as usize,
                    )
                }
                _ => return Err(EnvelopeError::Malformed), // indeterminate length
            };
            if i + hlen + blen > bin.len() {
                return Err(EnvelopeError::Malformed);
            }
            out.push(RawPacket {
                tag,
                body: bin[i + hlen..i + hlen + blen].to_vec(),
            });
            i += hlen + blen;
            continue;
        }
        // New format.
        let tag = b0 & 0x3F;
        let (first, used) = read_new_length(bin, i + 1)?;
        let mut j = i + 1 + used; // first body octet / first chunk start
        let mut body = Vec::new();
        match first {
            LenKind::Definite(blen) => {
                if j + blen > bin.len() {
                    return Err(EnvelopeError::Malformed);
                }
                body.extend_from_slice(&bin[j..j + blen]);
                j += blen;
            }
            LenKind::Partial(mut chunk_len) => {
                // Partial body lengths (RFC 9580 §4.2.2.4) are how
                // GnuPG writes any message it streams — signed mail at
                // any size, and anything past ~512 B (messaging audit
                // MH2). They are accepted ONLY on the encrypted-data
                // packet (SEIP tag 18 / AED tag 20), which is always
                // the final packet of a message: chunks are accumulated
                // under the caller's submitted-bytes cap, the packet
                // must end the input, and the never-look-inside rule is
                // unchanged — the scanner still reads only body[0]
                // (version / AED header) of the assembled packet.
                if tag != TAG_SEIP && tag != TAG_AED {
                    return Err(EnvelopeError::Malformed);
                }
                loop {
                    if j + chunk_len > bin.len() {
                        return Err(EnvelopeError::Malformed);
                    }
                    body.extend_from_slice(&bin[j..j + chunk_len]);
                    j += chunk_len;
                    let (next, used) = read_new_length(bin, j)?;
                    j += used;
                    match next {
                        LenKind::Partial(c) => chunk_len = c,
                        LenKind::Definite(blen) => {
                            if j + blen > bin.len() {
                                return Err(EnvelopeError::Malformed);
                            }
                            body.extend_from_slice(&bin[j..j + blen]);
                            j += blen;
                            break;
                        }
                    }
                }
                if j != bin.len() {
                    return Err(EnvelopeError::Malformed); // a partial packet is final
                }
            }
        }
        out.push(RawPacket { tag, body });
        i = j;
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
        // New-format partial body length octet 224 declares a 1-byte
        // chunk; after it the stream ends with no terminating length
        // — truncated, refused. (Partial lengths themselves are
        // ACCEPTED on the final data packet since MH2; see
        // split_accepts_partial_on_final_data_packet.)
        assert!(split_packets(&[0xC0u8 | 18, 224, 1]).is_err());
        // Old-format indeterminate length (type 3) is refused.
        assert!(split_packets(&[0x80u8 | (1 << 2) | 3, 1, 2]).is_err());
        // Declared length beyond the buffer is refused.
        assert!(split_packets(&[0xC0u8 | 18, 50, 1]).is_err());
        // A packet header byte without the always-1 bit is refused.
        assert!(split_packets(&[0x12u8, 0x00]).is_err());
    }

    /// A v3 PKESK naming key ID 1111…11 (the recipient handle the
    /// hand-built contexts below use).
    fn pkesk_11() -> Vec<u8> {
        let mut v = vec![0xC0u8 | 1, 12, 3];
        v.extend_from_slice(&[0x11; 8]);
        v.extend_from_slice(&[1, 0xAA, 0xBB]);
        v
    }

    fn ctx_11() -> EnvelopeContext {
        EnvelopeContext {
            sender: KeyRef::from_fingerprint("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            recipient: KeyRef::from_fingerprint(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1111111111111111",
            ),
            recipient_retired_shown: vec![],
        }
    }

    #[test]
    fn split_accepts_partial_on_final_data_packet() {
        // SEIP body stream: version 1 + 8 junk bytes = 9 bytes,
        // framed as four 2-byte partial chunks + a 1-byte final chunk.
        let mut msg = pkesk_11();
        msg.push(0xC0 | 18);
        let stream = [1u8, 9, 9, 9, 9, 9, 9, 9, 9];
        for chunk in stream.chunks(2) {
            if chunk.len() == 2 {
                msg.push(225); // partial: 1 << (225 - 224) = 2 bytes
                msg.extend_from_slice(chunk);
            } else {
                msg.push(chunk.len() as u8); // final definite chunk
                msg.extend_from_slice(chunk);
            }
        }
        let ps = split_packets(&msg).unwrap();
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[1].tag, 18);
        assert_eq!(ps[1].body, stream.to_vec());
        // …and the whole envelope validates (v3 PKESK + SEIP v1).
        validate_envelope(&msg, &ctx_11()).unwrap();

        // The same framing on the AED packet (header check applies to
        // the ASSEMBLED body: version 1, AES-256, OCB, chunk 16, salt).
        let mut msg = pkesk_11();
        msg.push(0xC0 | 20);
        let mut stream = vec![1u8, 9, 2, 16];
        stream.extend(std::iter::repeat_n(0u8, 32)); // salt
        stream.extend(std::iter::repeat_n(7u8, 40)); // payload
        for chunk in stream.chunks(16) {
            if chunk.len() == 16 {
                msg.push(228); // partial: 1 << (228 - 224) = 16 bytes
                msg.extend_from_slice(chunk);
            } else {
                msg.push(chunk.len() as u8);
                msg.extend_from_slice(chunk);
            }
        }
        let ps = split_packets(&msg).unwrap();
        assert_eq!(ps[1].tag, 20);
        assert_eq!(ps[1].body, stream);
        validate_envelope(&msg, &ctx_11()).unwrap();
    }

    #[test]
    fn split_refuses_partial_off_the_data_packet() {
        // Partial length on a PKESK: refused even though the framing
        // is otherwise complete (2-byte partial chunk + 1-byte final).
        let mut pk = vec![0xC0u8 | 1, 224, 3, 0x11, 1, 0x11];
        let ps = split_packets(&pk);
        assert!(ps.is_err(), "partial PKESK must be refused");
        pk.clear();
        // A partial data packet that is NOT final (another packet
        // follows): refused.
        let mut msg = pkesk_11();
        msg.push(0xC0 | 18);
        msg.push(225); // 2-byte partial chunk
        msg.extend_from_slice(&[1, 9]);
        msg.push(1); // final 1-byte chunk
        msg.push(9);
        msg.extend_from_slice(&pkesk_11()); // trailing packet
        assert!(split_packets(&msg).is_err(), "partial packet must be final");
        // A partial chunk with nothing after it (no terminating
        // length): refused.
        let mut msg = pkesk_11();
        msg.push(0xC0 | 18);
        msg.push(225);
        msg.extend_from_slice(&[1, 9]);
        assert!(split_packets(&msg).is_err());
    }
}
