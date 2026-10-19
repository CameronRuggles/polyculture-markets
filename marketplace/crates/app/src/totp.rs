//! TOTP (RFC 6238) for moderator step-up authentication (amendments §7:
//! admin/moderator accounts require TOTP, works without JavaScript).
//!
//! This is the standard construction only — HMAC-SHA1 over the 30-second
//! counter, dynamic truncation, 6 digits — built from the vetted `hmac`
//! and `sha1` crates already in the locked dependency tree. Nothing
//! about the algorithm is invented here. Secrets are 160-bit, shown to
//! the user once as base32 for authenticator enrollment, and stored
//! encrypted with the key file (see `keyfile`).

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub const STEP_SECONDS: u64 = 30;
pub const DIGITS: u32 = 6;
/// Steps of clock skew accepted on either side.
pub const WINDOW: i64 = 1;

pub fn generate_secret() -> [u8; 20] {
    let mut s = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// RFC 4648 base32, uppercase, no padding (authenticator convention).
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32,
            '2'..='7' => 26 + (c as u32 - '2' as u32),
            '=' | ' ' => continue,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

pub fn code_at(secret: &[u8], unix_secs: u64) -> String {
    let counter = unix_secs / STEP_SECONDS;
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let code = binary % 10u32.pow(DIGITS);
    format!("{code:0width$}", width = DIGITS as usize)
}

/// Verify a user-presented code against the secret at `unix_secs`,
/// accepting ±WINDOW steps. Comparison is over the formatted codes
/// (fixed length, so a byte-wise fold is constant-time in the code).
pub fn verify(secret: &[u8], presented: &str, unix_secs: u64) -> bool {
    verify_step(secret, presented, unix_secs).is_some()
}

/// Like `verify`, but returns the time step (unix_secs / STEP_SECONDS)
/// the presented code belongs to. The account-security gates use the
/// step for replay protection (audit AL3): once a step has been
/// accepted for an account, no code from that step — or an older one —
/// is accepted again.
pub fn verify_step(secret: &[u8], presented: &str, unix_secs: u64) -> Option<u64> {
    let presented = presented.trim();
    if presented.len() != DIGITS as usize || !presented.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut matched: Option<u64> = None;
    for w in -WINDOW..=WINDOW {
        let t = unix_secs as i64 + w * STEP_SECONDS as i64;
        if t < 0 {
            continue;
        }
        let expected = code_at(secret, t as u64);
        let mut diff = 0u8;
        for (a, b) in expected.bytes().zip(presented.bytes()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            matched = Some(t as u64 / STEP_SECONDS);
        }
    }
    matched
}

/// otpauth URI for manual/QR enrollment (rendered as text; no JS).
pub fn otpauth_uri(issuer: &str, account: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_base32}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (SHA-1, seed = ASCII
    // "12345678901234567890"), truncated to 6 digits.
    #[test]
    fn rfc6238_vectors() {
        let seed = b"12345678901234567890";
        assert_eq!(code_at(seed, 59), "287082");
        assert_eq!(code_at(seed, 1_111_111_109), "081804");
        assert_eq!(code_at(seed, 1_234_567_890), "005924");
    }

    #[test]
    fn verify_window_and_shape() {
        let seed = b"12345678901234567890";
        let now = 1_234_567_890;
        assert!(verify(seed, "005924", now));
        assert!(verify(seed, &code_at(seed, now - 30), now), "previous step accepted");
        assert!(verify(seed, &code_at(seed, now + 30), now), "next step accepted");
        assert!(!verify(seed, &code_at(seed, now + 120), now), "two steps away rejected");
        assert!(!verify(seed, "5924", now), "short code rejected");
        assert!(!verify(seed, "00592x", now), "non-digit rejected");
        assert!(!verify(seed, "000000", now));
    }

    #[test]
    fn base32_bit_exact_edges() {
        // 0xff = 11111 111(00): distinguishes OR-accumulation from XOR.
        assert_eq!(base32_encode(&[0xff]), "74");
        assert_eq!(base32_encode(&[0x00]), "AA");
        assert_eq!(base32_encode(&[0xff, 0xff]), "777Q");
        // Padding and spaces are skipped on decode.
        assert_eq!(base32_decode("MY======").as_deref(), Some(b"f".as_slice()));
        assert_eq!(base32_decode("MZXW6 YTBOI").as_deref(), Some(b"foobar".as_slice()));
        assert_eq!(base32_decode("74").unwrap(), vec![0xff]);
    }

    #[test]
    fn base32_round_trip() {
        // RFC 4648 vectors.
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI").as_deref(), Some(b"foobar".as_slice()));
        assert_eq!(base32_decode("mzxw6").as_deref(), Some(b"foo".as_slice()));
        assert_eq!(base32_decode("MZXW6!"), None);
        let secret = generate_secret();
        assert_eq!(base32_decode(&base32_encode(&secret)).unwrap(), secret);
    }
}
