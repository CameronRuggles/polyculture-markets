//! Recovery codes (spec §7): single-use codes, SHA-256 hashed at rest.
//! Consuming one is the trigger for the core to revoke every session and
//! mark the profile recovered (30 days) — that side effect lives in db.rs;
//! this module owns generation and hashing.

use rand::Rng;
use sha2::{Digest, Sha256};

const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no 0/O/1/I/L

pub fn new_recovery_code() -> String {
    let mut rng = rand::thread_rng();
    (0..20)
        .map(|i| {
            let sep = if i > 0 && i % 5 == 0 { "-" } else { "" };
            let c = ALPHABET[rng.gen_range(0..ALPHABET.len())] as char;
            format!("{sep}{c}")
        })
        .collect()
}

pub fn hash_code(code: &str) -> [u8; 32] {
    let normalized: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();
    Sha256::digest(normalized.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        let c = new_recovery_code();
        assert_eq!(c.len(), 23); // 20 chars + 3 separators
        assert_eq!(hash_code(&c), hash_code(&c.to_lowercase().replace('-', " ")));
        assert_ne!(hash_code(&c), hash_code(&new_recovery_code()));
    }
}
