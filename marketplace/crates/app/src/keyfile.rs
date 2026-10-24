//! The marketplace key file (spec §16/§19): one 32-byte master secret
//! held OUTSIDE the database, from which Stage 9 derives its subkeys:
//!
//! - buyer tokens: HMAC-SHA256 over (seller id, buyer id) — counts
//!   distinct buyers per seller without linking a buyer across sellers
//!   in stored data (spec §13);
//! - encryption of secrets at rest: dispute disclosure content and
//!   TOTP secrets are stored encrypted with a key-file subkey, so a
//!   database leak alone yields neither (§3 threat table).
//!
//! Lifecycle (STAGE9-REPORT.md; the operations manual itself is a
//! Stage 10 deliverable): the file is created on first boot if absent
//! (mode 0600, hex-encoded 32 random bytes), must be backed up
//! separately from the database, and losing it makes stored
//! disclosures/TOTP secrets undecryptable and changes every buyer
//! token (reputation history by token is then orphaned — the facts
//! themselves remain). Path: env `KEY_FILE_PATH`, default
//! `marketplace.key` in the working directory.

use hmac::{Hmac, Mac};
use nettle::aead::{Aead, ChaChaPoly1305};
use rand::RngCore;
use sha2::Sha256;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct KeyFile {
    master: [u8; 32],
    pub path: PathBuf,
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

impl KeyFile {
    /// Load an EXISTING key file, refusing when it is absent (audit
    /// AL1): a missing file must never be silently replaced — the
    /// replacement key makes every stored TOTP secret and disclosure
    /// unreadable and changes every buyer token. Non-development
    /// profiles start through this path (main.rs).
    pub fn load_existing(path: &Path) -> std::io::Result<KeyFile> {
        let raw = std::fs::read(path)?;
        let master = parse_key_material(&raw).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "key file must contain 32 bytes (64 hex chars or raw)",
            )
        })?;
        Ok(KeyFile { master, path: path.to_path_buf() })
    }

    /// Load the key file, generating and persisting a fresh one if it
    /// does not exist. Accepts either 64 hex chars (what we write) or a
    /// raw 32-byte file. New files are created with mode 0600 FROM
    /// CREATION (audit AL1: no create-then-chmod window in which the
    /// secret sits world-readable).
    pub fn load_or_generate(path: &Path) -> std::io::Result<KeyFile> {
        if path.exists() {
            return Self::load_existing(path);
        }
        let mut master = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        use std::io::Write;
        file.write_all(hex::encode(master).as_bytes())?;
        Ok(KeyFile { master, path: path.to_path_buf() })
    }

    fn subkey(&self, label: &str) -> [u8; 32] {
        hmac(&self.master, label.as_bytes())
    }

    /// Device-cookie MAC for one account at one device epoch
    /// (verification-fix V1, OWASP's device-cookie pattern; epoch
    /// binding added by Code Audit 2 item 5, finding L1): a
    /// successful login sets a cookie carrying HMAC-SHA256
    /// (key-file subkey) over (account id, epoch). A later login
    /// presenting a cookie whose MAC verifies for the account AT
    /// THE ACCOUNT'S CURRENT EPOCH is a browser that has logged in
    /// before — the per-username failure budget, which exists to
    /// stop strangers guessing, does not apply to it, so an attacker
    /// who spends the budget cannot lock the owner out of a browser
    /// they already use. The epoch is per-account server state
    /// (`accounts.device_epoch`, migration 0018): incrementing it
    /// revokes every outstanding device cookie at once, which
    /// happens on passphrase change and recovery. The MAC is
    /// unforgeable without the key file, and it authorizes nothing
    /// by itself: the passphrase (and TOTP, when enrolled) is still
    /// verified in full.
    pub fn device_cookie_mac(&self, account_id: i64, epoch: i64) -> [u8; 32] {
        let key = self.subkey("device-cookie-v2");
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&account_id.to_be_bytes());
        data.extend_from_slice(&epoch.to_be_bytes());
        hmac(&key, &data)
    }

    /// Buyer token for one (seller, buyer) pair: HMAC-SHA256 keyed by
    /// the key-file subkey over both ids. Deterministic per pair,
    /// unlinkable across sellers (the seller id is inside the MAC).
    pub fn buyer_token(&self, seller_id: i64, buyer_id: i64) -> [u8; 32] {
        let key = self.subkey("buyer-token-v1");
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&seller_id.to_be_bytes());
        data.extend_from_slice(&buyer_id.to_be_bytes());
        hmac(&key, &data)
    }

    /// Encrypt a secret for storage: random 12-byte nonce prepended,
    /// ChaCha20-Poly1305 (Nettle) under the content subkey.
    /// Output: nonce || ciphertext || 16-byte tag.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let key = self.subkey("content-enc-v1");
        let mut nonce = [0u8; ChaChaPoly1305::NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut cipher = ChaChaPoly1305::with_key_and_nonce(&key, &nonce)
            .expect("key and nonce sizes are constants");
        let mut out = Vec::with_capacity(nonce.len() + plaintext.len() + ChaChaPoly1305::DIGEST_SIZE);
        out.extend_from_slice(&nonce);
        let mut ct = vec![0u8; plaintext.len()];
        cipher.encrypt(&mut ct, plaintext);
        out.extend_from_slice(&ct);
        let mut tag = [0u8; ChaChaPoly1305::DIGEST_SIZE];
        cipher.digest(&mut tag);
        out.extend_from_slice(&tag);
        out
    }

    /// Reverse `encrypt`; None on truncation or tag mismatch.
    pub fn decrypt(&self, stored: &[u8]) -> Option<Vec<u8>> {
        let ns = ChaChaPoly1305::NONCE_SIZE;
        let ds = ChaChaPoly1305::DIGEST_SIZE;
        if stored.len() < ns + ds {
            return None;
        }
        let key = self.subkey("content-enc-v1");
        let mut cipher = ChaChaPoly1305::with_key_and_nonce(&key, &stored[..ns]).ok()?;
        let body = &stored[ns..stored.len() - ds];
        let mut pt = vec![0u8; body.len()];
        cipher.decrypt(&mut pt, body);
        let mut tag = [0u8; ChaChaPoly1305::DIGEST_SIZE];
        cipher.digest(&mut tag);
        // Constant-time tag comparison.
        let mut diff = 0u8;
        for (a, b) in tag.iter().zip(stored[stored.len() - ds..].iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return None;
        }
        Some(pt)
    }
}

fn parse_key_material(raw: &[u8]) -> Option<[u8; 32]> {
    if raw.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(raw);
        return Some(k);
    }
    let text = std::str::from_utf8(raw).ok()?.trim();
    let bytes = hex::decode(text).ok()?;
    if bytes.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        Some(k)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kf() -> KeyFile {
        KeyFile { master: [7u8; 32], path: PathBuf::from("/nonexistent") }
    }

    #[test]
    fn token_matches_independent_known_answer() {
        // Computed independently (Python hmac/hashlib) from the
        // documented construction: subkey = HMAC-SHA256(master,
        // "buyer-token-v1"); token = HMAC-SHA256(subkey,
        // seller_id.to_be_bytes() || buyer_id.to_be_bytes()).
        // Pins the subkey derivation itself, not just pair properties.
        let k = kf();
        assert_eq!(
            hex::encode(k.buyer_token(10, 20)),
            "2733f03554b05efd7b0cae81250042db91e54310116d389af1f6adf3834241c2"
        );
    }

    #[test]
    fn device_cookie_mac_is_account_specific() {
        let k = kf();
        assert_eq!(k.device_cookie_mac(7, 0), k.device_cookie_mac(7, 0), "deterministic per account+epoch");
        assert_ne!(k.device_cookie_mac(7, 0), k.device_cookie_mac(8, 0), "bound to the account");
        assert_ne!(
            k.device_cookie_mac(7, 0),
            k.device_cookie_mac(7, 1),
            "an epoch bump changes the MAC — old cookies stop verifying (Audit 2 item 5)"
        );
        assert_ne!(k.device_cookie_mac(7, 0), k.buyer_token(7, 7), "separate subkey from buyer tokens");
    }

    #[test]
    fn tokens_are_pair_specific_and_unlinkable() {
        let k = kf();
        let a = k.buyer_token(10, 20);
        assert_eq!(a, k.buyer_token(10, 20), "deterministic per pair");
        assert_ne!(a, k.buyer_token(11, 20), "same buyer, other seller differs");
        assert_ne!(a, k.buyer_token(10, 21), "other buyer differs");
    }

    #[test]
    fn encrypt_round_trips_empty_plaintext() {
        // Boundary: stored length == nonce + tag exactly. Pins the
        // minimum-length guard in decrypt (a <= mutant would refuse).
        let k = kf();
        let ct = k.encrypt(b"");
        assert_eq!(ct.len(), ChaChaPoly1305::NONCE_SIZE + ChaChaPoly1305::DIGEST_SIZE);
        assert_eq!(k.decrypt(&ct), Some(vec![]));
    }

    #[test]
    fn encrypt_round_trips_and_detects_tampering() {
        let k = kf();
        let ct = k.encrypt(b"a disclosed message");
        assert_ne!(ct.as_slice(), b"a disclosed message");
        assert_eq!(k.decrypt(&ct).as_deref(), Some(b"a disclosed message".as_slice()));
        let mut bad = ct.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(k.decrypt(&bad), None, "tag mismatch must fail");
        assert_eq!(k.decrypt(&ct[..8]), None, "truncation must fail");
    }

    #[test]
    fn load_existing_refuses_missing_and_generated_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "kf-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.key");
        // Missing: refused, and nothing is created (AL1).
        assert!(KeyFile::load_existing(&path).is_err());
        assert!(!path.exists());
        // Generated: 0600 in the final state, loadable via the strict path.
        let kf = KeyFile::load_or_generate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new key file must be 0600, got {mode:o}");
        let kf2 = KeyFile::load_existing(&path).unwrap();
        assert_eq!(kf.buyer_token(3, 4), kf2.buyer_token(3, 4));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_material_parsing() {
        assert!(parse_key_material(&[1u8; 32]).is_some());
        assert!(parse_key_material(hex::encode([2u8; 32]).as_bytes()).is_some());
        assert!(parse_key_material(b"too short").is_none());
    }
}
