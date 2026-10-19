//! Identity keys (spec §8): certificate validation, detached-signature
//! verification, and the key-rotation statement. Sequoia runs on the
//! Nettle backend (decision log Q8); the server never sees a private key.

use sequoia_openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper, VerifierBuilder,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::Cert;
use sqlx::PgPool;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    Malformed,
    PolicyInvalid, // expired, revoked, or not valid under the standard policy
    NoEncryptionSubkey,
    NoSigningKey,
}

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub fingerprint: String, // primary, uppercase hex
    pub user_ids: Vec<String>,
    pub warnings: Vec<String>,
}

fn uid_warning(uid: &str) -> Option<String> {
    if uid.contains('@') {
        return Some(format!(
            "User ID \"{uid}\" looks like an email address and will be public."
        ));
    }
    let name = uid.split(['<', '(']).next().unwrap_or("").trim();
    let words: Vec<&str> = name.split_whitespace().collect();
    if words.len() >= 2
        && words
            .iter()
            .all(|w| w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
    {
        return Some(format!(
            "User ID \"{uid}\" looks like a real name and will be public."
        ));
    }
    None
}

pub fn validate_cert(bytes: &[u8]) -> Result<CertInfo, KeyError> {
    let cert = Cert::from_bytes(bytes).map_err(|_| KeyError::Malformed)?;
    let policy = StandardPolicy::new();
    let valid = cert
        .with_policy(&policy, None)
        .map_err(|_| KeyError::PolicyInvalid)?;
    // with_policy validates structure, bindings, and revocation, but NOT
    // liveness: an expired primary still produces a ValidCert. Contract
    // §9 requires the cert be valid under the standard policy — "not
    // expired, not revoked" — so expiry is enforced explicitly here.
    // (Found by the Stage 3 blind suite, 2026-10-14: a cert gpg reported
    // as expired was accepted.)
    valid.alive().map_err(|_| KeyError::PolicyInvalid)?;
    let enc = valid
        .keys()
        .subkeys()
        .any(|ka| ka.for_storage_encryption() || ka.for_transport_encryption());
    if !enc {
        return Err(KeyError::NoEncryptionSubkey);
    }
    let signing = valid.keys().any(|ka| ka.for_signing());
    if !signing {
        return Err(KeyError::NoSigningKey);
    }
    let user_ids: Vec<String> = valid
        .userids()
        .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
        .collect();
    let warnings = user_ids.iter().filter_map(|u| uid_warning(u)).collect();
    Ok(CertInfo {
        fingerprint: valid.fingerprint().to_hex(),
        user_ids,
        warnings,
    })
}

struct Helper {
    cert: Cert,
    good: bool,
}
impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[sequoia_openpgp::KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }
    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    match r {
                        Ok(_) => self.good = true,
                        Err(e) => {
                            return Err(anyhow::Error::msg(format!("bad signature: {e:?}")));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Verify an armored detached signature over exact bytes, against a cert.
/// Any bad signature result fails the whole check.
pub fn verify_detached(cert_bytes: &[u8], message: &[u8], sig_armored: &[u8]) -> bool {
    let Ok(cert) = Cert::from_bytes(cert_bytes) else {
        return false;
    };
    let policy = StandardPolicy::new();
    let Ok(mut verifier) = (|| {
        DetachedVerifierBuilder::from_bytes(sig_armored)?
            .with_policy(&policy, None, Helper { cert, good: false })
    })() else {
        return false;
    };
    if verifier.verify_bytes(message).is_err() {
        return false;
    }
    verifier.into_helper().good
}

// -- rotation statement (spec §10, marketplace-key-rotation-v1) --------------

#[derive(Debug, PartialEq, Eq)]
pub struct RotationStatement {
    pub account_id: String,
    pub old_fingerprint: String,
    pub new_fingerprint: String,
    pub rotated_at: String,
}

pub fn parse_rotation_statement(text: &str, marketplace_id: &str) -> Option<RotationStatement> {
    if text.chars().any(|c| !('\u{20}'..='\u{7e}').contains(&c) && c != '\n') {
        return None;
    }
    let mut lines = text.split('\n');
    let mut get = |want: &str| -> Option<String> {
        let line = lines.next()?;
        let (k, v) = line.split_once(": ")?;
        if k == want {
            Some(v.to_string())
        } else {
            None
        }
    };
    if get("statement-format")? != "marketplace-key-rotation-v1" {
        return None;
    }
    if get("marketplace-id")? != marketplace_id {
        return None;
    }
    let account_id = get("account-id")?;
    if !modules_api::validate_public_id(&account_id, "acct_") {
        return None;
    }
    let fp = |s: &str| -> bool {
        (s.len() == 40 || s.len() == 64)
            && s.chars().all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c))
    };
    let old_fingerprint = get("old-fingerprint")?;
    if !fp(&old_fingerprint) {
        return None;
    }
    let new_fingerprint = get("new-fingerprint")?;
    if !fp(&new_fingerprint) {
        return None;
    }
    let rotated_at = get("rotated-at")?;
    if !domain::validate_canonical_timestamp(&rotated_at) {
        return None;
    }
    // Exactly one trailing LF, nothing after.
    if lines.next() != Some("") || lines.next().is_some() {
        return None;
    }
    Some(RotationStatement {
        account_id,
        old_fingerprint,
        new_fingerprint,
        rotated_at,
    })
}

// -- persistence ---------------------------------------------------------------

pub async fn current_key(pool: &PgPool, account_id: i64) -> Result<Option<(String, Vec<u8>, i32)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT fingerprint, certificate, version FROM identity_keys
         WHERE account_id = $1 AND status = 'current'",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await
}

pub async fn key_history(pool: &PgPool, account_id: i64) -> Result<Vec<(String, i32, String, String, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT fingerprint, version, status,
                to_char(created_at, 'YYYY-MM-DD'), to_char(retired_at, 'YYYY-MM-DD')
         FROM identity_keys WHERE account_id = $1 ORDER BY version",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

/// Install a cert as the account's current key. Retires any current key and
/// records the rotation. `certified` distinguishes dual-signed rotation
/// from lost-key replacement (§8).
pub async fn install_key(
    pool: &PgPool,
    account_id: i64,
    cert_bytes: &[u8],
    info: &CertInfo,
    rotation: Option<(&[u8], Option<&[u8]>, Option<&[u8]>, bool)>, // (statement, sig_old, sig_new, certified)
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let old: Option<(String,)> =
        sqlx::query_as("SELECT fingerprint FROM identity_keys WHERE account_id = $1 AND status = 'current'")
            .bind(account_id)
            .fetch_optional(&mut *tx)
            .await?;
    let next_version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM identity_keys WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;
    if let Some((old_fpr,)) = &old {
        sqlx::query("UPDATE identity_keys SET status = 'retired', retired_at = now() WHERE account_id = $1 AND status = 'current'")
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        if let Some((statement, sig_old, sig_new, certified)) = rotation {
            sqlx::query(
                "INSERT INTO key_rotations (account_id, old_fpr, new_fpr, statement, sig_old, sig_new, certified)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(account_id)
            .bind(old_fpr)
            .bind(&info.fingerprint)
            .bind(statement)
            .bind(sig_old)
            .bind(sig_new)
            .bind(certified)
            .execute(&mut *tx)
            .await?;
        }
    }
    sqlx::query(
        "INSERT INTO identity_keys (account_id, certificate, fingerprint, version, status)
         VALUES ($1, $2, $3, $4, 'current')",
    )
    .bind(account_id)
    .bind(cert_bytes)
    .bind(&info.fingerprint)
    .bind(next_version)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Record that `account_id`'s key (`fingerprint` / `key_id`) was presented to
/// `shown_to` inside `conversation_id` (Q16 key-sighting storage, migration
/// 0006). Called whenever the server shows a participant's key in a
/// conversation context. Idempotent per (conversation, key, viewer).
pub async fn record_key_sighting(
    pool: &PgPool,
    conversation_id: i64,
    account_id: i64,
    fingerprint: &str,
    key_id: &str,
    shown_to: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO conversation_key_sightings (conversation_id, account_id, fingerprint, key_id, shown_to)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (conversation_id, account_id, fingerprint, key_id, shown_to) DO NOTHING",
    )
    .bind(conversation_id)
    .bind(account_id)
    .bind(fingerprint)
    .bind(key_id)
    .bind(shown_to)
    .execute(pool)
    .await?;
    Ok(())
}

/// Q16's question: was this key already shown to the other party in THIS
/// conversation? True when a sighting was recorded for the conversation, or
/// when the key was the account's current key at the moment the
/// conversation was created (its validity interval covers the
/// conversation's start, so the compose flow presented it then). A key
/// installed only after the conversation began counts solely via a
/// recorded sighting — the interval fallback must not turn later key
/// history into "shown" retroactively. Key history from OTHER
/// conversations never counts (leak fix, 2026-10-13), and a
/// non-participant's keys never count.
pub async fn key_shown_in_conversation(
    pool: &PgPool,
    conversation_id: i64,
    account_id: i64,
    fingerprint: &str,
) -> Result<bool, sqlx::Error> {
    let shown: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM conversation_participants p
             WHERE p.conversation_id = $1 AND p.account_id = $2
         ) AND (
             EXISTS (
                 SELECT 1 FROM conversation_key_sightings
                 WHERE conversation_id = $1 AND account_id = $2 AND fingerprint = $3
             ) OR EXISTS (
                 SELECT 1 FROM identity_keys k
                 JOIN conversations c ON c.id = $1
                 WHERE k.account_id = $2 AND k.fingerprint = $3
                   AND k.created_at <= c.created_at
                   AND (k.retired_at IS NULL OR k.retired_at > c.created_at)
             )
         )",
    )
    .bind(conversation_id)
    .bind(account_id)
    .bind(fingerprint)
    .fetch_one(pool)
    .await?;
    Ok(shown)
}

/// Was the account's latest rotation uncertified, and when? (Profile warning
/// shows for 90 days, §8.)
pub async fn latest_uncertified_rotation(pool: &PgPool, account_id: i64) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(bool, String)> = sqlx::query_as(
        "SELECT certified, to_char(created_at, 'YYYY-MM-DD') FROM key_rotations
         WHERE account_id = $1 AND created_at > now() - interval '90 days'
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((false, date)) => Some(date),
        _ => None,
    })
}

// -- certificate refresh (messaging audit MM3) -------------------------------

/// Validate a same-fingerprint certificate refresh: the submitter
/// re-exports the SAME certificate after renewing its signatures —
/// an expiry extension, a revocation (of the cert or a subkey), a new
/// self-signature. Key material and user IDs must be identical to
/// the stored certificate; anything else is a rotation. The
/// refreshed certificate must also pass the ordinary upload policy
/// (`validate_cert`): a refresh that kills the last encryption subkey
/// is refused here and belongs on the rotation path.
pub fn validate_refresh(old_cert: &[u8], new_cert: &[u8]) -> Result<CertInfo, String> {
    let new_info = validate_cert(new_cert).map_err(|e| {
        let why = match e {
            KeyError::Malformed => "not a parseable certificate",
            KeyError::PolicyInvalid => "expired or revoked under the standard policy",
            KeyError::NoEncryptionSubkey => "no living encryption subkey",
            KeyError::NoSigningKey => "no signing-capable key",
        };
        format!("The refreshed certificate is not usable: {why}.")
    })?;
    let old = Cert::from_bytes(old_cert)
        .map_err(|_| "The stored certificate could not be parsed.".to_string())?;
    let new = Cert::from_bytes(new_cert)
        .map_err(|_| "That is not a parseable OpenPGP certificate.".to_string())?;
    if old.fingerprint() != new.fingerprint() {
        return Err(
            "That certificate has a different fingerprint. Replacing the key itself \
             is a rotation, not a refresh — use the rotation form."
                .to_string(),
        );
    }
    let key_set = |c: &Cert| -> std::collections::BTreeSet<String> {
        c.keys()
            .map(|k| format!("{:X}", k.key().fingerprint()))
            .collect()
    };
    if key_set(&old) != key_set(&new) {
        return Err(
            "That certificate carries a different set of keys. A refresh may only \
             renew signatures (revocations, expiry) — new key material is a rotation."
                .to_string(),
        );
    }
    let uid_set = |c: &Cert| -> std::collections::BTreeSet<String> {
        c.userids()
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .collect()
    };
    if uid_set(&old) != uid_set(&new) {
        return Err(
            "That certificate carries different user IDs. A refresh may only renew \
             signatures (revocations, expiry)."
                .to_string(),
        );
    }
    Ok(new_info)
}

/// Merge a validated refresh INTO the stored certificate
/// (verification-fix V7): the caller stores the MERGE, never the
/// submission alone. `validate_refresh` checks the submission in
/// isolation, so before this fix a user could submit an old export
/// of their own certificate — one made before they revoked a
/// subkey — and the stored copy would quietly lose the revocation,
/// leaving a compromised subkey looking clean. Sequoia's
/// `merge_public` unions the signature packets, so a revocation
/// present in EITHER copy survives. The merged result must itself
/// pass the full upload policy before it is stored.
pub fn merged_refresh(old_cert: &[u8], new_cert: &[u8]) -> Result<Vec<u8>, String> {
    let old = Cert::from_bytes(old_cert)
        .map_err(|_| "The stored certificate could not be parsed.".to_string())?;
    let new = Cert::from_bytes(new_cert)
        .map_err(|_| "That is not a parseable OpenPGP certificate.".to_string())?;
    let merged = old
        .merge_public(new)
        .map_err(|_| "The certificates could not be merged.".to_string())?;
    // Serialize armored, matching what users paste and the DB
    // stores everywhere else.
    let bytes = {
        use sequoia_openpgp::serialize::stream::{Armorer, Message};
        let mut sink = Vec::new();
        let message = Message::new(&mut sink);
        let mut armorer = Armorer::new(message)
            .kind(sequoia_openpgp::armor::Kind::PublicKey)
            .build()
            .map_err(|_| "The merged certificate could not be serialized.".to_string())?;
        use sequoia_openpgp::serialize::Serialize as _;
        merged
            .serialize(&mut armorer)
            .map_err(|_| "The merged certificate could not be serialized.".to_string())?;
        armorer
            .finalize()
            .map_err(|_| "The merged certificate could not be serialized.".to_string())?;
        sink
    };
    validate_cert(&bytes).map_err(|_| {
        "The merged certificate is not usable under the upload policy.".to_string()
    })?;
    Ok(bytes)
}

/// Store a validated refresh: the current key row keeps its version
/// and fingerprint; only the certificate bytes change (the fuller
/// signature set supersedes the stored one).
pub async fn refresh_certificate(
    pool: &PgPool,
    account_id: i64,
    new_cert: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE identity_keys SET certificate = $2
         WHERE account_id = $1 AND status = 'current'",
    )
    .bind(account_id)
    .bind(new_cert)
    .execute(pool)
    .await?;
    Ok(())
}

// -- disclosure unwrap (messaging audit MM1) ---------------------------------

/// A message recovered from a `gpg --unwrap --armor` paste: the
/// plaintext the server extracted, and whether an embedded signature
/// verified against the expected certificate. An unwrapped paste can
/// carry a signature made by anyone (or none); only a signature that
/// checks out against the OTHER party's order-pinned certificate
/// makes it evidence.
pub struct UnwrappedMessage {
    pub plaintext: String,
    pub verified: bool,
    /// When the first good signature was created, from its own
    /// creation-time subpacket, as a unix timestamp (verification-
    /// fix V4: disclosures compare this against the named message's
    /// arrival time — a signature far older than the message it
    /// claims to unwrap cannot make the disclosure verified
    /// evidence OF THAT MESSAGE). `None` with no good signature.
    pub signature_created_unix: Option<i64>,
}

struct UnwrapHelper {
    cert: Cert,
    good: usize,
    bad: usize,
    sig_created: Option<std::time::SystemTime>,
}

impl VerificationHelper for UnwrapHelper {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }
    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        // Never fail the stream on a bad signature: the plaintext is
        // still extracted and the disclosure is stored as an
        // unverified claim (the same standing a bad detached signature
        // had under the pre-MM1 form). Only the counts are recorded.
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    match r {
                        Ok(good) => {
                            self.good += 1;
                            if self.sig_created.is_none() {
                                use sequoia_openpgp::packet::signature::subpacket::{
                                    SubpacketTag, SubpacketValue,
                                };
                                if let Some(sp) = good
                                    .sig
                                    .hashed_area()
                                    .subpacket(SubpacketTag::SignatureCreationTime)
                                {
                                    if let SubpacketValue::SignatureCreationTime(ts) = sp.value()
                                    {
                                        self.sig_created = Some((*ts).into());
                                    }
                                }
                            }
                        }
                        Err(_) => self.bad += 1,
                    }
                }
            }
        }
        Ok(())
    }
}

/// Read a `gpg --unwrap --armor` paste as a (possibly signed) message
/// against the expected certificate, extracting the plaintext with
/// Sequoia. Returns None when the paste is not a readable OpenPGP
/// message at all. `verified` is true only when at least one
/// signature was present and every signature result was good.
pub fn extract_unwrapped_message(cert_bytes: &[u8], pasted: &[u8]) -> Option<UnwrappedMessage> {
    use std::io::Read as _;
    let cert = Cert::from_bytes(cert_bytes).ok()?;
    let policy = StandardPolicy::new();
    let mut verifier = VerifierBuilder::from_bytes(pasted)
        .ok()?
        .with_policy(&policy, None, UnwrapHelper { cert, good: 0, bad: 0, sig_created: None })
        .ok()?;
    let mut out = Vec::new();
    verifier.read_to_end(&mut out).ok()?;
    let helper = verifier.into_helper();
    Some(UnwrappedMessage {
        plaintext: String::from_utf8_lossy(&out).into_owned(),
        verified: helper.good > 0 && helper.bad == 0,
        signature_created_unix: helper.sig_created.map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &[u8] = include_bytes!("../tests/fixtures/key-a.asc");
    const KEY_B: &[u8] = include_bytes!("../tests/fixtures/key-b.asc");

    #[test]
    fn fixture_certs_validate() {
        let a = validate_cert(KEY_A).unwrap();
        assert_eq!(a.fingerprint, "72DD4E472D98B828FBFD4B6E509752BE48DA109D");
        assert!(a.warnings.iter().any(|w| w.contains("email")), "{:?}", a.warnings);
        let b = validate_cert(KEY_B).unwrap();
        assert_eq!(b.fingerprint, "3183B78A92ED3504BF1F00F6899089B33BDED014");
    }

    #[test]
    fn garbage_cert_rejected() {
        assert_eq!(validate_cert(b"not a key").unwrap_err(), KeyError::Malformed);
        assert_eq!(validate_cert(b"").unwrap_err(), KeyError::Malformed);
    }

    #[test]
    fn rotation_statement_parsing() {
        let good = "statement-format: marketplace-key-rotation-v1\nmarketplace-id: mkt_0123456789abcdef0123456789abcdef\naccount-id: acct_0123456789abcdef0123456789abcdef\nold-fingerprint: 72DD4E472D98B828FBFD4B6E509752BE48DA109D\nnew-fingerprint: 3183B78A92ED3504BF1F00F6899089B33BDED014\nrotated-at: 2026-10-13T16:00:00Z\n";
        let st = parse_rotation_statement(good, "mkt_0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(st.old_fingerprint.len(), 40);
        // Tampered: lowercase fingerprint, wrong marketplace, missing LF.
        assert!(parse_rotation_statement(&good.replace("72DD", "72dd"), "mkt_0123456789abcdef0123456789abcdef").is_none());
        assert!(parse_rotation_statement(good, "mkt_ffffffffffffffffffffffffffffffff").is_none());
        assert!(parse_rotation_statement(good.trim_end(), "mkt_0123456789abcdef0123456789abcdef").is_none());
    }
}
