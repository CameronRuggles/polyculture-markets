//! OpenPGP key handling for the helper (§14): certificate parsing,
//! detached-signature verification (the same construction the
//! marketplace uses against pinned keys), detached signing with the
//! user's own key, and reading a signature's creation time (the
//! buyer's verify checks the assignment's expiry against when it was
//! actually signed, §14 check 6). Sequoia is the backend, as
//! everywhere in this build (Q8).

use sequoia_openpgp::armor::Kind as ArmorKind;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use sequoia_openpgp::parse::{PacketParser, Parse};
use sequoia_openpgp::packet::Packet;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
use sequoia_openpgp::serialize::Marshal;
use sequoia_openpgp::Cert;
use std::io::Write;

/// The primary fingerprint of a certificate, uppercase hex.
pub fn fingerprint_of(cert_bytes: &[u8]) -> Result<String, String> {
    let cert = Cert::from_bytes(cert_bytes).map_err(|e| format!("unparseable certificate: {e}"))?;
    Ok(cert.fingerprint().to_hex())
}

struct Helper {
    cert: Cert,
    good: bool,
}

impl VerificationHelper for Helper {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
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

/// Verify an armored detached signature over exact bytes against a
/// certificate. Any bad signature result fails the whole check.
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

/// The creation time of the first signature packet in a detached
/// signature, as unix seconds. OpenPGP signatures always carry a
/// creation time; `None` means the input held no readable signature.
pub fn signature_created(sig_armored: &[u8]) -> Option<i64> {
    let sequoia_openpgp::parse::PacketParserResult::Some(parser) =
        PacketParser::from_bytes(sig_armored).ok()?
    else {
        return None;
    };
    let (packet, _) = parser.next().ok()?;
    if let Packet::Signature(sig) = packet {
        let created = sig.signature_creation_time()?;
        return created
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs() as i64);
    }
    None
}

/// Produce an armored detached signature over `message` with the
/// signing key of a secret certificate. `passphrase` decrypts an
/// encrypted key; a wrong or missing passphrase for an encrypted
/// key is an error, never a silent skip.
pub fn sign_detached(
    secret_cert_bytes: &[u8],
    passphrase: Option<&str>,
    message: &[u8],
) -> Result<String, String> {
    let cert = Cert::from_bytes(secret_cert_bytes)
        .map_err(|e| format!("unparseable secret key: {e}"))?;
    if !cert.is_tsk() {
        return Err("the key file holds no secret key material".to_string());
    }
    let policy = StandardPolicy::new();
    let mut keypair = None;
    for ka in cert
        .keys()
        .with_policy(&policy, None)
        .secret()
        .for_signing()
    {
        let key = ka.key().clone();
        let key = if key.secret().is_encrypted() {
            match passphrase {
                Some(p) => match key.decrypt_secret(&p.into()) {
                    Ok(k) => k,
                    Err(_) => return Err("the key passphrase was not accepted".to_string()),
                },
                None => return Err("the signing key is encrypted: a passphrase is required".to_string()),
            }
        } else {
            key
        };
        match key.into_keypair() {
            Ok(kp) => {
                keypair = Some(kp);
                break;
            }
            Err(_) => continue,
        }
    }
    let keypair = keypair.ok_or_else(|| "no usable signing key on the certificate".to_string())?;
    let mut sink = Vec::new();
    {
        let message_writer = Message::new(&mut sink);
        let message_writer = Armorer::new(message_writer)
            .kind(ArmorKind::Signature)
            .build()
            .map_err(|e| format!("signing failed: {e}"))?;
        let mut signer = Signer::new(message_writer, keypair)
            .map_err(|e| format!("signing failed: {e}"))?
            .detached()
            .build()
            .map_err(|e| format!("signing failed: {e}"))?;
        signer
            .write_all(message)
            .map_err(|e| format!("signing failed: {e}"))?;
        signer
            .finalize()
            .map_err(|e| format!("signing failed: {e}"))?;
    }
    String::from_utf8(sink).map_err(|_| "signature armor was not UTF-8".to_string())
}

/// Generate a throwaway signing+encryption certificate for tests
/// and first-run flows; returns (secret armored, public armored).
/// NOT a substitute for the user's own long-lived key — the helper
/// never generates a user's identity key in normal operation (§14:
/// users bring existing keys); this exists so tests and demos can
/// run without GnuPG.
pub fn generate_test_cert(user_id: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (cert, _rev) = CertBuilder::new()
        .add_userid(user_id)
        .add_signing_subkey()
        .add_storage_encryption_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .map_err(|e| format!("key generation failed: {e}"))?;
    fn armor(kind: ArmorKind, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut w = sequoia_openpgp::armor::Writer::new(Vec::new(), kind)
            .map_err(|e| e.to_string())?;
        w.write_all(bytes).map_err(|e| e.to_string())?;
        w.finalize().map_err(|e| e.to_string())
    }
    let mut secret = Vec::new();
    cert.as_tsk().serialize(&mut secret).map_err(|e| e.to_string())?;
    let mut public = Vec::new();
    cert.serialize(&mut public).map_err(|e| e.to_string())?;
    Ok((
        armor(ArmorKind::SecretKey, &secret)?,
        armor(ArmorKind::PublicKey, &public)?,
    ))
}
