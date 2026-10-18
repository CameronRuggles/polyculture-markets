//! Spike 2: ciphertext envelope validation (spec §14) via sequoia-openpgp
//! packet-level parsing. The server never decrypts — it only inspects the
//! packet structure and PKESK recipient key IDs.

use sequoia_openpgp as openpgp;
use openpgp::packet::Packet;
use openpgp::parse::Parse;
use std::collections::HashSet;

pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeReject {
    TooLarge,
    NotArmoredOrBinary,
    Plaintext,
    SymmetricSessionKey,
    LegacyNoIntegrity,
    WildcardRecipient,
    WrongRecipient,
    UnknownRecipient,
    Malformed,
}

/// All key IDs and fingerprints of every key (primary + subkeys) in a cert,
/// as uppercase hex. Key IDs of v4 keys are the low 64 bits of the fingerprint,
/// so a PKESK naming a key matches either its full fingerprint or its key ID.
fn cert_key_handles(cert_bytes: &[u8]) -> Result<HashSet<String>, EnvelopeReject> {
    let cert = openpgp::Cert::from_bytes(cert_bytes).map_err(|_| EnvelopeReject::Malformed)?;
    let mut set = HashSet::new();
    for k in cert.keys() {
        let key = k.key();
        set.insert(format!("{:X}", key.fingerprint()));
        set.insert(format!("{:X}", key.keyid()));
    }
    Ok(set)
}

fn handle_matches(handle: &openpgp::KeyHandle, set: &HashSet<String>) -> bool {
    let h = format!("{handle:X}");
    if set.contains(&h) {
        return true;
    }
    // A v6 fingerprint handle: its key ID is the *first* 8 bytes; a v4
    // fingerprint's key ID is the *last* 8 bytes. Accept either alias.
    if h.len() > 16 {
        if set.contains(&h[..16]) || set.contains(&h[h.len() - 16..]) {
            return true;
        }
        // Or the handle is a key ID and the set holds the full fingerprint ending/starting with it.
        return set.iter().any(|f| f.ends_with(&h) || f.starts_with(&h));
    }
    set.iter().any(|f| f.ends_with(&h))
}

pub fn validate_envelope(
    msg: &[u8],
    recipient_cert_armored: &[u8],
    sender_cert_armored: &[u8],
) -> Result<(), EnvelopeReject> {
    // §14 step 1: size before parsing.
    if msg.len() > MAX_MESSAGE_BYTES {
        return Err(EnvelopeReject::TooLarge);
    }
    let recipient_keys = cert_key_handles(recipient_cert_armored)?;
    let sender_keys = cert_key_handles(sender_cert_armored)?;

    let pile = openpgp::PacketPile::from_bytes(msg).map_err(|_| EnvelopeReject::NotArmoredOrBinary)?;
    let top: Vec<&Packet> = pile.children().collect();
    if top.is_empty() {
        return Err(EnvelopeReject::Malformed);
    }
    // §14.1 packet-count cap (32). NOTE: this counts top-level packets only —
    // the SEIP body is (correctly) unparsed, so nested packets inside the
    // encrypted container are not visible to the envelope check at all.
    // Blind-suite ambiguity E5 refers.
    if top.len() > 32 {
        return Err(EnvelopeReject::Malformed);
    }
    // SKESK anywhere at the top level is an immediate reject (§14.2).
    if top.iter().any(|p| matches!(p, Packet::SKESK(_))) {
        return Err(EnvelopeReject::SymmetricSessionKey);
    }
    // First packet(s) must be PKESK; a literal/compressed first packet is plaintext structure.
    let mut idx = 0;
    let mut pkesk_recipients: Vec<Option<openpgp::KeyHandle>> = Vec::new();
    while idx < top.len() {
        match &top[idx] {
            Packet::PKESK(p) => {
                pkesk_recipients.push(p.recipient());
                idx += 1;
            }
            _ => break,
        }
    }
    if pkesk_recipients.is_empty() {
        return match &top[0] {
            Packet::Literal(_) | Packet::CompressedData(_) => Err(EnvelopeReject::Plaintext),
            Packet::SEIP(_) => Err(EnvelopeReject::Malformed), // encrypted to nobody visible
            _ => Err(EnvelopeReject::Plaintext),
        };
    }
    // Exactly one packet after the PKESKs, and it must be a SEIP (integrity-protected).
    if idx >= top.len() {
        return Err(EnvelopeReject::LegacyNoIntegrity); // PKESKs but no data packet found
    }
    match &top[idx] {
        Packet::SEIP(_) => {}
        // FINDING (spike): GnuPG 2.4 emits the LibrePGP AEAD Encrypted Data
        // packet (tag 20, AED) by default for AEAD-capable keys; sequoia 2.4
        // surfaces it as Packet::Unknown with tag AED. It IS integrity
        // protected (AEAD), and §14's own suggested gpg command produces it,
        // so the spike accepts it. The spec should say explicitly whether
        // tag-20 AED counts alongside SEIPD v1 / SEIP v2 — flagged in report.
        Packet::Unknown(u) if u.tag() == openpgp::packet::Tag::AED => {}
        // Legacy symmetrically-encrypted packet without integrity protection,
        // or a bare literal packet trailing the session keys.
        _ => return Err(EnvelopeReject::LegacyNoIntegrity),
    }
    if idx != top.len() - 1 {
        return Err(EnvelopeReject::Malformed); // trailing packets after the SEIP
    }

    // §14.3 recipients: no wildcards; every PKESK names recipient's or sender's own key;
    // at least one names the recipient.
    let mut saw_recipient = false;
    for r in &pkesk_recipients {
        match r {
            None => return Err(EnvelopeReject::WildcardRecipient),
            Some(h) => {
                let hs = format!("{h:X}");
                if hs == "0000000000000000" || hs.chars().all(|c| c == '0') {
                    return Err(EnvelopeReject::WildcardRecipient);
                }
                if handle_matches(h, &recipient_keys) {
                    saw_recipient = true;
                } else if handle_matches(h, &sender_keys) {
                    // sender encrypting to self: allowed (§14 compose guidance)
                } else {
                    return Err(EnvelopeReject::UnknownRecipient);
                }
            }
        }
    }
    if !saw_recipient {
        return Err(EnvelopeReject::WrongRecipient);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::OnceLock;

    /// GPG fixture keyring built once per test run: recipient, sender, stranger.
    struct Fixture {
        dir: std::path::PathBuf,
        recipient_cert: Vec<u8>,
        sender_cert: Vec<u8>,
        recipient_fpr: String,
        sender_fpr: String,
        stranger_fpr: String,
    }

    static FIXTURE: OnceLock<Fixture> = OnceLock::new();

    fn fixture() -> &'static Fixture {
        FIXTURE.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("stage0-env-{}", std::process::id()));
            let home = dir.join("gnupg");
            std::fs::create_dir_all(&home).unwrap();
            // Restrictive perms or gpg refuses the homedir.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let gpg = |args: &[&str], input: Option<&str>| -> String {
                let mut cmd = Command::new("gpg");
                cmd.args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""])
                    .arg("--homedir").arg(&home).args(args);
                let out = if let Some(inp) = input {
                    use std::io::Write;
                    let mut child = cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
                    child.stdin.as_mut().unwrap().write_all(inp.as_bytes()).unwrap();
                    child.wait_with_output().unwrap()
                } else {
                    cmd.output().unwrap()
                };
                assert!(out.status.success(), "gpg {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
                String::from_utf8_lossy(&out.stdout).to_string()
            };
            let mk = |name: &str| -> String {
                gpg(&["--quick-generate-key", &format!("{name} <{name}@spike.test>"), "ed25519", "sign", "never"], None);
                let list = gpg(&["--with-colons", "--list-keys", &format!("{name}@spike.test")], None);
                let mut fpr = String::new();
                for line in list.lines() {
                    let f: Vec<&str> = line.split(':').collect();
                    if f.first() == Some(&"fpr") { fpr = f[9].to_string(); break; }
                }
                assert!(!fpr.is_empty(), "no fpr for {name}");
                gpg(&["--quick-add-key", &fpr, "cv25519", "encr", "never"], None);
                fpr
            };
            let recipient_fpr = mk("recipient");
            let sender_fpr = mk("sender");
            let stranger_fpr = mk("stranger");
            let export = |fpr: &str| gpg(&["--armor", "--export", fpr], None).into_bytes();
            Fixture {
                recipient_cert: export(&recipient_fpr),
                sender_cert: export(&sender_fpr),
                dir,
                recipient_fpr,
                sender_fpr,
                stranger_fpr,
            }
        })
    }

    fn gpg_encrypt(fx: &Fixture, extra_args: &[&str], recipients: &[&str]) -> Vec<u8> {
        let home = fx.dir.join("gnupg");
        let mut cmd = Command::new("gpg");
        cmd.args(["--batch", "--yes", "--trust-model", "always", "--pinentry-mode", "loopback", "--passphrase", "", "--armor", "--encrypt"])
            .arg("--homedir").arg(&home).args(extra_args);
        for r in recipients {
            cmd.arg("--recipient").arg(r);
        }
        use std::io::Write;
        let mut child = cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.as_mut().unwrap().write_all(b"shipping address inside").unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "encrypt failed: {}", String::from_utf8_lossy(&out.stderr));
        out.stdout
    }

    #[test]
    fn accepts_encrypt_to_recipient_and_sender() {
        let fx = fixture();
        let msg = gpg_encrypt(fx, &[], &[&fx.recipient_fpr, &fx.sender_fpr]);
        assert_eq!(validate_envelope(&msg, &fx.recipient_cert, &fx.sender_cert), Ok(()));
    }

    #[test]
    fn accepts_seipd1_in_rfc4880_mode() {
        let fx = fixture();
        let msg = gpg_encrypt(fx, &["--openpgp", "--force-mdc", "--cipher-algo", "AES256"], &[&fx.recipient_fpr, &fx.sender_fpr]);
        assert_eq!(validate_envelope(&msg, &fx.recipient_cert, &fx.sender_cert), Ok(()));
    }

    #[test]
    fn rejects_plaintext() {
        let fx = fixture();
        assert_eq!(
            validate_envelope(b"just plain text, no packets here at all", &fx.recipient_cert, &fx.sender_cert),
            Err(EnvelopeReject::NotArmoredOrBinary)
        );
        // A literal-data-only PGP message (gpg clearsign-style data packet) is not encryption.
        let home = fx.dir.join("gnupg");
        let out = Command::new("gpg").args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--store"])
            .arg("--homedir").arg(&home)
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .spawn().and_then(|mut c| { use std::io::Write; c.stdin.as_mut().unwrap().write_all(b"hello").unwrap(); c.wait_with_output() }).unwrap();
        if out.status.success() {
            assert_eq!(
                validate_envelope(&out.stdout, &fx.recipient_cert, &fx.sender_cert),
                Err(EnvelopeReject::Plaintext)
            );
        }
    }

    #[test]
    fn rejects_symmetric_skesk() {
        let fx = fixture();
        let home = fx.dir.join("gnupg");
        let mut child = Command::new("gpg").args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "pw12345", "--armor", "--symmetric", "--cipher-algo", "AES256"])
            .arg("--homedir").arg(&home)
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(b"secret").unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        assert_eq!(
            validate_envelope(&out.stdout, &fx.recipient_cert, &fx.sender_cert),
            Err(EnvelopeReject::SymmetricSessionKey)
        );
    }

    #[test]
    fn rejects_wrong_recipient_stranger() {
        let fx = fixture();
        let msg = gpg_encrypt(fx, &[], &[&fx.stranger_fpr]);
        let r = validate_envelope(&msg, &fx.recipient_cert, &fx.sender_cert);
        assert!(r == Err(EnvelopeReject::UnknownRecipient) || r == Err(EnvelopeReject::WrongRecipient), "got {r:?}");
    }

    #[test]
    fn rejects_hidden_recipient() {
        let fx = fixture();
        let msg = gpg_encrypt(fx, &["--throw-keyids"], &[&fx.recipient_fpr]);
        assert_eq!(
            validate_envelope(&msg, &fx.recipient_cert, &fx.sender_cert),
            Err(EnvelopeReject::WildcardRecipient)
        );
    }

    #[test]
    fn rejects_oversized_before_parsing() {
        let fx = fixture();
        let big = vec![b'A'; MAX_MESSAGE_BYTES + 1];
        assert_eq!(validate_envelope(&big, &fx.recipient_cert, &fx.sender_cert), Err(EnvelopeReject::TooLarge));
    }
}
