// BLIND security tests — OpenPGP envelope validation.
// Authored independently from spec v2 (section 14, plus s3 and s23) and
// the Stage 0 API contract ONLY. The author has not seen any
// implementation code.
//
// Spec clauses traced (all s14 unless noted):
//   - s3 #13: only encrypted OpenPGP messages are accepted.
//   - s14.1 (size first): message size (64 KiB) is checked BEFORE parsing.
//   - s14.2 (structure): one or more PKESK packets, then exactly one
//     integrity-protected data packet (SEIPD v1 with MDC, or v2 AEAD).
//     Reject password-based session keys (SKESK), top-level literal or
//     compressed data, and legacy packets without integrity protection.
//   - s14.3 (recipients): at least one PKESK must name an encryption
//     subkey of the recipient's current certificate; any other PKESK must
//     name one of the sender's own registered keys; wildcard (hidden)
//     recipient IDs are rejected.
//   - s23 (Messaging): "Plaintext, SKESK, top-level literal data, legacy
//     unprotected packets, wildcard recipients, and wrong-recipient
//     messages are rejected. A message encrypted to the recipient and to
//     the sender's own key is accepted."
//
// Fixtures are generated at test time with the system `gpg` binary
// (std::process::Command only; no external crates): three fresh
// ed25519/cv25519 keys — recipient, sender, stranger — in a throwaway
// GNUPGHOME per test. Nothing here reads pre-made fixture files.
//
// Assertion style: `matches!` is used throughout so these tests do not
// assume trait derives (e.g. PartialEq / Debug) that the API contract
// does not state for EnvelopeReject. Where the contract maps a case to
// exactly one variant, that variant is asserted exactly. Where the
// variant classification is genuinely ambiguous in the contract, the
// test asserts the SET of plausible variants (and the rejection itself);
// each such case is recorded in README-BLIND.md.

use stage0_spike::envelope::{validate_envelope, EnvelopeReject};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const RECIPIENT: &str = "recipient@example.invalid";
const SENDER: &str = "sender@example.invalid";
const STRANGER: &str = "stranger@example.invalid";

const SIZE_CAP: usize = 64 * 1024; // s14.1 / contract: 64 KiB

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

fn run_gpg(home: &std::path::Path, args: &[String], what: &str) -> Vec<u8> {
    let out = Command::new("gpg")
        .env("GNUPGHOME", home)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{what}: failed to spawn gpg: {e}"));
    if !out.status.success() {
        panic!(
            "{what}: gpg exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.stdout
}

struct Fixture {
    home: PathBuf,
    recipient_cert: Vec<u8>,
    sender_cert: Vec<u8>,
    #[allow(dead_code)]
    stranger_cert: Vec<u8>,
}

impl Fixture {
    fn new(tag: &str) -> Fixture {
        let home = std::env::temp_dir().join(format!("blind-envelope-{tag}-{}", unique_suffix()));
        fs::create_dir_all(&home).expect("create GNUPGHOME");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700))
                .expect("restrict GNUPGHOME permissions");
        }
        for (role, email) in [
            ("Recipient", RECIPIENT),
            ("Sender", SENDER),
            ("Stranger", STRANGER),
        ] {
            // ed25519 signing primary + cv25519 encryption subkey, matching
            // the s8 requirement of a signing-capable key and an
            // encryption-capable subkey.
            let params = format!(
                "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nSubkey-Type: ecdh\nSubkey-Curve: cv25519\nName-Real: Blind {role}\nName-Email: {email}\nExpire-Date: 0\n%commit\n"
            );
            let param_path = home.join(format!("gen-{role}.params"));
            fs::write(&param_path, params).expect("write keygen params");
            run_gpg(
                &home,
                &[
                    "--batch".to_string(),
                    "--gen-key".to_string(),
                    param_path.to_string_lossy().into_owned(),
                ],
                &format!("generate {role} key"),
            );
        }
        let export = |email: &str| {
            run_gpg(
                &home,
                &[
                    "--armor".to_string(),
                    "--export".to_string(),
                    email.to_string(),
                ],
                &format!("export cert for {email}"),
            )
        };
        let recipient_cert = export(RECIPIENT);
        let sender_cert = export(SENDER);
        let stranger_cert = export(STRANGER);
        assert!(recipient_cert.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(sender_cert.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(stranger_cert.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        Fixture {
            home,
            recipient_cert,
            sender_cert,
            stranger_cert,
        }
    }

    /// Encrypt `plaintext` to `recipients`. `extra` passes raw additional
    /// gpg flags (e.g. --throw-keyids, --disable-mdc).
    fn encrypt(
        &self,
        plaintext: &[u8],
        recipients: &[&str],
        armor: bool,
        sign_as_sender: bool,
        extra: &[&str],
    ) -> Vec<u8> {
        let stem = format!("msg-{}", unique_suffix());
        let plain_path = self.home.join(format!("{stem}.txt"));
        let out_path = self.home.join(format!("{stem}.pgp"));
        fs::write(&plain_path, plaintext).expect("write plaintext");
        let mut args: Vec<String> = vec![
            "--batch".into(),
            "--yes".into(),
            "--pinentry-mode".into(),
            "loopback".into(),
            "--trust-model".into(),
            "always".into(),
        ];
        if armor {
            args.push("--armor".into());
        }
        if sign_as_sender {
            args.push("--sign".into());
            args.push("--local-user".into());
            args.push(SENDER.into());
        }
        args.push("--encrypt".into());
        for flag in extra {
            args.push((*flag).into());
        }
        for r in recipients {
            args.push("--recipient".into());
            args.push((*r).into());
        }
        args.push("--output".into());
        args.push(out_path.to_string_lossy().into_owned());
        args.push(plain_path.to_string_lossy().into_owned());
        run_gpg(&self.home, &args, "encrypt message");
        fs::read(&out_path).expect("read encrypted output")
    }

    /// Symmetric-only encryption: produces an SKESK packet (plus the data
    /// packet) and no PKESK at all.
    fn symmetric_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let stem = format!("sym-{}", unique_suffix());
        let plain_path = self.home.join(format!("{stem}.txt"));
        let out_path = self.home.join(format!("{stem}.pgp"));
        fs::write(&plain_path, plaintext).expect("write plaintext");
        let args: Vec<String> = vec![
            "--batch".into(),
            "--yes".into(),
            "--pinentry-mode".into(),
            "loopback".into(),
            "--passphrase".into(),
            "blind-test-passphrase".into(),
            "--armor".into(),
            "--symmetric".into(),
            "--output".into(),
            out_path.to_string_lossy().into_owned(),
            plain_path.to_string_lossy().into_owned(),
        ];
        run_gpg(&self.home, &args, "symmetric encrypt");
        fs::read(&out_path).expect("read symmetric output")
    }

    fn validate(&self, msg: &[u8]) -> Result<(), EnvelopeReject> {
        validate_envelope(msg, &self.recipient_cert, &self.sender_cert)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

const PLAINTEXT: &[u8] = b"blind test message body";

// ------------------------------------------------------------- acceptance ---

#[test]
fn accept_sign_encrypt_to_recipient_and_sender_armored() {
    // s14.3 + s23: THE canonical accepted shape — PKESK for the recipient
    // and PKESK for the sender's own key, then one integrity-protected
    // data packet. Signing follows the s14 compose-page guidance
    // (sign-then-encrypt); envelope validation itself is packet-level.
    let fx = Fixture::new("accept-both");
    let msg = fx.encrypt(PLAINTEXT, &[RECIPIENT, SENDER], true, true, &[]);
    let res = fx.validate(&msg);
    assert!(res.is_ok(), "recipient+sender sign+encrypt must be accepted");
}

#[test]
fn accept_encrypt_to_recipient_only_armored() {
    // s14.3: "at least one PKESK must name ... the recipient's" — a
    // recipient-only message satisfies the rule; extra PKESKs are the
    // constrained case, not a requirement.
    let fx = Fixture::new("accept-recipient-only");
    let msg = fx.encrypt(PLAINTEXT, &[RECIPIENT], true, false, &[]);
    let res = fx.validate(&msg);
    assert!(res.is_ok(), "recipient-only encryption must be accepted");
}

#[test]
fn accept_sign_encrypt_to_recipient_and_sender_binary() {
    // Contract: input may be "armored or binary". Same message as the
    // first acceptance test, without ASCII armor.
    let fx = Fixture::new("accept-binary");
    let msg = fx.encrypt(PLAINTEXT, &[RECIPIENT, SENDER], false, true, &[]);
    assert!(
        !msg.starts_with(b"-----BEGIN"),
        "test construction failed: expected binary, got armor"
    );
    let res = fx.validate(&msg);
    assert!(res.is_ok(), "binary recipient+sender message must be accepted");
}

// -------------------------------------------------------------- rejection ---

#[test]
fn reject_plaintext() {
    // s3 #13 / s23: plaintext is not an encrypted OpenPGP message.
    // Variant classification is ambiguous (see README-BLIND.md item E1):
    // raw text is arguably Plaintext, Malformed, or NotArmoredOrBinary.
    // The security property asserted here is rejection with one of those.
    let fx = Fixture::new("reject-plaintext");
    let res = fx.validate(b"this is a plaintext message, not ciphertext");
    assert!(
        matches!(
            res,
            Err(EnvelopeReject::Plaintext)
                | Err(EnvelopeReject::Malformed)
                | Err(EnvelopeReject::NotArmoredOrBinary)
        ),
        "plaintext must be rejected as Plaintext/Malformed/NotArmoredOrBinary"
    );
}

#[test]
fn reject_symmetric_only_skesk() {
    // s14.2: password-based session keys (SKESK) are rejected. The
    // contract maps this to exactly one variant: SymmetricSessionKey.
    let fx = Fixture::new("reject-skesk");
    let msg = fx.symmetric_encrypt(PLAINTEXT);
    let res = fx.validate(&msg);
    assert!(
        matches!(res, Err(EnvelopeReject::SymmetricSessionKey)),
        "symmetric-only (SKESK) message must be rejected as SymmetricSessionKey"
    );
}

#[test]
fn reject_encrypt_to_stranger_only() {
    // s14.3 / s23: no PKESK names the recipient -> wrong recipient.
    // Variant is ambiguous between WrongRecipient and UnknownRecipient
    // (README-BLIND.md item E2); rejection with either is asserted.
    let fx = Fixture::new("reject-stranger");
    let msg = fx.encrypt(PLAINTEXT, &[STRANGER], true, false, &[]);
    let res = fx.validate(&msg);
    assert!(
        matches!(
            res,
            Err(EnvelopeReject::WrongRecipient) | Err(EnvelopeReject::UnknownRecipient)
        ),
        "stranger-only encryption must be rejected"
    );
}

#[test]
fn reject_encrypt_to_recipient_and_stranger() {
    // s14.3: "Any other PKESK must name one of the sender's own registered
    // keys." A valid recipient PKESK does NOT launder an additional
    // stranger PKESK.
    let fx = Fixture::new("reject-recipient-plus-stranger");
    let msg = fx.encrypt(PLAINTEXT, &[RECIPIENT, STRANGER], true, false, &[]);
    let res = fx.validate(&msg);
    assert!(
        matches!(
            res,
            Err(EnvelopeReject::WrongRecipient) | Err(EnvelopeReject::UnknownRecipient)
        ),
        "recipient+stranger encryption must be rejected"
    );
}

#[test]
fn reject_throw_keyids_wildcard_recipient() {
    // s14.3: wildcard (hidden) recipient IDs are rejected. gpg's
    // --throw-keyids zeroes the key ID in every PKESK packet, which is
    // exactly the wildcard shape. The contract maps this to exactly one
    // variant: WildcardRecipient.
    let fx = Fixture::new("reject-wildcard");
    let msg = fx.encrypt(PLAINTEXT, &[RECIPIENT], true, false, &["--throw-keyids"]);
    let res = fx.validate(&msg);
    assert!(
        matches!(res, Err(EnvelopeReject::WildcardRecipient)),
        "hidden-recipient (throw-keyids) message must be rejected as WildcardRecipient"
    );
}

#[test]
fn reject_legacy_packet_without_integrity_protection() {
    // s14.2: legacy packets without integrity protection are rejected.
    // gpg's --disable-mdc produces a symmetrically-encrypted data packet
    // with no MDC (SEIPD absent). The contract maps this to exactly one
    // variant: LegacyNoIntegrity. (Assumes a gpg that honours
    // --disable-mdc; see README-BLIND.md item E4.)
    let fx = Fixture::new("reject-legacy");
    let msg = fx.encrypt(PLAINTEXT, &[RECIPIENT], true, false, &["--disable-mdc"]);
    let res = fx.validate(&msg);
    assert!(
        matches!(res, Err(EnvelopeReject::LegacyNoIntegrity)),
        "message without integrity protection must be rejected as LegacyNoIntegrity"
    );
}

#[test]
fn reject_oversize_input_before_parsing() {
    // s14.1 / contract: the 64 KiB cap is checked BEFORE parsing, so even
    // unparseable oversize input must come back as TooLarge, not as a
    // parse error.
    let fx = Fixture::new("reject-oversize-garbage");
    let big = vec![b'A'; SIZE_CAP + 1];
    let res = fx.validate(&big);
    assert!(
        matches!(res, Err(EnvelopeReject::TooLarge)),
        "oversize input must be rejected as TooLarge before parsing"
    );
}

#[test]
fn reject_oversize_but_otherwise_valid_message() {
    // s14.1: the cap applies to real messages too — a properly encrypted
    // message over 64 KiB is still rejected. (The plaintext alone exceeds
    // the cap, so this holds whether the cap is measured on the armored
    // bytes or the decoded bytes; see README-BLIND.md item E3.)
    let fx = Fixture::new("reject-oversize-valid");
    let big_plain = vec![b'x'; SIZE_CAP + 8_192];
    let msg = fx.encrypt(&big_plain, &[RECIPIENT], true, false, &[]);
    assert!(msg.len() > SIZE_CAP, "test construction failed: message not oversize");
    let res = fx.validate(&msg);
    assert!(
        matches!(res, Err(EnvelopeReject::TooLarge)),
        "oversize valid message must be rejected as TooLarge"
    );
}

#[test]
fn reject_empty_input() {
    // An empty submission is not an OpenPGP message. Variant ambiguous
    // between Malformed and NotArmoredOrBinary (README-BLIND.md item E1).
    let fx = Fixture::new("reject-empty");
    let res = fx.validate(&[]);
    assert!(
        matches!(
            res,
            Err(EnvelopeReject::Malformed) | Err(EnvelopeReject::NotArmoredOrBinary)
        ),
        "empty input must be rejected"
    );
}
