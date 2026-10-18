//! BLIND SECURITY SUITE — Stage 3: identity keys, rotation, key-history storage.
//!
//! Written from the specification alone (Spec v2 §8/§10/§16, the ratified
//! amendments, and `docs/api-contract.md` §9). The author has never seen the
//! implementation. Failures are to be fixed in the code, never in these tests
//! (spec §22); fixture *constructions* may change only with the owner's sight
//! of the diff.
//!
//! =========================================================================
//! PLAIN-LANGUAGE ASSERTION LIST (for the owner)
//! =========================================================================
//!
//! A. Certificate validation (validate_cert)
//!  1. A normal key (signing primary + encryption subkey) is accepted.
//!  2. The fingerprint it reports is exactly the primary fingerprint gpg
//!     reports for that key, in uppercase hex.
//!  3. Every user ID on the key is listed in the result.
//!  4. The same key exported in binary (non-armored) form is also accepted
//!     and reports the same fingerprint.
//!  5. A key whose user ID contains an email address produces a warning
//!     that mentions email (that user ID becomes public on the site).
//!  6. A key whose only user ID is a plain one-word pseudonym produces no
//!     warnings at all.
//!  7. Random garbage bytes are rejected as Malformed.
//!  8. Empty input is rejected as Malformed.
//!  9. A key that can sign but has NO encryption subkey is rejected with
//!     NoEncryptionSubkey.
//! 10. A key that can encrypt but has NO signing-capable key is rejected
//!     with NoSigningKey.
//! 11. An expired key is rejected with PolicyInvalid.
//! 12. A revoked key is rejected with PolicyInvalid (skipped at runtime if
//!     the revocation fixture cannot be constructed deterministically).
//!
//! B. Detached signature verification (verify_detached)
//! 13. A signature made by a key over some exact bytes verifies as true
//!     against that key's certificate.
//! 14. Changing even one byte of the signed bytes makes verification false.
//! 15. A signature made by a DIFFERENT key does not verify against the
//!     first key's certificate.
//! 16. Garbage signature bytes return false — they must not crash or error
//!     the caller (the function returns a plain bool).
//! 17. An empty signature returns false.
//! 18. Both the old key and the new key can sign a key-rotation statement
//!     and each signature verifies against its own certificate (this is
//!     what a certified rotation is built from).
//! 19. The old key's statement signature does NOT verify against the new
//!     key's certificate.
//!
//! C. Rotation statement parsing (parse_rotation_statement)
//! 20. A statement built exactly by the rules (fixed field order,
//!     statement-format / marketplace-id / account-id / old-fingerprint /
//!     new-fingerprint / rotated-at) parses, and every field comes back
//!     exactly as written.
//! 21. A statement using 64-hex fingerprints also parses (both lengths
//!     are legal).
//! Each of these single changes makes the statement be rejected:
//! 22. The marketplace-id in the statement is not this instance's id.
//! 23. The account-id uses the old short shape (acct_ + 12 hex) instead of
//!     the pinned acct_ + 32 hex shape.
//! 24. A fingerprint is lowercase.
//! 25. A fingerprint is 39 characters long.
//! 26. A fingerprint is 41 characters long.
//! 27. Two fields are swapped out of their fixed order.
//! 28. The final newline is missing.
//! 29. There are two final newlines instead of exactly one.
//! 30. A line ends with CRLF instead of LF.
//! 31. A tab character appears anywhere in the statement.
//! 32. rotated-at has month 13 (a date that does not exist).
//! 33. rotated-at has a leap second (:60), which is not allowed.
//! 34. rotated-at is missing its trailing Z.
//! 35. rotated-at uses a space instead of the T between date and time.
//! 36. An extra, unknown field line is present.
//! 37. A required field line is missing.
//!
//! D. Key storage (database; skipped unless DATABASE_URL is set)
//! 38. Installing an account's first key makes it the one current key,
//!     at version 1, and current_key returns it.
//! 39. Installing a second key retires the first key in the same
//!     operation: afterwards there is still exactly ONE current key, the
//!     old key's history entry says "retired" with a real retirement
//!     date, and the new key's validity starts at or after the moment
//!     the old one was retired.
//! 40. A record of that rotation exists in key_rotations, naming the old
//!     and new fingerprints.
//! 41. The account's key history lists both keys (old and new).
//! 42. A rotation recorded as certified is NOT reported as an uncertified
//!     rotation.
//! 43. A rotation recorded as uncertified (old key lost) IS reported by
//!     latest_uncertified_rotation (it is inside the 90-day window).
//! 44. An account that never rotated has no uncertified rotation.
//!
//! E. Conversation key sightings — the Q16 leak fix (database)
//! 45. In a conversation, the key that was current when the conversation
//!     was created counts as "shown" even before any sighting is
//!     recorded — derived from the contract: sightings OR the key's
//!     validity interval overlapping the conversation.
//! 46. A key that was already retired BEFORE the conversation was created
//!     does NOT count as shown in it (its interval never overlaps).
//! 47. Once the server records that the retired key was shown in that
//!     exact conversation, it counts as shown there.
//! 48. Recording a sighting in one conversation does NOT make the key
//!     count as shown in a different conversation — history from other
//!     conversations must never leak across (the Q16 leak-fix probe).
//! 49. A key that was only installed AFTER a conversation was created,
//!     and was never sighted in it, does not count as shown in it.
//! 50. A key belonging to an account that is not a participant in the
//!     conversation never counts as shown in it.
//!
//! NOT COVERED HERE (by assignment): "account recovery never touches
//! keys" is a Stage 1 / web-layer property and is not testable through
//! the Stage 3 surface.
//! =========================================================================

use app::keys::{self, KeyError};
use sqlx::PgPool;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// gpg fixture construction (allowed: fixtures, not implementation knowledge)
// ---------------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "blind-stage3-{}-{}-{}",
        std::process::id(),
        tag,
        n
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    std::io::Read::read_exact(&mut f, &mut buf).expect("read /dev/urandom");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// A throwaway GNUPGHOME. Offline by construction: batch mode, loopback
/// pinentry, no keyserver options anywhere.
struct GpgHome {
    dir: PathBuf,
}

impl GpgHome {
    fn new(tag: &str) -> Self {
        let dir = unique_dir(tag);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod GNUPGHOME");
        }
        GpgHome { dir }
    }

    fn run(&self, args: &[&str]) -> String {
        let out = Command::new("gpg")
            .args(["--batch", "--yes", "--pinentry-mode", "loopback"])
            .args(args)
            .env("GNUPGHOME", &self.dir)
            .output()
            .expect("run gpg");
        assert!(
            out.status.success(),
            "gpg {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn run_bytes(&self, args: &[&str]) -> Vec<u8> {
        let out = Command::new("gpg")
            .args(["--batch", "--yes", "--pinentry-mode", "loopback"])
            .args(args)
            .env("GNUPGHOME", &self.dir)
            .output()
            .expect("run gpg");
        assert!(
            out.status.success(),
            "gpg {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    /// Generate a key from a batch parameter block; returns the primary
    /// fingerprint (uppercase hex) as reported by gpg itself.
    fn gen_key(&self, params: &str) -> String {
        let param_file = self.dir.join("params.txt");
        std::fs::write(&param_file, params).expect("write key params");
        self.run(&["--gen-key", param_file.to_str().unwrap()]);
        self.primary_fingerprint()
    }

    fn primary_fingerprint(&self) -> String {
        let listing = self.run(&["--with-colons", "--list-keys"]);
        for line in listing.lines() {
            if line.starts_with("fpr:") {
                let fpr = line.split(':').nth(9).expect("fpr field").to_string();
                assert_eq!(fpr.len(), 40, "expected a v4 fingerprint from gpg");
                return fpr;
            }
        }
        panic!("no fingerprint in gpg listing:\n{listing}");
    }

    /// The first user ID string exactly as gpg reports it, e.g.
    /// "nightowl <nightowl@example.com>" or "nightowl".
    fn first_user_id(&self) -> String {
        let listing = self.run(&["--with-colons", "--list-keys"]);
        for line in listing.lines() {
            if line.starts_with("uid:") {
                return line.split(':').nth(9).expect("uid field").to_string();
            }
        }
        panic!("no uid in gpg listing:\n{listing}");
    }

    fn export_armored(&self, fpr: &str) -> Vec<u8> {
        self.run_bytes(&["--armor", "--export", fpr])
    }

    fn export_binary(&self, fpr: &str) -> Vec<u8> {
        self.run_bytes(&["--export", fpr])
    }

    /// Armored detached signature over `message`, made by `fpr`.
    fn sign_detached(&self, fpr: &str, message: &[u8]) -> Vec<u8> {
        let msg_file = self.dir.join("message.bin");
        std::fs::write(&msg_file, message).expect("write message");
        let sig_file = self.dir.join("message.asc");
        self.run(&[
            "--armor",
            "--detach-sign",
            "--local-user",
            fpr,
            "--output",
            sig_file.to_str().unwrap(),
            msg_file.to_str().unwrap(),
        ]);
        std::fs::read(&sig_file).expect("read signature")
    }

    fn is_revoked(&self) -> bool {
        let listing = self.run(&["--with-colons", "--list-keys"]);
        listing
            .lines()
            .any(|l| l.starts_with("pub:") && l.split(':').nth(1) == Some("r"))
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Standard fixture: signing-capable ed25519 primary + cv25519 encryption
/// subkey, no passphrase. `email: Some(..)` puts an email in the user ID.
fn standard_key(tag: &str, uid: &str, email: Option<&str>) -> (GpgHome, String) {
    let home = GpgHome::new(tag);
    let mut params = String::from(
        "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign\n",
    );
    params.push_str(&format!("Name-Real: {uid}\n"));
    if let Some(e) = email {
        params.push_str(&format!("Name-Email: {e}\n"));
    }
    params.push_str(
        "Expire-Date: 0\nSubkey-Type: ecdh\nSubkey-Curve: cv25519\nSubkey-Usage: encrypt\n%commit\n",
    );
    let fpr = home.gen_key(&params);
    (home, fpr)
}

// ---------------------------------------------------------------------------
// A. Certificate validation
// ---------------------------------------------------------------------------

#[test]
fn valid_cert_validates_and_matches_gpg_fingerprint() {
    let (home, fpr) = standard_key("valid", "nightowl", None);
    let cert = home.export_armored(&fpr);
    let info = keys::validate_cert(&cert).expect("well-formed cert must validate");
    assert_eq!(
        info.fingerprint, fpr,
        "reported fingerprint must be gpg's primary fingerprint (uppercase hex)"
    );
    assert_eq!(
        info.fingerprint,
        info.fingerprint.to_uppercase(),
        "fingerprint must be uppercase hex"
    );
    let uid = home.first_user_id();
    assert_eq!(
        info.user_ids,
        vec![uid],
        "every user ID on the cert must be surfaced"
    );
}

#[test]
fn binary_cert_validates_with_same_fingerprint() {
    let (home, fpr) = standard_key("binary", "nightowl", None);
    let cert = home.export_binary(&fpr);
    let info = keys::validate_cert(&cert).expect("binary cert must validate");
    assert_eq!(info.fingerprint, fpr);
}

#[test]
fn email_user_id_produces_email_warning() {
    let (home, fpr) = standard_key("emailuid", "nightowl", Some("nightowl@example.com"));
    let cert = home.export_armored(&fpr);
    let info = keys::validate_cert(&cert).expect("cert with email UID is still valid");
    assert!(
        info.user_ids
            .iter()
            .any(|u| u.contains("nightowl@example.com")),
        "the email-bearing user ID must be surfaced, got {:?}",
        info.user_ids
    );
    assert!(
        info.warnings
            .iter()
            .any(|w| w.to_lowercase().contains("email")),
        "a user ID containing an email address must produce an email warning, got {:?}",
        info.warnings
    );
}

#[test]
fn pseudonym_user_id_produces_no_warnings() {
    let (home, fpr) = standard_key("pseudo", "nightowl", None);
    let cert = home.export_armored(&fpr);
    let info = keys::validate_cert(&cert).expect("pseudonym cert must validate");
    assert!(
        info.warnings.is_empty(),
        "a plain pseudonym user ID must produce no warning, got {:?}",
        info.warnings
    );
}

#[test]
fn garbage_and_empty_input_rejected_as_malformed() {
    assert!(
        matches!(keys::validate_cert(b"this is not an openpgp certificate"), Err(KeyError::Malformed)),
        "garbage bytes must be Malformed"
    );
    assert!(
        matches!(keys::validate_cert(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]), Err(KeyError::Malformed)),
        "random bytes must be Malformed"
    );
    assert!(
        matches!(keys::validate_cert(b""), Err(KeyError::Malformed)),
        "empty input must be Malformed"
    );
}

#[test]
fn signing_key_without_encryption_subkey_rejected() {
    let home = GpgHome::new("noenc");
    let fpr = home.gen_key(
        "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign\n\
         Name-Real: signonly\nExpire-Date: 0\n%commit\n",
    );
    let cert = home.export_armored(&fpr);
    assert!(
        matches!(keys::validate_cert(&cert), Err(KeyError::NoEncryptionSubkey)),
        "a cert with no encryption-capable subkey must be NoEncryptionSubkey"
    );
}

#[test]
fn encryption_key_without_signing_key_rejected() {
    // Certify-only primary + encryption subkey: nothing on the cert can sign.
    // If this fixture cannot be constructed with the local gpg, skip rather
    // than assert something about a different key than intended.
    let home = GpgHome::new("nosign");
    let param_file = home.dir.join("params.txt");
    std::fs::write(
        &param_file,
        "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: cert\n\
         Name-Real: certonly\nExpire-Date: 0\nSubkey-Type: ecdh\nSubkey-Curve: cv25519\n\
         Subkey-Usage: encrypt\n%commit\n",
    )
    .expect("write params");
    let out = Command::new("gpg")
        .args(["--batch", "--yes", "--pinentry-mode", "loopback", "--gen-key"])
        .arg(&param_file)
        .env("GNUPGHOME", &home.dir)
        .output()
        .expect("run gpg");
    if !out.status.success() {
        eprintln!("SKIP: certify-only fixture not constructible with this gpg");
        return;
    }
    let fpr = home.primary_fingerprint();
    // Sanity: the primary must not be signing-capable in gpg's own view.
    let listing = home.run(&["--with-colons", "--list-keys"]);
    let pub_caps = listing
        .lines()
        .find(|l| l.starts_with("pub:"))
        .and_then(|l| l.split(':').nth(11).map(str::to_string))
        .unwrap_or_default();
    if pub_caps.contains('s') {
        eprintln!("SKIP: fixture primary turned out signing-capable ({pub_caps})");
        return;
    }
    let cert = home.export_armored(&fpr);
    assert!(
        matches!(keys::validate_cert(&cert), Err(KeyError::NoSigningKey)),
        "a cert with no signing-capable key must be NoSigningKey"
    );
}

#[test]
fn expired_cert_rejected_as_policy_invalid() {
    // CONSTRUCTION FIX (implementer, 2026-10-14; assertion unchanged —
    // listed in RETROFIT-REPORT.md): the original construction expired
    // the primary "one second from now" via `--quick-set-expire <fpr> 1`
    // and slept 2 s, but gpg reads that bare number as DAYS (verified
    // against gpg --with-colons: the expiration lands exactly 86400 s
    // after creation), so the fixture cert was still valid at validation
    // time and expiry was never actually exercised. gpg also refuses an
    // expiration date in the past. The key below is therefore generated
    // under a faked system time three days in the past with a one-day
    // expiry — genuinely expired two days ago at real validation time.
    let home = GpgHome::new("expired");
    let params = "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nKey-Usage: sign\n\
                  Name-Real: nightowl\nExpire-Date: 1\n\
                  Subkey-Type: ecdh\nSubkey-Curve: cv25519\nSubkey-Usage: encrypt\n%commit\n";
    let param_file = home.dir.join("params.txt");
    std::fs::write(&param_file, params).expect("write key params");
    let three_days_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
        - 3 * 86_400;
    home.run(&[
        "--faked-system-time",
        // NOTE: plain epoch seconds. The "@epoch" spelling makes this
        // gpg build silently use time 0 (verified in shell).
        &format!("{three_days_ago}"),
        "--gen-key",
        param_file.to_str().unwrap(),
    ]);
    let fpr = home.primary_fingerprint();
    let cert = home.export_armored(&fpr);
    assert!(
        matches!(keys::validate_cert(&cert), Err(KeyError::PolicyInvalid)),
        "an expired cert must be PolicyInvalid under the standard policy"
    );
}

#[test]
fn revoked_cert_rejected_as_policy_invalid() {
    // Deterministic construction is attempted; if the local gpg will not
    // produce/import a revocation non-interactively, this test skips and
    // the skip is reported in the suite summary (per assignment).
    let (home, fpr) = standard_key("revoked", "nightowl", None);
    let rev_path = home.dir.join("rev.asc");
    let mut child = match Command::new("gpg")
        .args([
            "--command-fd",
            "0",
            "--status-fd",
            "1",
            "--pinentry-mode",
            "loopback",
            "--output",
            rev_path.to_str().unwrap(),
            "--gen-revoke",
            &fpr,
        ])
        .env("GNUPGHOME", &home.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            eprintln!("SKIP: could not spawn gpg for revocation fixture");
            return;
        }
    };
    // Prompts: create cert? y / reason: 0 (unspecified) / description:
    // (empty line ends it) / is this okay? y
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"y\n0\n\ny\n")
        .expect("answer revocation prompts");
    let status = child.wait().expect("wait for gpg");
    if !status.success() || !rev_path.exists() {
        eprintln!("SKIP: revocation certificate was not produced");
        return;
    }
    home.run(&["--import", rev_path.to_str().unwrap()]);
    if !home.is_revoked() {
        eprintln!("SKIP: revocation did not take effect in fixture keyring");
        return;
    }
    let cert = home.export_armored(&fpr);
    assert!(
        matches!(keys::validate_cert(&cert), Err(KeyError::PolicyInvalid)),
        "a revoked cert must be PolicyInvalid under the standard policy"
    );
}

// ---------------------------------------------------------------------------
// B. Detached signature verification
// ---------------------------------------------------------------------------

#[test]
fn valid_detached_signature_verifies() {
    let (home, fpr) = standard_key("sigok", "signerone", None);
    let cert = home.export_armored(&fpr);
    let message = b"exact bytes that were signed";
    let sig = home.sign_detached(&fpr, message);
    assert!(
        keys::verify_detached(&cert, message, &sig),
        "a signature by the cert's key over the exact bytes must verify"
    );
}

#[test]
fn tampered_message_fails_verification() {
    let (home, fpr) = standard_key("sigtamper", "signerone", None);
    let cert = home.export_armored(&fpr);
    let message = b"exact bytes that were signed";
    let sig = home.sign_detached(&fpr, message);
    let mut tampered = message.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        !keys::verify_detached(&cert, &tampered, &sig),
        "one changed byte in the message must fail verification"
    );
}

#[test]
fn signature_from_different_cert_fails() {
    let (home_a, fpr_a) = standard_key("sigother-a", "signerone", None);
    let (home_b, fpr_b) = standard_key("sigother-b", "signertwo", None);
    let cert_a = home_a.export_armored(&fpr_a);
    let message = b"signed by B, checked against A";
    let sig_by_b = home_b.sign_detached(&fpr_b, message);
    assert!(
        !keys::verify_detached(&cert_a, message, &sig_by_b),
        "a signature by a different cert must not verify against this cert"
    );
}

#[test]
fn garbage_and_empty_signatures_fail_without_panic() {
    let (home, fpr) = standard_key("siggarbage", "signerone", None);
    let cert = home.export_armored(&fpr);
    assert!(
        !keys::verify_detached(&cert, b"msg", b"this is not a signature"),
        "garbage signature bytes must be false, not a panic"
    );
    assert!(
        !keys::verify_detached(&cert, b"msg", b""),
        "an empty signature must be false"
    );
    assert!(
        !keys::verify_detached(b"not a cert", b"msg", b"also not a sig"),
        "garbage on every input must still be a plain false"
    );
}

// ---------------------------------------------------------------------------
// C. Rotation statement parsing (contract §9 + §4 canonical rules)
// ---------------------------------------------------------------------------

/// This instance's marketplace id, in the pinned `mkt_` + 32 lowercase hex
/// shape (amendments §10 — the spec's short examples were superseded).
const MKT: &str = "mkt_0123456789abcdef0123456789abcdef";
const ACCT: &str = "acct_0123456789abcdef0123456789abcdef";
const OLD_FPR: &str = "ABABABABABABABABABABABABABABABABABABABAB"; // 40 uppercase hex
const NEW_FPR: &str = "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"; // 40 uppercase hex
const ROTATED_AT: &str = "2026-10-13T16:00:00Z";

fn rotation_statement() -> String {
    format!(
        "statement-format: marketplace-key-rotation-v1\n\
         marketplace-id: {MKT}\n\
         account-id: {ACCT}\n\
         old-fingerprint: {OLD_FPR}\n\
         new-fingerprint: {NEW_FPR}\n\
         rotated-at: {ROTATED_AT}\n"
    )
}

fn assert_rejected(text: &str, why: &str) {
    assert!(
        keys::parse_rotation_statement(text, MKT).is_none(),
        "statement must be rejected: {why}"
    );
}

#[test]
fn valid_rotation_statement_parses() {
    let st = keys::parse_rotation_statement(&rotation_statement(), MKT)
        .expect("a statement built exactly per contract §9 must parse");
    assert_eq!(st.account_id, ACCT);
    assert_eq!(st.old_fingerprint, OLD_FPR);
    assert_eq!(st.new_fingerprint, NEW_FPR);
    assert_eq!(st.rotated_at, ROTATED_AT);
}

#[test]
fn rotation_statement_with_64_hex_fingerprints_parses() {
    let old64 = "AB".repeat(32);
    let new64 = "CD".repeat(32);
    let text = rotation_statement()
        .replace(OLD_FPR, &old64)
        .replace(NEW_FPR, &new64);
    let st = keys::parse_rotation_statement(&text, MKT)
        .expect("64-hex fingerprints are legal (contract §4/§9)");
    assert_eq!(st.old_fingerprint, old64);
    assert_eq!(st.new_fingerprint, new64);
}

#[test]
fn rotation_statement_wrong_marketplace_id_rejected() {
    // Statement names a different instance than the one parsing it.
    let other = "mkt_ffffffffffffffffffffffffffffffff";
    let text = rotation_statement().replace(MKT, other);
    assert!(
        keys::parse_rotation_statement(&text, MKT).is_none(),
        "marketplace-id must equal this instance's id"
    );
    // And the mirror image: our statement, parsed by another instance.
    assert!(
        keys::parse_rotation_statement(&rotation_statement(), other).is_none(),
        "marketplace-id must equal the parsing instance's id"
    );
}

#[test]
fn rotation_statement_old_shape_account_id_rejected() {
    // The pre-amendment shape (acct_ + 12 hex, as in the spec §10 example)
    // must NOT parse; the pinned pattern is acct_ + 32 lowercase hex.
    let text = rotation_statement().replace(ACCT, "acct_5e2a8c1b3f9d");
    assert_rejected(&text, "account-id with the old 48-bit shape");
    // Uppercase hex in the account id is likewise off-pattern.
    let text = rotation_statement().replace(ACCT, "acct_0123456789ABCDEF0123456789ABCDEF");
    assert_rejected(&text, "account-id with uppercase hex");
}

#[test]
fn rotation_statement_lowercase_fingerprint_rejected() {
    let text = rotation_statement().replace(OLD_FPR, &OLD_FPR.to_lowercase());
    assert_rejected(&text, "fingerprints are uppercase hex only");
}

#[test]
fn rotation_statement_fingerprint_wrong_length_rejected() {
    let short = &OLD_FPR[..39];
    let text = rotation_statement().replace(OLD_FPR, short);
    assert_rejected(&text, "39-char fingerprint");
    let long = format!("{OLD_FPR}A");
    let text = rotation_statement().replace(OLD_FPR, &long);
    assert_rejected(&text, "41-char fingerprint");
}

#[test]
fn rotation_statement_reordered_fields_rejected() {
    let text = format!(
        "statement-format: marketplace-key-rotation-v1\n\
         marketplace-id: {MKT}\n\
         account-id: {ACCT}\n\
         new-fingerprint: {NEW_FPR}\n\
         old-fingerprint: {OLD_FPR}\n\
         rotated-at: {ROTATED_AT}\n"
    );
    assert_rejected(&text, "field order is fixed (old- before new-fingerprint)");
}

#[test]
fn rotation_statement_missing_trailing_lf_rejected() {
    let valid = rotation_statement();
    let text = &valid[..valid.len() - 1];
    assert_rejected(text, "exactly one final LF is required");
}

#[test]
fn rotation_statement_two_trailing_lfs_rejected() {
    let text = format!("{}\n", rotation_statement());
    assert_rejected(&text, "two trailing LFs (a blank final line) are not canonical");
}

#[test]
fn rotation_statement_crlf_rejected() {
    let text = rotation_statement().replacen('\n', "\r\n", 1);
    assert_rejected(&text, "statements are LF-only; CR is forbidden");
}

#[test]
fn rotation_statement_tab_rejected() {
    let text = rotation_statement().replace("account-id: ", "account-id:\t");
    assert_rejected(&text, "a tab anywhere is forbidden");
    let text = format!("{}\t", rotation_statement().trim_end_matches('\n'));
    let text = format!("{text}\n");
    assert_rejected(&text, "a trailing tab is forbidden");
}

#[test]
fn rotation_statement_month_13_rejected() {
    let text = rotation_statement().replace(ROTATED_AT, "2026-13-13T16:00:00Z");
    assert_rejected(&text, "rotated-at must be a real calendar date (month 13)");
}

#[test]
fn rotation_statement_leap_second_rejected() {
    let text = rotation_statement().replace(ROTATED_AT, "2026-10-13T16:00:60Z");
    assert_rejected(&text, "leap seconds (:60) are rejected");
}

#[test]
fn rotation_statement_noncanonical_timestamp_rejected() {
    let text = rotation_statement().replace(ROTATED_AT, "2026-10-13T16:00:00");
    assert_rejected(&text, "rotated-at without the trailing Z is not canonical");
    let text = rotation_statement().replace(ROTATED_AT, "2026-10-13 16:00:00Z");
    assert_rejected(&text, "rotated-at with a space instead of T is not canonical");
}

#[test]
fn rotation_statement_extra_field_rejected() {
    let text = rotation_statement().replace(
        "rotated-at:",
        "comment: hello\nrotated-at:",
    );
    assert_rejected(&text, "an extra unknown field line is forbidden");
}

#[test]
fn rotation_statement_missing_field_rejected() {
    let text = rotation_statement().replace(&format!("rotated-at: {ROTATED_AT}\n"), "");
    assert_rejected(&text, "a missing field line (rotated-at) is forbidden");
    let text = rotation_statement().replace(&format!("account-id: {ACCT}\n"), "");
    assert_rejected(&text, "a missing field line (account-id) is forbidden");
}

// ---------------------------------------------------------------------------
// B (continued). Signatures over a rotation statement — the certified path
// ---------------------------------------------------------------------------

#[test]
fn rotation_statement_signatures_verify_for_both_certs() {
    let (home_old, fpr_old) = standard_key("rot-old", "rotator", None);
    let (home_new, fpr_new) = standard_key("rot-new", "rotator", None);
    let cert_old = home_old.export_armored(&fpr_old);
    let cert_new = home_new.export_armored(&fpr_new);

    // A statement naming the real account and both real fingerprints.
    let statement = format!(
        "statement-format: marketplace-key-rotation-v1\n\
         marketplace-id: {MKT}\n\
         account-id: {ACCT}\n\
         old-fingerprint: {fpr_old}\n\
         new-fingerprint: {fpr_new}\n\
         rotated-at: {ROTATED_AT}\n"
    );
    assert!(
        keys::parse_rotation_statement(&statement, MKT).is_some(),
        "the statement used for the certified path must itself parse"
    );

    let sig_old = home_old.sign_detached(&fpr_old, statement.as_bytes());
    let sig_new = home_new.sign_detached(&fpr_new, statement.as_bytes());
    assert!(
        keys::verify_detached(&cert_old, statement.as_bytes(), &sig_old),
        "the old key's signature over the statement must verify"
    );
    assert!(
        keys::verify_detached(&cert_new, statement.as_bytes(), &sig_new),
        "the new key's signature over the statement must verify"
    );
    assert!(
        !keys::verify_detached(&cert_new, statement.as_bytes(), &sig_old),
        "the old key's signature must not verify against the new cert"
    );
}

// ---------------------------------------------------------------------------
// D + E. Key storage and conversation sightings (database integration)
//
// DATABASE_URL is read from the environment; when unset every test in this
// section returns early (the harness provides
// postgres://postgres:dev@localhost/marketplace_dev).
// Accounts/conversations are created directly in the DB using the spec §16
// table shapes named in the assignment. Rows created here are cleaned up
// (children first — the schema has no cascades by design).
// ---------------------------------------------------------------------------

async fn db_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(
        PgPool::connect(&url)
            .await
            .expect("DATABASE_URL is set but the database is unreachable"),
    )
}

/// Creates an account row directly; returns (internal id, public id).
async fn create_account(pool: &PgPool) -> i64 {
    let suffix = rand_hex(16);
    let public_id = format!("acct_{suffix}");
    let username = format!("blind3_{}", &suffix[..16]);
    sqlx::query_scalar(
        "INSERT INTO accounts (public_id, username, password_hash, role, created_at) \
         VALUES ($1, $2, 'not-a-real-hash', 'buyer', now()) RETURNING id",
    )
    .bind(&public_id)
    .bind(&username)
    .fetch_one(pool)
    .await
    .expect("create account row")
}

/// Creates a conversation with the given participants; returns its
/// internal id.
async fn create_conversation(pool: &PgPool, participants: &[i64]) -> i64 {
    let public_id = rand_hex(16);
    let conv_id: i64 = sqlx::query_scalar(
        "INSERT INTO conversations (public_id, order_id) VALUES ($1, NULL) RETURNING id",
    )
    .bind(&public_id)
    .fetch_one(pool)
    .await
    .expect("create conversation row");
    for p in participants {
        sqlx::query(
            "INSERT INTO conversation_participants (conversation_id, account_id) \
             VALUES ($1, $2)",
        )
        .bind(conv_id)
        .bind(p)
        .execute(pool)
        .await
        .expect("add conversation participant");
    }
    conv_id
}

async fn cleanup_account(pool: &PgPool, account_id: i64) {
    let _ = sqlx::query("DELETE FROM key_rotations WHERE account_id = $1")
        .bind(account_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM identity_keys WHERE account_id = $1")
        .bind(account_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account_id)
        .execute(pool)
        .await;
}

async fn cleanup_conversation(pool: &PgPool, conversation_id: i64) {
    let _ = sqlx::query("DELETE FROM conversation_key_sightings WHERE conversation_id = $1")
        .bind(conversation_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM conversation_participants WHERE conversation_id = $1")
        .bind(conversation_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(conversation_id)
        .execute(pool)
        .await;
}

fn key_id_of(fingerprint: &str) -> String {
    // OpenPGP key ID = low 64 bits of the fingerprint (last 16 hex chars).
    fingerprint[fingerprint.len() - 16..].to_string()
}

// CONSTRUCTION FIX (implementer, 2026-10-14; assertions unchanged — listed
// in RETROFIT-REPORT.md): the author's calls used the contract-prose shape
// `install_key(pool, account, cert, certified)`; the real signature is
// `install_key(pool, account, cert_bytes, &CertInfo, Option<rotation>)`.
// This adapter builds the CertInfo from the fixture cert and, when the
// account already has a current key, records a rotation whose `certified`
// flag is exactly the author's boolean argument. First installs pass no
// rotation. Statement/signature payloads are not under test in these DB
// tests; the statement is a fixed fixture byte string.
const ROTATION_STATEMENT_FIXTURE: &[u8] =
    b"blind-suite rotation fixture (statement bytes not under test here)";
async fn install(
    pool: &PgPool,
    account: i64,
    cert: &[u8],
    certified: bool,
) -> Result<(), sqlx::Error> {
    let info = keys::validate_cert(cert).expect("fixture cert must validate");
    let rotation = match keys::current_key(pool, account)
        .await
        .expect("current_key query")
    {
        Some(_) => Some((ROTATION_STATEMENT_FIXTURE, None, None, certified)),
        None => None,
    };
    keys::install_key(pool, account, cert, &info, rotation).await
}

#[tokio::test]
async fn first_install_becomes_single_current_key_version_1() {
    let Some(pool) = db_pool().await else { return };
    let account = create_account(&pool).await;
    let (home, fpr) = standard_key("db-first", "dbuser", None);
    let cert = home.export_armored(&fpr);

    let installed = install(&pool, account, &cert, false).await;
    assert!(
        installed.is_ok(),
        "installing a first key must succeed: {installed:?}"
    );

    let current = keys::current_key(&pool, account)
        .await
        .expect("current_key query must succeed")
        .expect("a current key must exist after the first install");
    assert_eq!(current.0, fpr, "current_key must return the installed key");

    let current_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_keys WHERE account_id = $1 AND status = 'current'",
    )
    .bind(account)
    .fetch_one(&pool)
    .await
    .expect("count current rows");
    assert_eq!(current_rows, 1, "exactly one current key row may exist");

    let version: i32 = sqlx::query_scalar(
        "SELECT version FROM identity_keys WHERE account_id = $1 AND fingerprint = $2",
    )
    .bind(account)
    .bind(&fpr)
    .fetch_one(&pool)
    .await
    .expect("read installed key version");
    assert_eq!(version, 1, "the first key is version 1");

    cleanup_account(&pool, account).await;
}

#[tokio::test]
async fn rotation_retires_previous_key_in_same_operation() {
    let Some(pool) = db_pool().await else { return };
    let account = create_account(&pool).await;
    let (home1, fpr1) = standard_key("db-rot-1", "dbuser", None);
    let (home2, fpr2) = standard_key("db-rot-2", "dbuser", None);
    let cert1 = home1.export_armored(&fpr1);
    let cert2 = home2.export_armored(&fpr2);

    install(&pool, account, &cert1, false)
        .await
        .expect("install first key");
    install(&pool, account, &cert2, true)
        .await
        .expect("install second key (certified rotation)");

    // Exactly one current row afterwards, and it is the new key.
    let current_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_keys WHERE account_id = $1 AND status = 'current'",
    )
    .bind(account)
    .fetch_one(&pool)
    .await
    .expect("count current rows");
    assert_eq!(current_rows, 1, "rotation must leave exactly one current key");
    let current = keys::current_key(&pool, account)
        .await
        .expect("current_key query")
        .expect("a current key must exist");
    assert_eq!(current.0, fpr2, "the new key is the current key");

    // The old key's history entry: status retired, retirement date set.
    let old_status: String = sqlx::query_scalar(
        "SELECT status FROM identity_keys WHERE account_id = $1 AND fingerprint = $2",
    )
    .bind(account)
    .bind(&fpr1)
    .fetch_one(&pool)
    .await
    .expect("read old key status");
    assert_eq!(old_status, "retired", "the rotated-away key must be retired");
    let old_has_retired_at: bool = sqlx::query_scalar(
        "SELECT retired_at IS NOT NULL FROM identity_keys \
         WHERE account_id = $1 AND fingerprint = $2",
    )
    .bind(account)
    .bind(&fpr1)
    .fetch_one(&pool)
    .await
    .expect("read old key retired_at");
    assert!(old_has_retired_at, "the retired key must carry a retirement date");

    // The new key's validity starts at or after the old one's retirement.
    let interval_ordered: bool = sqlx::query_scalar(
        "SELECT (SELECT created_at FROM identity_keys WHERE account_id = $1 AND fingerprint = $3) \
              >= (SELECT retired_at FROM identity_keys WHERE account_id = $1 AND fingerprint = $2)",
    )
    .bind(account)
    .bind(&fpr1)
    .bind(&fpr2)
    .fetch_one(&pool)
    .await
    .expect("compare validity interval bounds");
    assert!(
        interval_ordered,
        "the new key's validity interval must start at/after the old key's retirement"
    );

    // A key_rotations record exists for this rotation, marked certified.
    let rotation_certified: Option<bool> = sqlx::query_scalar(
        "SELECT certified FROM key_rotations \
         WHERE account_id = $1 AND old_fpr = $2 AND new_fpr = $3",
    )
    .bind(account)
    .bind(&fpr1)
    .bind(&fpr2)
    .fetch_optional(&pool)
    .await
    .expect("read key_rotations row");
    assert_eq!(
        rotation_certified,
        Some(true),
        "a key_rotations record must exist and record certified = true"
    );

    // Key history remains queryable and lists both versions.
    let history = keys::key_history(&pool, account)
        .await
        .expect("key_history query must succeed");
    assert_eq!(history.len(), 2, "history must list both keys");
    assert!(
        history.iter().any(|k| k.0 == fpr1),
        "history must include the retired key"
    );
    assert!(
        history.iter().any(|k| k.0 == fpr2),
        "history must include the current key"
    );

    cleanup_account(&pool, account).await;
}

#[tokio::test]
async fn uncertified_rotation_is_reported_certified_is_not() {
    let Some(pool) = db_pool().await else { return };

    // Account with an UNCERTIFIED rotation (old key lost).
    let uncert = create_account(&pool).await;
    let (h1, f1) = standard_key("db-uncert-1", "dbuser", None);
    let (h2, f2) = standard_key("db-uncert-2", "dbuser", None);
    install(&pool, uncert, &h1.export_armored(&f1), false)
        .await
        .expect("install first key");
    install(&pool, uncert, &h2.export_armored(&f2), false)
        .await
        .expect("install replacement key without certification");
    let reported = keys::latest_uncertified_rotation(&pool, uncert)
        .await
        .expect("latest_uncertified_rotation query");
    assert!(
        reported.is_some(),
        "an uncertified rotation inside the 90-day window must be reported"
    );

    // Account with a CERTIFIED rotation only.
    let cert_account = create_account(&pool).await;
    let (h3, f3) = standard_key("db-cert-1", "dbuser", None);
    let (h4, f4) = standard_key("db-cert-2", "dbuser", None);
    install(&pool, cert_account, &h3.export_armored(&f3), false)
        .await
        .expect("install first key");
    install(&pool, cert_account, &h4.export_armored(&f4), true)
        .await
        .expect("install second key (certified rotation)");
    let reported = keys::latest_uncertified_rotation(&pool, cert_account)
        .await
        .expect("latest_uncertified_rotation query");
    assert!(
        reported.is_none(),
        "a certified rotation must never be reported as uncertified"
    );

    // Account that never rotated.
    let fresh = create_account(&pool).await;
    let (h5, f5) = standard_key("db-fresh-1", "dbuser", None);
    install(&pool, fresh, &h5.export_armored(&f5), false)
        .await
        .expect("install first key");
    let reported = keys::latest_uncertified_rotation(&pool, fresh)
        .await
        .expect("latest_uncertified_rotation query");
    assert!(reported.is_none(), "no rotation means no uncertified rotation");

    cleanup_account(&pool, uncert).await;
    cleanup_account(&pool, cert_account).await;
    cleanup_account(&pool, fresh).await;
}

#[tokio::test]
async fn q16_key_shown_in_conversation_is_conversation_scoped() {
    let Some(pool) = db_pool().await else { return };

    let owner = create_account(&pool).await; // key owner ("seller")
    let other_party = create_account(&pool).await; // conversation participant
    let unrelated = create_account(&pool).await; // never a participant

    // Timeline: key_old installed, then rotated away (retired) — all BEFORE
    // either conversation below is created. key_mid is current at that point.
    let (h_old, fpr_old) = standard_key("q16-old", "dbuser", None);
    let (h_mid, fpr_mid) = standard_key("q16-mid", "dbuser", None);
    install(&pool, owner, &h_old.export_armored(&fpr_old), false)
        .await
        .expect("install key_old");
    install(&pool, owner, &h_mid.export_armored(&fpr_mid), true)
        .await
        .expect("rotate to key_mid (key_old retires here)");

    let c1 = create_conversation(&pool, &[owner, other_party]).await;
    let c2 = create_conversation(&pool, &[owner, other_party]).await;

    // Derivation (contract §9): key_shown_in_conversation is answered from
    // (a) recorded sightings in THIS conversation, or (b) the key's validity
    // interval overlapping the conversation. key_mid was current when C1 was
    // created, so its interval overlaps C1 ⇒ shown, with no sighting yet.
    assert!(
        keys::key_shown_in_conversation(&pool, c1, owner, &fpr_mid)
            .await
            .expect("key_shown query"),
        "the key current at conversation creation counts as shown (validity-interval overlap)"
    );

    // key_old was retired BEFORE C1 existed: its interval cannot overlap
    // C1, and no sighting has been recorded ⇒ not shown.
    assert!(
        !keys::key_shown_in_conversation(&pool, c1, owner, &fpr_old)
            .await
            .expect("key_shown query"),
        "a key retired before the conversation began is not shown in it (yet)"
    );
    assert!(
        !keys::key_shown_in_conversation(&pool, c2, owner, &fpr_old)
            .await
            .expect("key_shown query"),
        "the same holds in the second conversation before any sighting"
    );

    // The server presents key_old inside C1 (e.g. a key download in
    // conversation context): a sighting is recorded for C1 only.
    keys::record_key_sighting(
        &pool,
        c1,
        owner,
        &fpr_old,
        &key_id_of(&fpr_old),
        other_party,
    )
    .await
    .expect("record sighting in C1");

    assert!(
        keys::key_shown_in_conversation(&pool, c1, owner, &fpr_old)
            .await
            .expect("key_shown query"),
        "after a recorded sighting in C1, the retired key counts as shown in C1"
    );
    // THE LEAK-FIX PROBE: the C1 sighting must not leak into C2. History
    // from other conversations never counts.
    assert!(
        !keys::key_shown_in_conversation(&pool, c2, owner, &fpr_old)
            .await
            .expect("key_shown query"),
        "a sighting in C1 must never make the key count as shown in C2 (Q16 leak fix)"
    );

    // A key installed only AFTER C2 was created, never sighted in C2, is
    // not shown in C2 — it did not exist when the conversation began.
    let (h_new, fpr_new) = standard_key("q16-new", "dbuser", None);
    install(&pool, owner, &h_new.export_armored(&fpr_new), true)
        .await
        .expect("rotate to key_new after C2 exists");
    assert!(
        !keys::key_shown_in_conversation(&pool, c2, owner, &fpr_new)
            .await
            .expect("key_shown query"),
        "a key installed after the conversation was created is not shown in it"
    );

    // A non-participant's key is never "shown" in the conversation.
    let (h_u, fpr_u) = standard_key("q16-unrelated", "dbuser", None);
    install(&pool, unrelated, &h_u.export_armored(&fpr_u), false)
        .await
        .expect("install unrelated account's key");
    assert!(
        !keys::key_shown_in_conversation(&pool, c1, unrelated, &fpr_u)
            .await
            .expect("key_shown query"),
        "a non-participant's key must never count as shown in the conversation"
    );

    cleanup_conversation(&pool, c1).await;
    cleanup_conversation(&pool, c2).await;
    cleanup_account(&pool, owner).await;
    cleanup_account(&pool, other_party).await;
    cleanup_account(&pool, unrelated).await;
}
