//! Spike 3: canonical statement format (spec §10).
//! Printable ASCII + LF only, fixed key order, `key: value` with one space,
//! exactly one final LF. The parser re-serializes and rejects anything whose
//! re-serialization is not byte-identical to the input.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    pub marketplace_id: String,
    pub invoice_id: String,
    pub order_id: String,
    pub seller_fingerprint: String,
    pub network: String, // monero-mainnet | monero-stagenet | monero-testnet
    pub destination: String,
    pub amount_atomic: u64,
    pub expires_at: String,
    pub terms_sha256: String,
}

const KEYS: [&str; 10] = [
    "statement-format",
    "marketplace-id",
    "invoice-id",
    "order-id",
    "seller-key-fingerprint",
    "network",
    "destination",
    "amount-atomic",
    "expires-at",
    "terms-sha256",
];

pub fn serialize_invoice(inv: &Invoice) -> Vec<u8> {
    let text = format!(
        "statement-format: marketplace-invoice-v1\n\
         marketplace-id: {mid}\n\
         invoice-id: {iid}\n\
         order-id: {oid}\n\
         seller-key-fingerprint: {fpr}\n\
         network: {net}\n\
         destination: {dst}\n\
         amount-atomic: {amt}\n\
         expires-at: {exp}\n\
         terms-sha256: {terms}\n",
        mid = inv.marketplace_id,
        iid = inv.invoice_id,
        oid = inv.order_id,
        fpr = inv.seller_fingerprint,
        net = inv.network,
        dst = inv.destination,
        amt = inv.amount_atomic,
        exp = inv.expires_at,
        terms = inv.terms_sha256,
    );
    text.into_bytes()
}

fn is_upper_hex(s: &str, lens: &[usize]) -> bool {
    lens.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn is_rfc3339_z(s: &str) -> bool {
    // YYYY-MM-DDTHH:MM:SSZ — shape check only (calendar validity is a v1 concern noted in the report).
    let b = s.as_bytes();
    b.len() == 20
        && b[4] == b'-' && b[7] == b'-' && b[10] == b'T'
        && b[13] == b':' && b[16] == b':' && b[19] == b'Z'
        && [0,1,2,3,5,6,8,9,11,12,14,15,17,18].iter().all(|&i| b[i].is_ascii_digit())
}

pub fn parse_invoice(bytes: &[u8]) -> Result<Invoice, String> {
    // Byte alphabet: printable ASCII 0x20-0x7E plus LF. This alone kills CR, tab, NUL, UTF-8.
    if bytes.iter().any(|&b| !(0x20..=0x7E).contains(&b) && b != b'\n') {
        return Err("non-printable-ASCII byte".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not utf8")?;
    if !text.ends_with('\n') || text.ends_with("\n\n") {
        return Err("must end with exactly one LF".into());
    }
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if lines.len() != KEYS.len() {
        return Err(format!("expected {} lines, got {}", KEYS.len(), lines.len()));
    }
    let mut vals: Vec<&str> = Vec::with_capacity(KEYS.len());
    for (i, line) in lines.iter().enumerate() {
        if line.ends_with(' ') || line.is_empty() {
            return Err("blank line or trailing space".into());
        }
        let (k, v) = line.split_once(": ").ok_or("missing ': ' separator")?;
        if k != KEYS[i] {
            return Err(format!("key order/name mismatch at line {}: {k}", i + 1));
        }
        if v.is_empty() || v.starts_with(' ') || v.contains(": ") && i == 0 {
            return Err("bad value spacing".into());
        }
        vals.push(v);
    }
    if vals[0] != "marketplace-invoice-v1" {
        return Err("bad statement-format value".into());
    }
    if !is_upper_hex(vals[4], &[40, 64]) {
        return Err("fingerprint must be uppercase hex, 40 or 64 chars".into());
    }
    if !matches!(vals[5], "monero-mainnet" | "monero-stagenet" | "monero-testnet") {
        return Err("bad network value".into());
    }
    let amount_atomic: u64 = vals[7].parse().map_err(|_| "bad amount")?;
    // Reject non-canonical amount spellings ("007", "+7") via the re-serialization check below, but parse must succeed first.
    if !is_rfc3339_z(vals[8]) {
        return Err("bad expires-at".into());
    }
    if !is_lower_hex64(vals[9]) {
        return Err("terms-sha256 must be lowercase hex, 64 chars".into());
    }
    let inv = Invoice {
        marketplace_id: vals[1].to_string(),
        invoice_id: vals[2].to_string(),
        order_id: vals[3].to_string(),
        seller_fingerprint: vals[4].to_string(),
        network: vals[5].to_string(),
        destination: vals[6].to_string(),
        amount_atomic,
        expires_at: vals[8].to_string(),
        terms_sha256: vals[9].to_string(),
    };
    // The §10 rule: re-serialize and demand byte identity.
    if serialize_invoice(&inv) != bytes {
        return Err("not byte-identical to canonical re-serialization".into());
    }
    Ok(inv)
}

/// Verify a detached armored OpenPGP signature over the exact statement bytes
/// against the seller's certificate, using Sequoia with the standard policy.
pub fn verify_detached(
    statement: &[u8],
    sig_armored: &[u8],
    cert_armored: &[u8],
) -> Result<(), String> {
    use sequoia_openpgp as openpgp;
    use openpgp::parse::stream::*;
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use std::borrow::Cow;

    struct Helper {
        cert: openpgp::Cert,
        good: bool,
    }
    impl VerificationHelper for Helper {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
            Ok(vec![self.cert.clone()])
        }
        fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
            for layer in structure {
                if let MessageLayer::SignatureGroup { results } = layer {
                    for r in results {
                        match r {
                            Ok(_) => self.good = true,
                            Err(e) => return Err(anyhow::Error::msg(format!("bad signature: {e:?}"))),
                        }
                    }
                }
            }
            Ok(())
        }
    }

    let policy = StandardPolicy::new();
    let cert = openpgp::Cert::from_bytes(cert_armored).map_err(|e| format!("cert parse: {e}"))?;
    let helper = Helper { cert, good: false };
    let mut verifier = DetachedVerifierBuilder::from_bytes(sig_armored)
        .map_err(|e| format!("sig parse: {e}"))?
        .with_policy(&policy, None, helper)
        .map_err(|e| format!("verifier build: {e}"))?;
    verifier.verify_bytes(statement).map_err(|e| format!("verify: {e}"))?;
    let helper = verifier.into_helper();
    if helper.good {
        Ok(())
    } else {
        let _: Cow<str> = Cow::Borrowed("");
        Err("no good signature found".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample() -> Invoice {
        Invoice {
            marketplace_id: "mkt_4f9c2a7e".into(),
            invoice_id: "inv_8d1e5b0c3a7f".into(),
            order_id: "ord_2b6a9e4d1c08".into(),
            seller_fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567".into(),
            network: "monero-stagenet".into(),
            destination: "5".repeat(95).into(),
            amount_atomic: 1_250_000_000_000,
            expires_at: "2026-10-16T17:00:00Z".into(),
            terms_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn roundtrip_byte_exact() {
        let inv = sample();
        let bytes = serialize_invoice(&inv);
        assert!(bytes.ends_with(b"\n") && !bytes.ends_with(b"\n\n"));
        let parsed = parse_invoice(&bytes).expect("canonical form parses");
        assert_eq!(parsed, inv);
    }

    #[test]
    fn detached_signature_verifies_and_tamper_fails() {
        use std::io::Write;
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("stage0-stmt-{}", std::process::id()));
        let home = dir.join("gnupg");
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let run = |args: &[&str], input: Option<&[u8]>| -> (bool, Vec<u8>) {
            let mut cmd = Command::new("gpg");
            cmd.args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""])
                .arg("--homedir").arg(&home).args(args);
            if input.is_some() {
                let mut child = cmd.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
                child.stdin.as_mut().unwrap().write_all(input.unwrap()).unwrap();
                let out = child.wait_with_output().unwrap();
                (out.status.success(), out.stdout)
            } else {
                let out = cmd.output().unwrap();
                (out.status.success(), out.stdout)
            }
        };
        let (ok, _) = run(&["--quick-generate-key", "seller <seller@spike.test>", "ed25519", "sign", "never"], None);
        assert!(ok);
        let stmt = serialize_invoice(&sample());
        let (ok, sig) = run(&["--armor", "--detach-sign", "--local-user", "seller@spike.test"], Some(&stmt));
        assert!(ok, "gpg detach-sign failed");
        let (ok, cert) = run(&["--armor", "--export", "seller@spike.test"], None);
        assert!(ok);
        // Positive: exact bytes + real signature + cert verify.
        verify_detached(&stmt, &sig, &cert).expect("valid detached signature must verify");
        // Negative: one byte changed in the amount must fail.
        let mut tampered = stmt.clone();
        let pos = tampered.windows(13).position(|w| w == b"1250000000000").unwrap();
        tampered[pos] = b'9';
        assert!(verify_detached(&tampered, &sig, &cert).is_err(), "tampered statement must not verify");
        // Negative: clearsigned-style / garbage signature must fail.
        assert!(verify_detached(&stmt, b"-----BEGIN PGP SIGNATURE-----\n\ngarbage\n-----END PGP SIGNATURE-----\n", &cert).is_err());
    }

    #[test]
    fn rejects_noncanonical_variants() {
        let good = serialize_invoice(&sample());
        let good_str = String::from_utf8(good.clone()).unwrap();
        let variants: Vec<Vec<u8>> = vec![
            good_str.replace('\n', "\r\n").into_bytes(),                 // CRLF
            good_str.replacen(": ", ":\t", 1).into_bytes(),              // tab
            good_str.replacen(": ", ":  ", 1).into_bytes(),              // two spaces
            good_str.replace("\n", " \n").into_bytes(),                  // trailing spaces
            good_str.trim_end_matches('\n').as_bytes().to_vec(),         // no final LF
            format!("{good_str}\n").into_bytes(),                        // extra blank line
            good_str.replacen("0123456789ABCDEF", "0123456789abcdef", 1).into_bytes(), // lowercase fpr
            good_str.replacen(&"a".repeat(64), &"A".repeat(64), 1).into_bytes(),          // uppercase digest
            good_str.replacen("amount-atomic: 1250000000000", "amount-atomic: 01250000000000", 1).into_bytes(), // leading zero
            good_str.replacen("invoice-id", "invoice_id", 1).into_bytes(),  // bad key name
        ];
        for (i, v) in variants.iter().enumerate() {
            assert!(parse_invoice(v).is_err(), "variant {i} must be rejected");
        }
        // Key order: swap lines 3 and 4.
        let mut lines: Vec<&str> = good_str.trim_end().split('\n').collect();
        lines.swap(2, 3);
        let swapped = format!("{}\n", lines.join("\n"));
        assert!(parse_invoice(swapped.as_bytes()).is_err(), "wrong key order must be rejected");
    }
}
