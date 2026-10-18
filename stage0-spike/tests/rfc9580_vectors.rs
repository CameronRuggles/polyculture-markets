use stage0_spike::envelope::validate_envelope;
#[test]
fn rfc9580_a8_seipd_v2_message_accepted() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures-rfc9580");
    let cert = std::fs::read(format!("{base}/a3-cert.asc")).unwrap();
    let msg = std::fs::read(format!("{base}/a8-message.asc")).unwrap();
    // A.8 message is encrypted to the A.3 cert's subkey; sender == recipient cert here.
    let r = validate_envelope(&msg, &cert, &cert);
    assert_eq!(r, Ok(()), "RFC 9580 A.8 SEIPD v2 vector must validate: {r:?}");
}
