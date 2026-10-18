// BLIND security tests — address validation.
// Authored independently from spec v2 (sections 3, 9, 23) and the Stage 0
// API contract ONLY. The author has not seen any implementation code.
//
// Spec clauses traced:
//   - s3 invariant 7: every invoice destination is a Monero subaddress on
//     the configured network; primary and integrated addresses are rejected.
//   - s23 (Payments): "Primary, integrated, and wrong-network addresses are
//     rejected."
//   - API contract (address module): only a subaddress on the expected
//     network is accepted; primary/integrated -> Err(NotSubaddress);
//     wrong network -> Err(WrongNetwork); unparseable / bad checksum ->
//     Err(Parse).
//
// Fixture provenance (each string was checksum-verified by the blind author
// with a standalone Monero base58 + Keccak-256 decoder written for fixture
// checking only -- it is NOT the project implementation):
//   * MAINNET_SUBADDRESS_MONEROPEDIA: published in the Moneropedia "address"
//     entry of the Monero project website source (monero-site repository)
//     as the Monero donation address. Decodes to prefix byte 42 (mainnet
//     subaddress); checksum valid.
//   * MAINNET_SUBADDRESS_2 / MAINNET_PRIMARY / MAINNET_INTEGRATED: published
//     as worked examples on the Coin Wallet "Monero address example" page
//     (coin.space). Prefix bytes 42 / 18 / 19 respectively; checksums valid.
//     (Note: a different site's published "examples" FAILED checksum
//     verification by the blind author and were deliberately discarded.)
//   * STAGENET_PRIMARY: published test wallet address in the
//     bh-php-monero-explorer "TestingWithMoneroStagenet" example. Prefix
//     byte 24 (stagenet standard); checksum valid.
//   * STAGENET_SUBADDRESS / TESTNET_SUBADDRESS: constructed by the blind
//     author by re-encoding the public spend/view keys of STAGENET_PRIMARY
//     under the documented stagenet-subaddress prefix (36) / testnet-
//     subaddress prefix (63) with a recomputed checksum, per the address
//     format described in Moneropedia (prefix byte || public spend key ||
//     public view key || first 4 bytes of Keccak-256 of the preceding
//     bytes, Monero block-base58 encoded). Both re-verify: correct length
//     (95), correct prefix byte, valid checksum, and they carry the same
//     (real, on-curve) public keys as the published stagenet wallet.

use stage0_spike::address::{validate_destination, DestinationInfo, Network, Reject};

/// Prefix 42 (mainnet subaddress), 95 chars, checksum verified.
const MAINNET_SUBADDRESS_MONEROPEDIA: &str =
    "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H";
/// Prefix 42 (mainnet subaddress), 95 chars, checksum verified.
const MAINNET_SUBADDRESS_2: &str =
    "84EgZVjXKF4d1JkEhZSxm4LQQEx64AvqQEwkvWPtHEb5JMrB1Y86y1vCPSCiXsKzbfS9x8vCpx3gVgPaHCpobPYqQzANTnC";
/// Prefix 18 (mainnet standard / primary), 95 chars, checksum verified.
const MAINNET_PRIMARY: &str =
    "45GjcbHh1fvEyXEA6mDAKqNDMmy1Gon6CNHrdhp9hghfLXQNQj4J76TLtwYGoooKApWLM7kaZwdAxLycceHmuVcELCSFPHq";
/// Prefix 19 (mainnet integrated), 106 chars, checksum verified.
const MAINNET_INTEGRATED: &str =
    "4FKZ5LYDj98gmRH9ex4GCUi7SCpBeckyX5vi97A2YSN9a5wHYGXKfMfZXHXZGJn87X6NDHAB2jZWWRnnysWoeHTw6XGSCDXRoad4zyZZt5";
/// Prefix 24 (stagenet standard / primary), 95 chars, checksum verified.
const STAGENET_PRIMARY: &str =
    "57AaCDLE3GeBsgrK513QiUFePcBbSp5QYhn2Q2S1P9DsceUmeVkvBMJBQDFTfS9f21LfhXJSWNGN16mvXQmffGsA7KCVBxh";
/// Prefix 36 (stagenet subaddress), 95 chars, checksum verified.
/// Constructed from STAGENET_PRIMARY's keys; see header comment.
const STAGENET_SUBADDRESS: &str =
    "77aeMuA9LUrBsgrK513QiUFePcBbSp5QYhn2Q2S1P9DsceUmeVkvBMJBQDFTfS9f21LfhXJSWNGN16mvXQmffGsA7GpCnKz";
/// Prefix 63 (testnet subaddress), 95 chars, checksum verified.
/// Constructed from STAGENET_PRIMARY's keys; see header comment.
const TESTNET_SUBADDRESS: &str =
    "BdWojhGTkhpBsgrK513QiUFePcBbSp5QYhn2Q2S1P9DsceUmeVkvBMJBQDFTfS9f21LfhXJSWNGN16mvXQmffGsA7J2UPXo";

fn assert_reject(res: Result<DestinationInfo, Reject>, expected: Reject, what: &str) {
    match res {
        Err(e) => assert_eq!(e, expected, "{what}: wrong rejection variant"),
        Ok(_) => panic!("{what}: expected Err({expected:?}) but the address was ACCEPTED"),
    }
}

fn assert_accepted(res: Result<DestinationInfo, Reject>, expected_network: Network, what: &str) {
    match res {
        Ok(info) => {
            assert_eq!(info.network, expected_network, "{what}: wrong network reported");
            assert_eq!(info.kind, "subaddress", "{what}: kind must be \"subaddress\"");
        }
        Err(e) => panic!("{what}: expected acceptance but got Err({e:?})"),
    }
}

// ---------------------------------------------------------------- accept ---

#[test]
fn valid_mainnet_subaddress_accepted_on_mainnet() {
    // s3 #7; s23 Payments.
    assert_accepted(
        validate_destination(MAINNET_SUBADDRESS_MONEROPEDIA, Network::Mainnet),
        Network::Mainnet,
        "Moneropedia mainnet subaddress",
    );
}

#[test]
fn second_valid_mainnet_subaddress_accepted_on_mainnet() {
    // s3 #7. A second, independently published fixture guards against a
    // single-fixture accident.
    assert_accepted(
        validate_destination(MAINNET_SUBADDRESS_2, Network::Mainnet),
        Network::Mainnet,
        "second mainnet subaddress",
    );
}

#[test]
fn valid_stagenet_subaddress_accepted_on_stagenet() {
    // s3 #7 (network is a parameter, not hard-coded to mainnet).
    assert_accepted(
        validate_destination(STAGENET_SUBADDRESS, Network::Stagenet),
        Network::Stagenet,
        "stagenet subaddress",
    );
}

#[test]
fn valid_testnet_subaddress_accepted_on_testnet() {
    // s3 #7.
    assert_accepted(
        validate_destination(TESTNET_SUBADDRESS, Network::Testnet),
        Network::Testnet,
        "testnet subaddress",
    );
}

// ------------------------------------------------- reject: not subaddress ---

#[test]
fn primary_address_rejected_as_not_subaddress() {
    // s3 #7: "Primary and integrated addresses are rejected"; contract maps
    // this to Err(NotSubaddress).
    assert_reject(
        validate_destination(MAINNET_PRIMARY, Network::Mainnet),
        Reject::NotSubaddress,
        "mainnet primary address",
    );
}

#[test]
fn integrated_address_rejected_as_not_subaddress() {
    // s3 #7; s23 Payments.
    assert_reject(
        validate_destination(MAINNET_INTEGRATED, Network::Mainnet),
        Reject::NotSubaddress,
        "mainnet integrated address",
    );
}

#[test]
fn stagenet_primary_rejected_as_not_subaddress_on_stagenet() {
    // Network matches, kind is wrong: the rejection must be NotSubaddress,
    // not WrongNetwork. This isolates kind-checking from network-checking.
    assert_reject(
        validate_destination(STAGENET_PRIMARY, Network::Stagenet),
        Reject::NotSubaddress,
        "stagenet primary on stagenet",
    );
}

// -------------------------------------------------- reject: wrong network ---

#[test]
fn mainnet_subaddress_rejected_as_wrong_network_on_stagenet() {
    // s3 #7; s23 Payments: "wrong-network addresses are rejected".
    assert_reject(
        validate_destination(MAINNET_SUBADDRESS_2, Network::Stagenet),
        Reject::WrongNetwork,
        "mainnet subaddress checked against stagenet",
    );
}

#[test]
fn stagenet_subaddress_rejected_as_wrong_network_on_mainnet() {
    assert_reject(
        validate_destination(STAGENET_SUBADDRESS, Network::Mainnet),
        Reject::WrongNetwork,
        "stagenet subaddress checked against mainnet",
    );
}

#[test]
fn mainnet_subaddress_rejected_as_wrong_network_on_testnet() {
    assert_reject(
        validate_destination(MAINNET_SUBADDRESS_MONEROPEDIA, Network::Testnet),
        Reject::WrongNetwork,
        "mainnet subaddress checked against testnet",
    );
}

#[test]
fn stagenet_primary_on_mainnet_is_rejected() {
    // AMBIGUITY (recorded in README-BLIND.md, item A1): this input violates
    // two rules at once (wrong network AND not a subaddress) and neither the
    // spec nor the contract states which rejection takes precedence. This
    // test asserts only the security property -- rejection -- not a variant.
    let res = validate_destination(STAGENET_PRIMARY, Network::Mainnet);
    assert!(res.is_err(), "stagenet primary must not be accepted on mainnet");
}

// -------------------------------------------------------- reject: garbage ---

#[test]
fn garbage_string_rejected_as_parse() {
    // Contract: unparseable -> Err(Parse).
    assert_reject(
        validate_destination("not-a-monero-address", Network::Mainnet),
        Reject::Parse,
        "garbage string",
    );
}

#[test]
fn empty_string_rejected_as_parse() {
    assert_reject(
        validate_destination("", Network::Mainnet),
        Reject::Parse,
        "empty string",
    );
}

#[test]
fn bad_checksum_rejected_as_parse() {
    // Contract: bad checksum -> Err(Parse). The fixture is
    // MAINNET_SUBADDRESS_MONEROPEDIA with its final character changed
    // ('H' -> 'J'); the payload is untouched, one checksum character is
    // altered, so the embedded checksum cannot match.
    let mut bad = MAINNET_SUBADDRESS_MONEROPEDIA.to_string();
    assert!(bad.ends_with('H'));
    bad.replace_range(bad.len() - 1.., "J");
    assert_eq!(bad.len(), 95);
    assert_reject(
        validate_destination(&bad, Network::Mainnet),
        Reject::Parse,
        "subaddress with corrupted final (checksum) character",
    );
}

#[test]
fn truncated_address_rejected_as_parse() {
    // A 94-character prefix of a valid subaddress is not a valid address.
    let truncated = &MAINNET_SUBADDRESS_2[..94];
    assert_reject(
        validate_destination(truncated, Network::Mainnet),
        Reject::Parse,
        "truncated subaddress",
    );
}

#[test]
fn non_base58_characters_rejected_as_parse() {
    // '0' and 'O' are not in the Monero base58 alphabet. Same length as a
    // real address, so length alone cannot save it.
    let mut s = MAINNET_SUBADDRESS_2.to_string();
    s.replace_range(10..11, "0");
    s.replace_range(20..21, "O");
    assert_reject(
        validate_destination(&s, Network::Mainnet),
        Reject::Parse,
        "address containing non-base58 characters",
    );
}
