//! Username rules (spec §7): 3–24 chars, lowercase ASCII letters, digits,
//! `_` and `-`; uniqueness is case-insensitive via case-folding at input.

pub fn fold_username(input: &str) -> String {
    input.trim().to_lowercase()
}

pub fn validate_username(folded: &str) -> bool {
    // Contract §7 states the complete rule: 3–24 chars of [a-z0-9_-]
    // after folding, with no leading/trailing-character restriction.
    // (An earlier draft also rejected leading/trailing '-'; the contract
    // names no such restriction, so it was removed in the retrofit.)
    (3..=24).contains(&folded.len())
        && folded
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert!(validate_username(&fold_username("Alice_9")));
        assert!(validate_username("bob"));
        assert!(!validate_username("ab")); // too short
        assert!(!validate_username(&"a".repeat(25)));
        assert!(!validate_username("has space"));
        assert!(!validate_username("emoji\u{1F600}"));
        assert!(validate_username("-leading")); // contract §7: no leading-char restriction
        assert!(validate_username("_ab"));
        assert_eq!(fold_username("  MixedCASE "), "mixedcase");
    }
}
