//! Fuzz target (§22.5): the listing markup renderer.
//!
//! Real entry point: `domain::markup::render_listing_markup`, which the
//! listing page renders with Askama's `|safe` because the renderer
//! escapes first and emits only <p>, <ul>, <li>, <strong>. Beyond
//! no-panic, this target asserts the output-language invariant on every
//! input: the only `<` sequences in the output are the renderer's own
//! tags ( seller text is escaped, so a raw `<` from input can never
//! appear as a tag start other than these).
#![no_main]

use libfuzzer_sys::fuzz_target;

const ALLOWED_TAGS: &[&str] = &[
    "<p>", "</p>", "<ul>", "</ul>", "<li>", "</li>", "<strong>", "</strong>",
];

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let out = domain::markup::render_listing_markup(text);
    let mut rest = out.as_str();
    while let Some(i) = rest.find('<') {
        let tail = &rest[i..];
        assert!(
            ALLOWED_TAGS.iter().any(|t| tail.starts_with(t)),
            "renderer emitted a non-allowlisted tag: {tail:.40} (input: {text:.80})"
        );
        rest = &tail[1..];
    }
});
