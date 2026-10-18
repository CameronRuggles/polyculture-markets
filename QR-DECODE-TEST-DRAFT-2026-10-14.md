# DRAFT — QR decode-and-compare test (prepared 2026-10-14, NOT applied)

Status: draft for the next marketplace gate. No code was changed in
preparing this. It closes the one named open item from the Stage 6
gate: cargo-mutants found 11 surviving mutants in the QR-render
geometry in `crates/domain/src/statements.rs::payment_qr_png`
(scale, quiet-zone and module-offset changes) that no current test
catches, because both the unit tests and blind_stage6 check only PNG
magic, byte determinism and amount sensitivity — never the rendered
modules themselves (STAGE6-REPORT.md §6; blind author's note (d)).

## The fix — decode the PNG back and compare module-for-module

No new dependency is needed: the domain crate already depends on
`image` (png) and `qrcode`. The test renders a known invoice, decodes
the PNG with the image crate, samples the centre pixel of each
module (accounting for the pinned 4-module quiet zone and 8 px/module
scale), rebuilds the module matrix, and asserts it equals
`QrCode::new(payment_uri(...)).to_colors()` exactly. Any mutant that
changes scale, quiet zone, offsets, or inverts/flips modules fails.

Paste-ready unit test for the `#[cfg(test)] mod tests` block in
`crates/domain/src/statements.rs` (uses the fixtures and the exact
`parse_invoice_statement(&text, MKT, Network::Stagenet, MAX)` call
shape already in that module — verified in the tree 2026-10-14):

```rust
#[test]
fn qr_png_decodes_back_to_the_encoded_uri_modules() {
    let inv = parse_invoice_statement(&invoice_text(), MKT, Network::Stagenet, MAX)
        .expect("fixture invoice must parse");
    let png = payment_qr_png(&inv);
    assert!(!png.is_empty(), "QR render must produce a PNG");

    // Decode the PNG back to a grayscale image.
    let img = image::load_from_memory(&png)
        .expect("rendered QR must be a decodable PNG")
        .to_luma8();

    // Re-encode the same URI and take its module matrix as ground truth.
    let uri = payment_uri(&inv);
    let code = qrcode::QrCode::new(uri.as_bytes()).expect("URI must encode");
    let width = code.width();
    let colors = code.to_colors();

    // Pinned geometry: 4-module quiet zone, 8 px per module.
    let (scale, quiet) = (8usize, 4usize);
    let dim = ((width + quiet * 2) * scale) as u32;
    assert_eq!(img.dimensions(), (dim, dim),
        "PNG size must be (modules + 2*quiet) * scale in both axes");

    // Quiet zone must be entirely white.
    for y in 0..dim {
        for x in 0..dim {
            let in_qr = x >= (quiet * scale) as u32
                && x < ((quiet + width) * scale) as u32
                && y >= (quiet * scale) as u32
                && y < ((quiet + width) * scale) as u32;
            if !in_qr {
                assert_eq!(img.get_pixel(x, y).0[0], 255,
                    "quiet zone pixel ({x},{y}) must be white");
            }
        }
    }

    // Every module's centre pixel must match the encoded matrix.
    for my in 0..width {
        for mx in 0..width {
            let cx = ((mx + quiet) * scale + scale / 2) as u32;
            let cy = ((my + quiet) * scale + scale / 2) as u32;
            let dark = img.get_pixel(cx, cy).0[0] == 0;
            let expect_dark = colors[my * width + mx] == qrcode::Color::Dark;
            assert_eq!(dark, expect_dark,
                "module ({mx},{my}) rendered with the wrong colour");
        }
    }
}
```

## Verification when applied

1. `cargo test -p domain` — the new test passes against the current
   (correct) renderer.
2. Spot-check it has teeth: hand-apply the three classic geometry
   mutants one at a time (scale 8→7, quiet 4→3, module offset +1)
   and confirm the test fails on each, then revert. That is the
   exact hand-verification the Stage 6 mutants run had to do by
   reasoning instead of by test.
3. This belongs in the implementer unit layer, NOT in a locked blind
   suite — blind authors must keep working from the spec alone.

## Scope note

This does not reopen Stage 6's PASS. It removes the one blind spot
that gate named, so the next gate's mutants run on statements.rs
should show the 11 QR-geometry survivors caught instead of missed.
