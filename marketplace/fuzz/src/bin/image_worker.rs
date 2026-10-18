//! Fuzz target (§22.5): the image worker's decode/re-encode path.
//!
//! The media worker is a binary-only crate (§18 isolation: separate
//! process, no network), so it exposes no library entry point to link.
//! This target therefore reproduces, call for call, the exact pipeline
//! of `crates/media-worker/src/main.rs::run()` — same `image` crate
//! version and features, same format allowlist, same header dimension
//! pre-check and limits, same re-encode — minus only the filesystem
//! and argv plumbing. A crash here is a crash in the worker's decode
//! path; a divergence between this file and main.rs is a bug in this
//! target, so the two must be kept in step (the worker is ~70 lines).
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const MAX_INPUT_BYTES: usize = 5 * 1024 * 1024;
const MAX_DIM: u32 = 4096;
const MAX_PIXELS: u64 = 24_000_000;

fn sanitize(bytes: &[u8]) -> Result<(), i32> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(2);
    }
    let make_reader = || {
        image::ImageReader::new(Cursor::new(bytes))
            .with_guessed_format()
            .map_err(|_| 2)
    };
    let reader = make_reader()?;
    let format = reader.format().ok_or(2)?;
    if !matches!(format, image::ImageFormat::Jpeg | image::ImageFormat::Png) {
        return Err(2);
    }
    let (w, h) = make_reader()?.into_dimensions().map_err(|_| 2)?;
    if w > MAX_DIM || h > MAX_DIM || (w as u64) * (h as u64) > MAX_PIXELS {
        return Err(2);
    }
    let img = make_reader()?.decode().map_err(|_| 2)?;
    let mut out = Vec::new();
    match format {
        image::ImageFormat::Png => img
            .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
            .map_err(|_| 3)?,
        _ => img
            .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Jpeg)
            .map_err(|_| 3)?,
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = sanitize(data);
});
