//! media-worker — the isolated image sanitizer (spec §18).
//!
//! A separate process: the app passes it an input path and an output path;
//! it decodes (JPEG/PNG only, by content, never by extension), enforces
//! the size/dimension limits, re-encodes (which strips all metadata),
//! and prints `WIDTHxHEIGHT` on stdout. Exit codes: 0 ok, 2 rejected,
//! 3 internal error. It never opens the network and touches only the two
//! paths it is given; the app runs it under a timeout (deployment adds
//! seccomp / read-only-root wrapping, ops docs Stage 10).

use std::io::Cursor;
use std::process::ExitCode;

const MAX_INPUT_BYTES: u64 = 5 * 1024 * 1024;
const MAX_DIM: u32 = 4096;
const MAX_PIXELS: u64 = 24_000_000;

fn run() -> Result<(u32, u32), i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: media-worker <input> <output>");
        return Err(3);
    }
    let meta = std::fs::metadata(&args[1]).map_err(|_| 3)?;
    if meta.len() > MAX_INPUT_BYTES {
        eprintln!("input over 5 MiB");
        return Err(2);
    }
    let bytes = std::fs::read(&args[1]).map_err(|_| 3)?;

    let make_reader = || {
        image::ImageReader::new(Cursor::new(&bytes))
            .with_guessed_format()
            .map_err(|_| 2)
    };
    let reader = make_reader()?;
    let format = reader.format().ok_or(2)?;
    if !matches!(format, image::ImageFormat::Jpeg | image::ImageFormat::Png) {
        eprintln!("only JPEG and PNG");
        return Err(2);
    }
    // Dimension pre-check from the header, before full decode.
    let (w, h) = make_reader()?.into_dimensions().map_err(|_| 2)?;
    if w > MAX_DIM || h > MAX_DIM || (w as u64) * (h as u64) > MAX_PIXELS {
        eprintln!("dimensions over limit");
        return Err(2);
    }
    let img = make_reader()?.decode().map_err(|_| 2)?;

    // Re-encode from decoded pixels: every metadata chunk (EXIF, tEXt,
    // profiles) is dropped because only pixel data is written.
    let mut out = Vec::new();
    match format {
        image::ImageFormat::Png => img
            .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
            .map_err(|_| 3)?,
        _ => img
            .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Jpeg)
            .map_err(|_| 3)?,
    }
    std::fs::write(&args[2], &out).map_err(|_| 3)?;
    Ok((img.width(), img.height()))
}

fn main() -> ExitCode {
    match run() {
        Ok((w, h)) => {
            println!("{w}x{h}");
            ExitCode::from(0)
        }
        Err(code) => ExitCode::from(code as u8),
    }
}
