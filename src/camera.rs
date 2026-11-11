//! Reading the protocol's QR codes from a camera (feature `camera`).
//!
//! Frames come from the first camera; ZXing's reader (`rxing`), then `rqrr`,
//! finds a QR code in each, and the UR parts go to [`wire::Reader`] until the
//! payload is whole. Frames with no code, other UR types or parts of another
//! stream are skipped.

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::wire;

/// A camera failure, `Send` so that a caller can scan on another thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraError(pub String);

impl fmt::Display for CameraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "camera: {}", self.0)
    }
}

impl Error for CameraError {}

fn fail(e: impl fmt::Display) -> CameraError {
    CameraError(e.to_string())
}

/// What a scan reports while it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// The camera in use.
    Camera(String),
    /// Fountain fragments resolved so far, and the total.
    Fragments(usize, usize),
}

/// Finds and decodes a QR code in a grayscale image.
///
/// ZXing's reader (`rxing`) goes first: on webcam frames of a screen it reads
/// codes from about 2.5 camera pixels per module, where `rqrr` needs 4 to 5
/// (`examples/qr_bench.rs`), and it is faster. `rqrr` stays as a fallback.
/// Some cameras mirror their frames, and a mirrored QR code does not decode,
/// so the mirrored image is tried too. So are inverted codes (light on dark),
/// as a terminal with a light background shows the co-signer's.
pub fn detect(image: &image::GrayImage) -> Option<String> {
    // Whatever is in front of the camera is decoded: a frame a decoder fails
    // on, even by panicking, is skipped like a frame with no code.
    let zxing = |image: &image::GrayImage| {
        std::panic::catch_unwind(|| {
            rxing::helpers::detect_in_luma_slice_with_hints(
                image.as_raw(),
                image.width(),
                image.height(),
                Some(rxing::BarcodeFormat::QR_CODE),
                &mut rxing::DecodeHints {
                    AlsoInverted: Some(true),
                    ..Default::default()
                },
            )
            .ok()
            .map(|result| result.getText().to_string())
        })
        .ok()
        .flatten()
    };
    let rqrr = |image: image::GrayImage| {
        std::panic::catch_unwind(move || {
            let mut prepared = rqrr::PreparedImage::prepare(image);
            prepared
                .detect_grids()
                .into_iter()
                .find_map(|grid| grid.decode().ok().map(|(_, content)| content))
        })
        .ok()
        .flatten()
    };
    let mirrored = image::imageops::flip_horizontal(image);
    zxing(image)
        .or_else(|| zxing(&mirrored))
        .or_else(|| rqrr(image.clone()))
        .or_else(|| rqrr(mirrored))
}

/// A camera frame as a grayscale image: luma from YUYV (every other byte) and
/// NV12 (the first plane), weighted RGB or BGR, or decoded MJPEG.
pub fn to_luma(
    format: nokhwa::utils::FrameFormat,
    width: u32,
    height: u32,
    bytes: &[u8],
) -> Result<image::GrayImage, Box<dyn Error>> {
    use nokhwa::utils::FrameFormat;
    let pixels = (width as usize) * (height as usize);
    let weighted = |r: u8, g: u8, b: u8| -> u8 {
        ((299 * u32::from(r) + 587 * u32::from(g) + 114 * u32::from(b)) / 1000) as u8
    };
    let luma: Vec<u8> = match format {
        FrameFormat::MJPEG => return Ok(image::load_from_memory(bytes)?.to_luma8()),
        FrameFormat::YUYV => bytes.iter().step_by(2).copied().collect(),
        FrameFormat::NV12 => bytes.iter().take(pixels).copied().collect(),
        FrameFormat::GRAY => bytes.to_vec(),
        FrameFormat::RAWRGB => bytes
            .as_chunks::<3>()
            .0
            .iter()
            .map(|[r, g, b]| weighted(*r, *g, *b))
            .collect(),
        FrameFormat::RAWBGR => bytes
            .as_chunks::<3>()
            .0
            .iter()
            .map(|[b, g, r]| weighted(*r, *g, *b))
            .collect(),
    };
    image::GrayImage::from_raw(width, height, luma)
        .ok_or_else(|| format!("a {format:?} frame of the wrong size").into())
}

/// The first camera, streaming at its highest resolution, and its name.
fn open() -> Result<(nokhwa::Camera, String), CameraError> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::{ApiBackend, RequestedFormat, RequestedFormatType};

    nokhwa::nokhwa_initialize(|_| ());
    let cameras = nokhwa::query(ApiBackend::Auto).map_err(fail)?;
    let info = cameras.first().ok_or_else(|| fail("no camera found"))?;
    let mut camera = nokhwa::Camera::new(
        info.index().clone(),
        RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestResolution),
    )
    .map_err(fail)?;
    camera.open_stream().map_err(fail)?;
    Ok((camera, info.human_name()))
}

/// The next frame of `camera`, in grayscale.
fn next_frame(camera: &mut nokhwa::Camera) -> Result<image::GrayImage, CameraError> {
    let frame = camera.frame().map_err(fail)?;
    let resolution = frame.resolution();
    to_luma(
        frame.source_frame_format(),
        resolution.width_x,
        resolution.height_y,
        frame.buffer(),
    )
    .map_err(fail)
}

/// Reads one payload from the first camera. Returns `None` if `cancel` is set
/// before the payload is whole.
pub fn scan(
    cancel: &AtomicBool,
    mut progress: impl FnMut(Progress),
) -> Result<Option<Vec<u8>>, CameraError> {
    let (mut camera, name) = open()?;
    progress(Progress::Camera(name));
    let mut reader = wire::Reader::default();
    let mut last = (0, 0);
    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            break Ok(None);
        }
        let image = match next_frame(&mut camera) {
            Ok(image) => image,
            Err(e) => break Err(e),
        };
        if let Some(text) = detect(&image) {
            if let Ok(Some(payload)) = reader.receive(&text) {
                break Ok(Some(payload));
            }
            let now = reader.progress();
            if now != last {
                progress(Progress::Fragments(now.0, now.1));
                last = now;
            }
        }
    };
    let _ = camera.stop_stream();
    result
}

/// What [`test`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    /// The camera used.
    pub camera: String,
    /// The frame size it delivers.
    pub width: u32,
    /// The frame height.
    pub height: u32,
    /// Frames read.
    pub frames: usize,
    /// Frames in which a QR code was decoded.
    pub decoded: usize,
}

/// For a camera that does not seem to read the codes: streams the first
/// camera for `seconds`, calls `seen` with every QR code decoded, and saves
/// one frame per second as a JPEG file in `save`, if given, to look at what
/// the camera sees.
pub fn test(
    seconds: u64,
    save: Option<&std::path::Path>,
    mut seen: impl FnMut(&str),
) -> Result<TestReport, CameraError> {
    use std::time::{Duration, Instant};
    let (mut camera, name) = open()?;
    let mut report = TestReport {
        camera: name,
        width: 0,
        height: 0,
        frames: 0,
        decoded: 0,
    };
    let start = Instant::now();
    let mut next_save = start;
    let result = loop {
        if start.elapsed() > Duration::from_secs(seconds) {
            break Ok(());
        }
        let image = match next_frame(&mut camera) {
            Ok(image) => image,
            Err(e) => break Err(e),
        };
        (report.width, report.height) = image.dimensions();
        report.frames += 1;
        if let Some(text) = detect(&image) {
            report.decoded += 1;
            seen(&text);
        }
        if let Some(dir) = save
            && Instant::now() >= next_save
        {
            next_save += Duration::from_secs(1);
            let file = dir.join(format!("frame-{:04}.jpg", report.frames));
            if let Err(e) = image.save(&file) {
                break Err(fail(format!("cannot save {}: {e}", file.display())));
            }
        }
    };
    let _ = camera.stop_stream();
    result.map(|()| report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrcode::QrCode;

    const FRAGMENT: usize = 120;

    /// The reading pipeline without a camera: parts drawn as images, found and
    /// decoded by rqrr, reassembled by the reader.
    #[cfg(feature = "camera")]
    #[test]
    fn parts_drawn_as_images_are_read_back() {
        let payload: Vec<u8> = (0..3_000u32).map(|i| (i % 251) as u8).collect();
        let mut encoder = wire::encoder(&payload, FRAGMENT).unwrap();
        let mut reader = wire::Reader::default();
        for _ in 0..encoder.fragment_count() * 3 {
            let part = encoder.next_part().unwrap();
            let image = QrCode::new(part.to_ascii_uppercase())
                .unwrap()
                .render::<image::Luma<u8>>()
                .module_dimensions(4, 4)
                .build();
            let text = detect(&image).expect("a QR code in the image");
            if let Some(done) = reader.receive(&text).unwrap() {
                assert_eq!(done, payload);
                return;
            }
        }
        panic!("the payload never completed");
    }

    /// A part the size a 640x480 webcam sees on a screen across the room:
    /// 2.6 pixels per module, blurred by resampling. rqrr alone reads none of
    /// these (examples/qr_bench.rs); ZXing's reader does.
    #[cfg(feature = "camera")]
    #[test]
    fn a_small_blurred_code_is_read() {
        let part = wire::encoder(&[3u8; 2_000], FRAGMENT)
            .unwrap()
            .next_part()
            .unwrap();
        let code = QrCode::new(part.to_ascii_uppercase())
            .unwrap()
            .render::<image::Luma<u8>>()
            .module_dimensions(8, 8)
            .build();
        let side = code.width() * 26 / 80;
        let small =
            image::imageops::resize(&code, side, side, image::imageops::FilterType::Triangle);
        let small = image::imageops::blur(&small, 0.7);
        assert_eq!(detect(&small).unwrap().to_ascii_lowercase(), part);
    }

    /// Light modules on a dark background, as a terminal with a light theme
    /// shows the co-signer's codes.
    #[cfg(feature = "camera")]
    #[test]
    fn an_inverted_code_is_read() {
        let part = wire::encoder(&[5u8; 50], FRAGMENT)
            .unwrap()
            .next_part()
            .unwrap();
        let mut code = QrCode::new(part.to_ascii_uppercase())
            .unwrap()
            .render::<image::Luma<u8>>()
            .module_dimensions(4, 4)
            .build();
        image::imageops::invert(&mut code);
        assert_eq!(detect(&code).unwrap().to_ascii_lowercase(), part);
    }

    #[cfg(feature = "camera")]
    #[test]
    fn a_bgr_frame_and_a_mirrored_code_are_read() {
        use nokhwa::utils::FrameFormat;
        let part = wire::encoder(&[9u8; 50], FRAGMENT)
            .unwrap()
            .next_part()
            .unwrap();
        let gray = QrCode::new(part.to_ascii_uppercase())
            .unwrap()
            .render::<image::Luma<u8>>()
            .module_dimensions(4, 4)
            .build();
        let (width, height) = gray.dimensions();
        let bgr: Vec<u8> = gray.as_raw().iter().flat_map(|y| [*y, *y, *y]).collect();
        let luma = to_luma(FrameFormat::RAWBGR, width, height, &bgr).unwrap();
        assert_eq!(detect(&luma).unwrap().to_ascii_lowercase(), part);
        let mirrored = image::imageops::flip_horizontal(&gray);
        assert_eq!(detect(&mirrored).unwrap().to_ascii_lowercase(), part);
    }

    #[cfg(feature = "camera")]
    #[test]
    fn a_yuyv_frame_gives_its_luma() {
        use nokhwa::utils::FrameFormat;
        let part = wire::encoder(&[7u8; 50], FRAGMENT)
            .unwrap()
            .next_part()
            .unwrap();
        let gray = QrCode::new(part.to_ascii_uppercase())
            .unwrap()
            .render::<image::Luma<u8>>()
            .module_dimensions(4, 4)
            .build();
        let (width, height) = gray.dimensions();
        // Y0 U Y1 V, with neutral chroma.
        let yuyv: Vec<u8> = gray.as_raw().iter().flat_map(|y| [*y, 128]).collect();
        let luma = to_luma(FrameFormat::YUYV, width, height, &yuyv).unwrap();
        assert_eq!(luma, gray);
        assert_eq!(detect(&luma).unwrap().to_ascii_lowercase(), part);
    }
}
