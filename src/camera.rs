//! Reading the protocol's QR codes from a camera (feature `camera`).
//!
//! Frames come from the first camera; `rqrr` finds a QR code in each, and the
//! UR parts go to [`wire::Reader`] until the payload is whole. Frames with no
//! code, other UR types or parts of another stream are skipped.

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

/// Finds and decodes a QR code in a grayscale image. Some cameras mirror or
/// flip their frames, and a mirrored QR code does not decode, so the flipped
/// images are tried too.
pub fn detect(image: &image::GrayImage) -> Option<String> {
    // Whatever is in front of the camera is decoded: a frame the decoder
    // fails on, even by panicking, is skipped like a frame with no code.
    let find = |image: image::GrayImage| {
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
    find(image.clone())
        .or_else(|| find(image::imageops::flip_horizontal(image)))
        .or_else(|| find(image::imageops::flip_vertical(image)))
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

/// Reads one payload from the first camera. Returns `None` if `cancel` is set
/// before the payload is whole.
pub fn scan(
    cancel: &AtomicBool,
    mut progress: impl FnMut(Progress),
) -> Result<Option<Vec<u8>>, CameraError> {
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
    progress(Progress::Camera(info.human_name()));
    let mut reader = wire::Reader::default();
    let mut last = (0, 0);
    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            break Ok(None);
        }
        let frame = match camera.frame() {
            Ok(frame) => frame,
            Err(e) => break Err(fail(e)),
        };
        let resolution = frame.resolution();
        let image = match to_luma(
            frame.source_frame_format(),
            resolution.width_x,
            resolution.height_y,
            frame.buffer(),
        ) {
            Ok(image) => image,
            Err(e) => break Err(fail(e)),
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
