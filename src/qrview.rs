//! Animated QR codes in the terminal, and reading them from a webcam.
//!
//! A payload is shown as an endless loop of UR fountain parts, one QR code per
//! frame, so the other device can start reading at any point and skip frames.
//! Reading takes frames from the first camera, finds a QR code in each with
//! `rqrr` and feeds the parts to [`wire::Reader`] until the payload is whole.

use std::error::Error;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossterm::{cursor, execute, terminal};
use frost_zec::wire;
use qrcode::QrCode;
use qrcode::render::unicode;

/// Bytes per fountain fragment: a QR code of about 50 modules, which fits a
/// terminal and is easy for a laptop camera to read.
pub const FRAGMENT: usize = 120;
const FRAME: Duration = Duration::from_millis(250);

/// One part as text: half-block characters, light on dark, with a quiet zone.
/// The part is uppercased so that the QR code uses the compact alphanumeric mode.
pub fn render(part: &str) -> Result<String, Box<dyn Error>> {
    let code = QrCode::new(part.to_ascii_uppercase())?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

/// A QR loop running on its own thread until stopped.
pub struct Display {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Display {
    pub fn start(payload: &[u8], title: String) -> Result<Display, Box<dyn Error>> {
        let mut encoder = wire::encoder(payload, FRAGMENT)?;
        let fragments = encoder.fragment_count();
        // Fail now, not in the thread, if a part does not fit in a QR code.
        render(&encoder.next_part().map_err(|e| e.to_string())?)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut out = io::stdout();
            let _ = execute!(out, terminal::Clear(terminal::ClearType::All));
            while !stopping.load(Ordering::Relaxed) {
                if let Ok(frame) = encoder
                    .next_part()
                    .map_err(|e| e.to_string())
                    .and_then(|part| render(&part).map_err(|e| e.to_string()))
                {
                    let _ = execute!(out, cursor::MoveTo(0, 0));
                    let _ = write!(
                        out,
                        "{title}\n{frame}\n({fragments} fragment(s), shown in a loop)\n"
                    );
                    let _ = out.flush();
                }
                thread::sleep(FRAME);
            }
            let _ = execute!(
                out,
                terminal::Clear(terminal::ClearType::All),
                cursor::MoveTo(0, 0)
            );
        });
        Ok(Display {
            stop,
            handle: Some(handle),
        })
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Display {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Finds and decodes a QR code in a grayscale image. Some cameras mirror or
/// flip their frames, and a mirrored QR code does not decode, so the flipped
/// images are tried too.
#[cfg(feature = "camera")]
pub fn detect(image: &image::GrayImage) -> Option<String> {
    let find = |image: image::GrayImage| {
        let mut prepared = rqrr::PreparedImage::prepare(image);
        prepared
            .detect_grids()
            .into_iter()
            .find_map(|grid| grid.decode().ok().map(|(_, content)| content))
    };
    find(image.clone())
        .or_else(|| find(image::imageops::flip_horizontal(image)))
        .or_else(|| find(image::imageops::flip_vertical(image)))
}

/// A camera frame as a grayscale image: luma from YUYV (every other byte) and
/// NV12 (the first plane), weighted RGB or BGR, or decoded MJPEG.
#[cfg(feature = "camera")]
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

/// Reads one payload from the first camera. Frames with no QR code, other UR
/// types or parts of another stream are skipped.
#[cfg(feature = "camera")]
pub fn scan(what: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    use nokhwa::pixel_format::RgbFormat;
    use nokhwa::utils::{ApiBackend, RequestedFormat, RequestedFormatType};

    nokhwa::nokhwa_initialize(|_| ());
    let cameras = nokhwa::query(ApiBackend::Auto)?;
    let info = cameras.first().ok_or("no camera found")?;
    let mut camera = nokhwa::Camera::new(
        info.index().clone(),
        RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestResolution),
    )?;
    camera.open_stream()?;
    eprintln!("  reading {what} with {} …", info.human_name());
    let mut reader = wire::Reader::default();
    let mut last = (0, 0);
    loop {
        let frame = camera.frame()?;
        let resolution = frame.resolution();
        let image = match to_luma(
            frame.source_frame_format(),
            resolution.width_x,
            resolution.height_y,
            frame.buffer(),
        ) {
            Ok(image) => image,
            Err(e) => {
                let _ = camera.stop_stream();
                return Err(e);
            }
        };
        if let Some(text) = detect(&image) {
            if let Ok(Some(payload)) = reader.receive(&text) {
                let _ = camera.stop_stream();
                return Ok(payload);
            }
            let progress = reader.progress();
            if progress != last {
                eprintln!("  {} / {} fragments", progress.0, progress.1);
                last = progress;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_part_of_a_large_payload_fits_in_a_qr_code() {
        let payload = vec![0xA5u8; 30_000];
        let mut encoder = wire::encoder(&payload, FRAGMENT).unwrap();
        for _ in 0..encoder.fragment_count() + 5 {
            render(&encoder.next_part().unwrap()).unwrap();
        }
    }

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
