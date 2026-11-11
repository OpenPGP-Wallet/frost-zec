//! Animated QR codes in the terminal (reading them is in `frost_zec::camera`).
//!
//! A payload is shown as an endless loop of UR fountain parts, one QR code per
//! frame, so the other device can start reading at any point and skip frames.

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
}
