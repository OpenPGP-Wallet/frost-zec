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

/// Bytes per fountain fragment, largest first. The largest whose code fits in
/// the terminal is used: a code cut by the window's edge cannot be read, and a
/// default Windows Terminal window has 30 rows, where a 120-byte fragment
/// needs about 36 with the text around it. Smaller fragments mean more parts.
const FRAGMENTS: [usize; 4] = [120, 80, 60, 40];
const FRAME: Duration = Duration::from_millis(250);
/// Lines shown besides the code: the title, the line under it, a margin.
const TEXT_LINES: usize = 3;

/// The fragment size to show `payload` with in a `columns` x `rows` terminal,
/// and whether its code fits whole.
fn fitting_fragment(
    payload: &[u8],
    title: &str,
    columns: usize,
    rows: usize,
) -> Result<(usize, bool), Box<dyn Error>> {
    let title_lines = title.chars().count().div_ceil(columns.max(1)).max(1);
    for fragment in FRAGMENTS {
        let mut encoder = wire::encoder(payload, fragment)?;
        // Later parts have longer sequence numbers: measure a few of them.
        let (mut width, mut height) = (0, 0);
        for _ in 0..encoder.fragment_count() + 2 {
            let frame = render(&encoder.next_part().map_err(|e| e.to_string())?)?;
            height = height.max(frame.lines().count());
            width = width.max(frame.lines().map(|l| l.chars().count()).max().unwrap_or(0));
        }
        if width <= columns && height + title_lines + TEXT_LINES <= rows {
            return Ok((fragment, true));
        }
    }
    Ok((FRAGMENTS[FRAGMENTS.len() - 1], false))
}

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
        let (columns, rows) = terminal::size().unwrap_or((u16::MAX, u16::MAX));
        let (fragment, fits) =
            fitting_fragment(payload, &title, usize::from(columns), usize::from(rows))?;
        let title = if fits && fragment == FRAGMENTS[0] {
            title
        } else if fits {
            format!("{title}\n(maximize this window: fewer, larger parts are read faster)")
        } else {
            format!(
                "{title}\nTHE WINDOW IS TOO SMALL FOR THE WHOLE CODE: enlarge it, or zoom out (Ctrl and -)."
            )
        };
        let mut encoder = wire::encoder(payload, fragment)?;
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
        for fragment in FRAGMENTS {
            let mut encoder = wire::encoder(&payload, fragment).unwrap();
            for _ in 0..encoder.fragment_count() + 5 {
                render(&encoder.next_part().unwrap()).unwrap();
            }
        }
    }

    /// A big terminal shows 120-byte fragments; a default Windows Terminal
    /// window (120 x 30) gets smaller ones whose code fits; a tiny one is told.
    #[test]
    fn the_code_shrinks_to_fit_the_terminal() {
        let payload = vec![0x5Au8; 3_000];
        let title = "4-cosigner-keys.ur: let the other device read this code, then press Enter.";
        assert_eq!(
            fitting_fragment(&payload, title, 200, 60).unwrap(),
            (120, true)
        );
        let (fragment, fits) = fitting_fragment(&payload, title, 120, 30).unwrap();
        assert!(fits && fragment < 120, "{fragment}");
        assert_eq!(
            fitting_fragment(&payload, title, 40, 15).unwrap(),
            (40, false)
        );
    }
}
