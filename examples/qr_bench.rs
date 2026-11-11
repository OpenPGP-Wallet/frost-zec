//! How well the camera pipeline reads the protocol's QR codes as a webcam sees
//! them on a screen: small, slightly turned, blurred, washed out, noisy and
//! JPEG-compressed, in a 640x480 frame.
//!
//! `cargo run --release --features camera --example qr_bench`
//!
//! For each fragment size and each number of camera pixels per QR module, it
//! prints the share of frames read by rqrr alone (the reader before ZXing's
//! was added) and by [`camera::detect`]. Then the time each takes per frame.

use frost_zec::{camera, wire};
use image::{GrayImage, Luma, imageops};
use qrcode::QrCode;
use rand::{Rng, SeedableRng, rngs::StdRng};

const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;
const TRIALS: usize = 12;

/// The QR code of one part, one pixel per module, with a quiet zone of 4, as
/// the wallet and the terminal draw it (error correction level M).
fn part_image(part: &str) -> (GrayImage, usize) {
    let code = QrCode::new(part.to_ascii_uppercase()).unwrap();
    let modules = code.width();
    let image = code
        .render::<Luma<u8>>()
        .module_dimensions(1, 1)
        .quiet_zone(true)
        .build();
    (image, modules)
}

/// A camera frame of the code: `scale` camera pixels per module, turned by
/// `angle` radians, on a dark background, then blurred, washed out, noisy and
/// compressed.
fn shoot(code: &GrayImage, scale: f32, angle: f32, rng: &mut StdRng) -> GrayImage {
    let side = ((code.width() as f32) * scale).round().max(1.0) as u32;
    // Optics average the screen: an area-like filter, not nearest-neighbour.
    let big = imageops::resize(
        code,
        code.width() * 8,
        code.height() * 8,
        imageops::FilterType::Nearest,
    );
    let small = imageops::resize(&big, side, side, imageops::FilterType::Triangle);
    let (cx, cy) = (
        WIDTH as f32 / 2.0 + rng.gen_range(-40.0..40.0),
        HEIGHT as f32 / 2.0 + rng.gen_range(-30.0..30.0),
    );
    let (sin, cos) = angle.sin_cos();
    let half = side as f32 / 2.0;
    let mut frame = GrayImage::from_pixel(WIDTH, HEIGHT, Luma([40]));
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            // Inverse rotation into the code's coordinates, bilinear sample.
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            let u = cos * dx + sin * dy + half;
            let v = -sin * dx + cos * dy + half;
            if u < 0.0 || v < 0.0 || u >= side as f32 - 1.0 || v >= side as f32 - 1.0 {
                continue;
            }
            let (u0, v0) = (u.floor() as u32, v.floor() as u32);
            let (fu, fv) = (u - u0 as f32, v - v0 as f32);
            let p = |a: u32, b: u32| small.get_pixel(a, b)[0] as f32;
            let value = p(u0, v0) * (1.0 - fu) * (1.0 - fv)
                + p(u0 + 1, v0) * fu * (1.0 - fv)
                + p(u0, v0 + 1) * (1.0 - fu) * fv
                + p(u0 + 1, v0 + 1) * fu * fv;
            frame.put_pixel(x, y, Luma([value as u8]));
        }
    }
    // Slight defocus, a screen seen through a camera (blacks are grey, whites
    // are not white), sensor noise.
    let mut frame = imageops::blur(&frame, 0.7);
    for pixel in frame.pixels_mut() {
        let washed = 45.0 + pixel[0] as f32 * (190.0 - 45.0) / 255.0;
        let noisy = washed + rng.gen_range(-8.0..8.0);
        pixel[0] = noisy.clamp(0.0, 255.0) as u8;
    }
    // The stream is compressed (iVCam sends H.264 over Wi-Fi; JPEG 40 is close).
    let mut bytes = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, 40)
        .encode_image(&frame)
        .unwrap();
    image::load_from_memory(&bytes).unwrap().to_luma8()
}

/// rqrr alone, as the pipeline was before ZXing's reader.
fn rqrr_only(image: &GrayImage) -> Option<String> {
    let mut prepared = rqrr::PreparedImage::prepare(image.clone());
    prepared
        .detect_grids()
        .into_iter()
        .find_map(|grid| grid.decode().ok().map(|(_, content)| content))
}

fn main() {
    let payload: Vec<u8> = (0..4_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut rng = StdRng::seed_from_u64(7);
    println!("fragment modules px/module   rqrr  detect   ({TRIALS} frames each)");
    for fragment in [120usize, 80] {
        let mut encoder = wire::encoder(&payload, fragment).unwrap();
        // A mixed part, as most parts of a long loop are.
        let part = (0..encoder.fragment_count() + 3)
            .map(|_| encoder.next_part().unwrap())
            .last()
            .unwrap();
        let (code, modules) = part_image(&part);
        let expected = part.to_ascii_uppercase();
        for scale in [2.0f32, 2.5, 3.0, 3.5, 4.0, 5.0] {
            let (mut old, mut new) = (0, 0);
            for _ in 0..TRIALS {
                let frame = shoot(&code, scale, rng.gen_range(-0.08f32..0.08), &mut rng);
                let ok = |found: Option<String>| found.as_deref() == Some(expected.as_str());
                old += usize::from(ok(rqrr_only(&frame)));
                new += usize::from(ok(camera::detect(&frame)));
            }
            let pct = |n: usize| n as f32 * 100.0 / TRIALS as f32;
            println!(
                "{fragment:8} {modules:7} {scale:9.1}  {:4.0}%  {:5.0}%",
                pct(old),
                pct(new)
            );
        }
    }

    // Time per frame, with a code and without one (most frames).
    let part = wire::encoder(&payload, 120).unwrap().next_part().unwrap();
    let with = shoot(&part_image(&part).0, 3.0, 0.03, &mut rng);
    let mut without = GrayImage::new(WIDTH, HEIGHT);
    for (x, y, p) in without.enumerate_pixels_mut() {
        p[0] = (((x / 7) ^ (y / 5)) % 2 * 120 + rng.gen_range(0..60)) as u8;
    }
    for (name, frame) in [("with a code", &with), ("without one", &without)] {
        let time = |f: &dyn Fn(&GrayImage) -> Option<String>| {
            let start = std::time::Instant::now();
            for _ in 0..20 {
                let _ = f(frame);
            }
            start.elapsed().as_secs_f64() * 1000.0 / 20.0
        };
        println!(
            "time per 640x480 frame, {name}: rqrr {:.1} ms, detect {:.1} ms",
            time(&|f| rqrr_only(f)),
            time(&|f| camera::detect(f))
        );
    }
}
