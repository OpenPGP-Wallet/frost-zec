//! Replays saved camera frames (`qr camera-test --save DIR`) through the
//! scan path: detect, then the UR reader, printing what each frame gives.
//!
//! `cargo run --release --features camera --example frames_replay -- DIR`

use frost_zec::{camera, wire};

fn main() {
    let dir = std::env::args().nth(1).expect("a directory of frames");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let mut reader = wire::Reader::default();
    for file in files {
        let frame = image::open(&file).unwrap().to_luma8();
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        match camera::detect(&frame) {
            None => println!("{name}: no code"),
            Some(text) => {
                let head: String = text.chars().take(28).collect();
                match reader.receive(&text) {
                    Ok(Some(payload)) => {
                        println!("{name}: {head} -> COMPLETE, {} bytes", payload.len());
                        return;
                    }
                    Ok(None) => println!("{name}: {head} -> progress {:?}", reader.progress()),
                    Err(e) => println!("{name}: {head} -> ERROR {e}"),
                }
            }
        }
    }
    println!("end of frames, progress {:?}", reader.progress());
}
