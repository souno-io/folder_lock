//! Build script: generate the application icon (.ico) and compile Windows resources.
//!
//! The icon (folder + padlock) is generated programmatically, saved to
//! assets/icon.ico, and referenced by build.rc which also includes the
//! application manifest. The .rc is compiled to a .res object with windres
//! (LLVM MinGW) and linked into the final exe.

use std::path::Path;

fn main() {
    // Generate the icon into assets/ (where build.rc references it).
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let assets_dir = Path::new(&manifest_dir).join("assets");
    std::fs::create_dir_all(&assets_dir).ok();
    let icon_path = assets_dir.join("icon.ico");

    generate_icon(&icon_path);

    // Help embed-resource find windres from LLVM MinGW.
    prepend_windres_to_path();

    // Compile the resource file (build.rc → .res) and link it into the exe.
    // windres compiles the .rc referencing icon.ico and manifest.xml.
    embed_resource::compile("build.rc", embed_resource::NONE);

    // Tell cargo to rerun if inputs change.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build.rc");
    println!("cargo:rerun-if-changed=assets/manifest.xml");
}

/// Find the LLVM MinGW windres install and prepend its directory to PATH.
fn prepend_windres_to_path() {
    let candidates = &[
        // winget-installed LLVM MinGW (MartinStorsjo)
        r"C:\Users\souno\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260602-ucrt-x86_64\bin",
        // Alternative: any MinGW bin directory
        r"C:\mingw64\bin",
    ];
    for cand in candidates {
        if Path::new(cand).is_dir() {
            let current = std::env::var("PATH").unwrap_or_default();
            // SAFETY: setting PATH in build.rs is deterministic and single-threaded.
            unsafe { std::env::set_var("PATH", format!("{};{}", cand, current)) };
            return;
        }
    }
}

/// Generate a 48×48 icon with a folder + padlock design.
///
/// Layout on the 48×48 canvas:
///   - Folder body: a yellow-tan rounded rectangle with a tab on top-left
///   - Padlock: overlaid in the lower-right area, silver/gray body with
///     a dark shackle and keyhole
fn generate_icon(path: &Path) {
    let image = draw_icon(48);
    let image_32 = draw_icon(32);
    save_as_ico(path, &[(&image, 48), (&image_32, 32)]);
}

fn draw_icon(size: u32) -> image::RgbaImage {
    let mut img = image::RgbaImage::new(size, size);
    let s = size as f64;
    let scale = s / 48.0;

    // Anti-aliased pixel setter (kept as a closure for reference, unused directly).
    let _put = |img: &mut image::RgbaImage, x: f64, y: f64, color: (u8, u8, u8, u8)| {
        let ix = x.round() as u32;
        let iy = y.round() as u32;
        if ix < size && iy < size {
            img.put_pixel(ix, iy, image::Rgba([color.0, color.1, color.2, color.3]));
        }
    };

    // ── Folder ──
    let tab_top = 4.0 * scale;
    let tab_left = 6.0 * scale;
    let tab_right = 24.0 * scale;
    let tab_bottom = 12.0 * scale;
    fill_rect_alpha(
        &mut img, tab_left, tab_top,
        tab_right - tab_left, tab_bottom - tab_top,
        image::Rgba([240, 185, 50, 255]),
    );

    let body_top = 12.0 * scale;
    let body_left = 4.0 * scale;
    let body_right = 44.0 * scale;
    let body_bottom = 36.0 * scale;
    fill_rect_alpha(
        &mut img, body_left, body_top,
        body_right - body_left, body_bottom - body_top,
        image::Rgba([245, 195, 60, 255]),
    );

    let front_top = 14.0 * scale;
    fill_rect_alpha(
        &mut img, body_left, front_top,
        body_right - body_left, body_bottom - front_top,
        image::Rgba([252, 218, 90, 255]),
    );

    draw_rect_outline(
        &mut img, 4.0 * scale, 4.0 * scale, 40.0 * scale, 32.0 * scale,
        image::Rgba([190, 140, 20, 255]), (1.5 * scale) as i32,
    );

    // ── Padlock (lower-right quadrant) ──
    let lock_cx = 30.0 * scale;
    let lock_top = 22.0 * scale;
    let lock_body_w = 14.0 * scale;
    let lock_body_h = 12.0 * scale;
    let lock_body_left = lock_cx - lock_body_w / 2.0;
    let lock_body_top = lock_top + 8.0 * scale;
    let _lock_body_bottom = lock_body_top + lock_body_h;

    let shackle_w = 8.0 * scale;
    let shackle_h = 10.0 * scale;
    let shackle_left = lock_cx - shackle_w / 2.0;
    let shackle_top = lock_body_top - shackle_h + 2.0 * scale;

    let bar_w = 2.0 * scale;
    fill_rect_alpha(
        &mut img, shackle_left, shackle_top, bar_w, shackle_h,
        image::Rgba([100, 100, 110, 255]),
    );
    fill_rect_alpha(
        &mut img, shackle_left + shackle_w - bar_w, shackle_top, bar_w, shackle_h,
        image::Rgba([100, 100, 110, 255]),
    );
    fill_rect_alpha(
        &mut img, shackle_left, shackle_top, shackle_w, bar_w,
        image::Rgba([120, 120, 130, 255]),
    );

    fill_rounded_rect(
        &mut img, lock_body_left, lock_body_top,
        lock_body_w, lock_body_h, (2.0 * scale) as i32,
        image::Rgba([180, 185, 190, 255]),
    );
    fill_rounded_rect(
        &mut img, lock_body_left + 1.0 * scale, lock_body_top + 1.0 * scale,
        lock_body_w - 2.0 * scale, lock_body_h / 2.0 - 1.0 * scale,
        (1.5 * scale) as i32,
        image::Rgba([210, 215, 220, 255]),
    );
    draw_rounded_rect_outline(
        &mut img, lock_body_left, lock_body_top,
        lock_body_w, lock_body_h, (2.0 * scale) as i32,
        image::Rgba([100, 105, 110, 255]), (1.0 * scale) as i32,
    );

    let kh_cx = lock_cx;
    let kh_cy = lock_body_top + lock_body_h * 0.42;
    let kh_r = 2.2 * scale;
    fill_circle(&mut img, kh_cx, kh_cy, kh_r, image::Rgba([60, 60, 65, 255]));
    fill_rect_alpha(
        &mut img, kh_cx - 1.0 * scale, kh_cy + kh_r * 0.4,
        2.0 * scale, 4.0 * scale,
        image::Rgba([60, 60, 65, 255]),
    );

    img
}

// ── Primitive drawing helpers ──

fn fill_rect_alpha(
    img: &mut image::RgbaImage, x: f64, y: f64, w: f64, h: f64,
    color: image::Rgba<u8>,
) {
    let x0 = x.round().max(0.0) as u32;
    let y0 = y.round().max(0.0) as u32;
    let x1 = (x + w).round().min(img.width() as f64) as u32;
    let y1 = (y + h).round().min(img.height() as f64) as u32;
    for py in y0..y1 {
        for px in x0..x1 {
            img.put_pixel(px, py, color);
        }
    }
}

fn fill_rounded_rect(
    img: &mut image::RgbaImage, x: f64, y: f64, w: f64, h: f64, r: i32,
    color: image::Rgba<u8>,
) {
    let ri = r as f64;
    let x0 = x.round().max(0.0) as u32;
    let y0 = y.round().max(0.0) as u32;
    let x1 = (x + w).round().min(img.width() as f64) as u32;
    let y1 = (y + h).round().min(img.height() as f64) as u32;
    let cx0 = x + ri;
    let cx1 = x + w - ri;
    let cy0 = y + ri;
    let cy1 = y + h - ri;
    for py in y0..y1 {
        for px in x0..x1 {
            let fx = px as f64;
            let fy = py as f64;
            let in_rect = fx >= x && fx <= x + w && fy >= y && fy <= y + h;
            let ok = if in_rect {
                if fx < cx0 && fy < cy0 {
                    (fx - cx0).powf(2.0) + (fy - cy0).powf(2.0) <= ri * ri
                } else if fx > cx1 && fy < cy0 {
                    (fx - cx1).powf(2.0) + (fy - cy0).powf(2.0) <= ri * ri
                } else if fx < cx0 && fy > cy1 {
                    (fx - cx0).powf(2.0) + (fy - cy1).powf(2.0) <= ri * ri
                } else if fx > cx1 && fy > cy1 {
                    (fx - cx1).powf(2.0) + (fy - cy1).powf(2.0) <= ri * ri
                } else {
                    true
                }
            } else {
                false
            };
            if ok {
                img.put_pixel(px, py, color);
            }
        }
    }
}

fn draw_rounded_rect_outline(
    img: &mut image::RgbaImage, x: f64, y: f64, w: f64, h: f64,
    r: i32, color: image::Rgba<u8>, thickness: i32,
) {
    let t = thickness as f64;
    let outer = fill_rounded_rect_tmp(img.width(), img.height(), x, y, w, h, r, color);
    let inner_color = image::Rgba([0, 0, 0, 0]);
    let inner = fill_rounded_rect_tmp(
        img.width(), img.height(),
        x + t, y + t, w - 2.0 * t, h - 2.0 * t,
        (r - thickness).max(1), inner_color,
    );
    for py in 0..img.height() {
        for px in 0..img.width() {
            let o = outer.get_pixel(px, py);
            let n = inner.get_pixel(px, py);
            if n[3] == 0 && o[3] > 0 {
                img.put_pixel(px, py, *o);
            }
        }
    }
}

fn fill_rounded_rect_tmp(
    w: u32, h: u32, x: f64, y: f64, rw: f64, rh: f64,
    r: i32, color: image::Rgba<u8>,
) -> image::RgbaImage {
    let mut tmp = image::RgbaImage::new(w, h);
    fill_rounded_rect(&mut tmp, x, y, rw, rh, r, color);
    tmp
}

fn draw_rect_outline(
    img: &mut image::RgbaImage, x: f64, y: f64, w: f64, h: f64,
    color: image::Rgba<u8>, thickness: i32,
) {
    let t = thickness as f64;
    fill_rect_alpha(img, x - t, y - t, w + 2.0 * t, t + 1.0, color);
    fill_rect_alpha(img, x - t, y + h, w + 2.0 * t, t + 1.0, color);
    fill_rect_alpha(img, x - t, y, t + 1.0, h, color);
    fill_rect_alpha(img, x + w, y, t + 1.0, h, color);
}

fn fill_circle(
    img: &mut image::RgbaImage, cx: f64, cy: f64, r: f64,
    color: image::Rgba<u8>,
) {
    let size_w = img.width() as f64;
    let size_h = img.height() as f64;
    let x0 = (cx - r).round().max(0.0) as u32;
    let y0 = (cy - r).round().max(0.0) as u32;
    let x1 = (cx + r).round().min(size_w) as u32;
    let y1 = (cy + r).round().min(size_h) as u32;
    for py in y0..y1 {
        for px in x0..x1 {
            let dx = px as f64 - cx;
            let dy = py as f64 - cy;
            if dx * dx + dy * dy <= r * r {
                img.put_pixel(px, py, color);
            }
        }
    }
}

// ── ICO file writer ──

fn save_as_ico(path: &Path, images: &[(&image::RgbaImage, u32)]) {
    use std::io::Write;

    let mut f = std::fs::File::create(path).expect("failed to create icon file");
    let count = images.len() as u16;

    f.write_all(&0u16.to_le_bytes()).unwrap();
    f.write_all(&1u16.to_le_bytes()).unwrap();
    f.write_all(&count.to_le_bytes()).unwrap();

    let dir_size = (count as usize) * 16;
    let data_start = 6 + dir_size;
    let mut data_bufs: Vec<Vec<u8>> = Vec::new();
    let mut offset = data_start as u32;

    for (img, _size) in images {
        let png_data = png_encode(img);
        let png_len = png_data.len() as u32;
        let w = img.width();
        let h = img.height();
        let entry = IcoDirEntry {
            width: if w < 256 { w as u8 } else { 0 },
            height: if h < 256 { h as u8 } else { 0 },
            color_count: 0,
            reserved: 0,
            planes: 1,
            bit_count: 32,
            size: png_len,
            offset,
        };
        f.write_all(&entry.to_bytes()).unwrap();
        data_bufs.push(png_data);
        offset += png_len;
    }

    for buf in &data_bufs {
        f.write_all(buf).unwrap();
    }
    f.sync_all().unwrap();
}

fn png_encode(img: &image::RgbaImage) -> Vec<u8> {
    use image::codecs::png::PngEncoder;
    use image::ImageEncoder;
    let mut buf = Vec::new();
    let encoder = PngEncoder::new(&mut buf);
    encoder
        .write_image(img.as_raw(), img.width(), img.height(), image::ExtendedColorType::Rgba8)
        .expect("failed to encode PNG");
    buf
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IcoDirEntry {
    width: u8,
    height: u8,
    color_count: u8,
    reserved: u8,
    planes: u16,
    bit_count: u16,
    size: u32,
    offset: u32,
}

impl IcoDirEntry {
    fn to_bytes(self) -> [u8; 16] {
        unsafe { std::mem::transmute(self) }
    }
}
