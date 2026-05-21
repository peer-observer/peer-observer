use std::process::Command;

fn main() {
    let hash = std::env::var("GIT_HASH")
        .ok()
        .filter(|h| h.len() >= 8)
        .or_else(|| {
            let output = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let h = String::from_utf8(output.stdout).ok()?.trim().to_string();
            if h.len() >= 8 {
                Some(h)
            } else {
                None
            }
        })
        .unwrap_or_else(|| "00000000".to_string());

    let b0 = u8::from_str_radix(&hash[0..2], 16).unwrap();
    let b1 = u8::from_str_radix(&hash[2..4], 16).unwrap();
    let b2 = u8::from_str_radix(&hash[4..6], 16).unwrap();
    let b3 = u8::from_str_radix(&hash[6..8], 16).unwrap();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let path = std::path::Path::new(&out_dir).join("git_hash.rs");
    std::fs::write(
        path,
        format!(
            "const GIT_HASH: [u8; 4] = [0x{:02x}, 0x{:02x}, 0x{:02x}, 0x{:02x}];\n",
            b0, b1, b2, b3
        ),
    )
    .unwrap();

    println!("cargo:rerun-if-env-changed=GIT_HASH");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
