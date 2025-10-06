// Ensures the workspace stays strictly under `crates/` by failing if
// top-level duplicate crate folders are reintroduced at `SoftEther-Rust/`.
//
// This runs as part of `cargo test` for the `cedar` crate and will fail the
// build in CI if forbidden directories are present.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points to: <workspace>/crates/cedar
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent() // crates
        .and_then(|p| p.parent()) // workspace root (SoftEther-Rust)
        .unwrap()
        .to_path_buf()
}

#[test]
fn no_root_level_duplicate_crates() {
    let root = workspace_root();
    let forbidden = ["client", "adapter", "pencore", "protocol"]; // must live under crates/

    let mut found: Vec<String> = Vec::new();
    for name in forbidden {
        let p = root.join(name);
        if p.is_dir() {
            found.push(format!("{} (at {})", name, p.display()));
        }
    }

    if !found.is_empty() {
        panic!(
            "Forbidden root-level crate folders found. Move them under crates/ and delete the root copies. Found: {}",
            found.join(", ")
        );
    }
}
