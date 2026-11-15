//! Embeds the built dashboard (`packages/dashboard/dist`) into the binary.
//!
//! If the directory is absent at compile time, nothing is embedded and `ozbox serve` says the dashboard is not built. That
//! is fine for a development build and never for a release: a **release build fails** when `dist` has no `index.html`
//! (the profile is `release`, or `OZBOX_RELEASE=1` is set, as the release workflows do), so a program that would serve the
//! placeholder can never be built, signed or shipped. `OZBOX_ALLOW_NO_DASHBOARD=1` overrides it, for a person who really
//! wants a release build without a UI.
//!
//! The content hash of what was embedded is recorded in the program (`OZBOX_DASHBOARD_SHA256`), so a dashboard can say which
//! UI it serves, and a release manifest can name it.
//!
//! It also embeds the box infrastructure (`infra/tofu/modules` and `infra/cloud-init`), which the program extracts and checks
//! by hash before rendering a box (see `ozbox_core::infra`).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        if path.is_dir() {
            collect(&path, root, out)?;
        } else if let Ok(rel) = path.strip_prefix(root) {
            let url = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((format!("/{url}"), path));
        }
    }
    Ok(())
}

/// SHA-256 over every embedded file's URL and bytes (each length-prefixed), or `none` when nothing is embedded.
fn content_hash(files: &[(String, PathBuf)]) -> String {
    if files.is_empty() {
        return "none".into();
    }
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for (url, path) in files {
        let bytes = std::fs::read(path).unwrap_or_default();
        ctx.update(&(url.len() as u64).to_be_bytes());
        ctx.update(url.as_bytes());
        ctx.update(&(bytes.len() as u64).to_be_bytes());
        ctx.update(&bytes);
    }
    ctx.finish()
        .as_ref()
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let dist = Path::new(&manifest).join("../../packages/dashboard/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    println!("cargo:rerun-if-changed=build.rs");

    let mut files = Vec::new();
    if dist.is_dir() {
        if let Ok(dist) = dist.canonicalize() {
            let _ = collect(&dist, &dist, &mut files);
        }
    }
    // Only embed a build that has an entry page.
    if !files.iter().any(|(u, _)| u == "/index.html") {
        files.clear();
    }

    let release = std::env::var("PROFILE").is_ok_and(|p| p == "release")
        || std::env::var("OZBOX_RELEASE").is_ok_and(|v| !v.is_empty() && v != "0");
    let allowed =
        std::env::var("OZBOX_ALLOW_NO_DASHBOARD").is_ok_and(|v| !v.is_empty() && v != "0");
    if files.is_empty() && release && !allowed {
        eprintln!(
            "error: this is a release build and the dashboard is not built ({} has no index.html). A program built this way would \
             serve the placeholder page. Build the dashboard first: `cd packages/dashboard && npm ci && npm run build`, then build ozbox \
             again. (Set OZBOX_ALLOW_NO_DASHBOARD=1 to build a release without a UI on purpose.)",
            dist.display()
        );
        std::process::exit(1);
    }
    println!("cargo:rerun-if-env-changed=OZBOX_RELEASE");
    println!("cargo:rerun-if-env-changed=OZBOX_ALLOW_NO_DASHBOARD");
    println!("cargo:rustc-check-cfg=cfg(dashboard_embedded)");
    if !files.is_empty() {
        println!("cargo:rustc-cfg=dashboard_embedded");
    }
    println!(
        "cargo:rustc-env=OZBOX_DASHBOARD_SHA256={}",
        content_hash(&files)
    );

    let mut src = String::from("pub static EMBEDDED: &[(&str, &[u8])] = &[\n");
    for (url, path) in &files {
        let _ = writeln!(
            src,
            "    ({url:?}, include_bytes!({:?})),",
            path.display().to_string()
        );
        println!("cargo:rerun-if-changed={}", path.display());
    }
    src.push_str("];\n");
    let out = std::env::var("OUT_DIR").unwrap_or_default();
    let _ = std::fs::write(Path::new(&out).join("dashboard_assets.rs"), src);

    embed_infra(Path::new(&manifest), Path::new(&out));
}

include!("infra_select.rs");

/// Embeds the box infrastructure this program renders (the OpenTofu, template and script files of `infra/cloud-init/**`
/// and `infra/tofu/modules/**`, without hidden files and `tests` folders; see `infra_select.rs`), so the program always
/// renders its own version of it (ADR 0036). Unlike the dashboard it is always in the source tree, so a build without
/// it, or with OpenTofu state or variables lying in it, is refused, release or not.
fn embed_infra(manifest: &Path, out: &Path) {
    let infra = manifest.join("../../infra");
    println!("cargo:rerun-if-changed=infra_select.rs");
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let mut refused = Vec::new();
    for dir in ["cloud-init", "tofu/modules"] {
        let base = infra.join(dir);
        println!("cargo:rerun-if-changed={}", base.display());
        let Ok(base) = base.canonicalize() else {
            continue;
        };
        let mut found = InfraFound::default();
        if let Err(e) = collect_infra(&base, "", &mut found) {
            eprintln!("error: {} could not be read: {e}", base.display());
            std::process::exit(1);
        }
        for d in &found.dirs {
            println!("cargo:rerun-if-changed={}", d.display());
        }
        refused.extend(found.refused);
        files.extend(
            found
                .files
                .into_iter()
                .map(|(rel, path)| (format!("{dir}/{rel}"), path)),
        );
    }
    if !refused.is_empty() {
        for r in &refused {
            println!("cargo:rerun-if-changed={}", r.display());
        }
        eprintln!(
            "error: OpenTofu state, variables or a saved plan is lying in the box modules, and the program would carry it: {}. Move it out of infra/ (ozbox keeps box state under ~/.local/share/ozbox/tofu since 2026-11-10) or delete it, then build again.",
            refused.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
        );
        std::process::exit(1);
    }
    files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    if !files.iter().any(|(p, _)| p == "cloud-init/box.yaml.tftpl")
        || !files
            .iter()
            .any(|(p, _)| p == "tofu/modules/aws-box/main.tf")
    {
        eprintln!(
            "error: the box modules were not found under {}; the program carries its own copy and cannot be built without it",
            infra.display()
        );
        std::process::exit(1);
    }
    let mut src = String::from("pub static EMBEDDED_INFRA: &[(&str, &[u8])] = &[\n");
    for (rel, path) in &files {
        let _ = writeln!(
            src,
            "    ({rel:?}, include_bytes!({:?})),",
            path.display().to_string()
        );
        println!("cargo:rerun-if-changed={}", path.display());
    }
    src.push_str("];\n");
    let _ = std::fs::write(out.join("infra_assets.rs"), src);
}
