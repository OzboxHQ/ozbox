#![allow(clippy::unwrap_used)]
//! The daemon's only listener is a Unix socket. Fails if network-listening code or an HTTP server framework slips in.

use std::fs;
use std::path::Path;

fn sources(dir: &Path, out: &mut Vec<String>) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(fs::read_to_string(&p).unwrap());
        }
    }
}

#[test]
fn no_tcp_or_udp_anywhere_in_the_daemon() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 10);
    let needles = [
        ["Tcp", "Listener"].concat(),
        ["Tcp", "Stream"].concat(),
        ["Udp", "Socket"].concat(),
        ["std::net::", "SocketAddr"].concat(),
        ["0.0.0", ".0:"].concat(),
        ["tokio", "::"].concat(),
        ["hy", "per::"].concat(),
        ["tiny", "_http"].concat(),
    ];
    for src in &files {
        for n in &needles {
            assert!(!src.contains(n.as_str()), "found {n:?} in daemon source");
        }
    }
}

#[test]
fn no_server_framework_dependencies() {
    let manifest =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    for dep in [
        "tokio",
        "hyper",
        "axum",
        "tiny_http",
        "actix",
        "warp",
        "rocket",
    ] {
        assert!(!manifest.contains(dep), "unexpected dependency {dep}");
    }
}
