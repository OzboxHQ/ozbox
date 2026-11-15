//! `ozbox env policy pin --tool NAME --release VERSION` and `--browser KIND --revision N`: the digest the box will see for a tool
//! or browser, worked out on the OWNER'S computer from the vendor's own download, so nobody has to fall back to `--on-box` (which
//! only freezes what an agent may already have changed). G5 third round, N-H2.
//!
//! **Tools.** The catalog says where the Linux release is and how it is checked. This fetches that release for the box's
//! architecture, checks its SHA-256 against the catalog's rule (the digest pinned in the catalog, or the vendor's published
//! checksum file) and refuses anything else, extracts it the way the box does (`--strip-components`), and prints `tree_digest` of
//! the result: the number the box computes over its own install. A mismatch on the box fails closed and costs nothing.
//!
//! **Browsers.** Playwright publishes no checksum for its builds. This downloads the Linux build from Playwright's own CDN over
//! HTTPS, prints the archive's SHA-256 (so the owner can compare it to a second download or a colleague's), writes the marker file
//! Playwright writes, and digests the folder. What it proves is that the digest is of what the vendor's server served over TLS, not
//! of what a mac or a box user produced. The page says so.
//!
//! The network is behind [`Source`], so a test supplies the bytes.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

use ozbox_catalog::{verify, Arch, Catalog, Step};

const MAX_ARCHIVE: u64 = 600 << 20;
const MAX_TEXT: u64 = 4 << 20;

/// Where bytes come from.
pub trait Source {
    fn get(&self, url: &str, max: u64) -> Result<Vec<u8>, String>;
}

/// The client: every connection it makes, the first and each redirect's, must be https (G5 fourth round, NV3-L1).
fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(900))
        .redirects(3)
        .https_only(true)
        .build()
}

/// The real network: HTTPS only, a time limit, a size limit.
pub struct Https;

impl Source for Https {
    fn get(&self, url: &str, max: u64) -> Result<Vec<u8>, String> {
        if !url.starts_with("https://") {
            return Err(format!("{url} is not an https address: refused"));
        }
        let resp = agent().get(url).call().map_err(|e| match e {
            ureq::Error::Status(c, _) => format!("{url} answered {c}"),
            ureq::Error::Transport(_) => format!("{url} could not be reached"),
        })?;
        let mut buf = Vec::new();
        resp.into_reader()
            .take(max + 1)
            .read_to_end(&mut buf)
            .map_err(|_| format!("{url} could not be read"))?;
        if buf.len() as u64 > max {
            return Err(format!("{url} is larger than {} MiB: refused", max >> 20));
        }
        Ok(buf)
    }
}

/// `amd64`, `arm64`, `linux-x64`, `linux-arm64`, `x64`, `aarch64`.
pub fn parse_arch(s: &str) -> Result<Arch, String> {
    match s {
        "amd64" | "x64" | "x86_64" | "linux-x64" => Ok(Arch::Amd64),
        "arm64" | "aarch64" | "linux-arm64" => Ok(Arch::Arm64),
        _ => Err(format!("--arch {s}: use amd64 or arm64 (the box's architecture: `uname -m` there says x86_64 or aarch64)")),
    }
}

/// What was verified and worked out.
#[derive(Debug, PartialEq, Eq)]
pub struct Fetched {
    pub sha256: String,
    pub archive_sha256: String,
    pub asset: String,
}

/// The catalog's folder URLs name the newest release (`latest-v22.x`); a specific release lives at `v<release>`.
fn at_release(url: &str, release: &str) -> String {
    let rel = release.trim_start_matches('v');
    let mut out = url.replace("{version}", rel);
    if let Some(i) = out.find("latest-v") {
        let end = out[i..].find('/').map_or(out.len(), |e| i + e);
        out.replace_range(i..end, &format!("v{rel}"));
    }
    out
}

fn extract(
    kind: ozbox_catalog::model::Extract,
    archive: &Path,
    dest: &Path,
    strip: u8,
) -> Result<(), String> {
    use ozbox_catalog::model::Extract;
    let flag = match kind {
        Extract::TarXz => "-xJf",
        Extract::TarGz => "-xzf",
        Extract::TarZst => return Err(
            "this tool's download is a zstd archive: extract it yourself and pass --tool NAME=DIR"
                .into(),
        ),
        Extract::None => {
            return Err("this tool's download is a single program: pass --tool NAME=DIR".into())
        }
    };
    let ok = Command::new("tar")
        .arg(flag)
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .arg(format!("--strip-components={strip}"))
        .arg("--no-same-owner")
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "tar is not installed on this computer".to_string())?;
    if ok.status.success() {
        Ok(())
    } else {
        Err("the download could not be extracted".into())
    }
}

/// The digest a catalog tool's release for `arch` has on the box.
pub fn tool_digest(
    src: &dyn Source,
    catalog: &Catalog,
    name: &str,
    release: &str,
    arch: Arch,
) -> Result<Fetched, String> {
    let tool = catalog
        .tools
        .iter()
        .find(|t| t.id == name)
        .ok_or_else(|| format!("{name} is not a tool in the catalog"))?;
    let step = tool
        .install
        .iter()
        .find(|d| (d.arch.is_empty() || d.arch.contains(&arch)) && matches!(d.step, Step::Release { .. }))
        .ok_or_else(|| format!("{name} is not a vendor release for {}: pass --tool {name}=DIR with a folder you extracted yourself", arch.as_str()))?;
    let Step::Release {
        base_url,
        asset,
        checksum_url,
        checksum_format,
        pinned_sha256,
        extract: kind,
        strip,
        arch_names,
        ..
    } = &step.step
    else {
        return Err(format!("{name} has no release to fetch"));
    };
    let an = arch_names
        .get(&arch)
        .ok_or_else(|| format!("{name} has no download for {}", arch.as_str()))?;
    let base = at_release(&base_url.replace("{arch}", an), release);
    let pattern = asset
        .replace("{arch}", an)
        .replace("{version}", release.trim_start_matches('v'));
    // the checksum the catalog's rule gives: pinned in the catalog, or the vendor's published file
    let mut file = pattern.clone();
    let mut want = pinned_sha256.get(&arch).cloned();
    if want.is_none() {
        let url = at_release(&checksum_url.replace("{arch}", an), release);
        if url.is_empty() {
            return Err(format!(
                "{name} has no checksum to check a download against: pass --tool {name}=DIR"
            ));
        }
        let text = String::from_utf8(src.get(&url, MAX_TEXT)?)
            .map_err(|_| "the checksum file is not text".to_string())?;
        if pattern.contains('*') {
            let rel = release.trim_start_matches('v');
            let names: Vec<String> = verify::names_matching(&text, &pattern)
                .into_iter()
                .filter(|n| n.contains(rel))
                .collect();
            file = match names.as_slice() {
                [one] => one.clone(),
                [] => {
                    return Err(format!(
                        "the vendor's checksum file lists no {pattern} for release {rel}"
                    ))
                }
                _ => {
                    return Err(format!(
                    "the vendor's checksum file lists more than one {pattern} for release {rel}"
                ))
                }
            };
        }
        let digest = match checksum_format {
            ozbox_catalog::model::ChecksumFormat::Sums => verify::digest_for(&text, &file),
            ozbox_catalog::model::ChecksumFormat::Single => verify::single_digest(&text),
        };
        want = Some(
            digest.ok_or_else(|| format!("the vendor's checksum file has no entry for {file}"))?,
        );
    }
    let want = want.unwrap_or_default();
    let bytes = src.get(
        &format!(
            "{}{}",
            if base.ends_with('/') {
                base.clone()
            } else {
                format!("{base}/")
            },
            file
        ),
        MAX_ARCHIVE,
    )?;
    let got = verify::sha256_hex(&bytes);
    if !verify::same_digest(&got, &want) {
        return Err(format!(
            "the download {file} does not match the checksum the catalog requires (expected {}, got {}): nothing was digested",
            &want[..want.len().min(12)],
            &got[..12]
        ));
    }
    let work = tempfile::tempdir().map_err(|_| "no temporary folder".to_string())?;
    let archive = work.path().join("download");
    std::fs::write(&archive, &bytes).map_err(|_| "cannot write the download".to_string())?;
    let dest = work.path().join("tree");
    std::fs::create_dir(&dest).map_err(|_| "cannot make a folder".to_string())?;
    extract(*kind, &archive, &dest, *strip)?;
    let sha256 = crate::runner_setup::tree_digest(&dest)?;
    Ok(Fetched {
        sha256,
        archive_sha256: got,
        asset: file,
    })
}

/// Playwright's build for one browser kind: the path under its CDN, and the folder name inside the cache.
fn browser_build(kind: &str, revision: &str, arch: Arch) -> Result<(String, String), String> {
    if revision.is_empty() || !revision.bytes().all(|b| b.is_ascii_digit()) {
        return Err(
            "--revision is the number Playwright names the folder with (chromium-1169 is 1169)"
                .into(),
        );
    }
    let suffix = match arch {
        Arch::Amd64 => "",
        Arch::Arm64 => "-arm64",
    };
    let (path, dir) = match kind {
        "chromium" => (format!("builds/chromium/{revision}/chromium-linux{suffix}.zip"), format!("chromium-{revision}")),
        "chromium_headless_shell" => (
            format!("builds/chromium/{revision}/chromium-headless-shell-linux{suffix}.zip"),
            format!("chromium_headless_shell-{revision}"),
        ),
        "ffmpeg" => (format!("builds/ffmpeg/{revision}/ffmpeg-linux{suffix}.zip"), format!("ffmpeg-{revision}")),
        _ => return Err(format!("--browser {kind}: use chromium, chromium_headless_shell or ffmpeg (one --revision each, as Playwright names them)")),
    };
    Ok((
        format!("https://cdn.playwright.dev/dbazure/download/playwright/{path}"),
        dir,
    ))
}

/// The digest, keyed by the cache folder's name, of one Playwright build downloaded from its CDN.
pub fn browser_digest(
    src: &dyn Source,
    kind: &str,
    revision: &str,
    arch: Arch,
) -> Result<(BTreeMap<String, String>, String), String> {
    let (url, dir) = browser_build(kind, revision, arch)?;
    let bytes = src.get(&url, MAX_ARCHIVE)?;
    let archive_sha = verify::sha256_hex(&bytes);
    let work = tempfile::tempdir().map_err(|_| "no temporary folder".to_string())?;
    let zip = work.path().join("download.zip");
    std::fs::write(&zip, &bytes).map_err(|_| "cannot write the download".to_string())?;
    let dest = work.path().join(&dir);
    std::fs::create_dir(&dest).map_err(|_| "cannot make a folder".to_string())?;
    let ok = Command::new("unzip")
        .arg("-q")
        .arg(&zip)
        .arg("-d")
        .arg(&dest)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "unzip is not installed on this computer".to_string())?;
    if !ok.status.success() {
        return Err("the browser download could not be unpacked".into());
    }
    // what Playwright's installer leaves once it is done
    std::fs::write(dest.join("INSTALLATION_COMPLETE"), b"")
        .map_err(|_| "cannot write the marker".to_string())?;
    let d = crate::runner_setup::tree_digest(&dest)?;
    Ok((BTreeMap::from([(dir, d)]), archive_sha))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// G5 fifth round, NV4-L4: the client refuses an http address at the connection, which is the check every redirect hop goes
    /// through too (ureq follows a redirect by connecting again). No TLS test server here, so a redirect itself is not driven: the
    /// proof is that the client never opens a socket to an http address, and `Https::get` refuses one before any client exists.
    #[test]
    fn the_client_never_connects_to_an_http_address() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let url = format!("http://{}/x", l.local_addr().unwrap());
        assert!(
            agent().get(&url).call().is_err(),
            "an http address must be refused by the client itself"
        );
        assert!(
            l.accept().is_err(),
            "the client opened a connection to an http address"
        );
        assert!(Https
            .get(&url, 10)
            .unwrap_err()
            .contains("not an https address"));
    }

    struct Fake {
        files: BTreeMap<String, Vec<u8>>,
        asked: RefCell<Vec<String>>,
    }
    impl Source for Fake {
        fn get(&self, url: &str, _: u64) -> Result<Vec<u8>, String> {
            self.asked.borrow_mut().push(url.to_string());
            self.files
                .get(url)
                .cloned()
                .ok_or_else(|| format!("{url} answered 404"))
        }
    }

    /// A tiny `node` release as a tar.xz with the vendor's one leading folder, and what the box would digest after `strip = 1`.
    fn node_archive(root: &Path) -> (Vec<u8>, String) {
        let tree = root.join("node-v22.20.0-linux-x64");
        std::fs::create_dir_all(tree.join("bin")).unwrap();
        std::fs::write(tree.join("bin/node"), "#!node\n").unwrap();
        std::fs::set_permissions(
            tree.join("bin/node"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(tree.join("README.md"), "hello\n").unwrap();
        let out = root.join("a.tar.xz");
        let ok = Command::new("tar")
            .arg("-cJf")
            .arg(&out)
            .arg("-C")
            .arg(root)
            .arg("node-v22.20.0-linux-x64")
            .status()
            .unwrap();
        assert!(ok.success());
        let digest = crate::runner_setup::tree_digest(&tree).unwrap();
        (std::fs::read(&out).unwrap(), digest)
    }

    fn fake_node(sums_digest: Option<&str>) -> (tempfile::TempDir, Fake, String) {
        let d = tempfile::tempdir().unwrap();
        let (bytes, tree) = node_archive(d.path());
        let sha = verify::sha256_hex(&bytes);
        let listed = sums_digest.map_or(sha.clone(), String::from);
        let mut files = BTreeMap::new();
        files.insert(
            "https://nodejs.org/dist/v22.20.0/SHASUMS256.txt".to_string(),
            format!(
                "{listed}  node-v22.20.0-linux-x64.tar.xz\n{}  node-v22.20.0-darwin-x64.tar.gz\n",
                "0".repeat(64)
            )
            .into_bytes(),
        );
        files.insert(
            "https://nodejs.org/dist/v22.20.0/node-v22.20.0-linux-x64.tar.xz".to_string(),
            bytes,
        );
        (
            d,
            Fake {
                files,
                asked: RefCell::default(),
            },
            tree,
        )
    }

    /// N-H2: the owner's computer gets, from the vendor's release for the BOX's architecture, the digest the box computes over its
    /// own install, after checking the download against the catalog's rule.
    #[test]
    fn a_tool_digest_is_worked_out_from_the_vendors_release_for_the_boxs_architecture() {
        let (_d, src, tree) = fake_node(None);
        let cat = ozbox_catalog::embedded().unwrap();
        let got = tool_digest(&src, &cat, "node", "22.20.0", Arch::Amd64).unwrap();
        assert_eq!(
            got.sha256, tree,
            "the digest the box would compute over its extracted install"
        );
        assert_eq!(got.asset, "node-v22.20.0-linux-x64.tar.xz");
        // the box's architecture decides the file, not this computer's
        let asked = src.asked.borrow().join(" ");
        assert!(
            asked.contains("linux-x64") && !asked.contains("arm64") && !asked.contains("darwin"),
            "{asked}"
        );
        // another release is another folder
        let e = tool_digest(&src, &cat, "node", "22.19.0", Arch::Amd64).unwrap_err();
        assert!(e.contains("404"), "{e}");
    }

    #[test]
    fn a_download_that_does_not_match_the_catalogs_checksum_is_refused_and_nothing_is_digested() {
        let (_d, src, _) = fake_node(Some(&"a".repeat(64)));
        let cat = ozbox_catalog::embedded().unwrap();
        let e = tool_digest(&src, &cat, "node", "22.20.0", Arch::Amd64).unwrap_err();
        assert!(e.contains("does not match the checksum"), "{e}");
    }

    #[test]
    fn a_tool_that_is_not_a_vendor_release_is_not_fetched() {
        let (_d, src, _) = fake_node(None);
        let cat = ozbox_catalog::embedded().unwrap();
        assert!(tool_digest(&src, &cat, "not-a-tool", "1", Arch::Amd64).is_err());
        assert!(tool_digest(&src, &cat, "ripgrep-no", "1", Arch::Amd64).is_err());
    }

    #[test]
    fn the_real_source_refuses_anything_but_https() {
        assert!(Https
            .get("http://example.com/x", 10)
            .unwrap_err()
            .contains("not an https"));
        assert_eq!(parse_arch("linux-x64").unwrap(), Arch::Amd64);
        assert_eq!(parse_arch("aarch64").unwrap(), Arch::Arm64);
        assert!(parse_arch("riscv").is_err());
    }

    /// A Playwright build: a zip from the CDN, unpacked into the cache folder's name, marker written, digested. The archive's own
    /// hash is reported so the owner can compare it.
    #[test]
    fn a_browser_build_is_downloaded_from_the_cdn_unpacked_and_digested_with_its_archive_hash() {
        let d = tempfile::tempdir().unwrap();
        let tree = d.path().join("chrome-linux");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("chrome"), "bin").unwrap();
        let zip = d.path().join("c.zip");
        let ok = Command::new("zip")
            .arg("-qr")
            .arg(&zip)
            .arg("chrome-linux")
            .current_dir(d.path())
            .status();
        let Ok(ok) = ok else { return };
        assert!(ok.success());
        let bytes = std::fs::read(&zip).unwrap();
        let url = "https://cdn.playwright.dev/dbazure/download/playwright/builds/chromium/1169/chromium-linux.zip";
        let src = Fake {
            files: BTreeMap::from([(url.to_string(), bytes.clone())]),
            asked: RefCell::default(),
        };
        let (m, archive) = browser_digest(&src, "chromium", "1169", Arch::Amd64).unwrap();
        assert_eq!(archive, verify::sha256_hex(&bytes));
        assert_eq!(m.keys().collect::<Vec<_>>(), ["chromium-1169"]);
        assert_eq!(m["chromium-1169"].len(), 64);
        // a revision that is not a number, and a kind that is not one, are refused before anything is fetched
        assert!(browser_digest(&src, "chromium", "../x", Arch::Amd64).is_err());
        assert!(browser_digest(&src, "opera", "1", Arch::Amd64).is_err());
        assert_eq!(src.asked.borrow().len(), 1);
    }
}
