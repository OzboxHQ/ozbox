//! The person's settings for browsing, the limits on one task, device presets and what a download may become.

use serde::{Deserialize, Serialize};

use crate::detect::Payments;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Settings for browsing, per project. Every field has a safe default, so an empty file is a working policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BrowserPolicy {
    /// Sites where submitting a form does not ask. Sending, posting and payments always do.
    pub safe_sites: Vec<String>,
    /// Purchases and payments: refused for the agent, or approved every time.
    pub payments: Payments,
    /// A proxy the person brings, `http://host:port`. Oz Box ships none.
    pub proxy: Option<String>,
    /// How long a recording is kept on the box, in days.
    pub retention_days: u32,
    /// Honour robots.txt for automated fetching.
    pub respect_robots: bool,
    /// Sites the person owns: robots.txt and the request rate do not apply.
    pub exempt_sites: Vec<String>,
    /// The least time between two page loads on one site, in milliseconds.
    pub min_gap_ms: u64,
    /// Sites whose pages only a local model may read.
    pub local_model_sites: Vec<String>,
    /// Most page actions and most minutes for one browsing task.
    pub max_actions: u32,
    pub max_minutes: u32,
    /// Most isolated sessions at once on one box.
    pub max_sessions: u32,
    /// Largest download, in bytes.
    pub max_download_bytes: u64,
    /// How long to wait for a person (approval, challenge, take-over) before the task pauses, in minutes.
    pub wait_minutes: u32,
    /// The profile the session uses (cookies), by name. `None` is a clean temporary profile.
    pub profile: Option<String>,
    /// The folders under `/work` a file may be uploaded from, as the person chose them (default `uploads`). The session's own
    /// downloads folder is always one. Nothing else is: not the home folder, not a dotfile or dotfolder, not a repository.
    pub upload_dirs: Vec<String>,
    /// The most memory one session's browser may use, in MiB. The box admits a session only when it has that much free.
    pub memory_mb: u32,
}

impl Default for BrowserPolicy {
    fn default() -> Self {
        Self {
            safe_sites: Vec::new(),
            payments: Payments::Refuse,
            proxy: None,
            retention_days: 30,
            respect_robots: true,
            exempt_sites: Vec::new(),
            min_gap_ms: 1000,
            local_model_sites: Vec::new(),
            max_actions: 200,
            max_minutes: 30,
            max_sessions: 3,
            max_download_bytes: 50 * 1024 * 1024,
            wait_minutes: 30,
            profile: None,
            upload_dirs: vec!["uploads".into()],
            memory_mb: 1536,
        }
    }
}

impl BrowserPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.retention_days == 0 || self.retention_days > 3650 {
            return Err("retention is 1 to 3650 days".into());
        }
        if self.max_actions == 0 || self.max_actions > 10_000 {
            return Err("the action limit is 1 to 10000".into());
        }
        if self.max_minutes == 0 || self.max_minutes > 24 * 60 {
            return Err("the time limit is 1 to 1440 minutes".into());
        }
        if self.max_sessions == 0 || self.max_sessions > 16 {
            return Err("sessions are 1 to 16 per box".into());
        }
        if self.wait_minutes == 0 || self.wait_minutes > 24 * 60 {
            return Err("the wait is 1 to 1440 minutes".into());
        }
        if self.max_download_bytes == 0 || self.max_download_bytes > 2 * 1024 * 1024 * 1024 {
            return Err("the download limit is up to 2 GiB".into());
        }
        if let Some(p) = &self.proxy {
            if !(p.starts_with("http://")
                || p.starts_with("https://")
                || p.starts_with("socks5://"))
                || p.len() > 300
                || p.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(
                    "the proxy is http://, https:// or socks5:// followed by host:port".into(),
                );
            }
        }
        for h in self
            .safe_sites
            .iter()
            .chain(&self.exempt_sites)
            .chain(&self.local_model_sites)
        {
            if !valid_host_pattern(h) {
                return Err(format!("{h} is not a host name"));
            }
        }
        if let Some(p) = &self.profile {
            if !valid_name(p) {
                return Err("a profile name is letters, digits, dashes and underscores".into());
            }
        }
        if self.upload_dirs.len() > 20 {
            return Err("name at most 20 upload folders".into());
        }
        for d in &self.upload_dirs {
            if !valid_upload_dir(d) {
                return Err(format!(
                    "{d} is not an upload folder: name a folder under /work, such as uploads or project/files (not the home folder, and no part may start with a dot)"
                ));
            }
        }
        if !(256..=8192).contains(&self.memory_mb) {
            return Err("a session's memory is 256 to 8192 MiB".into());
        }
        Ok(())
    }
}

/// An upload folder as a setting: a relative path under `/work`, no `..`, no part starting with a dot, not the home folder.
pub fn valid_upload_dir(d: &str) -> bool {
    let d = d.trim_end_matches('/');
    !d.is_empty()
        && d.len() <= 200
        && !d.starts_with('/')
        && d != "home"
        && !d.starts_with("home/")
        && d.split('/').all(|part| {
            !part.is_empty()
                && !part.eq_ignore_ascii_case("ozbox-browser")
                && !part.eq_ignore_ascii_case("ozbox-supervisor")
                && !part.starts_with('.')
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        })
}

/// Names that are never uploaded, wherever they are.
fn protected_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with('.')
        || n.ends_with(".pem")
        || n.ends_with(".key")
        || n.ends_with(".p12")
        || n.ends_with(".pfx")
        || n.starts_with("id_rsa")
        || n.starts_with("id_ed25519")
        || n.starts_with("id_ecdsa")
}

/// Where a file may be uploaded from (C2 of a security review, 2026-11-10): only from a folder the person chose, after the
/// path and every link in it are resolved. Returns the real path and how to show it (relative to `/work`).
///
/// Refused: a file outside every upload folder (including one a link points out of), anything in the home folder, any part
/// of the path that starts with a dot (credentials and tool settings live in dotfiles and dotfolders), key and certificate
/// files, and anything that is not a plain file.
pub fn upload_allowed(
    path: &std::path::Path,
    work: &std::path::Path,
    dirs: &[String],
    session_downloads: &std::path::Path,
    private_root: Option<&std::path::Path>,
) -> Result<(std::path::PathBuf, String), String> {
    let refuse = |m: &str| Err(m.to_string());
    let Ok(real) = std::fs::canonicalize(path) else {
        return refuse("that file does not exist");
    };
    if !real.is_file() {
        return refuse("only a file can be uploaded");
    }
    let work = std::fs::canonicalize(work).unwrap_or_else(|_| work.to_path_buf());
    if let Ok(home) = std::fs::canonicalize(work.join("home")) {
        if real.starts_with(&home) {
            return refuse(
                "nothing in the home folder is uploaded: copy the file into an upload folder first",
            );
        }
    }
    // What only the browser's own user may read (profiles with their cookies, held-back files) is never uploaded, however a link
    // reaches it: the worker can read it and the agent cannot, so the worker must not be the agent's way to it.
    let mut private: Vec<std::path::PathBuf> = vec![work.join("ozbox-browser/private")];
    if let Some(p) = private_root {
        private.push(p.to_path_buf());
        if let Ok(c) = std::fs::canonicalize(p) {
            private.push(c);
        }
    }
    if private.iter().any(|p| real.starts_with(p)) {
        return refuse("that file is in the browser's own private folder; it is never uploaded");
    }
    // An upload folder is used only where it really is: a folder the agent replaced with a link (to somewhere else on /work)
    // is not one the person chose.
    let mut roots: Vec<std::path::PathBuf> = dirs
        .iter()
        .filter(|d| valid_upload_dir(d))
        .filter_map(|d| {
            let want = work.join(d.trim_end_matches('/'));
            let real_root = std::fs::canonicalize(&want).ok()?;
            (real_root == want
                && real_root.starts_with(&work)
                && !private.iter().any(|p| real_root.starts_with(p)))
            .then_some(real_root)
        })
        .collect();
    if let Ok(dl) = std::fs::canonicalize(session_downloads) {
        roots.push(dl);
    }
    let Some(root) = roots.iter().find(|r| real.starts_with(r)) else {
        return refuse(&format!(
            "a file is uploaded only from an upload folder ({}), or this session's downloads; ask a person to put it there",
            if dirs.is_empty() {
                "none is set".to_string()
            } else {
                dirs.join(", ")
            }
        ));
    };
    let inside = real.strip_prefix(root).unwrap_or(&real);
    for c in inside.components() {
        let part = c.as_os_str().to_string_lossy();
        if part.starts_with('.') || protected_name(&part) {
            return refuse("that file is not one an agent may upload");
        }
    }
    let shown = real
        .strip_prefix(&work)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| {
            real.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
    Ok((real, shown))
}

pub fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 48
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn valid_host_pattern(h: &str) -> bool {
    let h = h.strip_prefix("*.").unwrap_or(h);
    !h.is_empty()
        && h.len() <= 253
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !h.starts_with('.')
        && !h.ends_with('.')
}

// ---- devices ---------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Device {
    #[default]
    Desktop,
    Tablet,
    Phone,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Metrics {
    pub width: u32,
    pub height: u32,
    pub scale: f64,
    pub mobile: bool,
}

impl Device {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "desktop" => Some(Self::Desktop),
            "tablet" => Some(Self::Tablet),
            "phone" => Some(Self::Phone),
            _ => None,
        }
    }
    pub fn metrics(self) -> Metrics {
        match self {
            Device::Desktop => Metrics {
                width: 1280,
                height: 800,
                scale: 1.0,
                mobile: false,
            },
            Device::Tablet => Metrics {
                width: 820,
                height: 1180,
                scale: 2.0,
                mobile: true,
            },
            Device::Phone => Metrics {
                width: 390,
                height: 844,
                scale: 3.0,
                mobile: true,
            },
        }
    }
    /// A touch device gets touch events; the browser's own string stays, with ours added, and a mobile one
    /// says "Mobile".
    pub fn user_agent(self, real: &str) -> String {
        let base = if self.metrics().mobile && !real.contains("Mobile") {
            format!("{} Mobile", real.trim())
        } else {
            real.trim().to_string()
        };
        crate::robots::honest_agent(&base, VERSION)
    }
}

// ---- limits ----------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Budget {
    Ok,
    /// 80% of the actions or the time is used: tell the person.
    Warn,
    Exceeded(&'static str),
}

/// Where a task stands against its limits. Pure: the caller passes the clock.
pub fn budget(policy: &BrowserPolicy, actions: u32, started_ms: u64, now_ms: u64) -> Budget {
    let spent = now_ms.saturating_sub(started_ms);
    let limit_ms = u64::from(policy.max_minutes) * 60_000;
    if actions >= policy.max_actions {
        return Budget::Exceeded("the action limit for this task is used");
    }
    if spent >= limit_ms {
        return Budget::Exceeded("the time limit for this task is used");
    }
    if u64::from(actions) * 5 >= u64::from(policy.max_actions) * 4 || spent * 5 >= limit_ms * 4 {
        return Budget::Warn;
    }
    Budget::Ok
}

// ---- downloads -------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", content = "why", rename_all = "snake_case")]
pub enum Download {
    /// A document the agent may open.
    Document,
    /// Held back: a script, an installer, an executable. Running one needs approval.
    Quarantine(String),
    TooLarge,
}

const DOC_EXT: [&str; 26] = [
    "pdf", "txt", "csv", "tsv", "json", "md", "xml", "yaml", "yml", "rtf", "png", "jpg", "jpeg",
    "gif", "webp", "svg", "xlsx", "xls", "ods", "docx", "doc", "odt", "pptx", "ppt", "odp", "epub",
];
/// Archives are held back: what is inside is not looked at, and it can be a program.
const ARCHIVE_EXT: [&str; 10] = [
    "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "zst", "cab",
];
/// Office documents are zip files inside: one whose parts include a macro or a program is held back.
const ZIP_DOC_EXT: [&str; 7] = ["docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"];
const RISKY_EXT: [&str; 31] = [
    "exe", "msi", "bat", "cmd", "com", "scr", "ps1", "vbs", "js", "jse", "wsf", "sh", "bash",
    "zsh", "py", "pl", "rb", "jar", "apk", "app", "dmg", "pkg", "deb", "rpm", "run", "bin", "dll",
    "so", "lnk", "iso", "hta",
];

/// Decide from the name, the size and the first bytes. The extension alone is not trusted: a file that starts like an
/// executable or a script is held whatever it is called, and a document extension followed by a risky one (`a.pdf.exe`) is
/// held too.
pub fn classify_download(name: &str, size: u64, head: &[u8], policy: &BrowserPolicy) -> Download {
    if size > policy.max_download_bytes {
        return Download::TooLarge;
    }
    let lower = name.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.iter().skip(1).any(|e| RISKY_EXT.contains(e)) {
        return Download::Quarantine("a program or script by its name".into());
    }
    if let Some(why) = sniff_executable(head) {
        return Download::Quarantine(why.into());
    }
    let ext = parts
        .last()
        .filter(|_| parts.len() > 1)
        .copied()
        .unwrap_or("");
    if ARCHIVE_EXT.contains(&ext) || parts.iter().skip(1).any(|e| ARCHIVE_EXT.contains(e)) {
        return Download::Quarantine("an archive: what is inside it is not checked".into());
    }
    if !DOC_EXT.contains(&ext) {
        return Download::Quarantine("not a kind of document that is opened automatically".into());
    }
    if ext == "svg"
        && String::from_utf8_lossy(head)
            .to_ascii_lowercase()
            .contains("<script")
    {
        return Download::Quarantine("an image that contains a script".into());
    }
    Download::Document
}

/// The names inside a zip file's central directory, read from its end (no decompression). `None` when it is not a zip.
pub fn zip_entry_names(data: &[u8]) -> Option<Vec<String>> {
    let le16 = |b: &[u8], i: usize| -> Option<usize> {
        Some(usize::from(*b.get(i)?) | (usize::from(*b.get(i + 1)?) << 8))
    };
    let le32 =
        |b: &[u8], i: usize| -> Option<usize> { Some(le16(b, i)? | (le16(b, i + 2)? << 16)) };
    // the end-of-directory record is in the last 64 KiB + 22 bytes
    let from = data.len().saturating_sub(65_557);
    let eocd = (from..data.len().saturating_sub(21))
        .rev()
        .find(|&i| data.get(i..i + 4) == Some(b"PK\x05\x06"))?;
    let count = le16(data, eocd + 10)?;
    let mut at = le32(data, eocd + 16)?;
    let mut names = Vec::new();
    for _ in 0..count.min(5000) {
        if data.get(at..at + 4) != Some(b"PK\x01\x02") {
            return None;
        }
        let (n, x, c) = (
            le16(data, at + 28)?,
            le16(data, at + 30)?,
            le16(data, at + 32)?,
        );
        let name = data.get(at + 46..at + 46 + n)?;
        names.push(String::from_utf8_lossy(name).into_owned());
        at += 46 + n + x + c;
    }
    Some(names)
}

/// For an office document (a zip inside): a reason to hold it back, from the names of its parts.
pub fn risky_zip_document(data: &[u8]) -> Option<&'static str> {
    let Some(names) = zip_entry_names(data) else {
        return Some("it says it is a document but its contents could not be read");
    };
    for n in names {
        let l = n.to_ascii_lowercase();
        if l.contains("vbaproject") || l.ends_with(".bin") && l.contains("macro") {
            return Some("a document with macros");
        }
        if l.rsplit('.').next().is_some_and(|e| RISKY_EXT.contains(&e)) {
            return Some("a document with a program inside");
        }
    }
    None
}

/// The whole check for a finished download: [`classify_download`] on its first bytes, then, for an office document, the
/// names of its parts.
pub fn classify_file(name: &str, data: &[u8], policy: &BrowserPolicy) -> Download {
    let head = &data[..data.len().min(512)];
    let class = classify_download(name, data.len() as u64, head, policy);
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if class == Download::Document && ZIP_DOC_EXT.contains(&ext.as_str()) {
        if let Some(why) = risky_zip_document(data) {
            return Download::Quarantine(why.into());
        }
    }
    class
}

/// Executable formats by their first bytes.
pub fn sniff_executable(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(b"MZ") {
        Some("a Windows program by its contents")
    } else if head.starts_with(b"\x7fELF") {
        Some("a Linux program by its contents")
    } else if head.starts_with(b"#!") {
        Some("a script by its contents")
    } else if head.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || head.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
    {
        Some("a macOS program by its contents")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_owners_choices_and_valid() {
        let p = BrowserPolicy::default();
        assert_eq!(
            (
                p.retention_days,
                p.max_actions,
                p.max_minutes,
                p.wait_minutes
            ),
            (30, 200, 30, 30)
        );
        assert_eq!(p.payments, Payments::Refuse);
        assert!(p.respect_robots && p.proxy.is_none());
        assert!(p.validate().is_ok());
        let q: BrowserPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(q, p);
    }

    #[test]
    fn a_bad_setting_is_refused_with_a_reason() {
        let bad = |f: fn(&mut BrowserPolicy)| {
            let mut p = BrowserPolicy::default();
            f(&mut p);
            p.validate().is_err()
        };
        assert!(bad(|p| p.retention_days = 0));
        assert!(bad(|p| p.max_actions = 0));
        assert!(bad(|p| p.max_sessions = 99));
        assert!(bad(|p| p.proxy = Some("ftp://x".into())));
        assert!(bad(|p| p.proxy = Some("http://a b".into())));
        assert!(bad(|p| p.safe_sites = vec!["http://x".into()]));
        assert!(bad(|p| p.profile = Some("../x".into())));
        assert!(bad(|p| p.upload_dirs = vec!["home/ozbox".into()]));
        assert!(bad(|p| p.memory_mb = 64));
        let ok = BrowserPolicy {
            proxy: Some("http://proxy.example:3128".into()),
            safe_sites: vec!["*.example.com".into()],
            ..BrowserPolicy::default()
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn devices_have_sizes_touch_and_an_honest_agent() {
        let m = Device::Phone.metrics();
        assert_eq!((m.width, m.height, m.mobile), (390, 844, true));
        assert!(!Device::Desktop.metrics().mobile);
        assert_eq!(Device::parse("tablet"), Some(Device::Tablet));
        assert_eq!(Device::parse("watch"), None);
        let ua = Device::Phone.user_agent("Mozilla/5.0 (X11) Chrome/130");
        assert!(
            ua.ends_with(&format!("Mobile OzboxAgent/{VERSION}")),
            "{ua}"
        );
        assert!(Device::Desktop
            .user_agent("Mozilla/5.0 Chrome/130")
            .ends_with(&format!("Chrome/130 OzboxAgent/{VERSION}")));
    }

    #[test]
    fn the_budget_warns_at_eighty_percent_and_stops_at_the_limit() {
        let p = BrowserPolicy::default();
        assert_eq!(budget(&p, 0, 0, 0), Budget::Ok);
        assert_eq!(budget(&p, 160, 0, 0), Budget::Warn);
        assert_eq!(budget(&p, 199, 0, 0), Budget::Warn);
        assert!(matches!(budget(&p, 200, 0, 0), Budget::Exceeded(_)));
        assert_eq!(budget(&p, 1, 0, 24 * 60_000), Budget::Warn);
        assert!(matches!(budget(&p, 1, 0, 30 * 60_000), Budget::Exceeded(_)));
    }

    #[test]
    fn documents_open_and_programs_are_held() {
        let p = BrowserPolicy::default();
        let d = |n: &str, s: u64, h: &[u8]| classify_download(n, s, h, &p);
        assert_eq!(d("report.pdf", 10, b"%PDF-1.7"), Download::Document);
        assert_eq!(d("Data.CSV", 10, b"a,b"), Download::Document);
        assert_eq!(d("photo.jpeg", 10, b"\xff\xd8"), Download::Document);
        assert!(matches!(d("setup.exe", 10, b"MZ"), Download::Quarantine(_)));
        assert!(matches!(d("run.sh", 10, b"echo"), Download::Quarantine(_)));
        assert!(matches!(
            d("invoice.pdf.exe", 10, b"x"),
            Download::Quarantine(_)
        ));
        // the first bytes win over a friendly name
        assert!(matches!(
            d("report.pdf", 10, b"\x7fELF...."),
            Download::Quarantine(_)
        ));
        assert!(matches!(
            d("notes.txt", 10, b"#!/bin/sh\n"),
            Download::Quarantine(_)
        ));
        assert!(matches!(
            d("x.svg", 10, b"<svg><script>alert(1)</script></svg>"),
            Download::Quarantine(_)
        ));
        assert!(matches!(d("mystery", 10, b"abc"), Download::Quarantine(_)));
        assert_eq!(d("big.pdf", 60 * 1024 * 1024, b"%PDF"), Download::TooLarge);
        // an archive is held back: what is inside is not looked at
        assert!(matches!(
            d("bundle.zip", 10, b"PK\x03\x04"),
            Download::Quarantine(_)
        ));
        assert!(matches!(
            d("logs.tar.gz", 10, b"\x1f\x8b"),
            Download::Quarantine(_)
        ));
    }

    /// A zip with the given part names, stored (no compression), as a test fixture.
    fn zip_of(names: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for n in names {
            let off = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[0u8; 22]);
            out.extend_from_slice(&(n.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(n.as_bytes());
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&[0u8; 24]);
            central.extend_from_slice(&(n.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0u8; 12]);
            central.extend_from_slice(&off.to_le_bytes());
            central.extend_from_slice(n.as_bytes());
        }
        let cd_at = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&(names.len() as u16).to_le_bytes());
        out.extend_from_slice(&(names.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_at.to_le_bytes());
        out.extend_from_slice(&[0u8; 2]);
        out
    }

    #[test]
    fn an_office_document_with_a_macro_or_a_program_inside_is_held() {
        let p = BrowserPolicy::default();
        let plain = zip_of(&["[Content_Types].xml", "word/document.xml"]);
        assert_eq!(zip_entry_names(&plain).unwrap().len(), 2);
        assert_eq!(classify_file("letter.docx", &plain, &p), Download::Document);
        let macro_doc = zip_of(&["word/document.xml", "word/vbaProject.bin"]);
        assert!(matches!(
            classify_file("letter.docx", &macro_doc, &p),
            Download::Quarantine(_)
        ));
        let with_exe = zip_of(&["xl/workbook.xml", "xl/embeddings/setup.exe"]);
        assert!(matches!(
            classify_file("sheet.xlsx", &with_exe, &p),
            Download::Quarantine(_)
        ));
        assert!(matches!(
            classify_file("fake.docx", b"not a zip", &p),
            Download::Quarantine(_)
        ));
    }

    #[test]
    fn an_upload_comes_only_from_a_chosen_folder() {
        let d = tempfile::tempdir().unwrap();
        let work = d.path();
        for f in [
            "uploads/report.pdf",
            "uploads/.env",
            "uploads/sub/.hidden/x.txt",
            "uploads/server.pem",
            "home/ozbox/.aws/credentials",
            "home/ozbox/.config/gh/hosts.yml",
            "home/ozbox/notes.txt",
            "project/src/main.rs",
            "dl/got.pdf",
        ] {
            let p = work.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, "x").unwrap();
        }
        let dirs = vec!["uploads".to_string()];
        let dl = work.join("dl");
        let ok = |f: &str| upload_allowed(&work.join(f), work, &dirs, &dl, None);
        assert_eq!(ok("uploads/report.pdf").unwrap().1, "uploads/report.pdf");
        assert!(ok("dl/got.pdf").is_ok());
        for bad in [
            "uploads/.env",
            "uploads/sub/.hidden/x.txt",
            "uploads/server.pem",
            "home/ozbox/.aws/credentials",
            "home/ozbox/.config/gh/hosts.yml",
            "home/ozbox/notes.txt",
            "project/src/main.rs",
            "uploads",
            "uploads/missing.pdf",
        ] {
            assert!(ok(bad).is_err(), "{bad}");
        }
        // a link inside the upload folder that points out of it is judged by where it points
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                work.join("home/ozbox/.aws/credentials"),
                work.join("uploads/creds.txt"),
            )
            .unwrap();
            std::os::unix::fs::symlink("/etc/hostname", work.join("uploads/host.txt")).unwrap();
            assert!(ok("uploads/creds.txt").is_err());
            assert!(ok("uploads/host.txt").is_err());
        }
        // the setting itself cannot name the home folder, a dotfolder, the browser's own folder or a way out
        for bad in [
            "home",
            "home/ozbox",
            ".ssh",
            "a/.git",
            "../etc",
            "/etc",
            "",
            "ozbox-browser",
            "a/ozbox-browser/private",
            "Ozbox-Supervisor",
        ] {
            assert!(!valid_upload_dir(bad), "{bad}");
        }
        assert!(valid_upload_dir("project/files"));
    }

    #[cfg(unix)]
    #[test]
    fn the_browsers_private_folder_is_never_uploaded_even_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let work = std::fs::canonicalize(d.path()).unwrap();
        let private = work.join("ozbox-browser/private");
        std::fs::create_dir_all(private.join("profiles/work/Default")).unwrap();
        std::fs::write(private.join("profiles/work/Default/Cookies"), "x").unwrap();
        std::fs::create_dir_all(work.join("repos/p")).unwrap();
        std::fs::create_dir_all(work.join("uploads")).unwrap();
        let dl = work.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        // the agent made the upload folder a link into the private folder
        std::os::unix::fs::symlink(&private, work.join("repos/p/files")).unwrap();
        let dirs = vec!["repos/p/files".to_string(), "uploads".to_string()];
        let via_link = work.join("repos/p/files/profiles/work/Default/Cookies");
        assert!(upload_allowed(&via_link, &work, &dirs, &dl, Some(&private)).is_err());
        // a link as the upload folder is not an upload folder at all
        std::fs::write(work.join("uploads/ok.txt"), "x").unwrap();
        assert!(upload_allowed(
            &work.join("uploads/ok.txt"),
            &work,
            &dirs,
            &dl,
            Some(&private)
        )
        .is_ok());
        // and the private folder itself, named directly, as a folder or a file, is refused
        assert!(upload_allowed(
            &private.join("profiles/work/Default/Cookies"),
            &work,
            &["ozbox-browser".to_string()],
            &dl,
            Some(&private)
        )
        .is_err());
        // a folder that is a link to another place under /work is not the folder the person chose
        std::fs::create_dir_all(work.join("elsewhere")).unwrap();
        std::fs::write(work.join("elsewhere/s.txt"), "x").unwrap();
        std::os::unix::fs::symlink(work.join("elsewhere"), work.join("uploads2")).unwrap();
        assert!(upload_allowed(
            &work.join("uploads2/s.txt"),
            &work,
            &["uploads2".to_string()],
            &dl,
            Some(&private)
        )
        .is_err());
    }
}
