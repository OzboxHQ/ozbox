//! Running the steps of a plan.
//!
//! One function per kind of step. Everything that touches the system goes through [`Sys`], so each step is tested with
//! a scripted fake. Downloads are made by `curl` (an argv array, https only), then checked here before they are used:
//! a SHA-256 read from a checksum file the vendor publishes, or an apt key whose fingerprint is one the vendor
//! published. A step that cannot be checked fails; nothing is used first and checked later.

use std::path::{Path, PathBuf};

use ozbox_catalog::model::{safe_rel, Extract};
use ozbox_catalog::verify::{
    digest_for, fingerprints_match, names_matching, primary_fingerprints, same_digest,
    single_digest, wildcard_capture,
};
use ozbox_catalog::{Action, HOME_TOKEN};

use super::sys::{Log, Sys};

/// Largest download accepted.
/// The largest vendor archive a release step downloads. It is checked against the vendor's digest before anything is
/// unpacked (the local-model runtimes are over a gigabyte).
pub const MAX_DOWNLOAD: u64 = 3 * 1024 * 1024 * 1024;
const MAX_SMALL: u64 = 2 * 1024 * 1024;

/// Where the root-class steps write. Fields so tests can point them at a temporary directory.
#[derive(Debug, Clone)]
pub struct RootPaths {
    pub keyrings: PathBuf,
    pub sources: PathBuf,
    pub apt_conf: PathBuf,
}

impl Default for RootPaths {
    fn default() -> Self {
        RootPaths {
            keyrings: "/etc/apt/keyrings".into(),
            sources: "/etc/apt/sources.list.d".into(),
            apt_conf: "/etc/apt/apt.conf.d".into(),
        }
    }
}

pub struct Ctx<'a> {
    pub sys: &'a dyn Sys,
    pub log: &'a Log,
    /// The box user's home directory (user steps).
    pub home: PathBuf,
    /// A scratch directory for downloads. Emptied by the caller.
    pub tmp: PathBuf,
    pub root: RootPaths,
}

fn s(v: &str) -> String {
    v.to_string()
}

/// PATH for the programs a step runs: the box user's own bin directories first.
pub fn env_for(home: &Path) -> Vec<(String, String)> {
    let h = home.display();
    vec![
        (
            s("PATH"),
            format!("{h}/.local/bin:{h}/.cargo/bin:/usr/local/bin:/usr/bin:/bin"),
        ),
        (s("HOME"), h.to_string()),
        (s("NPM_CONFIG_UPDATE_NOTIFIER"), s("false")),
        (s("DEBIAN_FRONTEND"), s("noninteractive")),
    ]
}

fn fill_home(arg: &str, home: &Path) -> String {
    arg.replace(HOME_TOKEN, &home.display().to_string())
}

fn expand_template(t: &str, arch: &str, version: Option<&str>, asset: Option<&str>) -> String {
    let mut out = t.replace("{arch}", arch);
    if let Some(v) = version {
        out = out.replace("{version}", v);
    }
    if let Some(a) = asset {
        out = out.replace("{asset}", a);
    }
    out
}

/// `curl` for a file: https only (also across redirects), a size ceiling, a few retries.
pub fn curl_argv(url: &str, dest: &Path, max_bytes: u64) -> Vec<String> {
    vec![
        s("curl"),
        s("--fail"),
        s("--silent"),
        s("--show-error"),
        s("--location"),
        s("--proto"),
        s("=https"),
        s("--proto-redir"),
        s("=https"),
        s("--tlsv1.2"),
        s("--retry"),
        s("3"),
        s("--max-filesize"),
        max_bytes.to_string(),
        s("--output"),
        dest.display().to_string(),
        url.to_string(),
    ]
}

fn download(ctx: &Ctx, url: &str, dest: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let code = ctx.sys.exec(
        &curl_argv(url, dest, max_bytes),
        &env_for(&ctx.home),
        ctx.log,
    )?;
    if code != 0 {
        return Err(format!("could not download {url} (curl exit {code})"));
    }
    ctx.sys
        .read_file(dest)
        .map_err(|e| format!("cannot read the download: {}", e.kind()))
}

/// Download to a file without reading it back into memory.
fn download_to(ctx: &Ctx, url: &str, dest: &Path, max_bytes: u64) -> Result<(), String> {
    let code = ctx.sys.exec(
        &curl_argv(url, dest, max_bytes),
        &env_for(&ctx.home),
        ctx.log,
    )?;
    if code != 0 {
        return Err(format!("could not download {url} (curl exit {code})"));
    }
    Ok(())
}

fn small_text(ctx: &Ctx, url: &str, name: &str) -> Result<String, String> {
    let dest = ctx.tmp.join(name);
    let bytes = download(ctx, url, &dest, MAX_SMALL)?;
    String::from_utf8(bytes).map_err(|_| format!("{url} is not text"))
}

fn exit_ok(code: i32, what: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{what} failed (exit {code})"))
    }
}

/// The host part of an https URL.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split('/').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_string())
}

/// The `apt-get` the root helper runs, and the same with apt's download user switch turned off.
///
/// apt normally drops to its `_apt` user (uid 42) for downloads (`http`, `https`, `store`, `gpgv`), which keeps the code that
/// parses network data before it is verified away from root. On the real box (0.1.1-alpha.0) that failed in this helper,
/// every time, with `seteuid 42 failed - seteuid (1: Operation not permitted)`, so no apt step ever ran. So a step runs
/// apt as it normally runs, and only when the output says that user switch was refused does it run once more with
/// `APT::Sandbox::User=root` (downloads then run as root, inside this unit; apt says "Download is performed unsandboxed as
/// root" in the tool's log; signatures and hashes are still checked). A box where the switch works never loses it.
///
/// Evidence (read from the real box `main`, 2026-11-12): `/var/lib/apt/periodic/update-success-stamp` is dated its first boot,
/// so a plain root `apt-get update` OUTSIDE this unit succeeded there. The cause is therefore something in
/// `ozbox-tools.service`'s own environment (NoNewPrivileges, PrivateTmp, ProtectHome, ProtectKernelModules,
/// ProtectKernelLogs, ProtectClock, LockPersonality, MemoryMax, TasksMax), not the box. Remove the fallback once it is
/// found; `collect-logs` now carries this unit's journal, the loaded security modules and the kernel's denial lines for that.
pub const APT_GET: [&str; 1] = ["apt-get"];
pub const APT_GET_UNSANDBOXED: [&str; 3] = ["apt-get", "-o", "APT::Sandbox::User=root"];

fn apt_get(sandbox_off: bool, rest: &[&str]) -> Vec<String> {
    let head: &[&str] = if sandbox_off {
        &APT_GET_UNSANDBOXED
    } else {
        &APT_GET
    };
    head.iter().chain(rest).map(|a| a.to_string()).collect()
}

/// One apt step: as apt normally runs, then once more without its user switch when (and only when) the log says that switch
/// was refused.
fn run_apt(
    ctx: &Ctx,
    env: &[(String, String)],
    rest: &[&str],
    extra: &[String],
    what: &str,
) -> Result<(), String> {
    let argv = |off: bool| {
        let mut a = apt_get(off, rest);
        a.extend(extra.iter().cloned());
        a
    };
    ctx.log.clear_privilege_drop_refusal();
    let code = ctx.sys.exec(&argv(false), env, ctx.log)?;
    if code != 0 && ctx.log.saw_privilege_drop_refusal() {
        ctx.log.line(
            "apt could not change to its download user in this unit; trying once more with downloads run as root (a stop-gap, see collect-logs)",
        );
        let code = ctx.sys.exec(&argv(true), env, ctx.log)?;
        return exit_ok(code, what);
    }
    exit_ok(code, what)
}

/// The `gpg` that lists a downloaded key's fingerprints, with a home folder of its own inside the step's scratch directory.
///
/// gpg will not start without a home folder it can write. The root helper runs with `ProtectHome=true`, which hides
/// `/root`, so with the default home gpg stopped (code 2, "can't create directory '/root/.gnupg'") before it read the key,
/// and the step reported a vendor key that matches its pin as "not the one its vendor publishes" (packer, 2026-11-17: the
/// key at <https://apt.releases.hashicorp.com/gpg> is D55C0D1AC78A8D8126CB631CFC9CA96ACA026560, exactly the pin). A
/// throwaway home also keeps a vendor key out of any keyring that is used for anything else.
fn gpg_show_keys(ctx: &Ctx, name: &str, key: &Path) -> Result<Vec<String>, String> {
    let home = ctx.tmp.join(format!("{name}.gnupg"));
    ctx.sys.create_dir_all(&home).map_err(io_err)?;
    Ok(vec![
        s("gpg"),
        s("--homedir"),
        home.display().to_string(),
        s("--batch"),
        s("--no-autostart"),
        s("--show-keys"),
        s("--with-colons"),
        key.display().to_string(),
    ])
}

/// Run one root-class step. Called only by the privileged helper.
pub fn run_root_action(ctx: &Ctx, action: &Action) -> Result<(), String> {
    let env = env_for(&ctx.home);
    match action {
        Action::AptUpdate => run_apt(ctx, &env, &["update"], &[], "apt-get update"),
        Action::AptInstall { packages } => run_apt(
            ctx,
            &env,
            &[
                "install",
                "-y",
                "--no-install-recommends",
                "-o",
                "Dpkg::Options::=--force-confold",
            ],
            packages,
            "apt-get install",
        ),
        Action::AptRemove { packages } => {
            run_apt(ctx, &env, &["remove", "-y"], packages, "apt-get remove")
        }
        Action::AptRepo {
            name,
            key_url,
            fingerprints,
            uri,
            suite,
            components,
        } => {
            let key_tmp = ctx.tmp.join(format!("{name}.key"));
            let key = download(ctx, key_url, &key_tmp, MAX_SMALL)?;
            let (code, listing) = ctx
                .sys
                .capture(&gpg_show_keys(ctx, name, &key_tmp)?, &env)?;
            if code != 0 {
                return Err(format!(
                    "the signing key for {name} could not be read (gpg stopped with code {code}), so it could not be checked against the one its vendor publishes; nothing was installed"
                ));
            }
            if !fingerprints_match(&listing, fingerprints) {
                let found = primary_fingerprints(&listing);
                return Err(format!(
                    "the signing key for {name} is not the one its vendor publishes (the key file holds {}, the catalog pins {}); nothing was installed",
                    if found.is_empty() { "no primary key".to_string() } else { found.join(", ") },
                    fingerprints.join(", ")
                ));
            }
            let armored = key.starts_with(b"-----BEGIN PGP");
            let key_path = ctx.root.keyrings.join(format!(
                "ozbox-{name}.{}",
                if armored { "asc" } else { "gpg" }
            ));
            let other = ctx.root.keyrings.join(format!(
                "ozbox-{name}.{}",
                if armored { "gpg" } else { "asc" }
            ));
            for d in [&ctx.root.keyrings, &ctx.root.sources, &ctx.root.apt_conf] {
                ctx.sys.create_dir_all(d).map_err(io_err)?;
            }
            ctx.sys.remove_path(&other).map_err(io_err)?;
            ctx.sys.write_file(&key_path, &key, 0o644).map_err(io_err)?;
            let sources = format!(
                "Types: deb\nURIs: {uri}\nSuites: {suite}\nComponents: {}\nSigned-By: {}\n",
                components.join(" "),
                key_path.display()
            );
            ctx.sys
                .write_file(
                    &ctx.root.sources.join(format!("ozbox-{name}.sources")),
                    sources.as_bytes(),
                    0o644,
                )
                .map_err(io_err)?;
            // Let unattended upgrades take new versions from this origin, so the tool keeps itself current.
            if let Some(host) = url_host(uri) {
                let conf = format!("Unattended-Upgrade::Origins-Pattern:: \"site={host}\";\n");
                ctx.sys
                    .write_file(
                        &ctx.root.apt_conf.join(format!("52ozbox-{name}")),
                        conf.as_bytes(),
                        0o644,
                    )
                    .map_err(io_err)?;
            }
            ctx.log.line(&format!("accepted the {name} signing key"));
            run_apt(ctx, &env, &["update"], &[], "apt-get update")
        }
        Action::AptRepoRemove { name } => {
            for p in [
                ctx.root.sources.join(format!("ozbox-{name}.sources")),
                ctx.root.apt_conf.join(format!("52ozbox-{name}")),
                ctx.root.keyrings.join(format!("ozbox-{name}.asc")),
                ctx.root.keyrings.join(format!("ozbox-{name}.gpg")),
            ] {
                ctx.sys.remove_path(&p).map_err(io_err)?;
            }
            run_apt(ctx, &env, &["update"], &[], "apt-get update")
        }
        _ => Err(s("that step does not run as root")),
    }
}

fn io_err(e: std::io::Error) -> String {
    format!("file operation failed: {}", e.kind())
}

/// Run one user-class step (as the box user, inside the job's capped run).
pub fn run_user_action(ctx: &Ctx, action: &Action) -> Result<(), String> {
    let env = env_for(&ctx.home);
    match action {
        Action::Exec { argv } => {
            let argv: Vec<String> = argv.iter().map(|a| fill_home(a, &ctx.home)).collect();
            exit_ok(ctx.sys.exec(&argv, &env, ctx.log)?, &argv[0])
        }
        Action::UserRemove { paths } => {
            for p in paths {
                if !safe_rel(p) {
                    return Err(format!("refusing to remove {p}"));
                }
                ctx.sys.remove_path(&ctx.home.join(p)).map_err(io_err)?;
            }
            Ok(())
        }
        Action::Note { text } => {
            ctx.log.line(text);
            Ok(())
        }
        Action::Release { .. } => release(ctx, action),
        _ => Err(s("that step runs as root")),
    }
}

fn release(ctx: &Ctx, action: &Action) -> Result<(), String> {
    let Action::Release {
        tool,
        version_url,
        base_url,
        asset,
        checksum_url,
        checksum_format,
        pinned_sha256,
        extract,
        strip,
        arch_name,
        bins,
    } = action
    else {
        return Err(s("not a release step"));
    };
    use ozbox_catalog::model::ChecksumFormat;
    let version = match version_url {
        Some(u) => {
            let text = small_text(ctx, u, "version.txt")?;
            let v = text.lines().next().unwrap_or("").trim().to_string();
            if v.is_empty()
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            {
                return Err(s("the vendor's version file did not hold a version"));
            }
            Some(v)
        }
        None => None,
    };
    let v = version.as_deref();
    let base = expand_template(base_url, arch_name, v, None);
    let pattern = expand_template(asset, arch_name, v, None);
    let sums_url = expand_template(checksum_url, arch_name, v, Some(&pattern));

    // A pinned digest is the checksum and nothing is fetched for it. Otherwise the checksum file is fetched first; a
    // wildcard asset is resolved from it, so the name is the vendor's own.
    let sums = match pinned_sha256 {
        Some(_) => String::new(),
        None => small_text(ctx, &sums_url, "checksums.txt")?,
    };
    let asset_name = if pattern.contains('*') {
        if *checksum_format != ChecksumFormat::Sums {
            return Err(s("a wildcard asset needs a list of checksums"));
        }
        let names = names_matching(&sums, &pattern);
        match names.as_slice() {
            [one] => {
                let _ = wildcard_capture(&pattern, one);
                one.clone()
            }
            [] => {
                return Err(format!(
                    "the vendor's checksum list has no file matching {pattern}"
                ))
            }
            _ => {
                return Err(format!(
                    "the vendor's checksum list has several files matching {pattern}"
                ))
            }
        }
    } else {
        pattern.clone()
    };
    let expected = match (pinned_sha256, checksum_format) {
        (Some(pin), _) => Some(pin.to_ascii_lowercase()),
        (None, ChecksumFormat::Sums) => digest_for(&sums, &asset_name),
        (None, ChecksumFormat::Single) => single_digest(&sums),
    }
    .ok_or_else(|| format!("the vendor's checksum list does not cover {asset_name}"))?;

    let file = ctx.tmp.join("asset");
    let url = format!("{base}{asset_name}");
    download_to(ctx, &url, &file, MAX_DOWNLOAD)?;
    let actual = ctx
        .sys
        .sha256_file(&file)
        .map_err(|e| format!("cannot read the download: {}", e.kind()))?;
    if !same_digest(&actual, &expected) {
        let _ = ctx.sys.remove_path(&file);
        return Err(format!(
            "the download of {asset_name} does not match the vendor's checksum; it was discarded"
        ));
    }
    ctx.log
        .line(&format!("checksum of {asset_name} matches the vendor's"));

    let dest = ctx.home.join(".local/opt").join(tool);
    ctx.sys.remove_path(&dest).map_err(io_err)?;
    ctx.sys.create_dir_all(&dest).map_err(io_err)?;
    match extract {
        Extract::None => {
            let b = &bins[0];
            let target = dest.join(&b.path);
            let data = ctx
                .sys
                .read_file(&file)
                .map_err(|e| format!("cannot read the download: {}", e.kind()))?;
            ctx.sys.write_file(&target, &data, 0o755).map_err(io_err)?;
        }
        Extract::TarXz | Extract::TarGz | Extract::TarZst => {
            // `--zstd` runs the box's own zstd program (installed from the operating system's archive before this step)
            let flag = match extract {
                Extract::TarXz => "-xJf",
                Extract::TarGz => "-xzf",
                _ => "--zstd",
            };
            let flags: Vec<String> = if *extract == Extract::TarZst {
                vec![s(flag), s("-xf")]
            } else {
                vec![s(flag)]
            };
            let mut argv = vec![s("tar")];
            argv.extend(flags);
            argv.extend([
                file.display().to_string(),
                s("-C"),
                dest.display().to_string(),
                format!("--strip-components={strip}"),
                s("--no-same-owner"),
            ]);
            exit_ok(ctx.sys.exec(&argv, &env_for(&ctx.home), ctx.log)?, "tar")?;
        }
    }
    let bin_dir = ctx.home.join(".local/bin");
    ctx.sys.create_dir_all(&bin_dir).map_err(io_err)?;
    for b in bins {
        let target = dest.join(&b.path);
        if !ctx.sys.exists(&target) {
            return Err(format!("{} was not in the download", b.path));
        }
        let link = bin_dir.join(&b.name);
        ctx.sys.remove_path(&link).map_err(io_err)?;
        ctx.sys.symlink(&target, &link).map_err(io_err)?;
    }
    let _ = ctx.sys.remove_path(&file);
    Ok(())
}
