//! `~/.config/ozbox/config.toml` (override the path with `OZBOX_CONFIG`).
//!
//! ```toml
//! provider = "hcloud"          # fake | hcloud | aws
//! domain = "boxes.example.org" # boxes are reached at https://<name>.<domain>
//!
//! [hcloud]
//! region = "fsn1"
//! image = "..."
//!
//! [aws]
//! region = "us-east-1"
//! image = "ami-..."
//! subnet_id = "subnet-..."   # required to create: a private subnet
//! secrets_key_arn = "arn:aws:kms:..."  # optional: the fleet's secrets key (aws-secrets-key module); with `fleet`
//! release_repo = "owner/name" # optional: whose signed releases `upgrade` trusts
//! image_publisher = "none"   # optional: AWS account whose public images `create` may use ("none" = only your own)
//! profile = "work"           # optional: AWS CLI profile for `ozbox connect --ssh`
//! ```
//!
//! The box modules and first-boot configuration come with the program (ADR 0036). `module_dir` (with `dev_modules = true`)
//! is only for developing the modules: a `module_dir` whose files are not the program's own is otherwise ignored.

use std::path::{Path, PathBuf};

use clap::ValueEnum;
use ozbox_core::{Error, Result};
use serde::Deserialize;

use crate::cli::ProviderKind;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSection {
    /// Developers only: the box module folder to render instead of the program's own copy. Used only when its files are
    /// the program's, or with `dev_modules = true` (then every plan says so); otherwise ignored with a warning.
    pub module_dir: Option<PathBuf>,
    /// Use `module_dir` although it is not the program's own copy (developing the modules). Same as `--dev-modules`.
    pub dev_modules: Option<bool>,
    pub region: Option<String>,
    /// AWS only: regions `list` searches (default: just `region`).
    pub regions: Option<Vec<String>>,
    pub image: Option<String>,
    /// AWS only: a private subnet, a customer-managed KMS key, the root disk size.
    pub subnet_id: Option<String>,
    pub kms_key_arn: Option<String>,
    /// AWS only: the fleet's secrets key and its fleet name (the aws-secrets-key module's `key_arn` and `fleet`). A box
    /// created while these are set keeps its secrets store's key in KMS, so an upgrade keeps the store; without them the
    /// key is kept in a file on the system disk.
    pub secrets_key_arn: Option<String>,
    pub fleet: Option<String>,
    /// AWS only: the off-box issuer's address and function (`ozbox init --issuer-package`). Recorded for the issuer's client
    /// (phase 2); nothing reads them yet.
    #[allow(dead_code)]
    pub issuer_url: Option<String>,
    #[allow(dead_code)]
    pub issuer_function_arn: Option<String>,
    pub root_disk_gb: Option<u32>,
    /// AWS only: the most minutes `ozbox upgrade` waits for the copy of the old system disk it keeps (default 30). The copy finishes
    /// by itself if it takes longer; the upgrade then stops before changing anything.
    pub snapshot_wait_minutes: Option<u32>,
    /// AWS only: the `owner/name` GitHub repository whose image workflow signs the Oz images, used to verify
    /// `ozbox upgrade --image latest` (default: the project's own).
    pub release_repo: Option<String>,
    /// AWS only: the account whose public Oz images `latest` (and so a bare `ozbox create`) may use when this account has
    /// none of its own: a 12-digit account id, or `none` to turn them off. Default: the project's own publisher account
    /// (ADR 0052). Set it with `release_repo` when you publish your own images.
    pub image_publisher: Option<String>,
    /// AWS only: the named AWS CLI profile every daily command uses (the operator role). `ozbox init` never writes it.
    pub profile: Option<String>,
    /// AWS only: the profile `ozbox init` was last run with (the setup identity). Recorded for reference; no daily command
    /// reads it, so setup rights are never used by accident.
    #[allow(dead_code)]
    pub setup_profile: Option<String>,
    /// AWS only: the encrypted bucket that holds the infrastructure state (written by `ozbox init`).
    #[allow(dead_code)] // recorded and read back through the file by `ozbox init`
    pub state_bucket: Option<String>,
    /// AWS only: the locked session-log bucket and the patch group the opt-in security services made
    /// (`ozbox init security`). Boxes created or rebuilt afterwards join them.
    pub session_log_bucket: Option<String>,
    pub patch_group: Option<String>,
    /// `local` (the default) or `s3`: where each box's OpenTofu state lives (ADR 0033). Set to `s3` only after
    /// `ozbox state migrate` has copied the boxes there.
    pub state_backend: Option<String>,
    /// The bucket's region when it is not this provider's own (always needed for hcloud; AWS defaults to `region`).
    pub state_region: Option<String>,
    /// A customer-managed KMS key for the state objects (the bucket's default encryption otherwise).
    pub state_kms_key_id: Option<String>,
}

/// Why a configuration file could not be edited.
#[derive(Debug)]
pub enum EditError {
    /// The file is not valid TOML: it is left exactly as it was.
    Invalid,
    /// A key that must be a table (a provider's section) is something else.
    NotTable(String),
    Io(std::io::Error),
}

/// Edit the configuration file in place, keeping comments, ordering and keys this program does not know. `top` sets keys at
/// the top level; `section` (a provider's name) with `set` and `remove` changes keys under that table. A backup
/// (`<file>.bak`) is made the first time, and the new text is written beside the file and renamed over it, so a failure never
/// leaves half a file. The caller names the file the loader reads ([`Config::active_path`]): this never picks a second one.
pub fn edit_config_file(
    path: &Path,
    top: &[(&str, &str)],
    section: Option<&str>,
    set: &[(&str, &str)],
    remove: &[&str],
) -> std::result::Result<(), EditError> {
    use toml_edit::{DocumentMut, Item, Table};
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(EditError::Io(e)),
    };
    let mut doc: DocumentMut = text.parse().map_err(|_| EditError::Invalid)?;
    for (k, v) in top {
        set_str(doc.as_table_mut(), k, v);
    }
    if let Some(name) = section {
        let item = doc.entry(name).or_insert_with(|| Item::Table(Table::new()));
        let Some(tbl) = item.as_table_like_mut() else {
            return Err(EditError::NotTable(name.to_string()));
        };
        for (k, v) in set {
            set_str(tbl, k, v);
        }
        for k in remove {
            tbl.remove(k);
        }
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(EditError::Io)?;
    }
    if !text.is_empty() {
        let bak = path.with_extension("toml.bak");
        if !bak.exists() {
            std::fs::write(&bak, &text).map_err(EditError::Io)?;
        }
    }
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, doc.to_string()).map_err(EditError::Io)?;
    std::fs::rename(&tmp, path).map_err(EditError::Io)
}

/// Set a string key, keeping the comment that sat on the old value and leaving an equal value untouched.
fn set_str(tbl: &mut dyn toml_edit::TableLike, key: &str, v: &str) {
    use toml_edit::{value, Item};
    if tbl.get(key).and_then(Item::as_str) == Some(v) {
        return;
    }
    let mut new = value(v);
    // replace in place: the key keeps its own decoration (a comment above it), the value the comment beside it
    if let Some(slot) = tbl.get_mut(key) {
        if let (Some(old), Some(nv)) = (slot.as_value(), new.as_value_mut()) {
            *nv.decor_mut() = old.decor().clone();
        }
        *slot = new;
        return;
    }
    tbl.insert(key, new);
}

/// Set one string key in a provider's section of the configuration file, keeping everything else (a backup is made the
/// first time). Used where a command, not a person, records a choice (`ozbox state migrate --switch`).
pub fn set_provider_key(path: &Path, section: &str, key: &str, value: &str) -> Result<()> {
    edit_config_file(path, &[], Some(section), &[(key, value)], &[]).map_err(|e| match e {
        EditError::Invalid => Error::Config(format!(
            "{} is not valid TOML, so it was not changed",
            path.display()
        )),
        EditError::NotTable(s) => Error::Config(format!("[{s}] is not a table")),
        EditError::Io(e) => e.into(),
    })
}

/// Which file the config came from (`None` = none existed) and every place that was looked at.
#[derive(Debug, Clone, Default)]
pub struct Source {
    pub found: Option<PathBuf>,
    pub looked: Vec<PathBuf>,
}

/// A warning when more than one config file exists: only the first is read, and the other is silently ignored otherwise.
pub fn both_files_warning(candidates: &[PathBuf]) -> Option<String> {
    let found: Vec<&PathBuf> = candidates.iter().filter(|p| p.is_file()).collect();
    if found.len() < 2 {
        return None;
    }
    Some(format!(
        "warning: both {} and {} exist. ozbox reads only {}; {} is ignored. Merge what you need into {} and remove the other.",
        found[0].display(),
        found[1].display(),
        found[0].display(),
        found[1].display(),
        found[0].display()
    ))
}

/// A warning for a command that needs a provider when none is configured, so it silently showing the built-in simulated
/// one (an empty fleet: "No boxes") is never mistaken for the real thing. `None` when a provider is configured.
pub fn fallback_warning(source: &Source, provider_configured: bool) -> Option<String> {
    if provider_configured {
        return None;
    }
    Some(match &source.found {
        Some(p) => format!(
            "warning: {} sets no `provider`, so ozbox is using the built-in simulated provider (no real boxes). Add `provider = \"aws\"` (or hcloud) to it.",
            p.display()
        ),
        None => format!(
            "warning: no ozbox config found (looked at {}), so ozbox is using the built-in simulated provider (no real boxes). Run `ozbox init`, or set OZBOX_CONFIG.",
            source
                .looked
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

/// The `AWS_PROFILE` to export so every `aws`, `tofu` and ssh ProxyCommand ozbox starts uses the profile the config names:
/// only when the config names one, and never over a profile the environment already chose.
pub fn aws_profile_to_export(config: &Config, current: Option<&str>) -> Option<String> {
    let p = config.aws.as_ref()?.profile.as_deref()?.trim();
    (!p.is_empty() && current.is_none_or(str::is_empty)).then(|| p.to_string())
}

/// `[ssh]` in the config.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshSection {
    /// Seconds to wait for an SSH connection to come up (5 to 300; default 30).
    pub connect_timeout_secs: Option<u64>,
}

/// The `OZBOX_SSH_CONNECT_TIMEOUT` to export from `[ssh] connect_timeout_secs`, unless the environment already set one.
pub fn ssh_timeout_to_export(config: &Config, current: Option<&str>) -> Option<String> {
    let n = config.ssh.as_ref()?.connect_timeout_secs?;
    current.is_none_or(str::is_empty).then(|| n.to_string())
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub provider: Option<String>,
    /// With `provider = "plugin"`: the name of the provider plugin (see `ozbox plugin`).
    pub plugin: Option<String>,
    pub ssh: Option<SshSection>,
    pub domain: Option<String>,
    pub hcloud: Option<ProviderSection>,
    pub aws: Option<ProviderSection>,
}

impl Config {
    /// Where the boxes' state is kept, as the provider's section says. `None` is the local state directory.
    /// `force` ignores `state_backend` (the migration writes to the bucket before anything is switched). A section that
    /// says `s3` without a bucket is an error, never a quiet fall back to local: that would split a box's state in two.
    pub fn s3_state(
        &self,
        kind: ProviderKind,
        force: bool,
    ) -> Result<Option<ozbox_core::tofu::S3State>> {
        let (name, sec) = match kind {
            ProviderKind::Aws => ("aws", self.aws.as_ref()),
            ProviderKind::Hcloud => ("hcloud", self.hcloud.as_ref()),
            ProviderKind::Fake | ProviderKind::Plugin => return Ok(None),
        };
        let Some(sec) = sec else {
            return if force {
                Err(Error::Config(
                    "there is no provider section to read the state bucket from; run `ozbox init`"
                        .into(),
                ))
            } else {
                Ok(None)
            };
        };
        match sec.state_backend.as_deref() {
            None | Some("local") if !force => return Ok(None),
            None | Some("local") | Some("s3") => {}
            Some(other) => {
                return Err(Error::Config(format!(
                    "[{name}] state_backend is \"{other}\"; it must be \"local\" or \"s3\""
                )))
            }
        }
        let bucket = sec.state_bucket.clone().ok_or_else(|| {
            Error::Config(format!(
                "[{name}] state_backend is \"s3\" but no state_bucket is set (`ozbox init` records it)"
            ))
        })?;
        let region = sec
            .state_region
            .clone()
            .or_else(|| {
                (kind == ProviderKind::Aws)
                    .then(|| sec.region.clone())
                    .flatten()
            })
            .ok_or_else(|| {
                Error::Config(format!(
                    "[{name}] needs state_region: the region the state bucket is in"
                ))
            })?;
        let s3 = ozbox_core::tofu::S3State {
            bucket,
            region,
            kms_key_id: sec.state_kms_key_id.clone(),
        };
        s3.validate()?;
        Ok(Some(s3))
    }

    pub fn path() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("OZBOX_CONFIG") {
            return Some(PathBuf::from(p));
        }
        dirs::home_dir().map(|h| h.join(".config/ozbox/config.toml"))
    }

    /// Every file the config may be in, in order: the path `OZBOX_CONFIG` names (only that one), else `config.toml` and
    /// then `fleet.toml` in `~/.config/ozbox/`. The second is read when the first is absent, because installs set up by
    /// hand (or by an earlier layout) keep the same settings there; it takes the same keys.
    pub fn candidates() -> Vec<PathBuf> {
        if let Some(p) = std::env::var_os("OZBOX_CONFIG") {
            return vec![PathBuf::from(p)];
        }
        match dirs::home_dir() {
            Some(h) => {
                let d = h.join(".config/ozbox");
                vec![d.join("config.toml"), d.join("fleet.toml")]
            }
            None => Vec::new(),
        }
    }

    /// The file the loader reads, and so the one every writer must edit: the first candidate that exists, else the default
    /// path (`config.toml`) for a first run. Never a second file that would shadow the first.
    pub fn active_path() -> Option<PathBuf> {
        Self::active_in(&Self::candidates())
    }

    pub(crate) fn active_in(candidates: &[PathBuf]) -> Option<PathBuf> {
        candidates
            .iter()
            .find(|p| p.is_file())
            .or(candidates.first())
            .cloned()
    }

    /// The config from the first candidate that exists, with where it came from and where it looked.
    pub fn load_found() -> Result<(Self, Source)> {
        Self::load_found_in(&Self::candidates())
    }

    pub(crate) fn load_found_in(candidates: &[PathBuf]) -> Result<(Self, Source)> {
        for p in candidates {
            if p.is_file() {
                return Ok((
                    Self::load_from(p)?,
                    Source {
                        found: Some(p.clone()),
                        looked: candidates.to_vec(),
                    },
                ));
            }
        }
        Ok((
            Self::default(),
            Source {
                found: None,
                looked: candidates.to_vec(),
            },
        ))
    }

    pub fn load() -> Result<Self> {
        Ok(Self::load_found()?.0)
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .map_err(|e| Error::Config(format!("{}: {}", path.display(), e.message()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn provider_kind(&self) -> Result<Option<ProviderKind>> {
        match &self.provider {
            None => Ok(None),
            Some(s) => ProviderKind::from_str(s, true).map(Some).map_err(|_| {
                Error::Config(format!(
                    "unknown provider {s:?} in the config: use fake, hcloud or aws"
                ))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_file() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let c: Config = toml::from_str(
            "provider = \"aws\"\ndomain = \"x.example.org\"\n[aws]\nregion = \"us-east-1\"\n",
        )?;
        assert_eq!(c.provider_kind()?, Some(ProviderKind::Aws));
        assert_eq!(c.domain.as_deref(), Some("x.example.org"));
        Ok(())
    }

    #[test]
    fn the_first_existing_candidate_is_read_and_fleet_toml_is_the_fallback(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let d = tempfile::tempdir()?;
        let (a, b) = (d.path().join("config.toml"), d.path().join("fleet.toml"));
        std::fs::write(&b, "provider = \"aws\"\n[aws]\nprofile = \"work\"\n")?;
        let (c, src) = Config::load_found_in(&[a.clone(), b.clone()])?;
        assert_eq!(c.provider_kind()?, Some(ProviderKind::Aws));
        assert_eq!(src.found.as_deref(), Some(b.as_path()));
        std::fs::write(&a, "provider = \"hcloud\"\n")?;
        let (c, src) = Config::load_found_in(&[a.clone(), b])?;
        assert_eq!(
            c.provider_kind()?,
            Some(ProviderKind::Hcloud),
            "config.toml wins"
        );
        assert_eq!(src.found.as_deref(), Some(a.as_path()));
        let (c, src) = Config::load_found_in(&[d.path().join("nope.toml")])?;
        assert!(c.provider.is_none() && src.found.is_none());
        Ok(())
    }

    #[test]
    fn a_missing_or_provider_less_config_warns_and_a_configured_one_does_not() {
        let none = Source {
            found: None,
            looked: vec![
                PathBuf::from("/h/.config/ozbox/config.toml"),
                PathBuf::from("/h/.config/ozbox/fleet.toml"),
            ],
        };
        let w = fallback_warning(&none, false).unwrap_or_default();
        assert!(
            w.contains("simulated") && w.contains("fleet.toml") && w.contains("ozbox init"),
            "{w}"
        );
        let some = Source {
            found: Some(PathBuf::from("/h/x.toml")),
            looked: Vec::new(),
        };
        assert!(fallback_warning(&some, false)
            .unwrap_or_default()
            .contains("sets no `provider`"));
        assert!(fallback_warning(&some, true).is_none());
    }

    #[test]
    fn the_configured_aws_profile_is_exported_unless_the_environment_chose_one() {
        let c: Config =
            toml::from_str("provider = \"aws\"\n[aws]\nprofile = \"work\"\n").unwrap_or_default();
        assert_eq!(aws_profile_to_export(&c, None).as_deref(), Some("work"));
        assert_eq!(aws_profile_to_export(&c, Some("")).as_deref(), Some("work"));
        assert_eq!(
            aws_profile_to_export(&c, Some("other")),
            None,
            "an explicit AWS_PROFILE wins"
        );
        assert_eq!(aws_profile_to_export(&Config::default(), None), None);
    }

    #[test]
    fn the_configured_ssh_timeout_is_exported_unless_the_environment_set_one() {
        let c: Config = toml::from_str("[ssh]\nconnect_timeout_secs = 45\n").unwrap_or_default();
        assert_eq!(ssh_timeout_to_export(&c, None).as_deref(), Some("45"));
        assert_eq!(ssh_timeout_to_export(&c, Some("60")), None);
        assert_eq!(ssh_timeout_to_export(&Config::default(), None), None);
    }

    #[test]
    fn unknown_keys_and_providers_are_errors() {
        assert!(toml::from_str::<Config>("colour = 1").is_err());
        let c = Config {
            provider: Some("gcp".into()),
            ..Config::default()
        };
        assert!(c.provider_kind().is_err());
    }

    #[test]
    fn both_files_present_warns_which_one_is_read(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let d = tempfile::tempdir()?;
        let (a, b) = (d.path().join("config.toml"), d.path().join("fleet.toml"));
        assert_eq!(both_files_warning(&[a.clone(), b.clone()]), None);
        std::fs::write(&b, "provider = \"aws\"\n")?;
        assert_eq!(
            both_files_warning(&[a.clone(), b.clone()]),
            None,
            "one file is normal"
        );
        std::fs::write(&a, "provider = \"aws\"\n")?;
        let w = both_files_warning(&[a.clone(), b.clone()]).ok_or("no warning")?;
        assert!(w.contains("config.toml") && w.contains("fleet.toml"), "{w}");
        assert!(w.contains("reads only") && w.contains("ignored"), "{w}");
        assert_eq!(Config::active_in(&[a.clone(), b]), Some(a));
        Ok(())
    }

    #[test]
    fn an_edit_keeps_comments_and_unknown_keys_and_refuses_broken_files(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let d = tempfile::tempdir()?;
        let f = d.path().join("fleet.toml");
        std::fs::write(&f, "# keep\nfuture_key = 1\n[aws]\nregion = \"a\" # note\n")?;
        edit_config_file(
            &f,
            &[("provider", "aws")],
            Some("aws"),
            &[("region", "b")],
            &[],
        )
        .map_err(|e| format!("{e:?}"))?;
        let t = std::fs::read_to_string(&f)?;
        assert!(
            t.contains("# keep") && t.contains("future_key = 1") && t.contains("# note"),
            "{t}"
        );
        assert!(
            t.contains("region = \"b\"") && t.contains("provider = \"aws\""),
            "{t}"
        );
        std::fs::write(&f, "provider = [")?;
        assert!(matches!(
            edit_config_file(&f, &[], Some("aws"), &[("a", "b")], &[]),
            Err(EditError::Invalid)
        ));
        assert_eq!(std::fs::read_to_string(&f)?, "provider = [");
        Ok(())
    }
}
