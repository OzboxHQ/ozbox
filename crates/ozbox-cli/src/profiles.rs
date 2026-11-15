//! Box profiles: a named set of tools plus box defaults, kept as plain TOML files so they can live in git and be shared.
//!
//! ```toml
//! description = "Web work"
//! tools = ["bundle:web", "neovim"]
//!
//! [box]
//! size = "M"
//! disk_gb = 200
//! auto_pause_minutes = 90
//! always_on = false
//! labels = { purpose = "web" }
//! ```
//!
//! Files live in `~/.config/ozbox/profiles/<name>.toml` (override the folder with `OZBOX_PROFILES`). A file is checked
//! when it is read, so a hand-edited profile that names an unknown or unverified tool is refused with the reason.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ozbox_catalog::model::is_id;
use ozbox_catalog::Catalog;
use ozbox_core::{BoxSpec, Size};
use serde::{Deserialize, Serialize};

pub const MAX_PROFILES: usize = 200;
const MAX_FILE: u64 = 64 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileBox {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_pause_minutes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always_on: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Tool ids and `bundle:<id>` names.
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default, rename = "box")]
    pub defaults: ProfileBox,
}

/// Labels reserved for the box's own use cannot be set from a profile.
const RESERVED: [&str; 2] = ["ozbox-box", "ozbox-managed"];

pub fn valid_name(name: &str) -> bool {
    is_id(name)
}

impl Profile {
    /// Every rule a profile must keep. Returns the first problem, in words a person can act on.
    pub fn validate(&self, catalog: &Catalog) -> Result<(), String> {
        if self.description.as_deref().is_some_and(|d| d.len() > 200) {
            return Err("the description is longer than 200 characters".into());
        }
        let ids = catalog.expand(&self.tools)?;
        for id in &ids {
            let t = catalog
                .tool(id)
                .ok_or_else(|| format!("no tool named {id}"))?;
            if !t.verified {
                return Err(format!(
                    "{id} cannot be installed yet: its source is not verified"
                ));
            }
        }
        if let Some(s) = &self.defaults.size {
            s.parse::<Size>().map_err(|e| e.to_string())?;
        }
        if let Some(d) = self.defaults.disk_gb {
            if d < BoxSpec::MIN_WORK_DISK_GB {
                return Err(format!(
                    "the work disk must be at least {} GB",
                    BoxSpec::MIN_WORK_DISK_GB
                ));
            }
        }
        if self
            .defaults
            .auto_pause_minutes
            .is_some_and(|m| !(5..=10_080).contains(&m))
        {
            return Err("auto-pause must be between 5 minutes and 7 days".into());
        }
        if self.defaults.labels.len() > 12 {
            return Err("a profile carries at most 12 labels".into());
        }
        for (k, v) in &self.defaults.labels {
            let ok = |s: &str| {
                !s.is_empty()
                    && s.len() <= 63
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            };
            if !ok(k) || !(v.is_empty() || ok(v)) {
                return Err(format!(
                    "the label {k:?} has characters a label may not have"
                ));
            }
            if RESERVED.contains(&k.as_str()) {
                return Err(format!("the label {k} is reserved"));
            }
        }
        Ok(())
    }
}

/// A folder of profile files.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Store {
        Store { dir: dir.into() }
    }

    /// The default folder, or `None` when there is no home directory.
    pub fn default_dir() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("OZBOX_PROFILES") {
            return Some(PathBuf::from(p));
        }
        crate::config::Config::path().map(|p| p.with_file_name("profiles"))
    }

    fn file(&self, name: &str) -> Result<PathBuf, String> {
        if !valid_name(name) {
            return Err("a profile name uses lowercase letters, digits and hyphens".into());
        }
        Ok(self.dir.join(format!("{name}.toml")))
    }

    pub fn load(&self, name: &str, catalog: &Catalog) -> Result<Profile, String> {
        let path = self.file(name)?;
        let meta =
            std::fs::metadata(&path).map_err(|_| format!("there is no profile named {name}"))?;
        if meta.len() > MAX_FILE {
            return Err(format!("the profile {name} is too large"));
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {name}: {}", e.kind()))?;
        let p: Profile =
            toml::from_str(&text).map_err(|e| format!("{name}.toml: {}", e.message()))?;
        p.validate(catalog)
            .map_err(|e| format!("{name}.toml: {e}"))?;
        Ok(p)
    }

    /// Names of the profile files, sorted. Files that are not valid are listed with the problem instead of hidden.
    pub fn list(&self, catalog: &Catalog) -> Vec<(String, Result<Profile, String>)> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = rd
            .filter_map(Result::ok)
            .filter_map(|e| {
                let n = e.file_name().into_string().ok()?;
                n.strip_suffix(".toml").map(str::to_string)
            })
            .filter(|n| valid_name(n))
            .collect();
        names.sort();
        names.truncate(MAX_PROFILES);
        names
            .into_iter()
            .map(|n| {
                let r = self.load(&n, catalog);
                (n, r)
            })
            .collect()
    }

    pub fn save(
        &self,
        name: &str,
        p: &Profile,
        catalog: &Catalog,
        overwrite: bool,
    ) -> Result<PathBuf, String> {
        let path = self.file(name)?;
        p.validate(catalog)?;
        if path.exists() && !overwrite {
            return Err(format!("a profile named {name} already exists"));
        }
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("cannot create the profiles folder: {}", e.kind()))?;
        let body = toml::to_string_pretty(p).map_err(|e| e.to_string())?;
        let text = format!("# An Oz Box profile. Keep it in git to share it: `ozbox create <box> --profile {name}`.\n{body}");
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)
            .map_err(|e| format!("cannot write the profile: {}", e.kind()))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| format!("cannot write the profile: {}", e.kind()))?;
        Ok(path)
    }

    pub fn delete(&self, name: &str) -> Result<(), String> {
        let path = self.file(name)?;
        std::fs::remove_file(&path).map_err(|_| format!("there is no profile named {name}"))
    }
}

/// A box's labels as a profile would carry them (reserved and simulator labels left out).
pub fn clean_labels(labels: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    labels
        .iter()
        .filter(|(k, _)| {
            !RESERVED.contains(&k.as_str()) && !k.starts_with("sim_") && !k.starts_with("ozbox-")
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cat() -> Catalog {
        ozbox_catalog::embedded().unwrap()
    }

    fn profile() -> Profile {
        Profile {
            description: Some("Web work".into()),
            tools: vec!["bundle:web".into(), "neovim".into()],
            defaults: ProfileBox {
                size: Some("M".into()),
                disk_gb: Some(200),
                auto_pause_minutes: Some(90),
                always_on: Some(false),
                labels: [("purpose".to_string(), "web".to_string())].into(),
            },
        }
    }

    #[test]
    fn a_profile_round_trips_through_a_plain_file() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::new(d.path().join("profiles"));
        let path = s.save("web", &profile(), &cat(), false).unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.starts_with("# An Oz Box profile") && text.contains("tools = ["));
        assert_eq!(s.load("web", &cat()).unwrap(), profile());
        assert!(s
            .save("web", &profile(), &cat(), false)
            .unwrap_err()
            .contains("already exists"));
        assert!(s.save("web", &profile(), &cat(), true).is_ok());
        let listed = s.list(&cat());
        assert_eq!(listed.len(), 1);
        s.delete("web").unwrap();
        assert!(s.load("web", &cat()).is_err());
        assert!(s.delete("web").is_err());
    }

    #[test]
    fn bad_profiles_are_refused_with_the_reason() {
        let c = cat();
        let mut p = profile();
        p.tools = vec!["nope".into()];
        assert!(p.validate(&c).unwrap_err().contains("nope"));
        p.tools = vec!["docker".into()];
        assert!(p.validate(&c).unwrap_err().contains("not verified"));
        let mut p = profile();
        p.defaults.size = Some("HUGE".into());
        assert!(p.validate(&c).is_err());
        p.defaults.size = None;
        p.defaults.disk_gb = Some(5);
        assert!(p.validate(&c).unwrap_err().contains("at least"));
        let mut p = profile();
        p.defaults
            .labels
            .insert("ozbox-managed".into(), "false".into());
        assert!(p.validate(&c).unwrap_err().contains("reserved"));
        let d = tempfile::tempdir().unwrap();
        let s = Store::new(d.path());
        std::fs::write(d.path().join("x.toml"), "surprise = 1\n").unwrap();
        assert!(s.load("x", &c).is_err());
        assert!(s.load("../x", &c).is_err());
        let listed = s.list(&c);
        assert!(listed[0].1.is_err());
    }

    #[test]
    fn names_are_ids_and_labels_drop_reserved_ones() {
        assert!(valid_name("web-2") && !valid_name("Web") && !valid_name("a/b") && !valid_name(""));
        let l: BTreeMap<String, String> = [
            ("ozbox-box", "x"),
            ("sim_profile", "failing"),
            ("purpose", "p"),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        assert_eq!(clean_labels(&l).len(), 1);
    }
}
