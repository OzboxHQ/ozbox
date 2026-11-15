//! What a box's root says about its secrets store, in one fixed shape both ends share (ADR 0029 Amendment 11, as amended
//! after the 2026-11-12 review).
//!
//! The box user can make the SSH answer say anything (a `~/.bashrc` on `/work` can replace `cat`, or the whole output), so
//! nothing destructive or lasting may be decided from it. The box prints these lines as **root** (`ozbox secrets
//! adopt-status`), and the laptop reads them through AWS Systems Manager Run Command, whose output comes from the SSM agent
//! running that program as root; the box user is not in that path. Every value is one word or a key ARN, parsed strictly:
//! anything else, or a missing line, is "not said" and nothing is decided from it.

use crate::secrets_adopt::arn_region;

/// The head names the shape. `=1` had 11 lines, then 15; `=2` had 16 and said what a probe of the grant came to; `=3` (this
/// one) has 17 and adds `names`, how many secrets the store holds, which `ozbox upgrade --use-fleet-key` rests on. A box whose
/// program is older answers `=2` (or `=1`, or knows no `adopt-status` at all), which this reader does not parse: the laptop says
/// the BOX is older.
const HEAD: &str = "ozbox-adopt-status=3";
const FIELDS: usize = 17;

/// What wraps a store, from its own `kek` label (or the service's state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kek {
    None,
    File,
    Kms,
    Other,
}

impl Kek {
    pub fn of(label: Option<&str>) -> Self {
        match label {
            None => Self::None,
            Some("file") => Self::File,
            Some("kms") => Self::Kms,
            Some(_) => Self::Other,
        }
    }
    fn word(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::File => "file",
            Self::Kms => "kms",
            Self::Other => "other",
        }
    }
    fn parse(w: &str) -> Option<Self> {
        Some(match w {
            "none" => Self::None,
            "file" => Self::File,
            "kms" => Self::Kms,
            "other" => Self::Other,
            _ => return None,
        })
    }
}

/// What asking the key service about a moved store's grant came to. Only [`Probe::Denied`] (the service's own "access denied")
/// says the grant is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Not asked: the box does not carry what a stranded move leaves.
    Na,
    /// KMS answered and the key wraps and unwraps.
    Ok,
    /// The key service refused this machine's role.
    Denied,
    /// It could not be asked or did not answer cleanly (a timeout, a network fault, a tool that would not start).
    Failed,
}

impl Probe {
    fn word(self) -> &'static str {
        match self {
            Self::Na => "na",
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
    fn parse(w: &str) -> Option<Self> {
        Some(match w {
            "na" => Self::Na,
            "ok" => Self::Ok,
            "denied" => Self::Denied,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

/// The facts, as root read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The service's own state (read as root, trusted only as the service's): ready, and what it says protects the store.
    pub service_ready: bool,
    pub service_kek: Kek,
    /// The `kek` label inside the store file, and inside its copy on `/work`.
    pub store_kek: Kek,
    pub persist_kek: Kek,
    /// The KMS key the settings name.
    pub settings_key: Option<String>,
    pub key_file: bool,
    pub backup: bool,
    /// A cancel was recorded on the box (root-owned): no move starts or finishes while it is there.
    pub cancelled: bool,
    /// A move (or a cancel) holds the box's lock right now.
    pub busy: bool,
    /// The box's own read of its instance tags.
    pub tag_adopt: Option<String>,
    pub tag_key: Option<String>,
    /// For a file-kept key: whether the service says a copy of it is escrowed off the box (`Some(true)`), not (`Some(false)`),
    /// or does not say. An upgrade rests on this, read as root, and not on the box user's SSH answer.
    pub service_escrow: Option<bool>,
    /// The service is down for the one reason an upgrade can do nothing more about: its store is there and its key is not,
    /// and no copy is held (`code=no-escrow`).
    pub service_no_escrow: bool,
    /// The metadata guard's table is loaded, so the box user cannot reach the instance role's credentials (L5).
    pub metadata_guard: bool,
    /// Minutes until a move that keeps being abandoned (the store keeps changing) tries again; 0 when it is not waiting.
    pub move_backoff_mins: u32,
    /// What the key service said to a probe of this box's grant (asked only when the box is moved and keeps its key file and
    /// copy). The laptop offers to put the copy back only on [`Probe::Denied`].
    pub kms_probe: Probe,
    /// How many secrets the owner or an agent put in the store (the service's own keys and records are not counted), as the
    /// service says. `Some(0)`: nothing a new key would lose. `None`: not said.
    pub names: Option<u32>,
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn arn_or_none(v: &Option<String>) -> String {
    v.clone().unwrap_or_else(|| "none".into())
}

impl Facts {
    pub fn render(&self) -> String {
        format!(
            "{HEAD}\nservice_ready={}\nservice_kek={}\nstore_kek={}\npersist_kek={}\nsettings_key={}\nkey_file={}\nbackup={}\ncancelled={}\nbusy={}\ntag_adopt={}\ntag_key={}\nservice_escrow={}\nservice_no_escrow={}\nmetadata_guard={}\nmove_backoff_mins={}\nkms_probe={}\nnames={}\n",
            yn(self.service_ready),
            self.service_kek.word(),
            self.store_kek.word(),
            self.persist_kek.word(),
            arn_or_none(&self.settings_key),
            yn(self.key_file),
            yn(self.backup),
            yn(self.cancelled),
            yn(self.busy),
            arn_or_none(&self.tag_adopt),
            arn_or_none(&self.tag_key),
            match self.service_escrow {
                Some(true) => "vault",
                Some(false) => "none",
                None => "unsaid",
            },
            yn(self.service_no_escrow),
            yn(self.metadata_guard),
            self.move_backoff_mins,
            self.kms_probe.word(),
            self.names
                .map_or_else(|| "unsaid".to_string(), |n| n.to_string()),
        )
    }

    /// Strict: the head line, then every field exactly once, each a value this program writes. `None` for anything else.
    pub fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        if lines.next()? != HEAD {
            return None;
        }
        let mut get = std::collections::BTreeMap::new();
        for l in lines {
            let (k, v) = l.split_once('=')?;
            if get.insert(k.to_string(), v.to_string()).is_some() {
                return None;
            }
        }
        if get.len() != FIELDS {
            return None;
        }
        let yes = |k: &str| match get.get(k)?.as_str() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        };
        let kek = |k: &str| Kek::parse(get.get(k)?);
        let arn = |k: &str| -> Option<Option<String>> {
            let v = get.get(k)?;
            if v == "none" {
                Some(None)
            } else {
                arn_region(v).map(|_| Some(v.clone()))
            }
        };
        Some(Self {
            service_ready: yes("service_ready")?,
            service_kek: kek("service_kek")?,
            store_kek: kek("store_kek")?,
            persist_kek: kek("persist_kek")?,
            settings_key: arn("settings_key")?,
            key_file: yes("key_file")?,
            backup: yes("backup")?,
            cancelled: yes("cancelled")?,
            busy: yes("busy")?,
            tag_adopt: arn("tag_adopt")?,
            tag_key: arn("tag_key")?,
            service_escrow: match get.get("service_escrow")?.as_str() {
                "vault" => Some(true),
                "none" => Some(false),
                "unsaid" => None,
                _ => return None,
            },
            service_no_escrow: yes("service_no_escrow")?,
            metadata_guard: yes("metadata_guard")?,
            move_backoff_mins: {
                let v = get.get("move_backoff_mins")?;
                if v.len() > 6 || !v.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                v.parse().ok()?
            },
            kms_probe: Probe::parse(get.get("kms_probe")?)?,
            names: {
                let v = get.get("names")?;
                if v == "unsaid" {
                    None
                } else if v.len() <= 9 && !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
                    Some(v.parse().ok()?)
                } else {
                    return None;
                }
            },
        })
    }

    /// The move to `arn` is complete on the box and safe to commit (write the real label): the service is ready on KMS, the
    /// store and its copy on `/work` are both KMS-wrapped under that key, nothing is running, and no cancel is recorded.
    pub fn committable(&self, arn: &str) -> bool {
        self.service_ready
            && self.service_kek == Kek::Kms
            && self.store_kek == Kek::Kms
            && self.persist_kek == Kek::Kms
            && self.settings_key.as_deref() == Some(arn)
            && !self.cancelled
            && !self.busy
    }

    /// The box is back on its file key and will not move: safe to take the grant away. The key file is there, the store and
    /// its `/work` copy are not KMS-wrapped, the settings name no KMS key, the service is ready on the file key, and the
    /// cancel is recorded, so no move can start whatever the instance tags still say.
    pub fn cancel_confirmed(&self) -> bool {
        self.cancelled
            && !self.busy
            && self.service_ready
            && self.service_kek == Kek::File
            && self.store_kek == Kek::File
            && self.persist_kek != Kek::Kms
            && self.settings_key.is_none()
            && self.key_file
    }

    /// A box that carries what a move leaves between its move and the commit: the store on KMS under the key the settings name,
    /// the key file and the copy beside the store, and no cancel recorded. Not yet "stranded": that also needs the cloud's word
    /// that no tag names the box (a read the laptop makes) and a probe that says the grant is [`Probe::Denied`].
    pub fn moved_and_kept(&self) -> bool {
        self.store_kek == Kek::Kms
            && self.settings_key.is_some()
            && self.key_file
            && self.backup
            && !self.cancelled
            && !self.busy
    }

    /// The copy of the store made before the move may be offered back: the box is [`moved_and_kept`](Self::moved_and_kept)
    /// and the key service itself refuses its role. A timeout or a blocked network is never enough.
    pub fn copy_restore_justified(&self) -> bool {
        self.moved_and_kept() && self.kms_probe == Probe::Denied
    }

    /// The move is finished: no key file and no copy beside the store, the copy on `/work` is KMS-wrapped.
    pub fn finished(&self) -> bool {
        !self.key_file && !self.backup && self.persist_kek == Kek::Kms && !self.busy
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod tests {
    use super::*;

    const ARN: &str = "arn:aws:kms:us-east-1:123456789012:key/0f0f0f0f-0000-4000-8000-000000000000";

    /// A box that has moved to KMS and waits for the laptop's word.
    pub fn on_kms() -> Facts {
        Facts {
            service_ready: true,
            service_kek: Kek::Kms,
            store_kek: Kek::Kms,
            persist_kek: Kek::Kms,
            settings_key: Some(ARN.into()),
            key_file: true,
            backup: true,
            cancelled: false,
            busy: false,
            tag_adopt: Some(ARN.into()),
            tag_key: None,
            service_escrow: None,
            service_no_escrow: false,
            metadata_guard: true,
            move_backoff_mins: 0,
            kms_probe: Probe::Na,
            names: Some(0),
        }
    }

    /// A box on its file key that has not moved.
    pub fn on_file() -> Facts {
        Facts {
            service_kek: Kek::File,
            store_kek: Kek::File,
            persist_kek: Kek::File,
            settings_key: None,
            backup: false,
            ..on_kms()
        }
    }

    #[test]
    fn facts_round_trip_and_only_a_strict_shape_is_read() {
        let f = on_kms();
        assert_eq!(Facts::parse(&f.render()).unwrap(), f);
        let r = f.render();
        // a missing line, an extra line, a repeated line, an odd value, a bad ARN, another head: not said
        assert!(Facts::parse(&r.replace("busy=no\n", "")).is_none());
        assert!(Facts::parse(&format!("{r}extra=1\n")).is_none());
        assert!(Facts::parse(&format!("{r}busy=no\n")).is_none());
        assert!(Facts::parse(&r.replace("busy=no", "busy=maybe")).is_none());
        assert!(Facts::parse(&r.replace(ARN, "arn:aws:kms:x")).is_none());
        assert!(Facts::parse(&r.replace(HEAD, "ozbox-adopt-status=1")).is_none());
        // the head before this one (16 fields, no `names`) is an older program: not parsed, so the laptop says the box is older
        assert!(Facts::parse(&r.replace(HEAD, "ozbox-adopt-status=2")).is_none());
        assert!(Facts::parse(&r.replace(HEAD, "ozbox-adopt-status=4")).is_none());
        assert!(Facts::parse(&r.replace("names=0", "names=many")).is_none());
        assert!(Facts::parse(&r.replace("names=0", "names=-1")).is_none());
        assert!(Facts::parse(&r.replace("names=0", "names=")).is_none());
        let unsaid = Facts {
            names: None,
            ..f.clone()
        };
        assert_eq!(Facts::parse(&unsaid.render()).unwrap(), unsaid);
        let three = Facts {
            names: Some(3),
            ..f.clone()
        };
        assert_eq!(Facts::parse(&three.render()).unwrap(), three);
        // a 16-field text under the new head is short of a field: refused
        assert!(Facts::parse(&r.replace("names=0\n", "")).is_none());
        assert!(Facts::parse(&r.replace("kms_probe=na", "kms_probe=maybe")).is_none());

        assert!(Facts::parse("ready\nkek=kms\nadopt=kms\n").is_none());
        assert!(Facts::parse("").is_none());
    }

    #[test]
    fn a_move_is_committable_only_when_everything_agrees() {
        let f = on_kms();
        assert!(f.committable(ARN));
        for broken in [
            Facts {
                service_ready: false,
                ..on_kms()
            },
            Facts {
                service_kek: Kek::File,
                ..on_kms()
            },
            Facts {
                store_kek: Kek::File,
                ..on_kms()
            },
            Facts {
                persist_kek: Kek::File,
                ..on_kms()
            },
            Facts {
                settings_key: None,
                ..on_kms()
            },
            Facts {
                cancelled: true,
                ..on_kms()
            },
            Facts {
                busy: true,
                ..on_kms()
            },
        ] {
            assert!(!broken.committable(ARN), "{broken:?}");
        }
        assert!(!f.committable(
            "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
        ));
    }

    #[test]
    fn a_cancel_is_confirmed_only_for_a_box_that_is_back_on_its_file_key_and_cannot_move() {
        let back = Facts {
            cancelled: true,
            ..on_file()
        };
        assert!(back.cancel_confirmed());
        for broken in [
            Facts {
                cancelled: false,
                ..back.clone()
            },
            Facts {
                busy: true,
                ..back.clone()
            },
            Facts {
                store_kek: Kek::Kms,
                ..back.clone()
            },
            Facts {
                persist_kek: Kek::Kms,
                ..back.clone()
            },
            Facts {
                settings_key: Some(ARN.into()),
                ..back.clone()
            },
            Facts {
                key_file: false,
                ..back.clone()
            },
            Facts {
                service_ready: false,
                ..back.clone()
            },
        ] {
            assert!(!broken.cancel_confirmed(), "{broken:?}");
        }
    }
}
