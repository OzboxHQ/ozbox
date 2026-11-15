//! The one-line-in, one-line-out protocol between the tool host and a session's worker, and the actions an agent can take.
//!
//! A request is a JSON object, `{"id":7,"op":"act", ...}`; the reply carries the same id. Both travel sealed (see
//! [`crate::channel`]): on the wire each is one line holding a numbered, encrypted envelope, and only the first line in, the
//! [`Start`], is in the clear. Frames and screenshots travel as base64 inside the sealed reply.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::policy::Device;

/// What an agent can do in the page. Typed text is a value the audit chain never sees (see [`Action::audit_words`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Navigate {
        url: String,
    },
    Back,
    Forward,
    Reload,
    Click {
        target: String,
    },
    Type {
        target: String,
        text: String,
        #[serde(default)]
        submit: bool,
        /// Clear the field first (default true).
        #[serde(default = "yes")]
        clear: bool,
    },
    Select {
        target: String,
        value: String,
    },
    Scroll {
        #[serde(default)]
        target: Option<String>,
        #[serde(default)]
        dy: i64,
    },
    Hover {
        target: String,
    },
    Press {
        key: String,
    },
    TabNew {
        #[serde(default)]
        url: Option<String>,
    },
    TabSwitch {
        index: usize,
    },
    TabClose {
        #[serde(default)]
        index: Option<usize>,
    },
    TabList,
    Wait {
        #[serde(default)]
        ms: Option<u64>,
        #[serde(default)]
        text: Option<String>,
        #[serde(default)]
        selector: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Upload {
        target: String,
        path: String,
    },
    Downloads,
    OpenDownload {
        name: String,
    },
    Snapshot,
    Screenshot {
        #[serde(default)]
        full_page: bool,
    },
    Extract {
        schema: Value,
    },
}

fn yes() -> bool {
    true
}

impl Action {
    /// The short word the audit chain records.
    pub fn word(&self) -> &'static str {
        match self {
            Action::Navigate { .. } => "navigate",
            Action::Back => "back",
            Action::Forward => "forward",
            Action::Reload => "reload",
            Action::Click { .. } => "click",
            Action::Type { .. } => "type",
            Action::Select { .. } => "select",
            Action::Scroll { .. } => "scroll",
            Action::Hover { .. } => "hover",
            Action::Press { .. } => "press",
            Action::TabNew { .. } => "tab_new",
            Action::TabSwitch { .. } => "tab_switch",
            Action::TabClose { .. } => "tab_close",
            Action::TabList => "tab_list",
            Action::Wait { .. } => "wait",
            Action::Upload { .. } => "upload",
            Action::Downloads => "downloads",
            Action::OpenDownload { .. } => "open_download",
            Action::Snapshot => "snapshot",
            Action::Screenshot { .. } => "screenshot",
            Action::Extract { .. } => "extract",
        }
    }

    /// Whether the action only looks at the page. Anything else is a write for the permission engine.
    pub fn reads(&self) -> bool {
        matches!(
            self,
            Action::TabList
                | Action::Wait { .. }
                | Action::Downloads
                | Action::Snapshot
                | Action::Screenshot { .. }
                | Action::Extract { .. }
                | Action::Scroll { .. }
                | Action::Hover { .. }
                | Action::TabSwitch { .. }
        )
    }

    /// The element an action names, if it names one.
    pub fn target(&self) -> Option<&str> {
        match self {
            Action::Click { target }
            | Action::Type { target, .. }
            | Action::Select { target, .. }
            | Action::Hover { target }
            | Action::Upload { target, .. } => Some(target),
            Action::Scroll { target, .. } => target.as_deref(),
            _ => None,
        }
    }

    /// What may go in the audit chain beyond the word: names, never values. Typed text, a selected value, a file path and
    /// an address never appear.
    pub fn audit_words(&self, field_name: Option<&str>) -> Vec<String> {
        let mut v = vec!["browser".to_string(), self.word().to_string()];
        if let Some(n) = field_name {
            v.push(n.chars().take(60).collect());
        }
        v
    }

    pub fn validate(&self) -> Result<(), String> {
        let long = |s: &str, max: usize, what: &str| {
            if s.len() > max || s.contains('\0') {
                Err(format!("{what} is too long or not text"))
            } else {
                Ok(())
            }
        };
        match self {
            Action::Navigate { url } => long(url, 2000, "the address"),
            Action::Type { text, target, .. } => {
                long(text, 8000, "the text")?;
                long(target, 100, "the target")
            }
            Action::Select { value, target } => {
                long(value, 500, "the value")?;
                long(target, 100, "the target")
            }
            Action::Press { key } => {
                if key.len() > 40 || key.is_empty() {
                    Err("a key is a short name such as Enter or Control+a".into())
                } else {
                    Ok(())
                }
            }
            Action::Wait { ms, timeout_ms, .. } => {
                if ms.is_some_and(|m| m > 30_000) || timeout_ms.is_some_and(|m| m > 60_000) {
                    Err("wait at most 30 seconds, or 60 for a condition".into())
                } else {
                    Ok(())
                }
            }
            Action::Upload { path, .. } => long(path, 500, "the path"),
            Action::OpenDownload { name } => {
                if name.contains('/') || name.contains("..") || name.starts_with('.') {
                    Err("a download is named by its file name only".into())
                } else {
                    Ok(())
                }
            }
            Action::Extract { schema } => crate::schema::check_schema(schema),
            _ => Ok(()),
        }
    }
}

/// Who is acting: the agent, or a person who has taken over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    Agent,
    Person,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// What would this action do, and how risky is it? Changes nothing.
    Preview {
        action: Action,
    },
    /// Do it. An action the worker judges risky runs only with a [`Grant`]: the proof that a person approved this approval
    /// request for this action on this state of the page. The permission engine allowing a call is not a grant.
    Act {
        action: Action,
        #[serde(default)]
        grant: Option<Grant>,
    },
    /// A person's pointer or key input, relayed from the live view. Only accepted while a person holds the session.
    Input {
        event: Value,
    },
    Takeover {
        who: String,
    },
    Handback,
    /// The latest live-view frame and the page it shows.
    Frame,
    Status,
    /// Save where the task is and stop: the pause after a long wait or a limit.
    Pause {
        reason: String,
    },
    Close,
}

/// A person's approval, as the worker accepts it: which approval request was decided, the page state it was shown (the
/// preview's fingerprint), the risk it was shown as, and a MAC over those and the exact action (see
/// [`crate::channel::Channel::grant`]). Good once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub approval: String,
    pub fingerprint: String,
    pub risk: String,
    pub mac: String,
}

impl Action {
    /// The bytes a grant is bound to: the action exactly as both ends serialise it.
    pub fn grant_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    #[serde(flatten)]
    pub op: Op,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub id: u64,
    pub ok: bool,
    /// A short code when not ok: `person_holds`, `risk`, `limit`, `robots`, `invalid`, `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub result: Value,
}

impl Reply {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            id,
            ok: true,
            code: None,
            error: None,
            result,
        }
    }
    pub fn err(id: u64, code: &str, error: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            code: Some(code.into()),
            error: Some(error.into()),
            result: Value::Null,
        }
    }
}

/// The settings a worker is started with: the first line on its standard input, the only one not sealed. Without a key the
/// worker does not start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Start {
    pub session: String,
    /// The session's channel key (never printed; see [`crate::channel::SessionKey`]).
    pub key: crate::channel::SessionKey,
    pub root: String,
    /// The box's `/work`. An upload comes only from the folders the policy names under it (see
    /// [`crate::policy::upload_allowed`]).
    pub work: String,
    #[serde(default)]
    pub device: Device,
    pub policy: crate::policy::BrowserPolicy,
    /// Hosts the project's allow-list names, so the worker's own preview can say "new domain".
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    pub run: Option<String>,
    /// Where the profiles, a saved place and the held-back downloads live when the worker runs as a user of its own (ADR
    /// 0037, amendment 4). Set, the worker keeps those out of `root` (which the box's other users may read: recordings and
    /// released documents) and in this folder only it can open. `None`: everything is under `root` and private to whoever
    /// runs the worker, which is how a worker on a person's own computer, and a test, runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_root: Option<String>,
    /// The memory the browser session may use. The worker does not enforce it: the launcher that starts it as its own user
    /// gives the cap to the service manager.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_max_bytes: Option<u64>,
    /// The longest the session may run, which the launcher also hands to the service manager as a backstop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_runtime_s: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn actions_parse_from_the_tool_arguments_and_name_themselves() {
        let a: Action =
            serde_json::from_value(json!({ "action": "type", "target": "e3", "text": "hi" }))
                .unwrap();
        assert_eq!(a.word(), "type");
        assert_eq!(a.target(), Some("e3"));
        assert!(matches!(
            a,
            Action::Type {
                clear: true,
                submit: false,
                ..
            }
        ));
        assert!(!a.reads());
        assert!(Action::Snapshot.reads());
        assert!(serde_json::from_value::<Action>(json!({ "action": "format_disk" })).is_err());
    }

    #[test]
    fn the_audit_words_never_hold_a_value() {
        let a = Action::Type {
            target: "e3".into(),
            text: "SENTINEL-abc".into(),
            submit: false,
            clear: true,
        };
        let w = a.audit_words(Some("password")).join(" ");
        assert_eq!(w, "browser type password");
        let n = Action::Navigate {
            url: "https://example.com/?token=SENTINEL-abc".into(),
        };
        assert_eq!(n.audit_words(None).join(" "), "browser navigate");
    }

    #[test]
    fn bad_arguments_are_refused() {
        assert!(Action::Press { key: String::new() }.validate().is_err());
        assert!(Action::Wait {
            ms: Some(99_000),
            text: None,
            selector: None,
            timeout_ms: None
        }
        .validate()
        .is_err());
        assert!(Action::OpenDownload {
            name: "../x".into()
        }
        .validate()
        .is_err());
        assert!(Action::Navigate {
            url: "x".repeat(3000)
        }
        .validate()
        .is_err());
        assert!(Action::Extract {
            schema: json!({ "pattern": "a" })
        }
        .validate()
        .is_err());
        assert!(Action::Click {
            target: "e1".into()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn a_request_is_one_flat_json_line() {
        let r = Request {
            id: 4,
            op: Op::Act {
                action: Action::Back,
                grant: None,
            },
        };
        let line = serde_json::to_string(&r).unwrap();
        assert!(!line.contains('\n'));
        let back: Request = serde_json::from_str(&line).unwrap();
        assert_eq!(back.id, 4);
        let r: Request = serde_json::from_str(r#"{"id":1,"op":"handback"}"#).unwrap();
        assert!(matches!(r.op, Op::Handback));
        // the old boolean is not an approval: it is ignored, and the act carries no grant
        let r: Request = serde_json::from_str(
            r#"{"id":2,"op":"act","action":{"action":"back"},"approved":true}"#,
        )
        .unwrap();
        assert!(matches!(r.op, Op::Act { grant: None, .. }));
    }

    #[test]
    fn a_start_without_a_key_is_not_a_start() {
        let no_key = json!({ "session": "b1", "root": "/r", "work": "/w", "policy": {} });
        assert!(serde_json::from_value::<Start>(no_key.clone()).is_err());
        let k = crate::channel::SessionKey::generate().unwrap();
        let mut with = no_key;
        with["key"] = serde_json::to_value(&k).unwrap();
        let s: Start = serde_json::from_value(with).unwrap();
        let shown = format!("{s:?}");
        assert!(!shown.contains(serde_json::to_value(&k).unwrap().as_str().unwrap()));
    }
}
