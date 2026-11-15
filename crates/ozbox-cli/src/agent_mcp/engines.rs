//! Writing the engines' MCP settings: the entry that makes a coding agent on the box start `ozbox agent-mcp bridge`.
//!
//! It runs as the box user, on the box user's own files (the dashboard cannot and must not touch them). The entry holds no
//! secret and never changes, so writing it is idempotent. Other servers a person has configured are never touched: the file
//! is read, one key is added, replaced (only when it is ours) or removed, and the file is written back whole, atomically,
//! with the same mode. A file that is not understood, or is a link, is left alone and said so.
//!
//! * Claude Code: `~/.claude.json`, `mcpServers.ozbox` (user scope, what `claude mcp add --scope user` writes).
//! * Gemini CLI: `~/.gemini/settings.json`, `mcpServers.ozbox`.
//! * OpenCode: `~/.config/opencode/opencode.json`, `mcp.ozbox` (a local server).
//! * Codex: `~/.codex/config.toml`, a marked `[mcp_servers.ozbox]` block (the file's comments are kept).
//!
//! The JSON files come back with their keys in alphabetical order when something changed: the parser does not keep a file's
//! own order. Nothing else about them changes.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Json {
        servers_key: &'static str,
        shape: Shape,
    },
    CodexToml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `{ "command": "...", "args": [...] }`, with a `type` for the engines that want one.
    Stdio { typed: bool },
    /// OpenCode's local server: `{ "type": "local", "command": [..], "enabled": true }`.
    OpenCode,
}

pub struct Engine {
    pub id: &'static str,
    pub name: &'static str,
    rel: &'static str,
    kind: Kind,
}

pub const ENGINES: &[Engine] = &[
    Engine {
        id: "claude-code",
        name: "Claude Code",
        rel: ".claude.json",
        kind: Kind::Json {
            servers_key: "mcpServers",
            shape: Shape::Stdio { typed: true },
        },
    },
    Engine {
        id: "codex",
        name: "Codex",
        rel: ".codex/config.toml",
        kind: Kind::CodexToml,
    },
    Engine {
        id: "gemini-cli",
        name: "Gemini CLI",
        rel: ".gemini/settings.json",
        kind: Kind::Json {
            servers_key: "mcpServers",
            shape: Shape::Stdio { typed: false },
        },
    },
    Engine {
        id: "opencode",
        name: "OpenCode",
        rel: ".config/opencode/opencode.json",
        kind: Kind::Json {
            servers_key: "mcp",
            shape: Shape::OpenCode,
        },
    },
];

/// The name of the entry in each engine's settings.
pub const ENTRY: &str = "ozbox";
const BRIDGE_ARGS: [&str; 2] = ["agent-mcp", "bridge"];
const BLOCK_START: &str = "# >>> Oz Box: coding agents on this box use the Oz Box tools (written by `ozbox agent-mcp install`; `ozbox agent-mcp remove` takes it out)";
const BLOCK_END: &str = "# <<< Oz Box";

/// What happened to one engine's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Wrote,
    Unchanged,
    Removed,
    /// Nothing of ours was there to remove.
    Absent,
    /// A server named `ozbox` that is not ours is there; it was not touched.
    LeftYours,
    /// The file was not touched, and why.
    Refused(String),
}

fn entry(shape: Shape, command: &str) -> Value {
    match shape {
        Shape::Stdio { typed } => {
            let mut v = json!({ "command": command, "args": BRIDGE_ARGS });
            if typed {
                v["type"] = json!("stdio");
                v["env"] = json!({});
            }
            v
        }
        Shape::OpenCode => {
            json!({ "type": "local", "command": [command, BRIDGE_ARGS[0], BRIDGE_ARGS[1]], "enabled": true })
        }
    }
}

/// Is this entry the one this program writes (whatever program path it names)?
fn is_ours(shape: Shape, v: &Value) -> bool {
    match shape {
        Shape::Stdio { .. } => v
            .get("args")
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() == 2 && a[0] == BRIDGE_ARGS[0] && a[1] == BRIDGE_ARGS[1]),
        Shape::OpenCode => v
            .get("command")
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() == 3 && a[1] == BRIDGE_ARGS[0] && a[2] == BRIDGE_ARGS[1]),
    }
}

fn refuse(why: &str) -> Outcome {
    Outcome::Refused(why.to_string())
}

/// The file as text: `Ok(None)` when it does not exist, an error for a link or anything not a plain file.
fn read_plain(path: &Path) -> Result<Option<(String, u32)>, Outcome> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(refuse("it is a link, so it was not changed")),
        Ok(m) if !m.is_file() => Err(refuse("it is not a plain file")),
        Ok(m) => std::fs::read_to_string(path)
            .map(|t| Some((t, m.permissions().mode() & 0o777)))
            .map_err(|_| refuse("it could not be read")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(refuse("it could not be read")),
    }
}

/// Said when the file changed between reading it and putting the new one in place (Claude Code rewrites `~/.claude.json`
/// while it runs); the caller reads again and retries, so the other writer's change is never lost.
pub(super) const CHANGED: &str = "it changed while it was being written";

/// Write beside, then rename: a reader never sees half a file. A new file is private to the user from the moment it exists.
/// `expect` is the text that was read (`None` for a file that was absent): just before the rename the file is
/// read again and the write is given up (`CHANGED`) if it is no longer that.
pub(super) fn write_atomic(
    path: &Path,
    text: &str,
    mode: Option<u32>,
    expect: Option<&Option<String>>,
) -> Result<(), Outcome> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().ok_or_else(|| refuse("it has no folder"))?;
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|_| refuse("its folder could not be made"))?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("settings");
    let tmp = dir.join(format!(".{name}.ozbox-{}.tmp", std::process::id()));
    let result = (|| {
        let _ = std::fs::remove_file(&tmp);
        // created with the file's own mode (or private) and never wider, so a key in it is not readable even for a moment
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode.unwrap_or(0o600))
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode.unwrap_or(0o600)))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(refuse("it could not be written"));
    }
    if let Some(want) = expect {
        let now = match read_plain(path) {
            Ok(v) => v.map(|(t, _)| t),
            Err(o) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(o);
            }
        };
        if now != *want {
            let _ = std::fs::remove_file(&tmp);
            return Err(refuse(CHANGED));
        }
    }
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(refuse("it could not be written"));
    }
    Ok(())
}

/// Run one change, reading the file afresh and trying again (a few times) when another program changed it meanwhile.
pub(super) fn retrying(mut change: impl FnMut() -> Outcome) -> Outcome {
    for _ in 0..5 {
        match change() {
            Outcome::Refused(w) if w == CHANGED => {}
            o => return o,
        }
    }
    refuse("another program kept changing it, so it was not changed; run this again")
}

fn json_change(
    path: &Path,
    servers_key: &str,
    shape: Shape,
    command: &str,
    remove: bool,
) -> Outcome {
    retrying(|| json_change_once(path, servers_key, shape, command, remove))
}

fn json_change_once(
    path: &Path,
    servers_key: &str,
    shape: Shape,
    command: &str,
    remove: bool,
) -> Outcome {
    let (text, mode) = match read_plain(path) {
        Ok(Some((t, m))) => (Some(t), Some(m)),
        Ok(None) => (None, None),
        Err(o) => return o,
    };
    let mut root: Value = match text.as_deref() {
        None => json!({}),
        Some(t) if t.trim().is_empty() => json!({}),
        Some(t) => match serde_json::from_str(t) {
            Ok(v) => v,
            Err(_) => return refuse("it is not valid JSON, so it was not changed"),
        },
    };
    let Some(obj) = root.as_object_mut() else {
        return refuse("it does not hold an object, so it was not changed");
    };
    if remove {
        let Some(servers) = obj.get_mut(servers_key).and_then(Value::as_object_mut) else {
            return Outcome::Absent;
        };
        return match servers.get(ENTRY) {
            None => Outcome::Absent,
            Some(v) if !is_ours(shape, v) => Outcome::LeftYours,
            Some(_) => {
                servers.remove(ENTRY);
                finish(path, &root, mode, &text, Outcome::Removed)
            }
        };
    }
    let want = entry(shape, command);
    let servers = obj
        .entry(servers_key.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(servers) = servers.as_object_mut() else {
        return refuse("its server list is not an object, so it was not changed");
    };
    match servers.get(ENTRY) {
        Some(v) if *v == want => return Outcome::Unchanged,
        Some(v) if !is_ours(shape, v) => return Outcome::LeftYours,
        _ => {}
    }
    servers.insert(ENTRY.to_string(), want);
    finish(path, &root, mode, &text, Outcome::Wrote)
}

fn finish(
    path: &Path,
    root: &Value,
    mode: Option<u32>,
    read: &Option<String>,
    ok: Outcome,
) -> Outcome {
    let mut text = serde_json::to_string_pretty(root).unwrap_or_default();
    text.push('\n');
    match write_atomic(path, &text, mode, Some(read)) {
        Ok(()) => ok,
        Err(o) => o,
    }
}

/// `text` without our block, and whether it had one (a start marker with no end counts as no block: nothing is guessed).
fn strip_block(text: &str) -> (String, bool) {
    let Some(a) = text.find(BLOCK_START) else {
        return (text.to_string(), false);
    };
    let Some(rel_end) = text[a..].find(BLOCK_END) else {
        return (text.to_string(), false);
    };
    let b = a + rel_end + BLOCK_END.len();
    let after = text[b..].strip_prefix('\n').unwrap_or(&text[b..]);
    let before = text[..a].trim_end_matches('\n');
    let joined = if before.is_empty() {
        after.to_string()
    } else if after.is_empty() {
        format!("{before}\n")
    } else {
        format!("{before}\n\n{after}")
    };
    (joined, true)
}

fn toml_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn codex_block(command: &str) -> String {
    format!(
        "{BLOCK_START}\n[mcp_servers.{ENTRY}]\ncommand = {}\nargs = [{}, {}]\n{BLOCK_END}\n",
        toml_string(command),
        toml_string(BRIDGE_ARGS[0]),
        toml_string(BRIDGE_ARGS[1]),
    )
}

fn codex_change(path: &Path, command: &str, remove: bool) -> Outcome {
    retrying(|| codex_change_once(path, command, remove))
}

fn codex_change_once(path: &Path, command: &str, remove: bool) -> Outcome {
    let (text, mode, read) = match read_plain(path) {
        Ok(Some((t, m))) => (t.clone(), Some(m), Some(t)),
        Ok(None) => (String::new(), None, None),
        Err(o) => return o,
    };
    let (rest, had) = strip_block(&text);
    let parsed: Result<toml::Table, _> = rest.parse();
    let Ok(table) = parsed else {
        return refuse("it is not valid TOML, so it was not changed");
    };
    let yours = table
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .is_some_and(|t| t.contains_key(ENTRY));
    if remove {
        if !had {
            return if yours {
                Outcome::LeftYours
            } else {
                Outcome::Absent
            };
        }
        return match write_atomic(path, &rest, mode, Some(&read)) {
            Ok(()) => Outcome::Removed,
            Err(o) => o,
        };
    }
    if yours {
        return Outcome::LeftYours;
    }
    let block = codex_block(command);
    let next = if rest.trim().is_empty() {
        block
    } else {
        format!("{}\n\n{block}", rest.trim_end_matches('\n'))
    };
    if next == text {
        return Outcome::Unchanged;
    }
    // what is about to be written must still be TOML (an inline `mcp_servers = { .. }` and an appended table are not), and
    // must still hold what was there: nothing is written that Codex would refuse to start on
    let Ok(after) = next.parse::<toml::Table>() else {
        return refuse("adding the entry would make the file invalid TOML (is `mcp_servers` an inline table?), so it was not changed");
    };
    if after
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get(ENTRY))
        .is_none()
    {
        return refuse("the entry would not be read back, so it was not changed");
    }
    match write_atomic(path, &next, mode, Some(&read)) {
        Ok(()) => Outcome::Wrote,
        Err(o) => o,
    }
}

fn apply(home: &Path, e: &Engine, command: &str, remove: bool) -> Outcome {
    let path: PathBuf = home.join(e.rel);
    match e.kind {
        Kind::Json { servers_key, shape } => {
            json_change(&path, servers_key, shape, command, remove)
        }
        Kind::CodexToml => codex_change(&path, command, remove),
    }
}

fn pick<'a>(only: Option<&str>) -> Vec<&'a Engine> {
    ENGINES
        .iter()
        .filter(|e| only.is_none_or(|o| o == e.id))
        .collect()
}

/// Add the entry to every engine's settings (or the one named). `command` is the program the engine starts.
pub fn install(home: &Path, command: &str, only: Option<&str>) -> Vec<(&'static str, Outcome)> {
    pick(only)
        .into_iter()
        .map(|e| (e.id, apply(home, e, command, false)))
        .collect()
}

/// Take the entry out where it is ours.
pub fn remove(home: &Path, only: Option<&str>) -> Vec<(&'static str, Outcome)> {
    pick(only)
        .into_iter()
        .map(|e| (e.id, apply(home, e, "", true)))
        .collect()
}

/// Is the entry in place (ours, as `install` would write it)?
pub fn status(home: &Path, command: &str) -> Vec<(&'static str, bool)> {
    ENGINES
        .iter()
        .map(|e| {
            let path = home.join(e.rel);
            let present = match (std::fs::read_to_string(&path), e.kind) {
                (Ok(t), Kind::Json { servers_key, shape }) => serde_json::from_str::<Value>(&t)
                    .ok()
                    .and_then(|v| v.get(servers_key)?.get(ENTRY).cloned())
                    .is_some_and(|v| v == entry(shape, command)),
                (Ok(t), Kind::CodexToml) => t.contains(&codex_block(command)),
                _ => false,
            };
            (e.id, present)
        })
        .collect()
}
