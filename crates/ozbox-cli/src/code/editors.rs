//! Desktop editors over SSH: the link that opens a box's folder in the editor, built from the box's SSH entry.
//!
//! A scheme is used only where a vendor documents it; where it does not, the link is marked [`Evidence::Unverified`]
//! (a fork that is believed to use the same handler) or there is none and the steps are shown instead.
//!
//! * VS Code: "Open a remote resource", `vscode://vscode-remote/{remoteName}+{authority}/{path}`, on
//!   <https://code.visualstudio.com/docs/configure/command-line> (checked 2026-11-09).
//! * Zed: `zed://ssh/[<user>@]<host>[:<port>]/<path>`, on <https://zed.dev/docs/remote-development> (checked 2026-11-09).
//! * Cursor, Windsurf and Antigravity are forks of VS Code and register `cursor://`, `windsurf://` and `antigravity://`.
//!   Their own documentation does not describe a remote-folder link, so these are unverified: the link is printed with a
//!   note, and a person can fall back to the steps.
//! * JetBrains: the Gateway link format appears only in older help pages and is incomplete there, so no link is built;
//!   the steps (Gateway, new SSH connection, the host entry) are shown.

use serde::Serialize;

use crate::sshconfig::host_alias;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Editor {
    Vscode,
    Cursor,
    Antigravity,
    Windsurf,
    Zed,
    Jetbrains,
}

pub const ALL: [Editor; 6] = [
    Editor::Vscode,
    Editor::Cursor,
    Editor::Antigravity,
    Editor::Windsurf,
    Editor::Zed,
    Editor::Jetbrains,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// The vendor's own documentation describes this link.
    Documented,
    /// No vendor page describes it; built on the assumption that a fork keeps its parent's handler.
    Unverified,
}

impl Editor {
    pub fn id(self) -> &'static str {
        match self {
            Editor::Vscode => "vscode",
            Editor::Cursor => "cursor",
            Editor::Antigravity => "antigravity",
            Editor::Windsurf => "windsurf",
            Editor::Zed => "zed",
            Editor::Jetbrains => "jetbrains",
        }
    }

    pub fn parse(s: &str) -> Option<Editor> {
        ALL.into_iter().find(|e| e.id() == s)
    }

    pub fn name(self) -> &'static str {
        match self {
            Editor::Vscode => "VS Code",
            Editor::Cursor => "Cursor",
            Editor::Antigravity => "Antigravity",
            Editor::Windsurf => "Windsurf",
            Editor::Zed => "Zed",
            Editor::Jetbrains => "JetBrains Gateway",
        }
    }

    /// The link that opens `path` on the box, or `None` where no link exists. `alias` is the box's SSH entry name
    /// (`ozbox-<box>`), which the editor resolves through the person's SSH configuration.
    pub fn url(self, alias: &str, path: &str) -> Option<(String, Evidence)> {
        if !alias_ok(alias) || !path.starts_with('/') || path.contains(['?', '#', ' ']) {
            return None;
        }
        let remote = |scheme: &str| format!("{scheme}://vscode-remote/ssh-remote+{alias}{path}");
        match self {
            Editor::Vscode => Some((remote("vscode"), Evidence::Documented)),
            Editor::Cursor => Some((remote("cursor"), Evidence::Unverified)),
            Editor::Antigravity => Some((remote("antigravity"), Evidence::Unverified)),
            Editor::Windsurf => Some((remote("windsurf"), Evidence::Unverified)),
            Editor::Zed => Some((format!("zed://ssh/{alias}{path}"), Evidence::Documented)),
            Editor::Jetbrains => None,
        }
    }

    /// The link for a box by name.
    pub fn url_for_box(self, box_name: &str, path: &str) -> Option<(String, Evidence)> {
        self.url(&host_alias(box_name), path)
    }
}

fn alias_ok(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= 64
        && a.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_follow_the_documented_forms() {
        let p = "/work/repos";
        assert_eq!(
            Editor::Vscode.url_for_box("dev", p),
            Some((
                "vscode://vscode-remote/ssh-remote+ozbox-dev/work/repos".into(),
                Evidence::Documented
            ))
        );
        assert_eq!(
            Editor::Zed.url_for_box("dev", p),
            Some((
                "zed://ssh/ozbox-dev/work/repos".into(),
                Evidence::Documented
            ))
        );
        for (e, scheme) in [
            (Editor::Cursor, "cursor"),
            (Editor::Antigravity, "antigravity"),
            (Editor::Windsurf, "windsurf"),
        ] {
            assert_eq!(
                e.url_for_box("dev", p),
                Some((
                    format!("{scheme}://vscode-remote/ssh-remote+ozbox-dev/work/repos"),
                    Evidence::Unverified
                ))
            );
        }
        assert_eq!(Editor::Jetbrains.url_for_box("dev", p), None);
    }

    #[test]
    fn nothing_odd_gets_into_a_link() {
        for alias in ["", "a b", "a/b", "a+b", "x?y"] {
            assert_eq!(Editor::Vscode.url(alias, "/work"), None, "{alias}");
        }
        for path in ["work", "/work repos", "/work?x=1", "/work#f"] {
            assert_eq!(Editor::Vscode.url("ozbox-dev", path), None, "{path}");
        }
    }

    #[test]
    fn every_editor_parses_from_its_id() {
        for e in ALL {
            assert_eq!(Editor::parse(e.id()), Some(e));
            assert!(!e.name().is_empty());
        }
        assert_eq!(Editor::parse("emacs"), None);
    }
}
