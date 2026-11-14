//! A `SKILL.md`'s front matter, read as real YAML, and what it (and the body) ask an agent program to do.
//!
//! A skill is content an agent follows, and Claude Code also *acts* on some of what a `SKILL.md` declares: `hooks` register
//! shell commands for the rest of the session, `allowed-tools` lets the agent use the listed tools without asking, `shell`
//! picks the shell for injected commands, `agent` names the subagent whose tools apply, and a `` !`command` `` or a
//! ```` ```! ```` block in the body is run before the agent reads the page. (Source: Claude Code's skills reference,
//! code.claude.com/docs/en/skills. Codex, Gemini CLI and OpenCode are not covered here: their handling of these fields has
//! not been checked, so nothing here says what they do.) Reading the front matter with a line splitter would let an indented
//! `command:` under `hooks:` pass as a top-level key, so it is parsed as YAML, with limits, and anything the parser could
//! expand (an alias) is refused rather than expanded.

use std::collections::BTreeMap;

use serde::Serialize;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::Marker;

/// The most front matter read: the description alone may be 1024 characters.
pub const MAX_FRONT_MATTER_BYTES: usize = 16 * 1024;
const MAX_DEPTH: usize = 8;
const MAX_NODES: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Scalar(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

impl Node {
    /// Nothing there: an empty or null scalar, an empty list or map.
    pub fn is_empty(&self) -> bool {
        match self {
            Node::Scalar(s) => {
                let t = s.trim();
                t.is_empty() || matches!(t, "~" | "null" | "Null" | "NULL")
            }
            Node::Seq(v) => v.iter().all(Node::is_empty),
            Node::Map(v) => v.iter().all(|(_, n)| n.is_empty()),
        }
    }

    /// Every scalar inside, in order: a list's items, a map's `key: value` pairs, or the scalar itself.
    pub fn flatten(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.collect(&mut out, "");
        out
    }

    fn collect(&self, out: &mut Vec<String>, prefix: &str) {
        match self {
            Node::Scalar(s) => {
                if !self.is_empty() {
                    out.push(format!("{prefix}{}", s.trim()));
                }
            }
            Node::Seq(v) => v.iter().for_each(|n| n.collect(out, prefix)),
            Node::Map(v) => {
                for (k, n) in v {
                    match n {
                        Node::Scalar(_) => {
                            let mut inner = Vec::new();
                            n.collect(&mut inner, "");
                            for i in inner {
                                out.push(format!("{prefix}{k}: {i}"));
                            }
                        }
                        _ => n.collect(out, &format!("{prefix}{k} / ")),
                    }
                }
            }
        }
    }
}

struct Builder {
    stack: Vec<Vec<Node>>, // the children so far of each open collection
    kinds: Vec<bool>,      // true = a map
    root: Option<Node>,
    docs: usize,
    nodes: usize,
    error: Option<String>,
}

impl Builder {
    fn fail(&mut self, why: &str) {
        if self.error.is_none() {
            self.error = Some(why.to_string());
        }
    }

    fn count(&mut self) {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            self.fail("the front matter holds too many entries");
        }
    }

    fn put(&mut self, n: Node) {
        match self.stack.last_mut() {
            None => self.root = Some(n),
            Some(children) => children.push(n),
        }
    }
}

impl MarkedEventReceiver for Builder {
    fn on_event(&mut self, ev: Event, _mark: Marker) {
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::DocumentStart => {
                self.docs += 1;
                if self.docs > 1 {
                    self.fail("the front matter holds more than one YAML document");
                }
            }
            Event::Alias(_) => {
                self.fail("YAML aliases (*name) are not allowed in a skill's front matter")
            }
            Event::Scalar(s, _, anchor, _) => {
                if anchor != 0 {
                    return self
                        .fail("YAML anchors (&name) are not allowed in a skill's front matter");
                }
                // every scalar is text here, whatever YAML would call it: the key decides what it means
                self.count();
                self.put(Node::Scalar(s));
            }
            Event::SequenceStart(anchor, _) | Event::MappingStart(anchor, _) => {
                if anchor != 0 {
                    return self
                        .fail("YAML anchors (&name) are not allowed in a skill's front matter");
                }
                if self.stack.len() >= MAX_DEPTH {
                    return self.fail("the front matter is nested too deeply");
                }
                self.count();
                self.kinds.push(matches!(ev, Event::MappingStart(..)));
                self.stack.push(Vec::new());
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let children = self.stack.pop().unwrap_or_default();
                let is_map = self.kinds.pop().unwrap_or(false);
                if is_map {
                    let mut pairs = Vec::new();
                    let mut it = children.into_iter();
                    while let Some(k) = it.next() {
                        let Node::Scalar(k) = k else {
                            return self.fail("a front matter key must be plain text");
                        };
                        let v = it.next().unwrap_or(Node::Scalar(String::new()));
                        pairs.push((k, v));
                    }
                    self.put(Node::Map(pairs));
                } else {
                    self.put(Node::Seq(children));
                }
            }
            _ => {}
        }
    }
}

/// The text between the first two `---` lines of a `SKILL.md`, and the body after them. `None` when the file does not start
/// with front matter.
pub fn split(text: &str) -> Result<Option<(&str, &str)>, String> {
    let mut lines = text.split_inclusive('\n');
    let first = lines.next().unwrap_or("");
    if first.trim_end() != "---" {
        return Ok(None);
    }
    let mut at = first.len();
    for l in lines {
        if l.trim_end() == "---" {
            let body_at = at + l.len();
            return Ok(Some((&text[first.len()..at], &text[body_at..])));
        }
        at += l.len();
    }
    Err("the front matter of SKILL.md is not closed with a line holding only ---".into())
}

/// Parse a front matter block. A map with text keys, no aliases or anchors, bounded depth and size, one document.
pub fn parse(block: &str) -> Result<Vec<(String, Node)>, String> {
    if block.len() > MAX_FRONT_MATTER_BYTES {
        return Err(format!(
            "the front matter of SKILL.md is over {} KB",
            MAX_FRONT_MATTER_BYTES / 1024
        ));
    }
    let mut b = Builder {
        stack: Vec::new(),
        kinds: Vec::new(),
        root: None,
        docs: 0,
        nodes: 0,
        error: None,
    };
    Parser::new_from_str(block)
        .load(&mut b, true)
        .map_err(|e| format!("the front matter of SKILL.md is not valid YAML: {e}"))?;
    if let Some(e) = b.error {
        return Err(e);
    }
    match b.root {
        Some(Node::Map(pairs)) => {
            let mut seen = BTreeMap::new();
            for (k, _) in &pairs {
                if seen.insert(k.to_ascii_lowercase(), ()).is_some() {
                    return Err(format!("the front matter names {k} twice"));
                }
            }
            Ok(pairs)
        }
        None => Ok(Vec::new()),
        Some(_) => Err("the front matter of SKILL.md must be a list of key: value lines".into()),
    }
}

/// A capability a person must knowingly accept before a skill can be approved, pushed or installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ask {
    /// A stable id: `hooks`, `shell`, `allowed-tools`, `agent` or `shell-injection`.
    pub key: &'static str,
    /// What was found: the declared values, or the lines of the body that run a command.
    pub detail: Vec<String>,
}

/// Everything a `SKILL.md` declares, sorted into what needs an acknowledgement and what is only shown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Asks {
    /// Run commands or widen what an agent may do. Each needs its own acknowledgement.
    pub acknowledge: Vec<Ask>,
    /// Other documented fields a reader should see (`model`, `context`, `paths`, …), as `key`, `value`.
    pub shown: Vec<(String, String)>,
    /// Fields no program documented here reads. Shown so nothing in the file is hidden from a reviewer.
    pub unknown: Vec<String>,
}

impl Asks {
    pub fn keys(&self) -> Vec<&'static str> {
        self.acknowledge.iter().map(|a| a.key).collect()
    }
}

/// Fields that are read into the pack itself (name, description, …) or documented as ignored by Claude Code.
const IDENTITY: &[&str] = &[
    "name",
    "description",
    "version",
    "license",
    "metadata",
    "compatibility",
];
/// Documented fields that change how or when the skill runs but neither run commands nor widen permission.
const SHOWN: &[&str] = &[
    "when_to_use",
    "argument-hint",
    "arguments",
    "disable-model-invocation",
    "user-invocable",
    "disallowed-tools",
    "model",
    "effort",
    "context",
    "background",
    "paths",
];

const CLIP: usize = 240;

fn clip(s: &str) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > CLIP {
        format!("{}…", one.chars().take(CLIP).collect::<String>())
    } else {
        one
    }
}

/// The lines of a `SKILL.md` body that run a command before the agent reads the page: `` !`…` `` anywhere, or a fenced
/// block opened with ```` ```! ```` (also with more backticks or with `~`). Over-reports on purpose: a false flag costs one
/// tick, a miss runs a command.
pub fn shell_injection_lines(body: &str) -> Vec<String> {
    body.lines()
        .filter(|l| {
            let t = l.trim_start();
            t.contains("!`")
                || ["`", "~"].iter().any(|f| {
                    t.starts_with(&f.repeat(3))
                        && t.trim_start_matches(f.chars().next().unwrap_or('`'))
                            .starts_with('!')
                })
        })
        .map(clip)
        .collect()
}

/// What a `SKILL.md` asks of an agent program. `Err` is a front matter that is not valid.
pub fn asks_of(skill_md: &str) -> Result<Asks, String> {
    let (pairs, body) = match split(skill_md)? {
        Some((fm, body)) => (parse(fm)?, body),
        None => (Vec::new(), skill_md),
    };
    let mut out = Asks::default();
    for (k, v) in &pairs {
        let key = k.to_ascii_lowercase();
        let flat = || v.flatten().iter().map(|s| clip(s)).collect::<Vec<_>>();
        match key.as_str() {
            "hooks" | "allowed-tools" | "shell" | "agent" if !v.is_empty() => {
                let id = match key.as_str() {
                    "hooks" => "hooks",
                    "allowed-tools" => "allowed-tools",
                    "shell" => "shell",
                    _ => "agent",
                };
                out.acknowledge.push(Ask {
                    key: id,
                    detail: flat(),
                });
            }
            "hooks" | "allowed-tools" | "shell" | "agent" => {}
            _ if SHOWN.contains(&key.as_str()) => {
                if !v.is_empty() {
                    out.shown.push((key, flat().join(", ")));
                }
            }
            _ if IDENTITY.contains(&key.as_str()) => {}
            _ => out.unknown.push(clip(k)),
        }
    }
    let inj = shell_injection_lines(body);
    if !inj.is_empty() {
        out.acknowledge.push(Ask {
            key: "shell-injection",
            detail: inj,
        });
    }
    out.acknowledge.sort_by_key(|a| a.key);
    Ok(out)
}
