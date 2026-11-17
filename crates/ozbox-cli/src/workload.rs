//! Workload secrets: the `.env` keys a project's commands need (ADR 0018, item 7). They are imported with a preview that
//! shows names and fingerprints and never a value, stored as `workload.<project>.<env>.<NAME>` with a production flag beside
//! them, handed to a command only if the command names them, and removed from everything the command prints.
//!
//! This module runs a command as whoever runs `ozbox env run` (a laptop, where the person is the owner). On a box the same
//! command goes to the root launcher (`runner.rs`), which starts it under the project's runner user instead.

use std::io::Read;
use std::process::{Command, Stdio};

use ring::digest;
use zeroize::Zeroizing;

use crate::secrets::{SecretError, SecretStore};
use crate::secrets_enc::{workload_name, EncryptedSecrets, Meta};
use crate::serve::auth::b64::{encode_std, encode_url};

/// One `NAME=value` entry of a `.env` file (a quoted value may span several lines).
pub struct EnvLine {
    pub name: String,
    pub value: Zeroizing<String>,
    /// The line the entry starts on (1-based), so a refusal can say where without printing anything of the entry.
    pub line: usize,
    /// Why the text is not a value, when it is not (see [`Malformed`]). The value is then the text as written.
    pub malformed: Option<Malformed>,
}

/// A quoted value that is not a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// A quote was opened and never closed: the rest of the file was read as part of it.
    Unclosed,
    /// Text follows the closing quote (other than a `# comment`).
    TextAfterQuote,
}

impl Malformed {
    pub fn reason(self) -> &'static str {
        match self {
            Malformed::Unclosed => {
                "a quote is opened and never closed (the rest of the file was read as part of it)"
            }
            Malformed::TextAfterQuote => "there is text after the closing quote",
        }
    }
}

/// A name that appears more than once in a file. The LAST one is kept (as a shell, python-dotenv and Docker Compose do), so
/// the report can say which line won and which were ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Duplicate {
    pub name: String,
    pub kept_line: usize,
    /// The earlier lines that were ignored, in file order.
    pub ignored_lines: Vec<usize>,
}

/// A line that is neither blank, a comment, nor `NAME=value`: it is never stored, and the report says where and why. The
/// reason is a fixed sentence and never quotes the line (it may be part of a key that was not quoted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub line: usize,
    pub reason: &'static str,
}

/// What a file holds, with everything [`parse_env`] drops silently accounted for: every entry of the file ends up in
/// `lines` (kept), `duplicates` (an earlier line of a name that appears again) or `rejected` (not `NAME=value`).
#[derive(Default)]
pub struct ParsedEnv {
    pub lines: Vec<EnvLine>,
    pub duplicates: Vec<Duplicate>,
    pub rejected: Vec<Rejected>,
}

impl ParsedEnv {
    /// How many entries the file has: kept ones, ignored duplicates and rejected lines. Blank lines and comments are not entries.
    pub fn entries(&self) -> usize {
        self.lines.len()
            + self
                .duplicates
                .iter()
                .map(|d| d.ignored_lines.len())
                .sum::<usize>()
            + self.rejected.len()
    }
}

/// Why a name cannot be a variable name, in words that never repeat the name (a "name" can be a piece of a value).
pub fn invalid_name_reason(name: &str) -> &'static str {
    if name.is_empty() {
        "the name before `=` is empty"
    } else if name.len() > 64 {
        "the name is longer than 64 characters"
    } else if name.chars().any(char::is_whitespace) {
        "the name contains a space (an unquoted value that runs over several lines? quote it)"
    } else if name.as_bytes()[0].is_ascii_digit() {
        "the name starts with a digit"
    } else if name.bytes().any(|b| b.is_ascii_lowercase()) {
        "the name has lower-case letters (names are capital letters, digits and _)"
    } else {
        "the name has a character other than capital letters, digits and _"
    }
}

/// The most lines one quoted value may span before it is called unclosed.
const MAX_QUOTED_LINES: usize = 4096;

/// The entries of a `.env` text without the accounting of [`parse_env_report`], which holds the rules.
#[cfg(test)]
pub fn parse_env(text: &str) -> Vec<EnvLine> {
    parse_env_report(text).lines
}

/// Parse `.env` text the way dotenv does (python-dotenv and Docker Compose; not Node's `dotenv`, which ends an unquoted
/// value at any `#`).
///
/// * Blank lines and `#` comment lines are skipped; a line without `=` is [`Rejected`] (and never stored). A byte-order mark
///   at the start of the file and Windows line endings (`\r\n`) are read as nothing.
/// * An `export ` (or `export<TAB>`) prefix is dropped.
/// * A value in matching double quotes loses the quotes, and what follows the closing quote (a ` # comment`) is ignored.
///   Inside double quotes `\"` is a quote, `\\` is a backslash and `\n` is a line break; any other backslash stays as
///   written. A value in matching single quotes is taken literally.
/// * **A quoted value may span lines** (a PEM key, a JSON document): the lines up to the closing quote are ONE value and
///   none of them is read as a `NAME=` line. A quote that is never closed takes the rest of the file and is marked
///   [`Malformed::Unclosed`]; text after the closing quote is [`Malformed::TextAfterQuote`]. Either way the text is kept
///   as written and is refused by [`plan`].
/// * An unquoted value ends at a ` #` (a space, then `#`) and is trimmed. `KEY=a#b` keeps the `#`.
///
/// The value is only parsed here; whether the store can hold it is decided by [`plan`].
///
/// Every entry is accounted for: a name that appears more than once keeps its LAST line (and the earlier ones are
/// [`Duplicate`]s), and a line without `=` is [`Rejected`] with its line number.
pub fn parse_env_report(text: &str) -> ParsedEnv {
    let mut out: Vec<EnvLine> = Vec::new();
    let mut duplicates: Vec<Duplicate> = Vec::new();
    let mut rejected: Vec<Rejected> = Vec::new();
    // a byte-order mark (what some editors put at the start of a file) is not part of the first name
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        let raw = lines[i];
        i += 1;
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = match l.strip_prefix("export") {
            Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
            _ => l,
        };
        let Some((k, v)) = l.split_once('=') else {
            rejected.push(Rejected {
                line: start + 1,
                reason: "not NAME=value (there is no `=` on the line)",
            });
            continue;
        };
        let name = k.trim().to_string();
        // `KEY= # note` is a blank value with a comment (a space, then `#`); `KEY=#x` keeps the `#`
        let comment_only = v.starts_with(char::is_whitespace) && v.trim_start().starts_with('#');
        let v = if comment_only { "" } else { v.trim() };
        let (value, malformed) = if v.starts_with('"') || v.starts_with('\'') {
            // read on, a line at a time, until the quote closes
            let mut buf = Zeroizing::new(v.to_string());
            loop {
                match scan_quoted(&buf) {
                    Scan::Closed(val) => break (val, None),
                    Scan::TextAfter => break (buf.to_string(), Some(Malformed::TextAfterQuote)),
                    Scan::Open => {
                        if i >= lines.len() || i - start >= MAX_QUOTED_LINES {
                            // never closed: everything read so far, as written
                            i = lines.len();
                            break (buf.to_string(), Some(Malformed::Unclosed));
                        }
                        buf.push('\n');
                        buf.push_str(lines[i]);
                        i += 1;
                    }
                }
            }
        } else {
            (unquoted_value(v), None)
        };
        // the last one wins, as a shell would; the earlier lines are remembered so the report can name them
        if let Some(pos) = out.iter().position(|e| e.name == name) {
            let earlier = out.remove(pos);
            match duplicates.iter_mut().find(|d| d.name == name) {
                Some(d) => {
                    d.ignored_lines.push(earlier.line);
                    d.kept_line = start + 1;
                }
                None => duplicates.push(Duplicate {
                    name: name.clone(),
                    kept_line: start + 1,
                    ignored_lines: vec![earlier.line],
                }),
            }
        }
        out.push(EnvLine {
            name,
            value: Zeroizing::new(value),
            line: start + 1,
            malformed,
        });
    }
    ParsedEnv {
        lines: out,
        duplicates,
        rejected,
    }
}

enum Scan {
    Closed(String),
    TextAfter,
    Open,
}

/// Read a value that starts with a quote. `v` may hold several lines joined by `\n`.
fn scan_quoted(v: &str) -> Scan {
    let mut chars = v.chars();
    let quote = chars.next().unwrap_or('"');
    let rest = chars.as_str();
    if quote == '\'' {
        return match rest.find('\'') {
            Some(end) => {
                let tail = rest[end + 1..].trim();
                if tail.is_empty() || tail.starts_with('#') {
                    Scan::Closed(rest[..end].to_string())
                } else {
                    Scan::TextAfter
                }
            }
            None => Scan::Open,
        };
    }
    let mut val = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('"') => val.push('"'),
                Some('\\') => val.push('\\'),
                Some('n') => val.push('\n'),
                Some(o) => {
                    val.push('\\');
                    val.push(o);
                }
                None => val.push('\\'),
            },
            '"' => {
                let tail = chars.as_str().trim();
                return if tail.is_empty() || tail.starts_with('#') {
                    Scan::Closed(val)
                } else {
                    Scan::TextAfter
                };
            }
            o => val.push(o),
        }
    }
    Scan::Open
}

fn unquoted_value(v: &str) -> String {
    // unquoted: a ` #` starts a comment
    let mut cut = v.len();
    let b = v.as_bytes();
    for i in 1..b.len() {
        if b[i] == b'#' && b[i - 1].is_ascii_whitespace() {
            cut = i;
            break;
        }
    }
    v[..cut].trim_end().to_string()
}

/// A short, stable tag of a value, so a person can tell two keys apart (and a changed key from an unchanged one) without
/// seeing either. Eight hex digits of SHA-256: enough to compare, not enough to guess a key from.
pub fn fingerprint(value: &str) -> String {
    digest::digest(&digest::SHA256, value.as_bytes())
        .as_ref()
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Why a key looks like a production or live credential, if it does. Conservative on purpose: a false alarm costs one flag.
pub fn live_reason(name: &str, value: &str, env: &str) -> Option<&'static str> {
    let up = name.to_ascii_uppercase();
    if env == "production" || env == "prod" || env == "live" {
        return Some("the environment is production");
    }
    if up.contains("PROD") || up.contains("LIVE") {
        return Some("the name says production or live");
    }
    // one list, shared with the approval rules (ADR 0041): a value the box calls live is a Production one there too
    for p in ozbox_core::approval_subject::LIVE_VALUE_PREFIXES {
        if value.starts_with(p) {
            return Some("the value is a live-mode key");
        }
    }
    if ozbox_core::approval_subject::value_says_production(value) {
        return Some("the address looks like production");
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Ready,
    /// Looks like a production key; stored only when named in the override.
    Live(&'static str),
    /// The name cannot be a variable name.
    Invalid,
    /// The value is empty (`KEY=` or `KEY=""`). Nothing is stored and it is not an error.
    Blank,
    /// The value cannot be stored (see `check_value`); the reason is a plain sentence, never the value.
    Unstorable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// As parsed. NEVER print this for an [`Status::Invalid`] row: a name that is not a variable name can be part of a
    /// value (a line of a key that was not quoted). Use [`Row::label`].
    pub name: String,
    pub line: usize,
    pub fingerprint: String,
    pub status: Status,
    /// The value is stored encoded (base64, marked in the entry) because the plain rule does not hold it. Anything that
    /// stores it must say so in the preview, and a box must be able to read it (see `capabilities`).
    pub encoded: bool,
}

impl Row {
    /// What may be shown for this row: its name, or for a name that is not valid, only where it was found.
    pub fn label(&self) -> String {
        if self.status == Status::Invalid {
            format!("line {}", self.line)
        } else {
            self.name.clone()
        }
    }
}

/// The preview: one row per key, names and fingerprints only.
///
/// What can be stored: any value that is not blank, has no NUL byte and is at most 96 KB. A value the plain rule
/// ([`crate::secrets::check_value`]) holds is stored as it is; every other value is stored encoded and read back exactly.
pub fn plan(lines: &[EnvLine], project: &str, env: &str) -> Vec<Row> {
    lines
        .iter()
        .map(|l| {
            let mut encoded = false;
            let status = if workload_name(project, env, &l.name).is_err() {
                Status::Invalid
            } else if let Some(m) = l.malformed {
                Status::Unstorable(m.reason().to_string())
            } else if l.value.is_empty() {
                Status::Blank
            } else if let Err(e) = crate::secrets_enc::check_exact(&l.value) {
                Status::Unstorable(e.0)
            } else {
                encoded = crate::secrets::check_value(&l.value).is_err();
                match live_reason(&l.name, &l.value, env) {
                    Some(r) => Status::Live(r),
                    None => Status::Ready,
                }
            };
            Row {
                name: l.name.clone(),
                line: l.line,
                fingerprint: fingerprint(&l.value),
                status,
                encoded,
            }
        })
        .collect()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub stored: Vec<String>,
    /// Looked like production and was not named in the override.
    pub held_back: Vec<String>,
    pub invalid: Vec<String>,
    /// Blank values, skipped.
    pub blank: Vec<String>,
    /// Values the store cannot hold, skipped, with the reason.
    pub unstorable: Vec<(String, String)>,
}

/// Store what the plan allows. A production-looking key is stored only if `allow_live` names it, and then it is flagged so a
/// command run for an agent never receives it.
#[cfg(test)]
pub fn apply(
    store: &EncryptedSecrets,
    project: &str,
    env: &str,
    lines: &[EnvLine],
    allow_live: &[String],
    owner: &str,
) -> Result<Applied, SecretError> {
    apply_marked(store, project, env, lines, allow_live, &[], owner)
}

/// [`apply`], with the names a person marked PUBLIC (`--public NAME`). A mark is stored only on a value that
/// [`crate::workload_policy::public_mark_refusal`] allows; any other marked line is not stored at all and is reported in
/// `unstorable` with the reason, so a mark that cannot be honoured never quietly stores the value as a secret the person thinks is
/// public. A marked name that is not in the file is reported the same way.
pub fn apply_marked(
    store: &EncryptedSecrets,
    project: &str,
    env: &str,
    lines: &[EnvLine],
    allow_live: &[String],
    public: &[String],
    owner: &str,
) -> Result<Applied, SecretError> {
    let mut done = Applied::default();
    for p in public {
        if !lines.iter().any(|l| &l.name == p) {
            done.unstorable.push((
                p.clone(),
                "it is marked public but is not in the file".to_string(),
            ));
        }
    }
    // All-or-nothing on what a person can fix: every name and value is checked (by `plan`) before the first key is
    // stored, so a skipped key never leaves the others half imported. A refusal that comes from the disk itself while
    // writing can still stop part-way; running the import again overwrites the same names and is safe.
    let rows = plan(lines, project, env);
    // asked once for the whole import, not once per line: each stored line changes the file, and a set built per line would unwrap
    // every production value again for each of them (G5 fourth round, NV3-L2). A set that cannot be built stops the import.
    let mut held = store.production_checker()?;
    // a value the store already holds as production is production here too, however it is named or which file it came from
    for (l, row) in lines.iter().zip(rows) {
        let row = if matches!(row.status, Status::Ready) && held.holds(&l.value) {
            Row {
                status: Status::Live("this value is already stored as production"),
                ..row
            }
        } else {
            row
        };
        let live = match row.status {
            Status::Invalid => {
                done.invalid.push(l.name.clone());
                continue;
            }
            Status::Blank => {
                done.blank.push(l.name.clone());
                continue;
            }
            Status::Unstorable(why) => {
                done.unstorable.push((l.name.clone(), why));
                continue;
            }
            Status::Live(_) if !allow_live.iter().any(|a| a == &l.name) => {
                done.held_back.push(l.name.clone());
                continue;
            }
            Status::Live(_) => true,
            Status::Ready => false,
        };
        let marked = public.iter().any(|p| p == &l.name);
        if marked {
            if let Some(why) = crate::workload_policy::public_mark_refusal(&l.name, &l.value, live)
            {
                done.unstorable
                    .push((l.name.clone(), format!("it cannot be marked public: {why}")));
                continue;
            }
        }
        let full = workload_name(project, env, &l.name)?;
        store.set_exact_with_meta(
            &full,
            &l.value,
            Meta {
                owner: owner.to_string(),
                production: live,
                public: marked,
            },
        )?;
        if live {
            held.add(&l.value);
        }
        done.stored.push(l.name.clone());
    }
    Ok(done)
}

/// The names a local import would store exactly as they already are: same value, same production flag, same public mark. Such a
/// name is not written again, and the report says "unchanged". `live_allowed` is the production-looking names the person
/// allowed; a production-looking name that is held back is never unchanged (it is held back).
pub fn unchanged_names(
    store: &EncryptedSecrets,
    project: &str,
    env: &str,
    lines: &[EnvLine],
    rows: &[Row],
    live_allowed: &dyn Fn(&str) -> bool,
    public: &[String],
) -> Result<Vec<String>, SecretError> {
    let mut out = Vec::new();
    for (l, r) in lines.iter().zip(rows) {
        let live = match r.status {
            Status::Ready => false,
            Status::Live(_) if live_allowed(&l.name) => true,
            _ => continue,
        };
        let full = workload_name(project, env, &l.name)?;
        let Some(meta) = store.meta(&full)? else {
            continue;
        };
        if meta.production != live || meta.public != public.iter().any(|p| p == &l.name) {
            continue;
        }
        if store
            .get(&full)?
            .map(Zeroizing::new)
            .is_some_and(|v| v.as_str() == l.value.as_str())
        {
            out.push(l.name.clone());
        }
    }
    Ok(out)
}

fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// The encodings of one piece of text the scan looks for: as is, base64 (standard and URL-safe, with and without padding)
/// and percent-encoded.
fn encodings(text: &str) -> Vec<String> {
    let std64 = encode_std(text.as_bytes());
    let url64 = encode_url(text.as_bytes());
    vec![
        text.to_string(),
        std64.trim_end_matches('=').to_string(),
        std64,
        url64.trim_end_matches('=').to_string(),
        url64,
        pct(text),
    ]
}

/// The most single lines of one multi-line value that are scanned for on their own.
const MAX_LINE_FORMS: usize = 64;

/// Every form of `value` the scan looks for: the value in the encodings above and, for a value that is not one plain
/// line, each of its lines as written (a program prints a key line by line) and its JSON-escaped form (a program prints a
/// secret inside JSON: `\n`, `\"`, `\\`). All of it is computed on the exact value, never on its stored encoding. A form
/// shorter than six characters is not scanned for (it would blank ordinary words). Cost: a plain one-line value costs
/// one JSON encoding more than before; only a multi-line value adds forms, at most [`MAX_LINE_FORMS`] of them, raw.
fn forms(value: &str) -> Vec<String> {
    let mut v = if value.len() >= 6 {
        encodings(value)
    } else {
        Vec::new()
    };
    if value.contains(['\n', '\r']) {
        let mut seen = std::collections::BTreeSet::new();
        for line in value.lines().map(str::trim) {
            if line.len() >= 6 && seen.len() < MAX_LINE_FORMS && seen.insert(line) {
                v.push(line.to_string());
            }
        }
    }
    if let Ok(j) = serde_json::to_string(value) {
        let inner = &j[1..j.len() - 1];
        if inner != value {
            v.push(inner.to_string());
        }
    }
    v.sort();
    v.dedup();
    v.retain(|s| s.len() >= 6);
    // longest first, so a value inside a longer encoding is not half removed
    v.sort_by_key(|s| std::cmp::Reverse(s.len()));
    v
}

/// Replace every known value, in every form above, with `[redacted]`. Returns the text and how many were replaced.
pub fn redact(text: &str, secrets: &[Zeroizing<String>]) -> (String, usize) {
    let mut out = text.to_string();
    let mut n = 0;
    for s in secrets {
        for f in forms(s) {
            let c = out.matches(&f).count();
            if c > 0 {
                n += c;
                out = out.replace(&f, "[redacted]");
            }
        }
    }
    (out, n)
}

/// The indexes of the values that appear in `text` in any of the forms above. Reports which, never what.
pub fn hits(text: &str, secrets: &[Zeroizing<String>]) -> Vec<usize> {
    secrets
        .iter()
        .enumerate()
        .filter(|(_, s)| forms(s).iter().any(|f| text.contains(f.as_str())))
        .map(|(i, _)| i)
        .collect()
}

pub struct RunSpec<'a> {
    pub project: &'a str,
    pub env: &'a str,
    /// The names this command may receive: the allow-list. Anything else is refused, whatever the command asks for.
    pub allow: &'a [String],
    /// Names put in the command's environment under their own name.
    pub env_names: &'a [String],
    pub argv: &'a [String],
}

#[derive(Debug)]
pub struct RunResult {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub redactions: usize,
    /// The names that were resolved, for the audit line. Never values.
    pub resolved: Vec<String>,
}

const MAX_OUT: u64 = 8 * 1024 * 1024;

/// Read a started child's output (bounded; stderr on its own thread so a full pipe never blocks it) and wait for it.
pub fn collect(mut child: std::process::Child) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let (mut so, mut se) = (Vec::new(), Vec::new());
    let err_pipe = child.stderr.take();
    let t = std::thread::spawn(move || {
        if let Some(mut p) = err_pipe {
            let _ = (&mut p).take(MAX_OUT).read_to_end(&mut se);
        }
        se
    });
    if let Some(mut p) = child.stdout.take() {
        let _ = (&mut p).take(MAX_OUT).read_to_end(&mut so);
    }
    let code = child.wait().ok().and_then(|s| s.code());
    (code, so, t.join().unwrap_or_default())
}

/// Every value of one project, for the output scan (a command may have read one it was not given).
pub fn known_values(
    store: &EncryptedSecrets,
    project: &str,
) -> Result<Vec<Zeroizing<String>>, SecretError> {
    let mut known = Vec::new();
    for name in store.names(&format!("workload.{project}."))? {
        if let Some(v) = store.get(&name)? {
            known.push(Zeroizing::new(v));
        }
    }
    Ok(known)
}

/// One audit line (names and counts only, never a value) beside the store.
pub fn audit(store_path: &std::path::Path, line: &str) {
    use std::io::Write;
    let path = store_path.with_file_name("workload-audit.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{} {line}", crate::tokenmac::now_ms());
    }
}

/// Run a command with its `{{secret:NAME}}` references and named environment variables filled from the store, then scan
/// everything it printed. Only the allow-listed names resolve; a production key never does.
pub fn run(store: &EncryptedSecrets, spec: &RunSpec<'_>) -> Result<RunResult, SecretError> {
    if spec.argv.is_empty() {
        return Err(SecretError("there is no command to run".into()));
    }
    let mut resolved: Vec<String> = Vec::new();
    let mut argv: Vec<Zeroizing<String>> = Vec::new();
    for a in spec.argv {
        let v = store.resolve_refs(spec.project, spec.env, a, spec.allow, false)?;
        let mut rest = a.as_str();
        while let Some(i) = rest.find("{{secret:") {
            let after = &rest[i + 9..];
            if let Some(j) = after.find("}}") {
                resolved.push(after[..j].to_string());
                rest = &after[j + 2..];
            } else {
                break;
            }
        }
        argv.push(v);
    }
    let mut envs: Vec<(String, Zeroizing<String>)> = Vec::new();
    for n in spec.env_names {
        // exactly what was stored: this goes into the environment with no text in between
        let v = store.resolve_exact(spec.project, spec.env, n, spec.allow, false)?;
        resolved.push(n.clone());
        envs.push((n.clone(), v));
    }
    let mut c = Command::new(&argv[0] as &str);
    c.args(argv[1..].iter().map(|s| s.as_str()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in &envs {
        c.env(k, v.as_str());
    }
    let child = c
        .spawn()
        .map_err(|_| SecretError("the command could not be started".into()))?;
    let (code, so, se) = collect(child);
    // every value of this project, not only the ones delivered: a command may have read another
    let known = known_values(store, spec.project)?;
    let (stdout, a) = redact(&String::from_utf8_lossy(&so), &known);
    let (stderr, b) = redact(&String::from_utf8_lossy(&se), &known);
    resolved.sort();
    resolved.dedup();
    Ok(RunResult {
        code,
        stdout,
        stderr,
        redactions: a + b,
        resolved,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::SecretStore;
    use crate::secrets_enc::{KeyProvider, LocalKekProvider};
    use std::sync::Arc;

    const SENTINEL: &str = "SENTINEL-workload-0123456789abcdef";
    /// A live-mode looking value, assembled here so no source line looks like a real key to a scanner.
    fn live_value() -> String {
        format!("sk_{}_abcdef123456", "live")
    }

    fn store(dir: &std::path::Path) -> EncryptedSecrets {
        let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        EncryptedSecrets::new(dir.join("s.json"), "box-a", p).unwrap()
    }

    /// G5 second review, N-M4: a value stored as production anywhere is production wherever else it is stored.
    #[test]
    fn a_production_value_is_production_under_any_name_and_is_never_resolved() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let prod = format!("PRODSVC{}", "x".repeat(24));
        // the owner's production file, imported (with its keys named) under the production environment
        let lines = parse_env(&format!("SERVICE_ROLE_KEY={prod}\n"));
        apply(
            &s,
            "shop",
            "production",
            &lines,
            &["SERVICE_ROLE_KEY".to_string()],
            "me",
        )
        .unwrap();
        // the same file imported again under staging: nothing in the name or the value says production, but it is a value held as one
        let a = apply(&s, "shop", "staging", &lines, &[], "me").unwrap();
        assert_eq!(a.held_back, ["SERVICE_ROLE_KEY"], "held back, not stored");
        assert!(s
            .get("workload.shop.staging.SERVICE_ROLE_KEY")
            .unwrap()
            .is_none());
        // and one that got in some other way is refused when it is resolved
        s.set_with_meta(
            "workload.shop.staging.SERVICE_ROLE_KEY",
            &prod,
            Meta {
                owner: "me".into(),
                production: false,
                ..Default::default()
            },
        )
        .unwrap();
        let e = s
            .resolve_exact(
                "shop",
                "staging",
                "SERVICE_ROLE_KEY",
                &["SERVICE_ROLE_KEY".to_string()],
                false,
            )
            .unwrap_err()
            .0;
        assert!(e.contains("production") && !e.contains(&prod), "{e}");
        // a value stored under an environment merely NAMED production counts, flagged or not
        s.set_with_meta(
            "workload.shop.live.OTHER",
            "plain-live-value-0001",
            Meta {
                owner: "me".into(),
                production: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(s.is_production_value("plain-live-value-0001").unwrap());
        // the environment's letter case does not matter, and a value that is not held as production is not one
        s.set_with_meta(
            "workload.shop.Production.OTHER2",
            "mixed-case-value-0002",
            Meta {
                owner: "me".into(),
                production: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(s.is_production_value("mixed-case-value-0002").unwrap());
        assert!(!s.is_production_value("staging-value-never-stored").unwrap());
    }

    fn value_of(text: &str) -> String {
        parse_env(text)[0].value.to_string()
    }

    #[test]
    fn values_are_read_the_way_dotenv_reads_them() {
        for (text, want) in [
            ("K=plain", "plain"),
            ("K=\"quoted\"", "quoted"),
            ("K='single'", "single"),
            ("export K=\"exported\"", "exported"),
            ("export\tK=tabbed", "tabbed"),
            ("K=value # a trailing comment", "value"),
            ("K=\"value\" # a trailing comment", "value"),
            ("K='value'   # c", "value"),
            ("K=a#b", "a#b"),
            ("K=#leading", "#leading"),
            ("K= # only a comment", ""),
            ("K=\"has # inside\"", "has # inside"),
            ("K=\"say \\\"hi\\\"\"", "say \"hi\""),
            ("K=\"a\\\\b\"", "a\\b"),
            ("K=\"a\\nb\"", "a\nb"),
            ("K='a\\nb'", "a\\nb"),
            ("K=\"\"", ""),
            ("K=", ""),
            ("K=\"unclosed", "\"unclosed"),
            ("K=  spaced  ", "spaced"),
        ] {
            assert_eq!(value_of(text), want, "{text}");
        }
        // `exporter=1` is a key called exporter, not an export prefix
        assert_eq!(parse_env("exporter=1")[0].name, "exporter");
    }

    #[test]
    fn a_quoted_value_may_span_lines_and_its_inner_lines_are_never_rows() {
        let pem = format!("{}{}", "-----BEGIN PRIV", "ATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC==\nPEMBODYLINE0123456789abcdef=\n-----END PRIVATE KEY-----");
        let text = format!(
            "A_FIRST=one-0123456789\nPEM=\"{pem}\"\nJSON='{{\n  \"private_key\": \"PEMFRAGMENT-abc123=\",\n  \"email\": \"a@b\"\n}}'\nAFTER=after-0123456789\n"
        );
        let lines = parse_env(&text);
        let names: Vec<_> = lines.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["A_FIRST", "PEM", "JSON", "AFTER"]);
        assert_eq!(lines[1].value.as_str(), pem);
        assert!(
            lines[2].value.contains("PEMFRAGMENT-abc123=") && lines[2].value.starts_with("{\n")
        );
        assert!(lines.iter().all(|l| l.malformed.is_none()));
        assert_eq!(lines[3].line, 10, "the line an entry starts on");
        // a "name" taken from a key's inner line never shows: only where it was found
        let rows = plan(
            &parse_env("-----BEGIN KEY-----\nPEMBODYLINE0123456789abcdef=\nOTHER=ok-0123456789\n"),
            "app",
            "staging",
        );
        assert_eq!(rows[0].status, Status::Invalid);
        assert_eq!(rows[0].label(), "line 2");
        assert!(!rows[0].label().contains("PEMBODY"));
    }

    #[test]
    fn a_quote_that_never_closes_takes_the_rest_of_the_file_and_is_refused_by_name() {
        let lines =
            parse_env("OPEN=\"never closed\nINNER_PART=SENTINEL-INNER-0123456789\nTHIRD=3\n");
        assert_eq!(
            lines.len(),
            1,
            "the following lines are part of it, not rows"
        );
        assert_eq!(lines[0].malformed, Some(Malformed::Unclosed));
        let rows = plan(&lines, "app", "staging");
        assert!(matches!(&rows[0].status, Status::Unstorable(w) if w.contains("never closed")));
        assert!(!format!("{rows:?}").contains("SENTINEL-INNER"));
        // text after the closing quote of a multi-line value is refused too
        let l = parse_env("T='a\nb' trailing\n");
        assert_eq!(l[0].malformed, Some(Malformed::TextAfterQuote));
    }

    #[test]
    fn blank_keys_are_skipped_by_name_and_values_with_spaces_and_json_are_stored_encoded() {
        let text = format!(
            "A_BLANK=\nB_EMPTY=\"\"\nC_SPACES=\"one two\"\nD_JSON={{\"k\":1}}\nE_GOOD={SENTINEL}\nF_GOOD=\"quoted-0123456789\"\n"
        );
        let lines = parse_env(&text);
        let rows = plan(&lines, "app", "staging");
        assert_eq!(rows[0].status, Status::Blank);
        assert_eq!(rows[1].status, Status::Blank);
        assert_eq!((&rows[2].status, rows[2].encoded), (&Status::Ready, true));
        assert_eq!((&rows[3].status, rows[3].encoded), (&Status::Ready, true));
        assert_eq!((&rows[4].status, rows[4].encoded), (&Status::Ready, false));
        // checked before anything is stored: the preview carries no value
        assert!(!format!("{rows:?}").contains("one two"));
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let done = apply(&s, "app", "staging", &lines, &[], "me").unwrap();
        assert_eq!(done.stored, ["C_SPACES", "D_JSON", "E_GOOD", "F_GOOD"]);
        assert_eq!(done.blank, ["A_BLANK", "B_EMPTY"]);
        assert!(done.unstorable.is_empty());
        assert_eq!(
            s.get("workload.app.staging.C_SPACES").unwrap().as_deref(),
            Some("one two")
        );
        assert_eq!(
            s.get("workload.app.staging.D_JSON").unwrap().as_deref(),
            Some("{\"k\":1}")
        );
        assert_eq!(
            s.get("workload.app.staging.F_GOOD").unwrap().as_deref(),
            Some("quoted-0123456789")
        );
        assert!(s.get("workload.app.staging.A_BLANK").unwrap().is_none());
    }

    #[test]
    fn the_preview_shows_names_and_fingerprints_and_holds_production_looking_keys_back() {
        let live = live_value();
        let text = format!(
            "# comment\nexport SUPABASE_URL=\"https://x.example.com\"\nAPI_KEY={SENTINEL}\nSTRIPE_KEY={live}\nPROD_DB=postgres://a\nbad-name=1\n"
        );
        let lines = parse_env(&text);
        let rows = plan(&lines, "app", "staging");
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].status, Status::Ready);
        assert!(
            matches!(rows[2].status, Status::Live(_)),
            "a live-mode value"
        );
        assert!(
            matches!(rows[3].status, Status::Live(_)),
            "a name that says production"
        );
        assert_eq!(rows[4].status, Status::Invalid);
        // the preview is names and fingerprints: no value anywhere in it
        let shown = format!("{rows:?}");
        assert!(!shown.contains(SENTINEL) && !shown.contains(&live_value()));
        assert_eq!(rows[1].fingerprint.len(), 8);
        // nothing production-looking is stored unless it is named, and then it is flagged
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let done = apply(&s, "app", "staging", &lines, &[], "me").unwrap();
        assert_eq!(done.stored, ["SUPABASE_URL", "API_KEY"]);
        assert_eq!(done.held_back, ["STRIPE_KEY", "PROD_DB"]);
        assert_eq!(done.invalid, ["bad-name"]);
        let done = apply(
            &s,
            "app",
            "staging",
            &lines,
            &["STRIPE_KEY".to_string()],
            "me",
        )
        .unwrap();
        assert!(done.stored.contains(&"STRIPE_KEY".to_string()) && done.held_back == ["PROD_DB"]);
        let m = s.meta("workload.app.staging.STRIPE_KEY").unwrap().unwrap();
        assert!(m.production);
        // a production environment holds every key back
        let all = apply(
            &s,
            "app",
            "production",
            &parse_env("A_KEY=abcdefgh\n"),
            &[],
            "me",
        )
        .unwrap();
        assert!(all.stored.is_empty() && all.held_back == ["A_KEY"]);
    }

    #[test]
    fn a_command_gets_only_its_allow_listed_names_and_never_a_production_key() {
        let live = live_value();
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        apply(
            &s,
            "app",
            "staging",
            &parse_env(&format!(
                "API_KEY={SENTINEL}\nOTHER_KEY=other-value-123456\nSTRIPE_KEY={live}\n"
            )),
            &["STRIPE_KEY".to_string()],
            "me",
        )
        .unwrap();
        let sh = |script: &str, allow: &[&str], envs: &[&str]| {
            let allow: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
            let envs: Vec<String> = envs.iter().map(|s| s.to_string()).collect();
            let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
            run(
                &s,
                &RunSpec {
                    project: "app",
                    env: "staging",
                    allow: &allow,
                    env_names: &envs,
                    argv: &argv,
                },
            )
        };
        // an allow-listed name arrives in the environment, and what the command prints has the value removed
        let r = sh("echo \"key=$API_KEY\"", &["API_KEY"], &["API_KEY"]).unwrap();
        assert_eq!(r.code, Some(0));
        assert!(r.stdout.contains("key=[redacted]") && !r.stdout.contains(SENTINEL));
        assert_eq!(r.resolved, ["API_KEY"]);
        // a name that is not on the list is refused, and so is a production key even if it is on the list
        assert!(sh("true", &["API_KEY"], &["OTHER_KEY"]).is_err());
        let e = sh("true", &["STRIPE_KEY"], &["STRIPE_KEY"]).err().unwrap();
        assert!(e.0.contains("production") && !e.0.contains("sk_live"));
        // another name the command did not ask for is not in its environment
        let r = sh(
            "echo \"other=${OTHER_KEY:-unset}\"",
            &["API_KEY"],
            &["API_KEY"],
        )
        .unwrap();
        assert!(r.stdout.contains("other=unset"));
    }

    #[test]
    fn a_value_is_removed_from_output_in_every_common_encoding_and_from_stderr_too() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        apply(
            &s,
            "app",
            "staging",
            &parse_env(&format!(
                "API_KEY={SENTINEL}\nOTHER_KEY=other-value-123456\n"
            )),
            &[],
            "me",
        )
        .unwrap();
        let std64 = encode_std(SENTINEL.as_bytes());
        let url64 = encode_url(SENTINEL.as_bytes());
        let script = format!(
            "echo exact:{SENTINEL}; echo b64:{std64}; echo b64u:{url64}; echo pct:{}; echo err:{SENTINEL} >&2; echo other:other-value-123456",
            pct("SENTINEL-workload-0123456789abcdef/x?y")
        );
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        // OTHER_KEY is never delivered, yet it is scrubbed: the command may have read it some other way
        let r = run(
            &s,
            &RunSpec {
                project: "app",
                env: "staging",
                allow: &[],
                env_names: &[],
                argv: &argv,
            },
        )
        .unwrap();
        let all = format!("{}{}", r.stdout, r.stderr);
        assert!(!all.contains(SENTINEL) && !all.contains(&std64) && !all.contains(&url64));
        assert!(!all.contains("other-value-123456"));
        assert!(!all.contains("SENTINEL-workload"), "{all}");
        assert!(r.redactions >= 5, "{}", r.redactions);
        // short values are not scanned for (they would blank ordinary words)
        assert_eq!(redact("yes and no", &[Zeroizing::new("yes".into())]).1, 0);
    }

    /// Every hostile value, through plan, apply and a real `run` on this computer: the program gets exactly what the file
    /// said, nothing it contains runs, its PATH is untouched, and what it prints is scrubbed.
    #[cfg(unix)]
    #[test]
    fn any_value_reaches_the_program_exactly_and_nothing_runs_or_leaks() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let marker = d.path().join("MARKER-RAN");
        let vals: Vec<String> = crate::secrets_enc::hostile::values()
            .into_iter()
            .map(|v| v.replace("MARKER", &marker.display().to_string()))
            .collect();
        let lines: Vec<EnvLine> = vals
            .iter()
            .enumerate()
            .map(|(i, v)| EnvLine {
                name: format!("H{i}"),
                value: Zeroizing::new(v.clone()),
                line: i + 1,
                malformed: None,
            })
            .collect();
        let rows = plan(&lines, "app", "staging");
        for (r, v) in rows.iter().zip(&vals) {
            assert_eq!(r.status, Status::Ready, "{}", r.name);
            assert_eq!(r.encoded, crate::secrets::check_value(v).is_err());
        }
        let done = apply(&s, "app", "staging", &lines, &[], "me").unwrap();
        assert_eq!(done.stored.len(), vals.len());
        for (i, v) in vals.iter().enumerate() {
            let out = d.path().join(format!("out{i}"));
            let path_out = d.path().join(format!("path{i}"));
            let name = format!("H{i}");
            let script = format!(
                "printf %s \"$H{i}\" > '{}'; printf %s \"$PATH\" > '{}'; printf %s \"$H{i}\"",
                out.display(),
                path_out.display()
            );
            let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];
            let r = run(
                &s,
                &RunSpec {
                    project: "app",
                    env: "staging",
                    allow: std::slice::from_ref(&name),
                    env_names: std::slice::from_ref(&name),
                    argv: &argv,
                },
            )
            .unwrap();
            assert_eq!(r.code, Some(0), "{i}");
            assert_eq!(
                std::fs::read(&out).unwrap(),
                v.as_bytes(),
                "the exact bytes, {i}"
            );
            assert_eq!(
                std::fs::read_to_string(&path_out).unwrap(),
                std::env::var("PATH").unwrap(),
                "PATH is untouched, {i}"
            );
            // what it printed has the value removed, in whole or by line
            assert!(r.redactions >= 1 && !r.stdout.contains(v.as_str()), "{i}");
            for line in v.lines().map(str::trim).filter(|l| l.len() >= 6) {
                assert!(!r.stdout.contains(line), "a line of {i} was printed");
            }
        }
        assert!(!marker.exists(), "nothing inside a value was run");
        // a reference in a command line is refused for a value that is not plain, and says to use the environment
        let argv = vec!["/bin/echo".to_string(), "{{secret:H0}}".to_string()];
        let e = run(
            &s,
            &RunSpec {
                project: "app",
                env: "staging",
                allow: &["H0".to_string()],
                env_names: &[],
                argv: &argv,
            },
        )
        .unwrap_err();
        assert!(e.0.contains("environment") && !e.0.contains("evil"));
    }

    #[test]
    fn a_multi_line_value_in_a_file_is_stored_encoded_and_the_preview_says_so_without_showing_it() {
        let text = "PEM=\"-----BEGIN KEY-----\nPEMLINE-0123456789abcdef=\n-----END KEY-----\"\nSPACED=\"two words here\"\nPLAIN=plain-0123456789\n";
        let lines = parse_env(text);
        let rows = plan(&lines, "app", "staging");
        assert!(rows[0].encoded && rows[1].encoded && !rows[2].encoded);
        assert!(rows.iter().all(|r| r.status == Status::Ready));
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let done = apply(&s, "app", "staging", &lines, &[], "me").unwrap();
        assert_eq!(done.stored, ["PEM", "SPACED", "PLAIN"]);
        // what cannot be stored at all is refused by name, with the reason
        let nul = [EnvLine {
            name: "N".into(),
            value: Zeroizing::new("a\0b".into()),
            line: 1,
            malformed: None,
        }];
        assert!(
            matches!(&plan(&nul, "app", "staging")[0].status, Status::Unstorable(w) if w.contains("NUL"))
        );
        assert_eq!(
            s.get("workload.app.staging.PEM").unwrap().as_deref(),
            Some("-----BEGIN KEY-----\nPEMLINE-0123456789abcdef=\n-----END KEY-----")
        );
        // the fingerprint is of the exact value, so a laptop and a box agree
        assert_eq!(rows[1].fingerprint, fingerprint("two words here"));
    }

    #[test]
    fn a_reference_in_an_argument_resolves_only_for_the_allow_list() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        apply(
            &s,
            "app",
            "staging",
            &parse_env(&format!("API_KEY={SENTINEL}\n")),
            &[],
            "me",
        )
        .unwrap();
        let argv = vec!["/bin/echo".to_string(), "{{secret:API_KEY}}".to_string()];
        let ok = run(
            &s,
            &RunSpec {
                project: "app",
                env: "staging",
                allow: &["API_KEY".into()],
                env_names: &[],
                argv: &argv,
            },
        )
        .unwrap();
        assert_eq!(ok.stdout.trim(), "[redacted]");
        assert_eq!(ok.resolved, ["API_KEY"]);
        let denied = run(
            &s,
            &RunSpec {
                project: "app",
                env: "staging",
                allow: &[],
                env_names: &[],
                argv: &argv,
            },
        );
        assert!(denied.err().unwrap().0.contains("not allowed"));
        // the store holds it, and no file beside it carries the value
        assert!(s.get("workload.app.staging.API_KEY").unwrap().is_some());
        for e in std::fs::read_dir(d.path()).unwrap().flatten() {
            assert!(!std::fs::read_to_string(e.path())
                .unwrap_or_default()
                .contains(SENTINEL));
        }
    }

    /// A JWT-shaped value assembled at run time (no literal that looks like a key): header.payload.signature.
    fn jwt(payload: &str) -> String {
        let b = |t: &str| {
            crate::serve::auth::b64::encode_url(t.as_bytes())
                .trim_end_matches('=')
                .to_string()
        };
        format!(
            "{}.{}.{}",
            b("{\"alg\":\"HS256\"}"),
            b(payload),
            b("signature-bytes-0123456789")
        )
    }

    /// ADR 0029 Amendment 12: a person's `--public` mark is stored beside the value and is the only thing that lets a name be
    /// resolved as a public value.
    #[test]
    fn a_marked_public_value_is_resolved_as_public_and_an_unmarked_one_never_is_whatever_it_looks_like(
    ) {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let anon = jwt(r#"{"role":"anon","ref":"stagingref"}"#);
        let lines = parse_env(&format!(
            "NEXT_PUBLIC_SUPABASE_ANON_KEY={anon}\nNEXT_PUBLIC_APP_URL=https://staging.example.com\nUNMARKED={anon}x\n"
        ));
        let public = vec![
            "NEXT_PUBLIC_SUPABASE_ANON_KEY".to_string(),
            "NEXT_PUBLIC_APP_URL".to_string(),
        ];
        let a = apply_marked(&s, "app", "staging", &lines, &[], &public, "me").unwrap();
        assert_eq!(a.stored.len(), 3, "{a:?}");
        let declared = vec![
            "NEXT_PUBLIC_SUPABASE_ANON_KEY".to_string(),
            "UNMARKED".to_string(),
        ];
        assert_eq!(
            s.resolve_public("app", "staging", "NEXT_PUBLIC_SUPABASE_ANON_KEY", &declared)
                .unwrap()
                .as_str(),
            anon
        );
        // a secret-shaped value that nobody marked is refused here, and says how to fix it
        let e = s
            .resolve_public("app", "staging", "UNMARKED", &declared)
            .unwrap_err()
            .0;
        assert!(e.contains("not marked public"), "{e}");
        // a name the command did not declare is not handed over even when marked
        let e = s
            .resolve_public("app", "staging", "NEXT_PUBLIC_APP_URL", &declared)
            .unwrap_err()
            .0;
        assert!(e.contains("not declared"), "{e}");
        // a re-import without the mark clears it
        apply(&s, "app", "staging", &lines, &[], "me").unwrap();
        assert!(s
            .resolve_public("app", "staging", "NEXT_PUBLIC_SUPABASE_ANON_KEY", &declared)
            .is_err());
        // and a marked entry that is flagged production is not public either
        s.set_with_meta(
            "workload.app.staging.NEXT_PUBLIC_APP_URL",
            "https://x.example.com",
            Meta {
                owner: "me".into(),
                production: true,
                public: true,
            },
        )
        .unwrap();
        assert!(s
            .resolve_public(
                "app",
                "staging",
                "NEXT_PUBLIC_APP_URL",
                &["NEXT_PUBLIC_APP_URL".to_string()]
            )
            .is_err());
    }

    /// ADR 0029 Amendment 12 (owner, 2026-11-13): a value can be marked public only if it is a KNOWN public kind. Fixtures are built
    /// at run time so no literal in this file is shaped like a key.
    #[test]
    fn only_a_known_public_kind_can_be_marked_public_and_every_other_secret_kind_is_refused() {
        use crate::workload_policy::public_mark_refusal as refuse;
        let b = |t: &str| {
            crate::serve::auth::b64::encode_url(t.as_bytes())
                .trim_end_matches('=')
                .to_string()
        };
        let tok = |head: &str, payload: &str| {
            format!(
                "{}.{}.{}",
                b(head),
                b(payload),
                b("signature-bytes-0123456789")
            )
        };
        let hs = r#"{"alg":"HS256","typ":"JWT"}"#;
        // allowed: an anonymous key (parsed, role == anon), a known public prefix, plain words, urls, ids
        for (n, v) in [
            (
                "NEXT_PUBLIC_SUPABASE_ANON_KEY",
                tok(hs, r#"{"role":"anon","ref":"abc"}"#),
            ),
            ("ANON", tok(r#"{ "alg": "HS256"}"#, r#"{"role": "anon"}"#)),
            (
                "NEXT_PUBLIC_STRIPE_KEY",
                concat!("pk_", "test_", "abcdefghijklmnopqrstuvwxyz0123456789").to_string(),
            ),
            (
                "NEXT_PUBLIC_LIVE_KEY",
                concat!("pk_", "live_", "abcdefghijklmnopqrstuvwxyz0123456789").to_string(),
            ),
            (
                "SB_KEY",
                concat!(
                    "sb_",
                    "publishable_",
                    "abcdefghijklmnopqrstuvwxyz0123456789"
                )
                .to_string(),
            ),
            (
                "POSTHOG",
                concat!("ph", "c_", "abcdefghijklmnopqrstuvwxyz0123456789").to_string(),
            ),
            (
                "NEXT_PUBLIC_APP_URL",
                "https://staging.example.com/path?x=1".replace('?', ""),
            ),
            ("HOST", "api.example.com".to_string()),
            ("PROJECT_REF", "abcdefghij".to_string()),
            ("REGION", "us-east-1".to_string()),
            ("UUID", "123e4567-e89b-12d3-a456-426614174000".to_string()),
        ] {
            assert_eq!(refuse(n, &v, false), None, "{n} should be allowed");
        }
        // refused: provider keys, other always-secret prefixes, a user-session JWT, odd headers, an escaped service role
        let long = "abcdefghijklmnopqrstuvwxyz0123456789";
        let mut bad: Vec<(&str, String)> = vec![
            ("A", format!("{}{}", concat!("sk", "-ant-"), "api03-abcdef")),
            (
                "B",
                format!("{}{}", concat!("sk", "-proj-"), "abcdef123456"),
            ),
            ("C", format!("{}{}", concat!("sb", "_secret_"), long)),
            ("D", format!("{}{}", concat!("sb", "p_"), long)),
            ("E", format!("{}{}", concat!("gl", "pat-"), "abcdef123456")),
            ("F", format!("{}{}", concat!("np", "m_"), long)),
            ("G", format!("{}{}", concat!("S", "G."), "abcdef.ghijkl")),
            ("H", format!("{}{}", concat!("r", "e_"), "abcdef123456")),
            (
                "I",
                format!("{}{}", concat!("AS", "IA"), "ABCDEFGHIJKLMNOP"),
            ),
            ("J", format!("{}{}", concat!("h", "f_"), "abcdef123456")),
            ("K", format!("{}{}", concat!("xa", "i-"), "abcdef123456")),
            ("L", tok(hs, r#"{"role":"authenticated","sub":"u"}"#)),
            ("M", tok(hs, r#"{"role":"service_role"}"#)),
            ("N", tok(hs, r#"{"role":"service\u005frole"}"#)),
            ("O", tok(hs, r#"{"role":"ANON"}"#)),
            ("P", tok(hs, r#"{"sub":"no role at all"}"#)),
            ("Q", tok(hs, r#"["anon"]"#)),
            (
                "R",
                tok(r#"{ "alg": "none"}"#, r#"{"role":"authenticated"}"#),
            ),
            ("S", format!("{}.{}.{}", b(hs), "!!!notbase64!!!", "x")),
            ("T", format!("{}.{}.{}", b(hs), b("not json at all"), "x")),
            // a bearer token with no recognisable shape at all but long and generated
            (
                "U",
                format!("{}{}", "Q1w2E3r4T5y6U7i8O9p0", "AaBbCcDdEeFfGgHhIiJj"),
            ),
        ];
        // an escaped JWT whose payload mentions the role only in an escape, with a header that does not start with eyJ
        bad.push((
            "V",
            tok(r#"  {"alg":"HS256"}"#, r#"{"role":"\u0073ervice_role"}"#),
        ));
        for (n, v) in &bad {
            assert!(refuse(n, v, false).is_some(), "{n} must be refused: {v}");
        }
        // a name that says it is secret and a production-looking value are refused whatever the value
        assert!(refuse("API_TOKEN", "plain", false).is_some());
        assert!(refuse("SERVICE_ROLE_KEY", "plain", false).is_some());
        assert!(refuse("PLAIN", "plain", true).is_some());
        // end to end: none of them is stored, and a reason never holds a value
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let body: String = bad.iter().map(|(n, v)| format!("{n}={v}\n")).collect();
        let lines = parse_env(&body);
        let public: Vec<String> = bad.iter().map(|(n, _)| n.to_string()).collect();
        let a = apply_marked(&s, "app", "staging", &lines, &[], &public, "me").unwrap();
        assert!(a.stored.is_empty(), "{:?}", a.stored);
        for (_, why) in &a.unstorable {
            assert!(bad.iter().all(|(_, v)| !why.contains(v.as_str())));
        }
    }

    /// The mark is checked again when the value is handed out, so a rule added later also covers what was stored earlier, and a
    /// stored value that no longer passes is refused rather than delivered as plain environment.
    #[test]
    fn a_marked_value_that_would_be_refused_today_is_not_handed_out() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        // stored directly with the mark, as an earlier version (or a hand-made file) could have
        let user_jwt = jwt(r#"{"role":"authenticated"}"#);
        let anthropic = format!("{}{}", concat!("sk", "-ant-"), "api03-abcdef");
        for (n, v) in [
            ("USER_JWT", user_jwt.as_str()),
            ("PROVIDER", anthropic.as_str()),
        ] {
            s.set_with_meta(
                &format!("workload.app.staging.{n}"),
                v,
                Meta {
                    owner: "me".into(),
                    production: false,
                    public: true,
                },
            )
            .unwrap();
            let e = s
                .resolve_public("app", "staging", n, &[n.to_string()])
                .unwrap_err()
                .0;
            assert!(e.contains("marked public but is not given"), "{e}");
            assert!(!e.contains(v), "an error never holds the value");
        }
        let anon = jwt(r#"{"role":"anon"}"#);
        s.set_with_meta(
            "workload.app.staging.ANON",
            &anon,
            Meta {
                owner: "me".into(),
                production: false,
                public: true,
            },
        )
        .unwrap();
        assert_eq!(
            s.resolve_public("app", "staging", "ANON", &["ANON".to_string()])
                .unwrap()
                .as_str(),
            anon
        );
    }

    /// A mark is a person's word, so it is checked against everything that is only ever secret.
    #[test]
    fn a_mark_is_refused_on_what_is_only_ever_secret_and_the_value_is_not_stored() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let service = jwt(r#"{"role":"service_role","ref":"stagingref"}"#);
        let github = format!("{}{}", "ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
        let body = format!(
            "SUPABASE_SERVICE_ROLE_KEY={service}\nAPI_TOKEN=plain-token-value\nANON_PLAIN={service}\nGH={github}\nUNREADABLE=eyJnotajwtatall\nSPACED=\"two words\"\nOK_URL=https://staging.example.com\n"
        );
        let lines = parse_env(&body);
        let public: Vec<String> = [
            "SUPABASE_SERVICE_ROLE_KEY",
            "API_TOKEN",
            "ANON_PLAIN",
            "GH",
            "UNREADABLE",
            "SPACED",
            "OK_URL",
        ]
        .map(String::from)
        .to_vec();
        let a = apply_marked(&s, "app", "staging", &lines, &[], &public, "me").unwrap();
        let refused: Vec<&str> = a.unstorable.iter().map(|(n, _)| n.as_str()).collect();
        for n in [
            "SUPABASE_SERVICE_ROLE_KEY",
            "API_TOKEN",
            "ANON_PLAIN",
            "GH",
            "UNREADABLE",
            "SPACED",
        ] {
            assert!(refused.contains(&n), "{n} must be refused: {refused:?}");
            assert!(
                s.get(&format!("workload.app.staging.{n}"))
                    .unwrap()
                    .is_none(),
                "{n} is not stored at all"
            );
        }
        assert_eq!(a.stored, ["OK_URL"]);
        for (_, why) in &a.unstorable {
            assert!(
                !why.contains(&service) && !why.contains(&github),
                "a reason never holds a value"
            );
        }
        // a production-looking value cannot be marked either, even when the person allows it as production
        let prod = parse_env(&format!("PUBLIC_THING={}\n", live_value()));
        let a = apply_marked(
            &s,
            "app",
            "staging",
            &prod,
            &["PUBLIC_THING".into()],
            &["PUBLIC_THING".into()],
            "me",
        )
        .unwrap();
        assert_eq!(a.unstorable.len(), 1, "{a:?}");
        // a mark on a name the file does not hold is reported, never ignored
        let a = apply_marked(
            &s,
            "app",
            "staging",
            &parse_env("A_B=1\n"),
            &[],
            &["NOT_THERE".into()],
            "me",
        )
        .unwrap();
        assert!(a.unstorable.iter().any(|(n, _)| n == "NOT_THERE"));
    }

    #[test]
    fn every_entry_of_a_file_is_kept_a_duplicate_or_rejected_and_the_last_duplicate_wins() {
        let text = "A=1\n# comment\nB=2\n\nA=3\nNOT A LINE\nA=4\nexport C=\"x\"\n=novalue\n";
        let p = parse_env_report(text);
        let names: Vec<_> = p.lines.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["B", "A", "C", ""], "the last A is kept");
        let a = p.lines.iter().find(|l| l.name == "A").unwrap();
        assert_eq!((a.value.as_str(), a.line), ("4", 7));
        assert_eq!(
            p.duplicates,
            [Duplicate {
                name: "A".into(),
                kept_line: 7,
                ignored_lines: vec![1, 5]
            }]
        );
        assert_eq!(
            p.rejected,
            [Rejected {
                line: 6,
                reason: "not NAME=value (there is no `=` on the line)"
            }]
        );
        // 4 kept + 2 ignored duplicates + 1 rejected
        assert_eq!(p.entries(), 7);
        // `parse_env` is the same rows without the accounting
        assert_eq!(parse_env(text).len(), 4);
        // blanks and comments are not entries
        assert_eq!(parse_env_report("\n# only a comment\n   \n").entries(), 0);
    }

    #[test]
    fn an_invalid_name_says_why_without_repeating_it() {
        for (name, why) in [
            ("", "is empty"),
            ("MY KEY", "contains a space"),
            ("1KEY", "starts with a digit"),
            ("my_key", "lower-case"),
            ("MY-KEY", "character other than"),
        ] {
            let r = invalid_name_reason(name);
            assert!(r.contains(why), "{name:?}: {r}");
            assert!(name.is_empty() || !r.contains(name));
        }
    }

    #[test]
    fn dotenv_values_end_to_end_a_quoted_blank_is_blank_and_a_comment_is_not_a_value() {
        let lines = parse_env(
            "export A_KEY='single # kept'\nB_KEY=\"dq \\\"q\\\" \\\\ end\" # c\nC_KEY=plain # c\nD_KEY=\"\"\nE_KEY=   \nF_KEY=''\n",
        );
        let v: Vec<_> = lines
            .iter()
            .map(|l| (l.name.as_str(), l.value.as_str()))
            .collect();
        assert_eq!(
            v,
            [
                ("A_KEY", "single # kept"),
                ("B_KEY", "dq \"q\" \\ end"),
                ("C_KEY", "plain"),
                ("D_KEY", ""),
                ("E_KEY", ""),
                ("F_KEY", ""),
            ]
        );
        let rows = plan(&lines, "app", "staging");
        let blank = rows.iter().filter(|r| r.status == Status::Blank).count();
        assert_eq!(blank, 3);
    }

    /// A fixture of the shapes real `.env` files take (B4-18 item 9): what each name's value is, and which are blank.
    #[test]
    fn dotenv_fixture_bom_crlf_spaces_export_and_comments() {
        let text = "\u{FEFF}FIRST=one\r\n# a comment\r\n\r\nexport   SECOND = \"two\"  # c\r\nTHIRD='three' \r\nFOURTH=four#not-a-comment\r\nFIFTH=\t# only a comment\r\nSIXTH=\"\"\r\n";
        let lines = parse_env(text);
        let v: Vec<_> = lines
            .iter()
            .map(|l| (l.name.as_str(), l.value.as_str()))
            .collect();
        assert_eq!(
            v,
            [
                ("FIRST", "one"),
                ("SECOND", "two"),
                ("THIRD", "three"),
                ("FOURTH", "four#not-a-comment"),
                ("FIFTH", ""),
                ("SIXTH", ""),
            ]
        );
        let rows = plan(&lines, "app", "staging");
        let blank: Vec<_> = rows
            .iter()
            .filter(|r| r.status == Status::Blank)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(blank, ["FIFTH", "SIXTH"]);
        assert!(
            rows.iter().all(|r| r.status != Status::Invalid),
            "the BOM is not part of a name"
        );
    }

    #[test]
    fn an_unchanged_name_is_one_already_stored_with_the_same_value_flag_and_mark() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let lines = parse_env("A_KEY=one-0123456789\nB_KEY=two-0123456789\n");
        let none = |_: &str| false;
        let rows = plan(&lines, "app", "staging");
        assert!(
            unchanged_names(&s, "app", "staging", &lines, &rows, &none, &[])
                .unwrap()
                .is_empty()
        );
        apply(&s, "app", "staging", &lines, &[], "me").unwrap();
        assert_eq!(
            unchanged_names(&s, "app", "staging", &lines, &rows, &none, &[]).unwrap(),
            ["A_KEY", "B_KEY"]
        );
        // a changed value is not unchanged; a different public mark is not either
        let again = parse_env("A_KEY=changed-0123456789\nB_KEY=two-0123456789\n");
        let rows = plan(&again, "app", "staging");
        assert_eq!(
            unchanged_names(&s, "app", "staging", &again, &rows, &none, &[]).unwrap(),
            ["B_KEY"]
        );
        assert!(unchanged_names(
            &s,
            "app",
            "staging",
            &again,
            &rows,
            &none,
            &["B_KEY".into()]
        )
        .unwrap()
        .is_empty());
    }
}
