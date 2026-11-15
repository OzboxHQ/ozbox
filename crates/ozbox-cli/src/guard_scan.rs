//! How the commit barrier reads a change, in batches (ADR 0041 phase 3).
//!
//! A change is a list of [`Added`] lines, each placed by commit, file and line. The shapes are checked line by line on this
//! machine. The stored values are asked of the box's secrets service in **batches** of about [`CHUNK`] bytes, however many files
//! and commits they come from, so a push of two hundred commits is a handful of calls and not thousands. Only when a batch holds a
//! stored value is it narrowed down, by halving, to the line that holds it, so a hold names `file:line` and the cost is paid by a
//! change that is held anyway.
//!
//! Nothing here skips anything. A line too long for one call is scanned in overlapping windows, a service that says "too many
//! scans" is waited for by the caller's scanner, and what cannot be checked at all is an error, which holds the change.
//!
//! **Sizes are measured as the service receives them.** A request is one line of JSON, and JSON writes a quote, a backslash or a
//! newline as two bytes and a control byte (a NUL in a file read with `--text`) as six. So a batch is sized by its *escaped*
//! length ([`esc_len`]), never by its raw one: two lines of 600 KB each are two calls, not one that the service refuses.

use std::collections::BTreeSet;

use crate::guard::{is_env_file, shape_rules, Finding, Scanner};

/// About how much text one call to the service carries, as JSON writes it (the request line may be a little over 1 MiB, and the
/// text itself at most 1 MiB): 900 KiB of escaped text leaves room for the envelope.
pub const CHUNK: usize = 900 * 1024;
/// A line longer than a call is scanned in windows of [`CHUNK`] that overlap by this much, so a value cut by a boundary is found.
const WINDOW_OVERLAP: usize = 64 * 1024;
/// The most calls spent narrowing one batch down to its lines. Beyond it the first line of what is left is named.
const LOCATE_BUDGET: u32 = 96;
/// The most a request can carry to the person. The box socket the hook files it on reads a line of at most 64 KiB, so what is held
/// is bounded by an estimate (escaped text, plus the header lines of every held line, counted generously) well under that, and
/// `guard_hold` measures the request it builds against [`REQUEST_MAX`] as well. More is held without a request: a code, or a
/// smaller change.
pub const HELD_MAX: usize = 40 * 1024;
/// The most one request line to the box socket may be (the socket reads 64 KiB; the rest is margin for the envelope).
pub const REQUEST_MAX: usize = 56 * 1024;

/// How many bytes JSON takes to write `s` between its quotes: a quote, a backslash and the usual whitespace escapes are two, any
/// other control byte is six, everything else its own length.
pub fn esc_len(s: &str) -> usize {
    s.chars()
        .map(|c| match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        })
        .sum()
}

/// One added line, placed. `commit` is empty for a staged change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    pub commit: String,
    pub file: String,
    pub line: u32,
    pub text: String,
}

/// A stored secret found in an added line. The name is for the person who approves (the owner's card), never for the box user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub commit: String,
    pub file: String,
    pub line: u32,
    pub name: String,
}

/// The result of checking a change.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    pub findings: Vec<Finding>,
    pub stored: Vec<Stored>,
    /// The lines that were held, in the order found: what a request to override carries, so the person is shown, and the service
    /// binds, exactly these.
    pub held: Vec<Added>,
    /// More was held than a request can carry: ask for a code, or push in smaller pieces.
    pub held_overflow: bool,
}

impl Verdict {
    pub fn clean(&self) -> bool {
        self.findings.is_empty() && self.stored.is_empty()
    }
}

/// Reads added lines, a commit at a time or all at once, and says what it holds.
pub struct Checker<'a> {
    scanner: Option<&'a dyn Scanner>,
    v: Verdict,
    pending: Vec<Added>,
    pending_bytes: usize,
    held_bytes: usize,
    env_seen: BTreeSet<(String, String)>,
    held_keys: BTreeSet<(String, String, u32)>,
}

impl<'a> Checker<'a> {
    pub fn new(scanner: Option<&'a dyn Scanner>) -> Self {
        Self {
            scanner,
            v: Verdict::default(),
            pending: Vec::new(),
            pending_bytes: 0,
            held_bytes: 0,
            env_seen: BTreeSet::new(),
            held_keys: BTreeSet::new(),
        }
    }

    fn hold(&mut self, a: &Added) {
        if !self
            .held_keys
            .insert((a.commit.clone(), a.file.clone(), a.line))
        {
            return;
        }
        // what the line costs in a request: its text, and (counted for every line, though a run shares them) the two file header
        // lines and a hunk header, all escaped
        let cost = esc_len(&a.text) + 2 * esc_len(&a.file) + 64;
        if self.held_bytes + cost > HELD_MAX {
            self.v.held_overflow = true;
            return;
        }
        self.held_bytes += cost;
        self.v.held.push(a.clone());
    }

    /// Check more lines.
    pub fn add(&mut self, lines: Vec<Added>) -> Result<(), String> {
        for a in lines {
            let public_jwt = crate::guard::public_jwt_line(&a.text);
            for r in shape_rules(&a.text) {
                // a `NEXT_PUBLIC_*` variable holding an anonymous client key is configuration, not a key
                if r == "signed-token" && public_jwt {
                    continue;
                }
                self.v.findings.push(Finding {
                    commit: a.commit.clone(),
                    file: a.file.clone(),
                    line: a.line,
                    rule: r.to_string(),
                });
                self.hold(&a);
            }
            if is_env_file(&a.file) {
                if self.env_seen.insert((a.commit.clone(), a.file.clone())) {
                    self.v.findings.push(Finding {
                        commit: a.commit.clone(),
                        file: a.file.clone(),
                        line: 0,
                        rule: "env-file".into(),
                    });
                }
                self.hold(&a);
            }
            if self.scanner.is_some() {
                // a line costs what JSON writes for it and its newline
                let cost = esc_len(&a.text) + 2;
                if cost > CHUNK {
                    self.scan_long(&a)?;
                } else {
                    // never add a line that takes the batch past a call: send what is waiting first
                    if !self.pending.is_empty() && self.pending_bytes + cost > CHUNK {
                        self.flush()?;
                    }
                    self.pending_bytes += cost;
                    self.pending.push(a);
                    if self.pending_bytes >= CHUNK {
                        self.flush()?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Check the names of the files a change adds: an environment file is held by its name even when it is empty, and a name is
    /// text a key can be put in, so each is read like a line (under the file name `<file name>`).
    pub fn add_paths(&mut self, commit: &str, paths: &[String]) -> Result<(), String> {
        let mut lines = Vec::new();
        for (i, p) in paths.iter().enumerate() {
            if is_env_file(p) && self.env_seen.insert((commit.to_string(), p.clone())) {
                self.v.findings.push(Finding {
                    commit: commit.to_string(),
                    file: p.clone(),
                    line: 0,
                    rule: "env-file".into(),
                });
                self.hold(&Added {
                    commit: commit.to_string(),
                    file: p.clone(),
                    line: 0,
                    text: String::new(),
                });
            }
            lines.push(Added {
                commit: commit.to_string(),
                file: "<file name>".into(),
                line: u32::try_from(i + 1).unwrap_or(u32::MAX),
                text: p.clone(),
            });
        }
        self.add(lines)
    }

    /// Check a block of text that is not a file's: a commit's message, a tag, a blob that was pushed on its own. Each line is read
    /// like an added line, under the file name `label`.
    pub fn add_text(&mut self, commit: &str, label: &str, text: &str) -> Result<(), String> {
        let lines = text
            .split('\n')
            .enumerate()
            .map(|(i, l)| Added {
                commit: commit.to_string(),
                file: label.to_string(),
                line: u32::try_from(i + 1).unwrap_or(u32::MAX),
                text: l.to_string(),
            })
            .collect();
        self.add(lines)
    }

    /// The end: scan what is left and hand back the verdict.
    pub fn finish(mut self) -> Result<Verdict, String> {
        self.flush()?;
        Ok(self.v)
    }

    fn scan(&self, text: &str) -> Result<Vec<String>, String> {
        match self.scanner {
            Some(s) => s.scan(text),
            None => Ok(Vec::new()),
        }
    }

    /// A line longer than one call: windows that overlap. A window is as long as [`CHUNK`] *escaped* bytes allow, so none is
    /// refused for size however many quotes or control bytes the line holds.
    fn scan_long(&mut self, a: &Added) -> Result<(), String> {
        let t = a.text.as_str();
        let mut from = 0usize;
        let mut names: BTreeSet<String> = BTreeSet::new();
        while from < t.len() {
            let mut end = from;
            let mut used = 0usize;
            for (i, c) in t[from..].char_indices() {
                let w = esc_len(c.encode_utf8(&mut [0u8; 4]));
                if used + w > CHUNK {
                    break;
                }
                used += w;
                end = from + i + c.len_utf8();
            }
            names.extend(self.scan(&t[from..end])?);
            if end >= t.len() {
                break;
            }
            // overlap by a stretch no value is longer than; a window is never shorter than CHUNK / 6 bytes
            let mut next = end.saturating_sub(WINDOW_OVERLAP).max(from + 1);
            while next < t.len() && !t.is_char_boundary(next) {
                next += 1;
            }
            from = next;
        }
        for n in names {
            self.record(a, n);
        }
        Ok(())
    }

    fn record(&mut self, a: &Added, name: String) {
        let hit = Stored {
            commit: a.commit.clone(),
            file: a.file.clone(),
            line: a.line,
            name,
        };
        if !self.v.stored.contains(&hit) {
            self.v.stored.push(hit);
        }
        self.hold(a);
    }

    fn flush(&mut self) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let batch = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        let names = self.scan(&join(&batch))?;
        if names.is_empty() {
            return Ok(());
        }
        let mut budget = LOCATE_BUDGET;
        self.locate(&batch, names, &mut budget)
    }

    /// Narrow a range of lines that holds a stored value down to the lines that hold it.
    fn locate(
        &mut self,
        lines: &[Added],
        names: Vec<String>,
        budget: &mut u32,
    ) -> Result<(), String> {
        if lines.len() == 1 || *budget < 2 {
            for n in names {
                self.record(&lines[0], n);
            }
            return Ok(());
        }
        let mid = lines.len() / 2;
        let (l, r) = lines.split_at(mid);
        *budget -= 2;
        let (ln, rn) = (self.scan(&join(l))?, self.scan(&join(r))?);
        if ln.is_empty() && rn.is_empty() {
            // a value that spans the middle: the first line of the range is the place
            for n in names {
                self.record(&lines[0], n);
            }
            return Ok(());
        }
        if !ln.is_empty() {
            self.locate(l, ln, budget)?;
        }
        if !rn.is_empty() {
            self.locate(r, rn, budget)?;
        }
        Ok(())
    }
}

fn join(lines: &[Added]) -> String {
    let mut s = String::with_capacity(lines.iter().map(|a| a.text.len() + 1).sum());
    for a in lines {
        s.push_str(&a.text);
        s.push('\n');
    }
    s
}

/// What a diff adds, each line placed, and the paths it names. `commit` labels the lines (empty for a staged change). A file git
/// printed without its bytes (a merge's binary file) is read whole through `binary`; what cannot be read is an error, which
/// holds the change.
pub fn read_diff(
    diff: &str,
    commit: &str,
    binary: &dyn Fn(&str) -> Result<String, String>,
) -> Result<(Vec<Added>, Vec<String>), String> {
    let p = crate::guard_diff::parse(diff)?;
    let mut out: Vec<Added> = p
        .added
        .into_iter()
        .map(|(file, line, text)| Added {
            commit: commit.to_string(),
            file,
            line,
            text,
        })
        .collect();
    let mut paths = p.paths;
    for f in p.binary {
        let t = binary(&f)?;
        for (i, l) in t.split('\n').enumerate() {
            out.push(Added {
                commit: commit.to_string(),
                file: f.clone(),
                line: u32::try_from(i + 1).unwrap_or(u32::MAX),
                text: l.to_string(),
            });
        }
        if !paths.contains(&f) {
            paths.push(f);
        }
    }
    Ok((out, paths))
}

/// The held lines as the unified diff a request carries. The service scans exactly this and binds its hash, and the hook builds the
/// same text again to spend, so it is a pure function of the lines: sorted by commit, file and line, one hunk per run of lines.
pub fn held_text(held: &[Added]) -> String {
    let mut sorted: Vec<&Added> = held.iter().collect();
    sorted.sort_by(|a, b| (&a.commit, &a.file, a.line).cmp(&(&b.commit, &b.file, b.line)));
    let mut out = String::new();
    let mut i = 0;
    let mut prev: Option<(&str, &str)> = None;
    while i < sorted.len() {
        // one hunk: the run of consecutive lines of one file of one commit, counted as git would count it
        let first = sorted[i];
        let mut j = i + 1;
        while j < sorted.len()
            && sorted[j].commit == first.commit
            && sorted[j].file == first.file
            && sorted[j].line == sorted[j - 1].line.saturating_add(1)
        {
            j += 1;
        }
        if prev != Some((first.commit.as_str(), first.file.as_str())) {
            out.push_str(&format!("--- a/{0}\n+++ b/{0}\n", first.file));
        }
        out.push_str(&format!("@@ -0,0 +{},{} @@\n", first.line, j - i));
        for a in &sorted[i..j] {
            out.push('+');
            out.push_str(&a.text);
            out.push('\n');
        }
        prev = Some((first.commit.as_str(), first.file.as_str()));
        i = j;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const SENTINEL: &str = "SENTINEL-scan-0123456789abcdef";

    struct Counting {
        calls: Cell<u32>,
        longest: Cell<usize>,
        seen: RefCell<Vec<usize>>,
        /// The longest request line the service would be sent, as JSON writes it.
        wire: Cell<usize>,
    }
    impl Counting {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
                longest: Cell::new(0),
                seen: RefCell::default(),
                wire: Cell::new(0),
            }
        }
    }
    impl Scanner for Counting {
        fn scan(&self, text: &str) -> Result<Vec<String>, String> {
            self.calls.set(self.calls.get() + 1);
            let line = serde_json::json!({"op": "scan", "text": text}).to_string();
            self.wire.set(self.wire.get().max(line.len() + 1));
            self.longest.set(self.longest.get().max(text.len()));
            self.seen.borrow_mut().push(text.len());
            Ok(if text.contains(SENTINEL) {
                vec!["workload.app.staging.API_KEY".into()]
            } else {
                vec![]
            })
        }
        fn override_ok(&self, _: &str, _: &crate::guard::Binding) -> Result<(), String> {
            Err("no".into())
        }
    }

    fn line(commit: usize, n: u32, text: &str) -> Added {
        Added {
            commit: format!("c{commit:011}"),
            file: format!("src/f{}.ts", commit % 7),
            line: n,
            text: text.to_string(),
        }
    }

    #[test]
    fn two_hundred_and_fifty_commits_are_a_few_calls_not_a_thousand() {
        let s = Counting::new();
        let mut c = Checker::new(Some(&s));
        for i in 0..250 {
            let lines = (1..=40)
                .map(|n| line(i, n, &format!("const value{i}_{n} = {n};")))
                .collect();
            c.add(lines).unwrap();
        }
        let v = c.finish().unwrap();
        assert!(v.clean());
        assert!(v.held.is_empty());
        assert!(s.calls.get() <= 2, "{} calls", s.calls.get());
        assert!(s.longest.get() <= CHUNK + 4096);
    }

    #[test]
    fn a_secret_in_the_middle_of_a_large_push_is_found_at_its_commit_file_and_line() {
        let s = Counting::new();
        let mut c = Checker::new(Some(&s));
        for i in 0..250 {
            let mut lines: Vec<Added> = (1..=40)
                .map(|n| line(i, n, &format!("const value{i}_{n} = {n};")))
                .collect();
            if i == 123 {
                lines[16] = line(i, 17, &format!("export const k = \"{SENTINEL}\";"));
            }
            c.add(lines).unwrap();
        }
        let v = c.finish().unwrap();
        assert_eq!(v.stored.len(), 1, "{:?}", v.stored);
        let h = &v.stored[0];
        assert_eq!(
            (h.commit.as_str(), h.file.as_str(), h.line),
            ("c00000000123", "src/f4.ts", 17)
        );
        // the held lines are exactly that one line
        assert_eq!(v.held.len(), 1);
        let t = held_text(&v.held);
        assert!(t.contains("+++ b/src/f4.ts") && t.contains("@@ -0,0 +17,1 @@"));
        // and finding it cost a few calls, not one per line
        assert!(s.calls.get() < 40, "{} calls", s.calls.get());
    }

    #[test]
    fn a_line_longer_than_a_call_is_scanned_in_windows_and_a_value_on_the_seam_is_found() {
        let s = Counting::new();
        let mut c = Checker::new(Some(&s));
        let mut t = "x".repeat(CHUNK - 10);
        t.push_str(SENTINEL);
        t.push_str(&"y".repeat(CHUNK));
        c.add(vec![line(0, 1, &t)]).unwrap();
        let v = c.finish().unwrap();
        assert_eq!(v.stored.len(), 1);
        assert!(s.longest.get() <= CHUNK);
    }

    #[test]
    fn the_held_text_is_a_pure_function_of_the_held_lines() {
        let a = vec![
            line(1, 9, "b"),
            line(1, 3, "a"),
            line(1, 4, "a2"),
            line(2, 1, "c"),
        ];
        let mut rev = a.clone();
        rev.reverse();
        assert_eq!(held_text(&a), held_text(&rev));
        let t = held_text(&a);
        // 3 and 4 are one hunk; 9 is another
        assert_eq!(t.matches("@@ -0,0").count(), 3, "{t}");
        assert!(crate::guard_diff::parse(&t)
            .unwrap()
            .added
            .iter()
            .any(|(f, n, x)| f == "src/f1.ts" && *n == 4 && x == "a2"));
    }

    /// The service reads a line of at most `MAX_LINE_BYTES` and at most 1 MiB of text.
    fn fits(s: &Counting) {
        assert!(
            (s.wire.get() as u64) <= crate::secrets_ingress::MAX_LINE_BYTES,
            "a request of {} bytes",
            s.wire.get()
        );
        assert!(s.longest.get() <= 1 << 20);
    }

    #[test]
    fn g8_two_lines_of_600_kb_are_two_calls_and_neither_is_too_big_for_the_service() {
        let s = Counting::new();
        let mut c = Checker::new(Some(&s));
        c.add(vec![
            line(0, 1, &"a".repeat(600 * 1024)),
            line(0, 2, &"b".repeat(600 * 1024)),
        ])
        .unwrap();
        assert!(c.finish().unwrap().clean());
        assert_eq!(s.calls.get(), 2);
        fits(&s);
    }

    #[test]
    fn g8_a_batch_is_sized_by_what_json_writes_not_by_raw_bytes() {
        // control bytes are six bytes each, quotes two: raw text well under a call is over it as JSON
        let s = Counting::new();
        let mut c = Checker::new(Some(&s));
        c.add(vec![
            line(0, 1, &"\u{0}".repeat(100_000)),
            line(0, 2, &"\"".repeat(300_000)),
            line(0, 3, &"\u{1}".repeat(100_000)),
            line(0, 4, "plain"),
        ])
        .unwrap();
        c.finish().unwrap();
        fits(&s);
        assert!(s.calls.get() >= 3, "{} calls", s.calls.get());
        // one line that is longer than a call as JSON writes it is windowed, and every window fits, a value on a seam is found
        let s = Counting::new();
        let mut c = Checker::new(Some(&s));
        let mut t = "\u{0}".repeat(250_000);
        t.push_str(SENTINEL);
        t.push_str(&"\u{2}".repeat(250_000));
        c.add(vec![line(0, 1, &t)]).unwrap();
        let v = c.finish().unwrap();
        assert_eq!(v.stored.len(), 1);
        fits(&s);
    }

    #[test]
    fn g8_what_is_held_always_fits_in_a_request_the_box_socket_reads() {
        // thousands of held lines in files with long names: the estimate overflows before the real request can
        let mut c = Checker::new(None);
        let file = format!("{}/.env", "d".repeat(300));
        let lines = (1..=20_000)
            .map(|n| Added {
                commit: String::new(),
                file: file.clone(),
                line: n,
                text: format!("K{n}=\"quoted\\value\""),
            })
            .collect();
        c.add(lines).unwrap();
        let v = c.finish().unwrap();
        assert!(v.held_overflow && !v.held.is_empty());
        let req =
            serde_json::json!({"op":"areq_file","scanned_text":held_text(&v.held)}).to_string();
        assert!(req.len() < REQUEST_MAX, "{} bytes", req.len());
    }

    #[test]
    fn the_held_text_reads_back_as_exactly_the_held_lines() {
        let held = vec![
            line(1, 3, "a"),
            line(1, 4, "++ /dev/null"),
            line(1, 5, ""),
            line(1, 9, "+++ b/x"),
            line(2, 1, "@@ -1 +1 @@"),
            Added {
                commit: "c".into(),
                file: "sp ace/f.ts".into(),
                line: 7,
                text: "x \t y".into(),
            },
            Added {
                commit: "c".into(),
                file: ".env".into(),
                line: 0,
                text: String::new(),
            },
        ];
        let p = crate::guard_diff::parse(&held_text(&held)).unwrap();
        // the text lists lines by commit, then file, then line
        let mut order: Vec<&Added> = held.iter().collect();
        order.sort_by(|a, b| (&a.commit, &a.file, a.line).cmp(&(&b.commit, &b.file, b.line)));
        let want: Vec<(String, u32, String)> = order
            .iter()
            .map(|a| (a.file.clone(), a.line, a.text.clone()))
            .collect();
        assert_eq!(p.added, want);
    }
}
