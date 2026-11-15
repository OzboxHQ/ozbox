//! Reading what git says a change adds (ADR 0041, and the merge form).
//!
//! The barrier reads text that git prints, so the one thing that must never happen is a line of the change being taken for a
//! line of git's own. The old reader decided what a line was from its first characters, so an added line that reads
//! `++ /dev/null` was printed as `+++ /dev/null`, taken for a file header, and every line after it was skipped. This reader
//! counts instead: a hunk header says how many lines the hunk holds, and exactly that many lines are content, whatever they
//! start with. Only between hunks does a line's start say what it is.
//!
//! One command and one flag set ([`DIFF_FLAGS`]) feed all three hooks, so what `pre-commit` reads is what `post-commit` and
//! `pre-push` read:
//!
//! - `--text` reads a file git would call binary (a NUL byte, or a `-diff` line in `.gitattributes`) as text;
//! - `--no-renames` shows a renamed and edited file as the new file, whole;
//! - `--diff-filter=d` keeps everything except deletions, so a symlink turned into a file (a type change) is read;
//! - `--cc` shows a merge commit as the combined diff against all its parents: the lines the person who merged wrote, which is
//!   what a conflict resolution adds. A clean merge adds none, and the commits it brings in are read as commits.
//!
//! Anything that cannot be parsed is an error, and an error holds the change: it is never a pass and never a skip.
//! Known limits, said in ADR 0041: a file stored as UTF-16 is read as the bytes it is (its text is not found by a literal
//! scan), and Git LFS commits a pointer, so the object is not read.

/// The flags every hook reads a change with. See the module doc for what each does.
pub const DIFF_FLAGS: [&str; 11] = [
    "-p",
    "-r",
    "--root",
    "--cc",
    "--no-commit-id",
    "-U0",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--text",
    "--no-renames",
];

/// The filter of every read: all but deletions (a deleted file adds nothing, a type change adds the new file).
pub const DIFF_FILTER: &str = "--diff-filter=d";

/// What a diff adds: each added line placed by file and number, and the path of each file the diff names (not deleted).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub added: Vec<(String, u32, String)>,
    pub paths: Vec<String>,
    /// Files of a merge that git printed as `Binary files differ` even with `--text` (the combined form does). The caller reads
    /// such a file whole from the commit; it is never skipped.
    pub binary: Vec<String>,
}

/// Where the parser is: between hunks, where a line's start says what it is, or inside one, where it counts.
enum State {
    Header,
    Hunk {
        /// One prefix column per parent (one for an ordinary diff).
        cols: usize,
        /// Lines still to come: per parent, and in the result.
        old: Vec<u64>,
        new: u64,
        /// The number of the next result line.
        next: u32,
    },
}

fn bad(what: &str) -> String {
    format!("git's output could not be read ({what})")
}

/// `a` or `a,b` of a hunk header: the start and the count (the count is 1 when it is left out).
fn range(tok: &str, sign: char) -> Option<(u32, u64)> {
    let t = tok.strip_prefix(sign)?;
    let (a, b) = match t.split_once(',') {
        Some((a, b)) => (a, b),
        None => (t, "1"),
    };
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// `@@ -a,b +c,d @@` or, for a merge, `@@@ -a,b -a2,b2 +c,d @@@`. Whatever follows the closing marks is git's note and is ignored.
fn hunk_header(line: &str) -> Result<State, String> {
    let k = line.bytes().take_while(|b| *b == b'@').count();
    if k < 2 {
        return Err(bad("a hunk header"));
    }
    let rest = &line[k..];
    let close = format!(" {}", "@".repeat(k));
    let end = rest.find(&close).ok_or_else(|| bad("a hunk header"))?;
    let toks: Vec<&str> = rest[..end].split(' ').filter(|t| !t.is_empty()).collect();
    let parents = k - 1;
    if toks.len() != parents + 1 {
        return Err(bad("a hunk header"));
    }
    let mut old = Vec::with_capacity(parents);
    for t in &toks[..parents] {
        old.push(range(t, '-').ok_or_else(|| bad("a hunk header"))?.1);
    }
    let (start, new) = range(toks[parents], '+').ok_or_else(|| bad("a hunk header"))?;
    Ok(State::Hunk {
        cols: parents,
        old,
        new,
        next: start,
    })
}

fn finished(s: &State) -> bool {
    match s {
        State::Header => true,
        State::Hunk { old, new, .. } => *new == 0 && old.iter().all(|o| *o == 0),
    }
}

/// A path as git prints it after `+++ `: with the `b/` prefix, in C-style quotes when it holds a special character, and with a
/// tab after it when it holds a space. Control characters are shown as `?` so a path can never break the text it is put in.
fn clean_path(raw: &str, strip_b: bool) -> String {
    let raw = raw.strip_suffix('\t').unwrap_or(raw);
    let unquoted: Vec<u8> = match raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Some(q) => {
            let b = q.as_bytes();
            let mut out = Vec::with_capacity(b.len());
            let mut i = 0;
            while i < b.len() {
                if b[i] != b'\\' || i + 1 >= b.len() {
                    out.push(b[i]);
                    i += 1;
                    continue;
                }
                i += 1;
                match b[i] {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'a' => out.push(7),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'v' => out.push(11),
                    b'0'..=b'7' => {
                        let mut v = 0u32;
                        let mut n = 0;
                        while n < 3 && i < b.len() && (b'0'..=b'7').contains(&b[i]) {
                            v = v * 8 + u32::from(b[i] - b'0');
                            i += 1;
                            n += 1;
                        }
                        out.push((v & 0xff) as u8);
                        continue;
                    }
                    c => out.push(c),
                }
                i += 1;
            }
            out
        }
        None => raw.as_bytes().to_vec(),
    };
    let s = String::from_utf8_lossy(&unquoted).to_string();
    let s = if strip_b {
        s.strip_prefix("b/").unwrap_or(&s)
    } else {
        &s
    };
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The end of the C-quoted token that starts at `s[0]` (a `"`): the index just past its closing quote, honouring `\"` and `\\`.
fn quoted_end(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// The path a `diff --git a/p b/p` or `diff --cc p` line names, for a file that has no `+++` line (an empty new file, a change of
/// mode). A name git quotes (a non-ASCII character, a tab) is unquoted like the `+++` line's: with `--no-renames` both halves name
/// the same file, so the second is the name. `None` only when the line cannot be told apart safely.
fn header_path(raw: &str) -> Option<String> {
    if let Some(p) = raw
        .strip_prefix("diff --cc ")
        .or_else(|| raw.strip_prefix("diff --combined "))
    {
        return Some(clean_path(p, false));
    }
    let r = raw.strip_prefix("diff --git ")?;
    if r.starts_with('"') {
        let end = quoted_end(r)?;
        let second = r[end..].strip_prefix(' ')?;
        if !second.starts_with('"') || quoted_end(second)? != second.len() {
            return None;
        }
        return Some(clean_path(second, true));
    }
    if r.len() < 5 || (r.len() - 5) % 2 != 0 {
        return None;
    }
    let l = (r.len() - 5) / 2;
    let p = r.get(2..2 + l)?;
    (r == format!("a/{p} b/{p}")).then(|| clean_path(p, false))
}

/// What a diff (`-U0`, ordinary or combined) adds. Errors on anything it cannot place: git saying a file is binary, a hunk that
/// ends early or runs long, a line that is neither inside a hunk nor one of git's own header lines.
pub fn parse(diff: &str) -> Result<Parsed, String> {
    let mut out = Parsed::default();
    let mut st = State::Header;
    let mut file = String::new();
    let mut header: Option<String> = None;
    let mut lines: Vec<&str> = diff.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    for raw in lines {
        if finished(&st) {
            st = State::Header;
        }
        match &mut st {
            State::Hunk {
                cols,
                old,
                new,
                next,
            } => {
                if raw.starts_with('\\') {
                    continue; // "\ No newline at end of file"
                }
                let b = raw.as_bytes();
                if b.len() < *cols || !b[..*cols].iter().all(|c| matches!(c, b' ' | b'+' | b'-')) {
                    return Err(bad("a line inside a hunk"));
                }
                let prefix = &b[..*cols];
                let content = &raw[*cols..];
                if prefix.contains(&b'-') {
                    // a line that is not in the result: it was in the parents marked `-`
                    for (i, c) in prefix.iter().enumerate() {
                        if *c == b'-' {
                            old[i] = old[i]
                                .checked_sub(1)
                                .ok_or_else(|| bad("a hunk that runs long"))?;
                        }
                    }
                } else {
                    *new = new
                        .checked_sub(1)
                        .ok_or_else(|| bad("a hunk that runs long"))?;
                    for (i, c) in prefix.iter().enumerate() {
                        if *c == b' ' {
                            old[i] = old[i]
                                .checked_sub(1)
                                .ok_or_else(|| bad("a hunk that runs long"))?;
                        }
                    }
                    if prefix.contains(&b'+') {
                        let name = if file.is_empty() { "(unnamed)" } else { &file };
                        out.added
                            .push((name.to_string(), *next, content.to_string()));
                    }
                    *next = next.saturating_add(1);
                }
            }
            State::Header => {
                if raw.starts_with("@@") {
                    st = hunk_header(raw)?;
                } else if let Some(p) = raw.strip_prefix("+++ ") {
                    if p == "/dev/null" {
                        file.clear();
                    } else {
                        file = clean_path(p, true);
                        if !out.paths.contains(&file) {
                            out.paths.push(file.clone());
                        }
                    }
                } else if raw.starts_with("diff ") {
                    file.clear();
                    header = header_path(raw);
                    if let Some(h) = &header {
                        if !out.paths.contains(h) {
                            out.paths.push(h.clone());
                        }
                    }
                } else if raw.starts_with("deleted file mode ") {
                    // a deleted file (or the old half of a type change) names no path that is kept
                    if let Some(h) = header.take() {
                        out.paths.retain(|p| *p != h);
                    }
                } else if raw == "Binary files differ" && header.is_some() {
                    // the combined form of a merge: read the file whole, from the commit
                    if let Some(h) = &header {
                        out.binary.push(h.clone());
                    }
                } else if raw.starts_with("Binary files ") || raw.starts_with("GIT binary patch") {
                    return Err(bad("a file git would not show as text"));
                } else if raw.starts_with('\\')
                    || raw.starts_with("--- ")
                    || raw.starts_with("index ")
                    || raw.starts_with("old mode ")
                    || raw.starts_with("new mode ")
                    || raw.starts_with("new file mode ")
                    || raw.starts_with("mode ")
                    || raw.starts_with("similarity index ")
                    || raw.starts_with("dissimilarity index ")
                    || raw.starts_with("rename from ")
                    || raw.starts_with("rename to ")
                    || raw.starts_with("copy from ")
                    || raw.starts_with("copy to ")
                {
                    // git's own lines between hunks
                } else {
                    return Err(bad("a line between hunks"));
                }
            }
        }
    }
    if !finished(&st) {
        return Err(bad("a hunk that ends early"));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn added(d: &str) -> Vec<(String, u32, String)> {
        parse(d).unwrap().added
    }

    #[test]
    fn an_added_line_that_looks_like_a_header_is_content() {
        // G1: the line `++ /dev/null` is printed `+++ /dev/null`; the lines after it are still read
        let d = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1,4 @@\n+one\n+++ /dev/null\n++++ b/other\n+last\n";
        let a = added(d);
        assert_eq!(
            a.iter()
                .map(|(f, n, t)| (f.as_str(), *n, t.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("x", 1, "one"),
                ("x", 2, "++ /dev/null"),
                ("x", 3, "+++ b/other"),
                ("x", 4, "last")
            ]
        );
        // and a following file header after the hunk is still a header
        let d2 = format!("{d}diff --git a/y b/y\n--- a/y\n+++ b/y\n@@ -0,0 +1 @@\n+y1\n");
        assert_eq!(added(&d2).last().unwrap().0, "y");
    }

    #[test]
    fn deleted_lines_and_the_no_newline_note_are_not_added_and_the_numbers_follow_the_result() {
        let d = "--- a/x\n+++ b/x\n@@ -3,2 +3,1 @@ fn main() {\n-gone\n-gone too\n+new\n\\ No newline at end of file\n@@ -9,0 +8,2 @@\n+a\n+b\n";
        assert_eq!(
            added(d),
            vec![
                ("x".to_string(), 3, "new".to_string()),
                ("x".to_string(), 8, "a".to_string()),
                ("x".to_string(), 9, "b".to_string())
            ]
        );
    }

    #[test]
    fn the_combined_form_of_a_merge_is_read_and_a_line_from_one_parent_is_not_new() {
        // two parents: `++` is new to both, ` -` / `- ` are removed lines, `+ ` / ` +` come from the other parent
        let d = "diff --cc f\nindex 19ab014,ca032aa..3429c3e\n--- a/f\n+++ b/f\n@@@ -3,2 -3,1 +3,3 @@@\n- MAIN\n -SIDE\n++RESOLVED ++ /dev/null\n++extra\n +from the other parent\n";
        let a = added(d);
        assert_eq!(
            a,
            vec![
                ("f".to_string(), 3, "RESOLVED ++ /dev/null".to_string()),
                ("f".to_string(), 4, "extra".to_string()),
                // present in the other parent but not the first: read, because reading more can never pass a key
                ("f".to_string(), 5, "from the other parent".to_string())
            ]
        );
    }

    #[test]
    fn what_cannot_be_read_is_an_error() {
        for d in [
            "Binary files /dev/null and b/c differ\n",
            "GIT binary patch\nliteral 1\n",
            "--- a/x\n+++ b/x\n@@ -0,0 +1,2 @@\n+only one\n",
            "--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n+one\n+two\n",
            "--- a/x\n+++ b/x\n@@ -0,0 +1 @\n+one\n",
            "--- a/x\n+++ b/x\n@@ nonsense @@\n",
            "surprise\n",
            "--- a/x\n+++ b/x\n@@ -1 +1 @@\nx\n",
            "--- a/x\n+++ b/x\n@@@ -1 -1 +1 @@@\n+\n",
        ] {
            assert!(parse(d).is_err(), "{d:?}");
        }
        assert_eq!(parse("").unwrap(), Parsed::default());
    }

    #[test]
    fn paths_are_unquoted_and_never_hold_a_control_character() {
        let d = "diff --git \"a/t\\tn.txt\" \"b/t\\tn.txt\"\n--- \"a/t\\tn.txt\"\n+++ \"b/t\\tn.txt\"\n@@ -0,0 +1 @@\n+a\ndiff --git \"a/\\303\\251.txt\" \"b/\\303\\251.txt\"\n--- /dev/null\n+++ \"b/\\303\\251.txt\"\n@@ -0,0 +1 @@\n+e\ndiff --git a/sp ace b/sp ace\n--- a/sp ace\t\n+++ b/sp ace\t\n@@ -0,0 +1 @@\n+s\n";
        let p = parse(d).unwrap();
        assert_eq!(p.paths, vec!["t?n.txt", "\u{e9}.txt", "sp ace"]);
        assert_eq!(p.added.len(), 3);
    }

    #[test]
    fn a_deleted_file_names_no_path_and_adds_nothing() {
        let d = "diff --git a/l b/l\ndeleted file mode 120000\n--- a/l\n+++ /dev/null\n@@ -1 +0,0 @@\n-target\n\\ No newline at end of file\n";
        let p = parse(d).unwrap();
        assert!(p.added.is_empty() && p.paths.is_empty());
    }

    #[test]
    fn a_file_with_no_hunk_still_names_its_path_and_a_binary_merge_file_is_listed_to_be_read_whole()
    {
        // an empty new file has no `+++` line; its name is a path all the same
        let d = "diff --git a/.env b/.env\nnew file mode 100644\nindex 0000000..e69de29\ndiff --git a/gone b/gone\ndeleted file mode 100644\nindex 1..0000000\n--- a/gone\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n";
        assert_eq!(parse(d).unwrap().paths, vec![".env"]);
        // a name git quotes has no `+++` line either when the file is empty
        let q = "diff --git \"a/\\303\\251/.env\" \"b/\\303\\251/.env\"\nnew file mode 100644\nindex 0000000..e69de29\ndiff --git \"a/t\\tab\" \"b/t\\tab\"\nnew file mode 100644\n";
        assert_eq!(parse(q).unwrap().paths, vec!["\u{e9}/.env", "t?ab"]);
        // the combined form prints a binary file without its bytes, even with --text
        let m = "diff --cc bin\nindex e4a64e0,5672a64..9854e26\nBinary files differ\n";
        let p = parse(m).unwrap();
        assert_eq!(p.binary, vec!["bin"]);
        assert!(p.added.is_empty());
        // an ordinary binary file is an error: it could not be read
        assert!(parse("diff --git a/x b/x\nBinary files a/x and b/x differ\n").is_err());
        // a mode line of the combined form
        assert!(parse("diff --cc f\nmode 100644,100755..100755\n").is_ok());
    }
}
