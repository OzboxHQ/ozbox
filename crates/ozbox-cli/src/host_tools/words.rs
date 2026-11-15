//! A shell command line, read just far enough to ask the permission engine about each command in it. This is not a shell:
//! it splits on the separators (`;` `&&` `||` `|` `&` and newlines), respects simple quotes, skips leading `NAME=value`
//! assignments and wrappers (`env`, `command`, `nohup`, `time`, `nice`, `xargs`), and says so when it cannot be sure
//! (command substitution, backticks, process substitution, here-documents, `eval`, an unclosed quote, a nested `sh -c`).
//! A command it cannot read is *complex*, and complex counts as sensitive: it asks.

/// The commands of a line, each as its words, and whether any part could not be read with confidence.
pub fn segments(line: &str) -> (Vec<Vec<String>>, bool) {
    let mut complex = line.contains('`')
        || line.contains("$(")
        || line.contains("<(")
        || line.contains(">(")
        || line.contains("<<");
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut have = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    let flush_word = |cur: &mut String, have: &mut bool, words: &mut Vec<String>| {
        if *have {
            words.push(std::mem::take(cur));
            *have = false;
        }
    };
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                    }
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    have = true;
                }
                '\\' => {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                        have = true;
                    }
                }
                ';' | '\n' | '|' | '&' => {
                    flush_word(&mut cur, &mut have, &mut words);
                    if !words.is_empty() {
                        out.push(std::mem::take(&mut words));
                    }
                    // `&&` and `||` are two separators in a row: the empty piece between them is skipped
                }
                c if c.is_whitespace() => flush_word(&mut cur, &mut have, &mut words),
                c => {
                    cur.push(c);
                    have = true;
                }
            },
        }
    }
    if quote.is_some() {
        complex = true;
    }
    flush_word(&mut cur, &mut have, &mut words);
    if !words.is_empty() {
        out.push(words);
    }
    let out: Vec<Vec<String>> = out.into_iter().map(unwrap_leading).collect();
    if out.iter().any(|w| {
        let p = base(w.first().map(String::as_str).unwrap_or(""));
        matches!(p, "eval" | "source" | "." | "exec")
            || (matches!(p, "sh" | "bash" | "zsh" | "dash")
                && w.iter().any(|a| a.starts_with("-c") || a == "-lc"))
    }) {
        complex = true;
    }
    (out, complex)
}

fn base(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn is_assignment(w: &str) -> bool {
    match w.split_once('=') {
        Some((n, _)) => {
            !n.is_empty()
                && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !n.starts_with(|c: char| c.is_ascii_digit())
        }
        None => false,
    }
}

/// Drop `NAME=value` prefixes and wrappers that only run what follows, so `env FOO=1 rm -rf x` is read as `rm -rf x`.
fn unwrap_leading(mut w: Vec<String>) -> Vec<String> {
    loop {
        match w.first().map(String::as_str) {
            Some(a) if is_assignment(a) => {
                w.remove(0);
            }
            Some(a)
                if matches!(
                    base(a),
                    "env" | "command" | "nohup" | "time" | "nice" | "xargs" | "builtin"
                ) =>
            {
                w.remove(0);
                // options of the wrapper itself (`env -i`, `nice -n 5` keeps its number: harmless to the match)
                while w
                    .first()
                    .is_some_and(|x| x.starts_with('-') || is_assignment(x))
                {
                    w.remove(0);
                }
            }
            _ => break,
        }
    }
    w
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn s(l: &str) -> (Vec<Vec<String>>, bool) {
        segments(l)
    }

    fn v(w: &[&str]) -> Vec<String> {
        w.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn a_line_is_split_into_its_commands() {
        let (seg, complex) = s("cd src && cargo test -- --nocapture; echo done | tee log");
        assert!(!complex);
        assert_eq!(
            seg,
            vec![
                v(&["cd", "src"]),
                v(&["cargo", "test", "--", "--nocapture"]),
                v(&["echo", "done"]),
                v(&["tee", "log"])
            ]
        );
    }

    #[test]
    fn quotes_keep_words_together_and_hide_separators() {
        let (seg, complex) = s(r#"git commit -m "fix; then && more" 'a b'"#);
        assert!(!complex);
        assert_eq!(
            seg,
            vec![v(&["git", "commit", "-m", "fix; then && more", "a b"])]
        );
    }

    #[test]
    fn assignments_and_wrappers_do_not_hide_the_command() {
        assert_eq!(
            s("FOO=1 BAR=2 rm -rf build").0,
            vec![v(&["rm", "-rf", "build"])]
        );
        assert_eq!(
            s("env -i FOO=1 rm -rf build").0,
            vec![v(&["rm", "-rf", "build"])]
        );
        assert_eq!(
            s("nohup /usr/bin/sudo reboot").0,
            vec![v(&["/usr/bin/sudo", "reboot"])]
        );
    }

    #[test]
    fn what_cannot_be_read_with_confidence_is_complex() {
        for l in [
            "echo $(rm -rf /)",
            "echo `id`",
            "cat <(curl x)",
            "cat <<EOF\nx\nEOF",
            "eval \"$X\"",
            "sh -c 'rm -rf /'",
            "bash -lc ls",
            "echo 'unclosed",
            "source ./x.sh",
            "exec rm x",
        ] {
            assert!(s(l).1, "{l}");
        }
        for l in [
            "ls -la",
            "git status",
            "cargo build --release",
            "echo 'a $b'",
        ] {
            assert!(!s(l).1, "{l}");
        }
    }

    #[test]
    fn empty_pieces_are_skipped() {
        assert!(s("").0.is_empty());
        assert!(s("  ;; && || ").0.is_empty());
        assert_eq!(s("a && b || c").0.len(), 3);
    }
}
