//! Paths an agent names, and what they may name. Everything is relative to the box's `/work`: `/work/a/b`, `a/b` and
//! `./a/../a/b` are the same place, and nothing outside it can be named. The check here is lexical; the backend then
//! resolves symlinks and refuses a path whose real location is outside `/work`.

pub const WORK: &str = "/work";
const MAX_PATH: usize = 1024;

/// The parts of a path under `/work`, with `.` and `..` resolved. A path that leaves `/work`, is absolute somewhere else,
/// or holds a NUL or a control character is refused.
pub fn normalize(requested: &str) -> Result<Vec<String>, String> {
    let r = requested.trim();
    if r.len() > MAX_PATH || r.chars().any(|c| c == '\0' || c.is_control()) {
        return Err("that path is not valid".into());
    }
    let rest = if r == WORK {
        ""
    } else if let Some(x) = r.strip_prefix("/work/") {
        x
    } else if r.starts_with('/') || r.starts_with('~') {
        return Err("a path must be inside /work".into());
    } else {
        r
    };
    let mut parts: Vec<String> = Vec::new();
    for p in rest.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err("a path must stay inside /work".into());
                }
            }
            x => parts.push(x.to_string()),
        }
    }
    Ok(parts)
}

pub fn join(parts: &[String]) -> String {
    if parts.is_empty() {
        WORK.to_string()
    } else {
        format!("{WORK}/{}", parts.join("/"))
    }
}

pub fn rel(parts: &[String]) -> String {
    parts.join("/")
}

/// Files an agent may neither read nor write through the files tools: the secrets of a project belong in the secret store
/// (ADR 0018), and a repository's own bookkeeping is changed with git.
pub fn protected(parts: &[String]) -> Option<&'static str> {
    if parts.iter().any(|p| p == ".git") {
        return Some("the repository's own files are changed with the git tools");
    }
    // a browser's profiles hold its cookies, and a download is held back until it has been checked
    if parts.windows(3).any(|w| {
        w[0] == ".ozbox" && w[1] == "browser" && matches!(w[2].as_str(), "profiles" | "tmp")
    }) || parts.iter().any(|p| p == ".quarantine")
    {
        return Some("a browser's profiles and held-back downloads are not for the files tools");
    }
    let last = parts.last().map(String::as_str).unwrap_or("");
    let secretish = last == ".env"
        || last.starts_with(".env.")
        || last.ends_with(".pem")
        || last.ends_with(".key")
        || last == "id_rsa"
        || last == "id_ed25519"
        || last == ".npmrc"
        || last == ".netrc";
    secretish.then_some("secrets are not kept in files: use the project's secret store")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_same_place_is_named_the_same_way() {
        let a = normalize("/work/a/b").unwrap();
        assert_eq!(a, normalize("a/b").unwrap());
        assert_eq!(a, normalize("./a/x/../b").unwrap());
        assert_eq!(join(&a), "/work/a/b");
        assert_eq!(normalize("/work").unwrap(), Vec::<String>::new());
        assert_eq!(normalize("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn a_path_that_leaves_work_is_refused() {
        for p in [
            "..",
            "../x",
            "a/../../x",
            "/etc/passwd",
            "/workshop",
            "~/x",
            "/work/../etc",
            "a\0b",
            "a\nb",
        ] {
            assert!(normalize(p).is_err(), "{p:?}");
        }
        assert!(normalize(&"a/".repeat(600)).is_err());
    }

    #[test]
    fn secret_files_and_git_internals_are_protected() {
        for p in [
            ".env",
            "app/.env.local",
            "keys/server.pem",
            ".git/config",
            "a/.git/hooks/pre-commit",
            "id_rsa",
            ".npmrc",
        ] {
            assert!(protected(&normalize(p).unwrap()).is_some(), "{p}");
        }
        for p in ["src/main.rs", "env.md", "README", "a/environment.ts"] {
            assert!(protected(&normalize(p).unwrap()).is_none(), "{p}");
        }
    }
}
