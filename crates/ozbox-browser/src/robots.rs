//! Site manners: robots.txt is honoured for automated fetching, requests to one site are spaced, and the
//! browser says what it is. A person can exempt their own sites.

use std::collections::HashMap;

/// One group of rules from a robots.txt, for the agents it names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Group {
    agents: Vec<String>,
    rules: Vec<(bool, String)>,
    crawl_delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Robots {
    groups: Vec<Group>,
}

impl Robots {
    pub fn parse(text: &str) -> Self {
        let mut groups: Vec<Group> = Vec::new();
        let mut cur = Group::default();
        let mut in_rules = false;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "user-agent" => {
                    if in_rules {
                        groups.push(std::mem::take(&mut cur));
                        in_rules = false;
                    }
                    cur.agents.push(v.to_ascii_lowercase());
                }
                "allow" | "disallow" => {
                    in_rules = true;
                    // an empty Disallow allows everything: it is no rule
                    if !v.is_empty() {
                        cur.rules.push((k == "allow", v.to_string()));
                    }
                }
                "crawl-delay" => {
                    in_rules = true;
                    if let Ok(s) = v.parse::<f64>() {
                        cur.crawl_delay_ms = Some((s.clamp(0.0, 60.0) * 1000.0) as u64);
                    }
                }
                _ => {}
            }
        }
        if !cur.agents.is_empty() {
            groups.push(cur);
        }
        Self { groups }
    }

    fn group_for(&self, agent: &str) -> Option<&Group> {
        let a = agent.to_ascii_lowercase();
        // the most specific named group wins; `*` is the fallback
        self.groups
            .iter()
            .filter(|g| g.agents.iter().any(|x| x != "*" && a.contains(x.as_str())))
            .max_by_key(|g| g.agents.iter().map(String::len).max().unwrap_or(0))
            .or_else(|| {
                self.groups
                    .iter()
                    .find(|g| g.agents.iter().any(|x| x == "*"))
            })
    }

    /// May `agent` fetch this path (with its query)? The longest matching rule wins; allow wins a tie.
    pub fn allowed(&self, agent: &str, path: &str) -> bool {
        let Some(g) = self.group_for(agent) else {
            return true;
        };
        let mut best: Option<(usize, bool)> = None;
        for (allow, pat) in &g.rules {
            if rule_matches(pat, path) {
                let len = pat.len();
                best = match best {
                    Some((l, a)) if l > len || (l == len && a) => Some((l, a)),
                    _ => Some((len, *allow)),
                };
            }
        }
        best.is_none_or(|(_, a)| a)
    }

    pub fn crawl_delay_ms(&self, agent: &str) -> Option<u64> {
        self.group_for(agent).and_then(|g| g.crawl_delay_ms)
    }
}

fn rule_matches(pat: &str, path: &str) -> bool {
    let (pat, anchored) = match pat.strip_suffix('$') {
        Some(p) => (p, true),
        None => (pat, false),
    };
    let parts: Vec<&str> = pat.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if !path.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if let Some(at) = path[pos..].find(part) {
            pos += at + part.len();
        } else {
            return false;
        }
    }
    !anchored || pos == path.len() || parts.last().is_some_and(|l| l.is_empty())
}

/// The path and query of a URL, as robots.txt rules are matched against.
pub fn path_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    match rest.find(['/', '?']) {
        Some(i) => {
            let p = &rest[i..];
            let p = p.split('#').next().unwrap_or(p);
            if p.starts_with('?') {
                format!("/{p}")
            } else {
                p.to_string()
            }
        }
        None => "/".to_string(),
    }
}

/// Spaces requests to one host. Time is passed in, so a test does not sleep.
#[derive(Debug, Default)]
pub struct RateLimiter {
    last: HashMap<String, u64>,
}

impl RateLimiter {
    /// How long to wait before a request to `host` at `now_ms`, given the minimum gap. Records the request as made at the
    /// time it may go.
    pub fn reserve(&mut self, host: &str, now_ms: u64, gap_ms: u64) -> u64 {
        let at = match self.last.get(host) {
            Some(prev) => (prev + gap_ms).max(now_ms),
            None => now_ms,
        };
        self.last.insert(host.to_string(), at);
        at - now_ms
    }
}

/// The honest identity: the browser's own string with ours added, never a made-up one.
pub fn honest_agent(real: &str, version: &str) -> String {
    format!("{} OzboxAgent/{}", real.trim(), version)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXT: &str = "User-agent: *\nDisallow: /private/\nAllow: /private/open\nDisallow: /*.pdf$\nCrawl-delay: 2\n\nUser-agent: ozboxagent\nDisallow: /agents-only-no\n";

    #[test]
    fn the_most_specific_group_and_the_longest_rule_decide() {
        let r = Robots::parse(TXT);
        assert!(r.allowed("Mozilla OzboxAgent/1", "/index.html"));
        assert!(!r.allowed("Mozilla OzboxAgent/1", "/agents-only-no/x"));
        // the named group replaces `*`, so /private/ is not disallowed for us
        assert!(r.allowed("Mozilla OzboxAgent/1", "/private/x"));
        assert!(!r.allowed("SomeoneElse", "/private/x"));
        assert!(r.allowed("SomeoneElse", "/private/open/page"));
        assert!(!r.allowed("SomeoneElse", "/docs/a.pdf"));
        assert!(r.allowed("SomeoneElse", "/docs/a.pdfx"));
        assert_eq!(r.crawl_delay_ms("SomeoneElse"), Some(2000));
        assert_eq!(r.crawl_delay_ms("OzboxAgent"), None);
    }

    #[test]
    fn no_file_or_an_empty_disallow_allows_everything() {
        assert!(Robots::parse("").allowed("x", "/anything"));
        assert!(Robots::parse("User-agent: *\nDisallow:\n").allowed("x", "/a"));
        assert!(!Robots::parse("User-agent: *\nDisallow: /\n").allowed("x", "/a"));
    }

    #[test]
    fn paths_are_taken_from_urls() {
        assert_eq!(path_of("https://a.example"), "/");
        assert_eq!(path_of("https://a.example/x/y?z=1#f"), "/x/y?z=1");
        assert_eq!(path_of("https://a.example?z=1"), "/?z=1");
    }

    #[test]
    fn requests_to_one_site_are_spaced_and_other_sites_are_not_held_up() {
        let mut l = RateLimiter::default();
        assert_eq!(l.reserve("a.example", 1000, 500), 0);
        assert_eq!(l.reserve("a.example", 1100, 500), 400);
        // the second request goes at 1500, so a third asked at 1200 goes at 2000
        assert_eq!(l.reserve("a.example", 1200, 500), 800);
        assert_eq!(l.reserve("b.example", 1200, 500), 0);
        assert_eq!(l.reserve("a.example", 9000, 500), 0);
    }

    #[test]
    fn the_identity_is_the_real_one_plus_ours() {
        assert_eq!(
            honest_agent("Mozilla/5.0 Chrome/130 ", "0.1.0"),
            "Mozilla/5.0 Chrome/130 OzboxAgent/0.1.0"
        );
    }
}
