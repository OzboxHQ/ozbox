//! Judging what a page asks the browser to fetch, at the destination (ADR 0037, amended 2026-11-11).
//!
//! Every request a tab, a popup, a frame (including one from another site, in its own process) or a worker makes is paused
//! by the browser and judged here before it goes out, and so is every hop of a redirect: Chromium pauses each one. The judge is
//! pure and works from facts the worker collects, so it is tested on fixtures and behaves the same on every box.
//!
//! The rules, in order:
//! 1. While a person holds the session, nothing is judged: it is their browsing.
//! 2. A page that is not a web address (`data:`, `blob:`, `javascript:` ...) is never loaded as a document, and nothing that
//!    is not a web address is sent anything.
//! 3. An address inside the box's network that is not the box itself is refused.
//! 4. A document (a page, a frame, a popup, a redirect) loads only from the box itself, a site on the project's allow-list,
//!    one a person approved for this session, or the destination of the action a person just approved.
//! 5. robots.txt is honoured for a page's own loads (with a site the person exempts, and the box itself, left out). A site whose
//!    robots.txt has not been read yet is held back once; the worker reads it and the agent tries again.
//! 6. Anything that is not a GET (a form post, a script's fetch, a beacon) goes out only to a destination a person approved for
//!    the action now running, or back to the page's own site when that site is marked safe. A page on a safe site posting to
//!    any other site is held, and so is a page with no referrer: the page's site is the one the browser shows, not a header.
//!
//! A page can still *load* images, styles and scripts from other sites with GET, and an address can carry data: that is the
//! web, and it is stated as a limit in the ADR.

use std::collections::HashMap;

use crate::detect::{classify_host, host_in, host_of, reads_only, HostClass};
use crate::robots::{self, Robots};

/// One request, as the browser paused it.
#[derive(Debug, Clone, Default)]
pub struct ReqFacts {
    pub method: String,
    pub url: String,
    /// The browser's resource type: `Document` is a page or a frame; others are `XHR`, `Fetch`, `Image`, `Script` ...
    pub resource_type: String,
    /// The tab's own page (not a frame inside it).
    pub main_frame: bool,
    /// The host of the page the tab shows now (empty when it is not a web address).
    pub top_host: String,
}

impl ReqFacts {
    fn is_document(&self) -> bool {
        self.resource_type.eq_ignore_ascii_case("document")
    }
}

#[derive(Debug, Clone, Default)]
pub struct GateState {
    pub person: bool,
    pub allowed: Vec<String>,
    /// Hosts a person approved for this session (a new domain, the destination of an approved form).
    pub approved: Vec<String>,
    pub safe_sites: Vec<String>,
    pub exempt_sites: Vec<String>,
    pub respect_robots: bool,
    /// robots.txt by host, as read so far.
    pub robots: HashMap<String, Robots>,
    pub agent: String,
    /// While an approved action runs: the destinations a person approved for it.
    pub grant: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// Not a web address.
    Scheme,
    Internal(String),
    NewDomain(String),
    /// Data sent somewhere no person approved.
    Submit(String),
    Robots(String),
    /// robots.txt for this host has not been read yet: the worker reads it, then the agent tries again.
    RobotsUnknown(String),
}

impl Block {
    pub fn host(&self) -> &str {
        match self {
            Block::Scheme => "",
            Block::Internal(h)
            | Block::NewDomain(h)
            | Block::Submit(h)
            | Block::Robots(h)
            | Block::RobotsUnknown(h) => h,
        }
    }

    pub fn word(&self) -> &'static str {
        match self {
            Block::Scheme => "not_a_web_address",
            Block::Internal(_) => "internal",
            Block::NewDomain(_) => "new_domain",
            Block::Submit(_) => "submit",
            Block::Robots(_) => "robots",
            Block::RobotsUnknown(_) => "robots_unread",
        }
    }
}

fn scheme_of(url: &str) -> String {
    url.split(':').next().unwrap_or("").to_ascii_lowercase()
}

/// Decide one request. `None` lets it go.
pub fn judge(st: &GateState, r: &ReqFacts) -> Option<Block> {
    if st.person {
        return None;
    }
    let scheme = scheme_of(&r.url);
    if scheme != "http" && scheme != "https" {
        // a data: image or a blob: video a page made for itself is fine; a document or a send is not
        return if r.is_document() || !reads_only(&r.method) {
            Some(Block::Scheme)
        } else {
            None
        };
    }
    let host = host_of(&r.url);
    let class = classify_host(&host);
    match class {
        HostClass::Invalid => return Some(Block::Scheme),
        HostClass::Internal => return Some(Block::Internal(host)),
        _ => {}
    }
    let granted = st
        .grant
        .as_ref()
        .is_some_and(|g| g.iter().any(|x| x == &host));
    if r.is_document()
        && class != HostClass::Loopback
        && !granted
        && !host_in(&st.allowed, &host)
        && !host_in(&st.approved, &host)
    {
        return Some(Block::NewDomain(host));
    }
    if !reads_only(&r.method) {
        let own_safe_site =
            !r.top_host.is_empty() && host == r.top_host && host_in(&st.safe_sites, &host);
        return if granted || own_safe_site {
            None
        } else {
            Some(Block::Submit(host))
        };
    }
    if r.is_document()
        && r.main_frame
        && st.respect_robots
        && class != HostClass::Loopback
        && !host_in(&st.exempt_sites, &host)
    {
        return match st.robots.get(&host) {
            Some(rb) if !rb.allowed(&st.agent, &robots::path_of(&r.url)) => {
                Some(Block::Robots(host))
            }
            Some(_) => None,
            None => Some(Block::RobotsUnknown(host)),
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st() -> GateState {
        GateState {
            allowed: vec!["app.example".into(), "*.docs.example".into()],
            safe_sites: vec!["app.example".into()],
            respect_robots: true,
            agent: "Chrome OzboxAgent/1".into(),
            robots: [
                ("app.example".to_string(), Robots::parse("")),
                (
                    "a.docs.example".to_string(),
                    Robots::parse("User-agent: *\nDisallow: /private/\n"),
                ),
            ]
            .into(),
            ..GateState::default()
        }
    }

    fn req(method: &str, url: &str, kind: &str, main: bool, top: &str) -> ReqFacts {
        ReqFacts {
            method: method.into(),
            url: url.into(),
            resource_type: kind.into(),
            main_frame: main,
            top_host: top.into(),
        }
    }

    #[test]
    fn a_safe_site_may_post_to_itself_but_not_to_anyone_else() {
        let s = st();
        assert_eq!(
            judge(
                &s,
                &req(
                    "POST",
                    "https://app.example/api",
                    "XHR",
                    false,
                    "app.example"
                )
            ),
            None
        );
        // the page is on a safe site; the destination is not the page's site
        assert_eq!(
            judge(
                &s,
                &req(
                    "POST",
                    "https://evil.example/x",
                    "Fetch",
                    false,
                    "app.example"
                )
            ),
            Some(Block::Submit("evil.example".into()))
        );
        // with no referrer the page's site is still the one the tab shows, so the post is judged the same
        assert_eq!(
            judge(
                &s,
                &req(
                    "PUT",
                    "https://evil.example/x",
                    "Fetch",
                    false,
                    "app.example"
                )
            ),
            Some(Block::Submit("evil.example".into()))
        );
        // a page that is not on a safe site posts nowhere without a person
        assert_eq!(
            judge(
                &s,
                &req(
                    "POST",
                    "https://a.docs.example/x",
                    "XHR",
                    false,
                    "a.docs.example"
                )
            ),
            Some(Block::Submit("a.docs.example".into()))
        );
        // a page that is not a web address has no site to be safe
        assert_eq!(
            judge(
                &s,
                &req("POST", "https://app.example/api", "XHR", false, "")
            ),
            Some(Block::Submit("app.example".into()))
        );
    }

    #[test]
    fn an_approval_covers_only_the_destinations_a_person_saw() {
        let mut s = st();
        s.grant = Some(vec!["forms.example".into()]);
        assert_eq!(
            judge(
                &s,
                &req(
                    "POST",
                    "https://forms.example/s",
                    "Document",
                    true,
                    "x.example"
                )
            ),
            None
        );
        assert_eq!(
            judge(
                &s,
                &req("POST", "https://other.example/s", "XHR", false, "x.example")
            ),
            Some(Block::Submit("other.example".into()))
        );
    }

    #[test]
    fn documents_frames_popups_and_redirects_load_only_from_known_sites() {
        let s = st();
        // a redirect hop, a popup's first page and a frame are all documents judged by where they go
        for (main, top) in [(true, "app.example"), (false, "app.example"), (true, "")] {
            assert_eq!(
                judge(
                    &s,
                    &req("GET", "https://new.example/", "Document", main, top)
                ),
                Some(Block::NewDomain("new.example".into()))
            );
        }
        assert_eq!(
            judge(
                &s,
                &req("GET", "http://127.0.0.1:3000/", "Document", true, "")
            ),
            None
        );
        let mut s2 = st();
        s2.approved = vec!["new.example".into()];
        s2.robots.insert("new.example".into(), Robots::parse(""));
        assert_eq!(
            judge(
                &s2,
                &req("GET", "https://new.example/", "Document", true, "")
            ),
            None
        );
        // a page may load pictures and scripts from other sites
        assert_eq!(
            judge(
                &s,
                &req(
                    "GET",
                    "https://cdn.example/a.js",
                    "Script",
                    false,
                    "app.example"
                )
            ),
            None
        );
    }

    #[test]
    fn non_web_documents_and_internal_addresses_are_refused() {
        let s = st();
        assert_eq!(
            judge(
                &s,
                &req(
                    "GET",
                    "data:text/html,<form>",
                    "Document",
                    true,
                    "app.example"
                )
            ),
            Some(Block::Scheme)
        );
        assert_eq!(
            judge(
                &s,
                &req(
                    "GET",
                    "blob:https://app.example/1",
                    "Document",
                    false,
                    "app.example"
                )
            ),
            Some(Block::Scheme)
        );
        assert_eq!(
            judge(
                &s,
                &req("POST", "data:text/plain,x", "Fetch", false, "app.example")
            ),
            Some(Block::Scheme)
        );
        assert_eq!(
            judge(
                &s,
                &req(
                    "GET",
                    "data:image/png;base64,AA",
                    "Image",
                    false,
                    "app.example"
                )
            ),
            None
        );
        assert_eq!(
            judge(
                &s,
                &req(
                    "GET",
                    "http://169.254.169.254/latest",
                    "XHR",
                    false,
                    "app.example"
                )
            ),
            Some(Block::Internal("169.254.169.254".into()))
        );
    }

    #[test]
    fn robots_apply_to_every_page_load_and_an_unread_site_is_held_once() {
        let s = st();
        assert_eq!(
            judge(
                &s,
                &req(
                    "GET",
                    "https://a.docs.example/private/x",
                    "Document",
                    true,
                    ""
                )
            ),
            Some(Block::Robots("a.docs.example".into()))
        );
        assert_eq!(
            judge(
                &s,
                &req("GET", "https://a.docs.example/public", "Document", true, "")
            ),
            None
        );
        assert_eq!(
            judge(
                &s,
                &req("GET", "https://b.docs.example/", "Document", true, "")
            ),
            Some(Block::RobotsUnknown("b.docs.example".into()))
        );
        let mut ex = st();
        ex.exempt_sites = vec!["*.docs.example".into()];
        assert_eq!(
            judge(
                &ex,
                &req(
                    "GET",
                    "https://a.docs.example/private/x",
                    "Document",
                    true,
                    ""
                )
            ),
            None
        );
    }

    #[test]
    fn a_person_holding_the_session_is_not_judged() {
        let mut s = st();
        s.person = true;
        assert_eq!(
            judge(
                &s,
                &req("POST", "https://pay.example/", "Document", true, "x")
            ),
            None
        );
    }
}
