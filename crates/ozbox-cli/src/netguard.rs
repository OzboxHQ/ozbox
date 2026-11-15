//! Outbound HTTP for everything that leaves this computer on someone else's say-so: alert webhooks, model endpoints,
//! chat APIs. One client, one policy:
//!
//! * `https` only (an explicit "local endpoint" may also use `http`, and only to a loopback address).
//! * The host is resolved **once**, by the resolver the connection itself uses, and every address it returns must be
//!   a public one. There is no second lookup to race, so a name that flips to a private address after a check is
//!   still refused. Private, loopback, link-local (including the cloud metadata address), shared (CGNAT),
//!   documentation, multicast and reserved ranges are refused, for IPv4, IPv6 and addresses that embed an IPv4.
//! * Redirects are never followed: a 3xx is returned to the caller as a failure.
//! * Errors never carry the URL, the headers or the body, because any of them may hold a token.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

const REFUSED_MARK: &str = "ozbox-refused-address";
const MAX_RESPONSE: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// Public internet only, over `https`.
    Public,
    /// A person's own server on a private network, marked as local: loopback and private-network (RFC 1918 and unique
    /// local) addresses over plain `http`, besides public ones. Link-local (the cloud metadata address) and shared
    /// (CGNAT) ranges stay refused.
    Private,
}

#[derive(Clone)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub guard: Guard,
    pub timeout: Duration,
}

/// A request prints without its header values and body: either may hold a key.
impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("guard", &self.guard)
            .field("header_names", &names)
            .field("has_body", &self.body.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpRequest {
    pub fn new(method: &'static str, url: impl Into<String>, guard: Guard) -> Self {
        HttpRequest {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            guard,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.to_string(), v.into()));
        self
    }

    /// An `application/x-www-form-urlencoded` body.
    pub fn form(mut self, pairs: &[(&str, &str)]) -> Self {
        self.headers.push((
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        self.body = Some(crate::channels::form_encode(pairs).into_bytes());
        self
    }

    pub fn json(mut self, body: &serde_json::Value) -> Self {
        self.headers
            .push(("Content-Type".into(), "application/json".into()));
        self.body = Some(body.to_string().into_bytes());
        self
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

impl HttpResponse {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// The destination is not allowed. The text is safe to show.
    Refused(&'static str),
    /// The request did not complete. The text never carries the URL or any credential.
    Transport(&'static str),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Refused(m) | HttpError::Transport(m) => f.write_str(m),
        }
    }
}

pub trait HttpClient: Send + Sync {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError>;
}

fn v4_public(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn v6_public(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() {
        return false;
    }
    // ::ffff:a.b.c.d, ::a.b.c.d (deprecated), 64:ff9b::/96 (NAT64) and 2002::/16 (6to4) carry an IPv4 address.
    let embedded =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if s[..5] == [0, 0, 0, 0, 0] && (s[5] == 0xffff || s[5] == 0) {
        return v4_public(embedded(s[6], s[7]));
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return v4_public(embedded(s[6], s[7]));
    }
    if s[0] == 0x2002 {
        return v4_public(embedded(s[1], s[2]));
    }
    !((s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link-local
        || (s[0] & 0xffc0) == 0xfec0 // site-local (deprecated)
        || (s[0] & 0xff00) == 0xff00 // multicast
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0])) // discard-only
}

/// Whether `ip` is a public internet address.
pub fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v4_public(v),
        IpAddr::V6(v) => v6_public(v),
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback(),
        IpAddr::V6(v) => v.is_loopback() || v.to_ipv4_mapped().is_some_and(|m| m.is_loopback()),
    }
}

/// RFC 1918 IPv4 and unique-local IPv6: a private network, not loopback, link-local or shared.
fn is_private_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, _, _] = v.octets();
            a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
        }
        IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}

pub fn address_allowed(guard: Guard, ip: IpAddr) -> bool {
    ip_is_public(ip)
        || (guard == Guard::Private && is_loopback(ip))
        || (guard == Guard::Private && is_private_network(ip))
}

/// The scheme and host rules, before any connection. `Err` carries a reason safe to show.
pub fn check_url(guard: Guard, url: &str) -> Result<(), &'static str> {
    let lower = url.to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if guard == Guard::Private && lower.starts_with("http://") {
        &lower["http://".len()..]
    } else {
        return Err("only https addresses are allowed");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err("the address must not carry a user name or password");
    }
    if url.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err("the address contains characters that are not allowed");
    }
    // plain http is for loopback only, whichever guard
    if lower.starts_with("http://") {
        let host = authority.rsplit_once(':').map_or(authority, |(h, p)| {
            if p.bytes().all(|b| b.is_ascii_digit()) {
                h
            } else {
                authority
            }
        });
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let ip = host.parse::<IpAddr>().ok();
        let loop_ok = host == "localhost" || ip.is_some_and(is_loopback);
        let private_ok = guard == Guard::Private && ip.is_some_and(is_private_network);
        if !(loop_ok || private_ok) {
            return Err(if guard == Guard::Private {
                "plain http is allowed only to this computer or a private network address"
            } else {
                "plain http is allowed only to this computer"
            });
        }
    }
    Ok(())
}

struct GuardResolver {
    guard: Guard,
}

impl ureq::Resolver for GuardResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
        if addrs.is_empty() || addrs.iter().any(|a| !address_allowed(self.guard, a.ip())) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                REFUSED_MARK,
            ));
        }
        Ok(addrs)
    }
}

/// The real client.
#[derive(Debug, Default, Clone, Copy)]
pub struct UreqClient;

fn perform(req: &HttpRequest) -> Result<ureq::Response, HttpError> {
    check_url(req.guard, &req.url).map_err(HttpError::Refused)?;
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(5))
        .timeout(req.timeout)
        .resolver(GuardResolver { guard: req.guard })
        .build();
    let mut r = agent.request(req.method, &req.url);
    for (k, v) in &req.headers {
        r = r.set(k, v);
    }
    let result = match &req.body {
        Some(b) => r.send_bytes(b),
        None => r.call(),
    };
    match result {
        Ok(r) => Ok(r),
        Err(ureq::Error::Status(_, r)) => Ok(r),
        Err(ureq::Error::Transport(t)) => {
            // `Display` of a transport error can include the URL; look only for our own marker.
            let text = format!("{t:?}");
            Err(if text.contains(REFUSED_MARK) {
                HttpError::Refused(
                    "that address resolves to a private or reserved network and is refused",
                )
            } else {
                HttpError::Transport("the request did not complete")
            })
        }
    }
}

impl HttpClient for UreqClient {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let resp = perform(req)?;
        let status = resp.status();
        let mut body = String::new();
        let _ = resp
            .into_reader()
            .take(MAX_RESPONSE)
            .read_to_string(&mut body);
        Ok(HttpResponse { status, body })
    }
}

/// A whole answer as bytes, for the credential broker, which relays model replies that are larger than a status check.
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

/// Send through the same address checks as every other outbound request, reading up to `max_bytes` of the answer.
pub fn send_raw(req: &HttpRequest, max_bytes: u64) -> Result<RawResponse, HttpError> {
    let resp = perform(req)?;
    let status = resp.status();
    let content_type = resp.header("content-type").map(str::to_string);
    let mut body = Vec::new();
    let _ = resp.into_reader().take(max_bytes).read_to_end(&mut body);
    Ok(RawResponse {
        status,
        body,
        content_type,
    })
}

/// A scripted client for tests: records every request and answers from a queue.
#[cfg(test)]
#[derive(Default)]
pub struct FakeHttp {
    pub sent: std::sync::Mutex<Vec<HttpRequest>>,
    pub replies: std::sync::Mutex<Vec<Result<HttpResponse, HttpError>>>,
}

#[cfg(test)]
impl FakeHttp {
    pub fn reply(&self, status: u16, body: &str) {
        if let Ok(mut r) = self.replies.lock() {
            r.push(Ok(HttpResponse {
                status,
                body: body.to_string(),
            }));
        }
    }

    pub fn requests(&self) -> Vec<HttpRequest> {
        self.sent.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
impl HttpClient for FakeHttp {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
        if let Ok(mut s) = self.sent.lock() {
            s.push(req.clone());
        }
        let next = self.replies.lock().ok().and_then(|mut r| {
            if r.is_empty() {
                None
            } else {
                Some(r.remove(0))
            }
        });
        next.unwrap_or(Ok(HttpResponse {
            status: 200,
            body: "{}".into(),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    #[test]
    fn address_table() {
        let refused = [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.8.8.8",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "2002:a9fe:a9fe::1",
            "fec0::1",
            "100::1",
        ];
        for a in refused {
            assert!(!ip_is_public(ip(a)), "{a} must be refused");
        }
        let allowed = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "172.32.0.1",
            "100.63.0.1",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ];
        for a in allowed {
            assert!(ip_is_public(ip(a)), "{a} must be allowed");
        }
    }

    #[test]
    fn local_guard_allows_only_loopback_besides_public() {
        assert!(address_allowed(Guard::Private, ip("::1")));
        assert!(address_allowed(Guard::Private, ip("10.0.0.1")));
        assert!(address_allowed(Guard::Private, ip("192.168.1.9")));
        assert!(address_allowed(Guard::Private, ip("172.16.0.4")));
        assert!(address_allowed(Guard::Private, ip("fd12::1")));
        assert!(address_allowed(Guard::Private, ip("127.0.0.1")));
        assert!(!address_allowed(Guard::Private, ip("169.254.169.254")));
        assert!(!address_allowed(Guard::Private, ip("100.64.0.1")));
        assert!(!address_allowed(Guard::Private, ip("fe80::1")));
        assert!(!address_allowed(Guard::Public, ip("10.0.0.1")));
        assert!(!address_allowed(Guard::Private, ip("169.254.169.254")));
        assert!(!address_allowed(Guard::Public, ip("127.0.0.1")));
    }

    #[test]
    fn url_rules() {
        assert!(check_url(Guard::Public, "https://example.com/hook").is_ok());
        for bad in [
            "http://example.com/",
            "ftp://example.com/",
            "file:///etc/passwd",
            "//example.com/",
            "https://user:pw@example.com/",
            "https:///nohost",
            "https://exa mple.com/",
        ] {
            assert!(check_url(Guard::Public, bad).is_err(), "{bad}");
        }
        assert!(check_url(Guard::Public, "http://localhost:8080/v1").is_err());
        assert!(check_url(Guard::Private, "http://localhost:8080/v1").is_ok());
        assert!(check_url(Guard::Private, "http://127.0.0.1:11434/v1").is_ok());
        assert!(check_url(Guard::Private, "http://[::1]:11434/v1").is_ok());
        assert!(check_url(Guard::Public, "http://localhost:8080/v1").is_err());
        assert!(check_url(Guard::Private, "http://example.com/v1").is_err());
        assert!(check_url(Guard::Private, "http://10.0.0.5:11434/v1").is_ok());
        assert!(check_url(Guard::Private, "http://[fd00::5]:8000/v1").is_ok());
        assert!(check_url(Guard::Private, "http://169.254.169.254/v1").is_err());
        assert!(check_url(Guard::Private, "http://example.com/v1").is_err());
        assert!(check_url(Guard::Private, "http://10.0.0.5@evil.example/v1").is_err());
        assert!(check_url(Guard::Public, "http://10.0.0.5/v1").is_err());
    }

    #[test]
    fn literal_private_hosts_are_refused_before_any_connection() {
        let c = UreqClient;
        for u in [
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/",
            "https://[::ffff:169.254.169.254]/",
        ] {
            let r = c.send(&HttpRequest::new("GET", u, Guard::Public));
            assert!(matches!(r, Err(HttpError::Refused(_))), "{u}: {r:?}");
        }
        let r = c.send(&HttpRequest::new(
            "GET",
            "http://example.com/",
            Guard::Public,
        ));
        assert!(matches!(r, Err(HttpError::Refused(_))));
    }

    #[test]
    fn local_endpoint_works_and_redirects_are_not_followed() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().map(|a| a.port()).unwrap_or(0);
        let t = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok(mut rq) = server.recv() else { return };
                let url = rq.url().to_string();
                let mut body = String::new();
                let _ = rq.as_reader().read_to_string(&mut body);
                let auth = rq
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("authorization"))
                    .map(|h| h.value.as_str().to_string())
                    .unwrap_or_default();
                if url == "/redir" {
                    let h = tiny_http::Header::from_bytes(
                        &b"Location"[..],
                        &b"http://169.254.169.254/"[..],
                    );
                    let mut r = tiny_http::Response::from_string("").with_status_code(302);
                    if let Ok(h) = h {
                        r = r.with_header(h);
                    }
                    let _ = rq.respond(r);
                } else {
                    let _ = rq.respond(tiny_http::Response::from_string(format!("{auth}|{body}")));
                }
            }
        });
        let c = UreqClient;
        let ok = c
            .send(
                &HttpRequest::new("POST", format!("http://127.0.0.1:{port}/x"), Guard::Private)
                    .header("Authorization", "Bearer k")
                    .json(&serde_json::json!({"a": 1})),
            )
            .unwrap();
        assert!(ok.ok());
        assert_eq!(ok.body, "Bearer k|{\"a\":1}");
        let r = c
            .send(&HttpRequest::new(
                "GET",
                format!("http://127.0.0.1:{port}/redir"),
                Guard::Private,
            ))
            .unwrap();
        assert_eq!(r.status, 302);
        let _ = t.join();
    }
}
