//! A deliberately tiny HTTP/1.1 reader/writer for the local Unix-socket API.
//!
//! Strict limits: request line + headers at most 16 KiB, at most 64 headers, body at most 64 KiB, a wall-clock
//! deadline per request. One request per connection (`Connection: close`). No chunked bodies, no upgrades, no
//! keep-alive: the API is local and small, and every extra feature would be attack surface.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::time::Instant;

pub const MAX_HEAD: usize = 16 * 1024;
pub const MAX_BODY: usize = 64 * 1024;
pub const MAX_HEADERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub body: Vec<u8>,
    /// The `X-Ozbox-Run-Capability` header: the secret a controlled run's starter was given (see
    /// `RunManager::start_controlled`). Never logged; the only header kept besides the length.
    pub capability: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, value: &impl serde::Serialize) -> Self {
        Self {
            status,
            body: serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec()),
        }
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": message }))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpError {
    #[error("malformed request: {0}")]
    Bad(&'static str),
    #[error("request head too large")]
    HeadTooLarge,
    #[error("request body too large")]
    BodyTooLarge,
    #[error("request timed out")]
    Timeout,
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("connection closed")]
    Closed,
}

impl HttpError {
    pub fn status(&self) -> u16 {
        match self {
            HttpError::Bad(_) => 400,
            HttpError::HeadTooLarge => 431,
            HttpError::BodyTooLarge => 413,
            HttpError::Timeout => 408,
            HttpError::NotImplemented(_) => 501,
            HttpError::Closed => 400,
        }
    }
}

fn read_some<R: Read>(r: &mut R, buf: &mut Vec<u8>, deadline: Instant) -> Result<usize, HttpError> {
    if Instant::now() >= deadline {
        return Err(HttpError::Timeout);
    }
    let mut chunk = [0u8; 2048];
    match r.read(&mut chunk) {
        Ok(0) => Err(HttpError::Closed),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(n)
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Err(HttpError::Timeout)
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(0),
        Err(_) => Err(HttpError::Closed),
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

pub fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            // A raw `+` stays `+` (RFC 3339 offsets are written that way by hand).
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn parse_query(q: &str) -> Result<BTreeMap<String, String>, HttpError> {
    let mut m = BTreeMap::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = percent_decode(k).ok_or(HttpError::Bad("bad query encoding"))?;
        let v = percent_decode(v).ok_or(HttpError::Bad("bad query encoding"))?;
        m.insert(k, v);
    }
    Ok(m)
}

/// A request whose head is parsed and whose body is not (yet) read: what a streamed upload needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub content_length: usize,
    /// Whether a Content-Length header was sent (an empty body is `0`, an absent length is not the same thing).
    pub length_given: bool,
    /// Body bytes that arrived with the head.
    pub early: Vec<u8>,
    pub capability: Option<String>,
}

/// Read the request line and headers only. `deadline` bounds the whole read, so a slow sender cannot hold a thread.
pub fn read_head<R: Read>(r: &mut R, deadline: Instant) -> Result<Head, HttpError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let head_end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err(HttpError::HeadTooLarge);
        }
        read_some(r, &mut buf, deadline)?;
    };
    if head_end > MAX_HEAD {
        return Err(HttpError::HeadTooLarge);
    }
    let head =
        std::str::from_utf8(&buf[..head_end]).map_err(|_| HttpError::Bad("head is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(HttpError::Bad("empty request"))?;
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) => (m, t, v),
        _ => return Err(HttpError::Bad("bad request line")),
    };
    if !(version == "HTTP/1.1" || version == "HTTP/1.0") {
        return Err(HttpError::Bad("unsupported HTTP version"));
    }
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(HttpError::Bad("bad method"));
    }
    if !target.starts_with('/') || target.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return Err(HttpError::Bad("bad target"));
    }
    let mut content_length: Option<usize> = None;
    let mut capability: Option<String> = None;
    let mut count = 0;
    for l in lines {
        count += 1;
        if count > MAX_HEADERS {
            return Err(HttpError::HeadTooLarge);
        }
        let (name, value) = l.split_once(':').ok_or(HttpError::Bad("bad header"))?;
        if name.is_empty() || name.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return Err(HttpError::Bad("bad header name"));
        }
        let lname = name.to_ascii_lowercase();
        if lname == "transfer-encoding" {
            return Err(HttpError::NotImplemented("transfer-encoding"));
        }
        if lname == "x-ozbox-run-capability" {
            let v = value.trim();
            if capability.is_some()
                || v.len() > 128
                || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(HttpError::Bad("bad capability"));
            }
            capability = Some(v.to_string());
        }
        if lname == "content-length" {
            if content_length.is_some() {
                return Err(HttpError::Bad("duplicate content-length"));
            }
            let v = value.trim();
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(HttpError::Bad("bad content-length"));
            }
            content_length = Some(v.parse().map_err(|_| HttpError::BodyTooLarge)?);
        }
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, parse_query(q)?),
        None => (target, BTreeMap::new()),
    };
    Ok(Head {
        method: method.to_string(),
        path: path.to_string(),
        query,
        content_length: content_length.unwrap_or(0),
        length_given: content_length.is_some(),
        early: buf[head_end + 4..].to_vec(),
        capability,
    })
}

/// Read one request, body included (at most [`MAX_BODY`]).
pub fn read_request<R: Read>(r: &mut R, deadline: Instant) -> Result<Request, HttpError> {
    let h = read_head(r, deadline)?;
    let want = h.content_length;
    if want > MAX_BODY {
        return Err(HttpError::BodyTooLarge);
    }
    let mut body = h.early;
    while body.len() < want {
        read_some(r, &mut body, deadline)?;
        if body.len() > MAX_BODY {
            return Err(HttpError::BodyTooLarge);
        }
    }
    body.truncate(want);
    Ok(Request {
        method: h.method,
        path: h.path,
        query: h.query,
        body,
        capability: h.capability,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Unknown",
    }
}

pub fn write_response<W: Write>(w: &mut W, resp: &Response) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        resp.status,
        reason(resp.status),
        resp.body.len()
    );
    w.write_all(head.as_bytes())?;
    w.write_all(&resp.body)?;
    w.flush()
}

/// Write a file-API reply: JSON from memory, or a body streamed from a reader with its Content-Length.
pub fn write_files_reply<W: Write>(
    w: &mut W,
    reply: crate::files::Reply,
    head_only: bool,
) -> io::Result<()> {
    use crate::files::Body;
    let (len, content_type_default) = match &reply.body {
        Body::Bytes(b) => (b.len() as u64, "application/json"),
        Body::Stream { len, .. } => (*len, "application/octet-stream"),
    };
    let mut head = format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status));
    let mut has_type = false;
    for (k, v) in &reply.headers {
        if k.eq_ignore_ascii_case("content-type") {
            has_type = true;
        }
        // Header values come from our own code, but a stray line break must never split a response.
        if k.bytes().all(|b| b.is_ascii_graphic()) && !v.bytes().any(|b| b == b'\r' || b == b'\n') {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    if !has_type {
        head.push_str(&format!("Content-Type: {content_type_default}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {len}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n"
    ));
    w.write_all(head.as_bytes())?;
    if !head_only {
        match reply.body {
            Body::Bytes(b) => w.write_all(&b)?,
            Body::Stream { mut reader, len } => {
                let copied = io::copy(&mut io::Read::take(&mut reader, len), w)?;
                if copied != len {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the file changed while it was being sent",
                    ));
                }
            }
        }
    }
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    fn parse(raw: &[u8]) -> Result<Request, HttpError> {
        read_request(
            &mut Cursor::new(raw.to_vec()),
            Instant::now() + Duration::from_secs(5),
        )
    }

    #[test]
    fn parses_get_with_query() {
        let r = parse(b"GET /v1/metrics?since=2026-11-09T10%3A00%3A00%2B01%3A00&step=1m HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/v1/metrics");
        assert_eq!(r.query["since"], "2026-11-09T10:00:00+01:00");
        assert_eq!(r.query["step"], "1m");
        assert_eq!(
            parse(b"GET /a?t=1+2 HTTP/1.1\r\n\r\n").unwrap().query["t"],
            "1+2"
        );
    }

    #[test]
    fn parses_post_body() {
        let r =
            parse(b"POST /v1/runs HTTP/1.1\r\nContent-Length: 7\r\n\r\n{\"a\":1}EXTRA").unwrap();
        assert_eq!(r.body, b"{\"a\":1}");
    }

    #[test]
    fn rejects_malformed_and_oversized() {
        assert_eq!(
            parse(b"GET\r\n\r\n").unwrap_err(),
            HttpError::Bad("bad request line")
        );
        assert!(matches!(
            parse(b"GET / HTTP/2\r\n\r\n"),
            Err(HttpError::Bad(_))
        ));
        assert!(matches!(
            parse(b"get / HTTP/1.1\r\n\r\n"),
            Err(HttpError::Bad(_))
        ));
        assert!(matches!(
            parse(b"GET http://x/ HTTP/1.1\r\n\r\n"),
            Err(HttpError::Bad(_))
        ));
        assert!(matches!(
            parse(b"GET / HTTP/1.1\r\nBad Header\r\n\r\n"),
            Err(HttpError::Bad(_))
        ));
        assert!(parse(b"GET /%zz HTTP/1.1\r\n\r\n").is_ok()); // path is not decoded; only the query is
        assert!(matches!(
            parse(b"GET /?a=%zz HTTP/1.1\r\n\r\n"),
            Err(HttpError::Bad(_))
        ));
        let long = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD + 10));
        assert_eq!(parse(long.as_bytes()).unwrap_err(), HttpError::HeadTooLarge);
        let big = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(parse(big.as_bytes()).unwrap_err(), HttpError::BodyTooLarge);
        assert_eq!(
            parse(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap_err(),
            HttpError::NotImplemented("transfer-encoding")
        );
        assert!(matches!(
            parse(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"),
            Err(HttpError::Bad(_))
        ));
        assert!(matches!(
            parse(b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n"),
            Err(HttpError::Bad(_))
        ));
        let many: String = (0..70).map(|i| format!("H{i}: v\r\n")).collect();
        assert_eq!(
            parse(format!("GET / HTTP/1.1\r\n{many}\r\n").as_bytes()).unwrap_err(),
            HttpError::HeadTooLarge
        );
        // truncated body / head
        assert_eq!(
            parse(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab").unwrap_err(),
            HttpError::Closed
        );
        assert_eq!(parse(b"GET / HTTP/1.1\r\n").unwrap_err(), HttpError::Closed);
    }

    #[test]
    fn expired_deadline_times_out() {
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            read_request(&mut Cursor::new(b"GET / HTTP/1.1\r\n".to_vec()), past).unwrap_err(),
            HttpError::Timeout
        );
    }

    #[test]
    fn writes_a_well_formed_response() {
        let mut out = Vec::new();
        write_response(&mut out, &Response::error(404, "nope")).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(s.contains("Content-Length: 16\r\n") && s.ends_with("{\"error\":\"nope\"}"));
    }
}
