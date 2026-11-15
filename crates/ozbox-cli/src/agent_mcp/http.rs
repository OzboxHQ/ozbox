//! The little HTTP/1.1 both ends of the agent socket speak: one request, one answer, the connection kept open between them.
//!
//! Only what the MCP endpoint needs: a request line, headers, a `Content-Length` body. A request that is larger than the
//! limits, that uses chunked bodies, or that is not well formed is refused, never guessed at.

use std::io::{BufRead, BufReader, Read, Write};

const MAX_HEAD: usize = 16 * 1024;

/// A request read off a connection.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Why a request could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The other end closed the connection between requests (not an error).
    Closed,
    TooLarge,
    Malformed,
    Io,
}

/// Read one request. `Closed` means a clean end before any byte of a new request.
pub fn read_request<R: Read>(r: &mut BufReader<R>, max_body: usize) -> Result<Request, ReadError> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = r
            .by_ref()
            .take((MAX_HEAD + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| ReadError::Io)?;
        if n == 0 {
            return Err(if head.is_empty() {
                ReadError::Closed
            } else {
                ReadError::Malformed
            });
        }
        if line.last() != Some(&b'\n') {
            return Err(ReadError::TooLarge);
        }
        let blank = line == b"\r\n" || line == b"\n";
        head.extend_from_slice(&line);
        if head.len() > MAX_HEAD {
            return Err(ReadError::TooLarge);
        }
        if blank {
            break;
        }
    }
    let text = String::from_utf8(head).map_err(|_| ReadError::Malformed)?;
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let first = lines.next().ok_or(ReadError::Malformed)?;
    let mut parts = first.split(' ');
    let (Some(method), Some(path), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ReadError::Malformed);
    };
    if !version.starts_with("HTTP/1.") || !path.starts_with('/') {
        return Err(ReadError::Malformed);
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            continue;
        }
        let (k, v) = l.split_once(':').ok_or(ReadError::Malformed)?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    let find = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
    };
    if find("transfer-encoding").is_some() {
        return Err(ReadError::Malformed);
    }
    let len: usize = match find("content-length") {
        None => 0,
        Some(v) => v.parse().map_err(|_| ReadError::Malformed)?,
    };
    if len > max_body {
        return Err(ReadError::TooLarge);
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|_| ReadError::Io)?;
    Ok(Request {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body,
    })
}

/// Write one answer (the connection stays open).
pub fn write_response<W: Write>(
    w: &mut W,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Error",
    };
    // a caller turned away for being too many is told when to come back
    let retry = if status == 429 {
        "Retry-After: 60\r\n"
    } else {
        ""
    };
    write!(
        w,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{retry}\r\n",
        body.len()
    )?;
    w.write_all(body)?;
    w.flush()
}

/// Write one request (the client's end).
pub fn write_request<W: Write>(
    w: &mut W,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<()> {
    write!(w, "{method} {path} HTTP/1.1\r\nHost: ozbox-agent-mcp\r\n")?;
    for (k, v) in headers {
        write!(w, "{k}: {v}\r\n")?;
    }
    write!(w, "Content-Length: {}\r\n\r\n", body.len())?;
    w.write_all(body)?;
    w.flush()
}

/// Read one answer: the status and the body.
pub fn read_response<R: Read>(
    r: &mut BufReader<R>,
    max_body: usize,
) -> Result<(u16, Vec<u8>), ReadError> {
    let mut line = String::new();
    r.by_ref()
        .take(MAX_HEAD as u64)
        .read_line(&mut line)
        .map_err(|_| ReadError::Io)?;
    if line.is_empty() {
        return Err(ReadError::Closed);
    }
    let status: u16 = line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(ReadError::Malformed)?;
    let mut len = 0usize;
    let mut total = line.len();
    loop {
        let mut h = String::new();
        r.by_ref()
            .take(MAX_HEAD as u64)
            .read_line(&mut h)
            .map_err(|_| ReadError::Io)?;
        total += h.len();
        if h.is_empty() || total > MAX_HEAD {
            return Err(ReadError::Malformed);
        }
        if h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().map_err(|_| ReadError::Malformed)?;
            }
        }
    }
    if len > max_body {
        return Err(ReadError::TooLarge);
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|_| ReadError::Io)?;
    Ok((status, body))
}
