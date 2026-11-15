//! The demo's stand-in for a box's IDE and desktop: a tiny HTTP server on loopback that answers every request with a page
//! saying so, and accepts a WebSocket upgrade (echoing what it is sent), so the proxy and the browser can be tried with no
//! box. Nothing here is real code-server or KasmVNC.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use super::auth::b64::encode_std;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn accept_key(key: &str) -> String {
    let d = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{GUID}").as_bytes(),
    );
    encode_std(d.as_ref())
}

/// Start the server; it lives as long as the process.
pub fn start(label: &'static str) -> std::io::Result<SocketAddr> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    let addr = l.local_addr()?;
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || serve_one(s, label));
        }
    });
    Ok(addr)
}

fn serve_one(mut s: TcpStream, label: &str) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        match s.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => return,
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let hdr = |n: &str| {
        text.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(n)
                .then(|| v.trim().to_string())
        })
    };
    if hdr("upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
        let key = hdr("sec-websocket-key").unwrap_or_default();
        let _ = write!(
            s,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_key(&key)
        );
        let mut buf = [0u8; 1024];
        while let Ok(n) = s.read(&mut buf) {
            if n == 0 || s.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        return;
    }
    // Read the request's body before answering. A server that answers and closes with request bytes still on their
    // way makes the closing side's kernel reset the connection, and macOS then throws away the part of the answer the
    // proxy had not read yet: the browser got the headers of the signed-in page and an empty body.
    let length = hdr("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut rest = vec![0u8; length.min(64 * 1024)];
    if s.read_exact(&mut rest).is_err() {
        return;
    }
    let first = text.lines().next().unwrap_or("");
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{label}</title></head>\
         <body><h1>{label}</h1><p>Simulated: this is the demo, not a real box.</p><p>{}</p></body></html>",
        first.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(120).collect::<String>().replace('<', "")
    );
    // One write, then a clean close: say we are done, and let the other side finish before the socket goes.
    let answer = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if s.write_all(answer.as_bytes()).is_err() {
        return;
    }
    let _ = s.shutdown(Shutdown::Write);
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut sink = [0u8; 1024];
    while matches!(s.read(&mut sink), Ok(n) if n > 0) {}
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_post_is_read_to_its_end_before_the_answer_and_the_answer_arrives_whole() {
        let addr = start("Simulated web IDE").unwrap();
        let mut c = TcpStream::connect(addr).unwrap();
        let form = "password=0123456789abcdef0123456789abcdef";
        c.write_all(
            format!(
                "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: {}\r\n\r\n",
                form.len()
            )
            .as_bytes(),
        )
        .unwrap();
        // the head alone is not a whole request: nothing comes back yet
        c.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut b = [0u8; 64];
        match c.read(&mut b) {
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "{e}"
            ),
            Ok(n) => panic!(
                "answered before the body arrived: {:?}",
                String::from_utf8_lossy(&b[..n])
            ),
        }
        c.write_all(form.as_bytes()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let (head, body) = out.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
        assert!(body.contains("Simulated web IDE") && body.ends_with("</html>"));
    }
}
