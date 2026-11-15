//! A small websocket client (RFC 6455), enough for Slack's Socket Mode: connect over TLS, read text messages, answer pings,
//! send text messages. No extensions, no compression, no server role. Light on purpose (ADR 0008): rustls and ring are
//! already dependencies, so there is no new crate and no async runtime.
//!
//! The protocol part ([`Ws`]) works over any `Read + Write`, so it is tested on in-memory streams; [`connect`] makes the TLS
//! stream, and only to public addresses (the same rule as every other outbound call).

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

use crate::channels::b64_std;
use crate::netguard::{address_allowed, Guard};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// The largest message accepted. Slack's envelopes are small.
pub const MAX_MESSAGE: usize = 512 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum WsError {
    Handshake(&'static str),
    Protocol(&'static str),
    Io(io::ErrorKind),
    Closed,
}

impl From<io::Error> for WsError {
    fn from(e: io::Error) -> Self {
        WsError::Io(e.kind())
    }
}

/// What reading gave.
#[derive(Debug, PartialEq, Eq)]
pub enum Msg {
    Text(String),
    /// Nothing arrived before the read timeout.
    Idle,
}

pub struct Ws<S: Read + Write> {
    s: S,
    /// Bytes read but not yet part of a whole frame.
    buf: Vec<u8>,
    /// A message being assembled from fragments.
    partial: Vec<u8>,
    rng: SystemRandom,
}

fn accept_key(key: &str) -> String {
    let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(key.as_bytes());
    ctx.update(GUID.as_bytes());
    b64_std(ctx.finish().as_ref())
}

/// The frame bytes for a client message: always masked, as the standard requires.
pub fn encode_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut f = vec![0x80 | (opcode & 0x0f)];
    let n = payload.len();
    if n < 126 {
        f.push(0x80 | n as u8);
    } else if n <= 0xffff {
        f.push(0x80 | 126);
        f.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        f.push(0x80 | 127);
        f.extend_from_slice(&(n as u64).to_be_bytes());
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

/// One frame from the front of `buf`: (fin, opcode, payload, bytes used). `None` while it is incomplete.
/// A frame read from the front of a buffer: (fin, opcode, payload, bytes used).
pub type Decoded = (bool, u8, Vec<u8>, usize);

pub fn decode_frame(buf: &[u8]) -> Result<Option<Decoded>, WsError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (fin, opcode) = (buf[0] & 0x80 != 0, buf[0] & 0x0f);
    if buf[0] & 0x70 != 0 {
        return Err(WsError::Protocol(
            "an extension was used that was not asked for",
        ));
    }
    let masked = buf[1] & 0x80 != 0;
    let mut len = (buf[1] & 0x7f) as usize;
    let mut at = 2;
    if len == 126 {
        if buf.len() < 4 {
            return Ok(None);
        }
        len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        at = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return Ok(None);
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[2..10]);
        let n = u64::from_be_bytes(b);
        if n > MAX_MESSAGE as u64 {
            return Err(WsError::Protocol("a message is too large"));
        }
        len = n as usize;
        at = 10;
    }
    if len > MAX_MESSAGE {
        return Err(WsError::Protocol("a message is too large"));
    }
    if opcode >= 8 && (!fin || len > 125) {
        return Err(WsError::Protocol(
            "a control frame is not allowed to be split or long",
        ));
    }
    let mask = if masked {
        if buf.len() < at + 4 {
            return Ok(None);
        }
        let m = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
        at += 4;
        Some(m)
    } else {
        None
    };
    if buf.len() < at + len {
        return Ok(None);
    }
    let mut payload = buf[at..at + len].to_vec();
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    Ok(Some((fin, opcode, payload, at + len)))
}

impl<S: Read + Write> Ws<S> {
    /// Do the opening handshake on a connected stream. `host` is the Host header, `path` the request path and query.
    pub fn handshake(mut s: S, host: &str, path: &str) -> Result<Self, WsError> {
        let rng = SystemRandom::new();
        let mut k = [0u8; 16];
        rng.fill(&mut k)
            .map_err(|_| WsError::Handshake("no secure random source"))?;
        let key = b64_std(&k);
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        s.write_all(req.as_bytes())?;
        s.flush()?;
        let mut head = Vec::new();
        let mut one = [0u8; 1];
        // read to the blank line; one byte at a time so nothing after it is taken from the first frame
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > 8192 {
                return Err(WsError::Handshake("the answer was too long"));
            }
            if s.read(&mut one)? == 0 {
                return Err(WsError::Handshake("the connection closed"));
            }
            head.push(one[0]);
        }
        let text = String::from_utf8_lossy(&head).to_string();
        if !text.starts_with("HTTP/1.1 101") {
            return Err(WsError::Handshake(
                "the server did not switch to a websocket",
            ));
        }
        let want = accept_key(&key);
        let ok = text.lines().any(|l| {
            l.split_once(':').is_some_and(|(n, v)| {
                n.eq_ignore_ascii_case("sec-websocket-accept") && v.trim() == want
            })
        });
        if !ok {
            return Err(WsError::Handshake(
                "the server's proof of the handshake was wrong",
            ));
        }
        Ok(Self {
            s,
            buf: Vec::new(),
            partial: Vec::new(),
            rng,
        })
    }

    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), WsError> {
        let mut mask = [0u8; 4];
        self.rng
            .fill(&mut mask)
            .map_err(|_| WsError::Protocol("no secure random source"))?;
        self.s.write_all(&encode_frame(opcode, payload, mask))?;
        self.s.flush()?;
        Ok(())
    }

    pub fn send_text(&mut self, text: &str) -> Result<(), WsError> {
        self.write_frame(0x1, text.as_bytes())
    }

    pub fn close(&mut self) {
        let _ = self.write_frame(0x8, &1000u16.to_be_bytes());
    }

    /// The next text message, answering pings on the way. `Idle` when the read timed out with nothing to say.
    pub fn read_message(&mut self) -> Result<Msg, WsError> {
        loop {
            while let Some((fin, op, payload, used)) = decode_frame(&self.buf)? {
                self.buf.drain(..used);
                match op {
                    0x8 => return Err(WsError::Closed),
                    0x9 => self.write_frame(0xA, &payload)?,
                    0xA => {}
                    0x0..=0x2 => {
                        if op != 0x0 {
                            self.partial.clear();
                        }
                        self.partial.extend_from_slice(&payload);
                        if self.partial.len() > MAX_MESSAGE {
                            return Err(WsError::Protocol("a message is too large"));
                        }
                        if fin {
                            let m = std::mem::take(&mut self.partial);
                            if op == 0x2 {
                                continue;
                            }
                            return String::from_utf8(m)
                                .map(Msg::Text)
                                .map_err(|_| WsError::Protocol("a message was not text"));
                        }
                    }
                    _ => return Err(WsError::Protocol("an unknown kind of frame")),
                }
            }
            let mut chunk = [0u8; 4096];
            match self.s.read(&mut chunk) {
                Ok(0) => return Err(WsError::Closed),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(Msg::Idle)
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// Connect to a `wss://` address over TLS, to public addresses only. The read timeout makes `read_message` return `Idle`
/// every few seconds, so the caller can stop or send a keep-alive.
pub fn connect(url: &str) -> Result<Ws<Tls>, WsError> {
    let rest = url
        .strip_prefix("wss://")
        .ok_or(WsError::Handshake("only wss:// addresses are used"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if path.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return Err(WsError::Handshake("the address is not valid"));
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| WsError::Handshake("the address is not valid"))?,
        ),
        None => (hostport, 443),
    };
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|_| WsError::Handshake("the name could not be found"))?
        .collect();
    if addrs.is_empty()
        || addrs
            .iter()
            .any(|a| !address_allowed(Guard::Public, a.ip()))
    {
        return Err(WsError::Handshake("that address is not allowed"));
    }
    let tcp = addrs
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, Duration::from_secs(8)).ok())
        .ok_or(WsError::Handshake("the server did not answer"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| WsError::Handshake("the secure connection could not be set up"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| WsError::Handshake("the name is not valid"))?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name)
        .map_err(|_| WsError::Handshake("the secure connection could not be set up"))?;
    Ws::handshake(rustls::StreamOwned::new(conn, tcp), hostport, path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A stream whose reads come from a script and whose writes are kept.
    struct Pipe {
        input: VecDeque<u8>,
        out: Vec<u8>,
    }
    impl Read for Pipe {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            if self.input.is_empty() {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let n = b.len().min(self.input.len());
            for slot in b.iter_mut().take(n) {
                *slot = self.input.pop_front().unwrap_or(0);
            }
            Ok(n)
        }
    }
    impl Write for Pipe {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.out.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn server_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![(if fin { 0x80 } else { 0 }) | opcode];
        if payload.len() < 126 {
            f.push(payload.len() as u8);
        } else {
            f.push(126);
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        f.extend_from_slice(payload);
        f
    }

    fn ws_with(frames: Vec<u8>) -> Ws<Pipe> {
        Ws {
            s: Pipe {
                input: frames.into(),
                out: Vec::new(),
            },
            buf: Vec::new(),
            partial: Vec::new(),
            rng: SystemRandom::new(),
        }
    }

    #[test]
    fn the_accept_key_matches_the_example_in_the_standard() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn a_client_frame_is_masked_and_a_server_frame_round_trips_at_every_length() {
        let f = encode_frame(0x1, b"hi", [1, 2, 3, 4]);
        assert_eq!(f[1], 0x80 | 2, "the mask bit is set");
        let (fin, op, payload, used) = decode_frame(&f).unwrap().unwrap();
        assert_eq!(
            (fin, op, payload.as_slice(), used),
            (true, 1, &b"hi"[..], f.len()),
            "decoding unmasks"
        );
        for n in [0usize, 125, 126, 70_000] {
            let p = vec![b'x'; n];
            let f = encode_frame(0x1, &p, [9, 8, 7, 6]);
            assert_eq!(decode_frame(&f).unwrap().unwrap().2, p, "{n}");
        }
        assert_eq!(
            decode_frame(&f[..f.len() - 1]).unwrap(),
            None,
            "an incomplete frame waits"
        );
        assert!(
            decode_frame(&[0xC1, 0x00]).is_err(),
            "an extension bit is refused"
        );
        assert!(
            decode_frame(&[0x89, 126, 0, 200]).is_err(),
            "a long control frame is refused"
        );
    }

    #[test]
    fn a_text_message_is_read_pings_are_answered_fragments_join_and_close_ends() {
        let mut frames = server_frame(0x9, true, b"p");
        frames.extend(server_frame(0x1, false, b"hel"));
        frames.extend(server_frame(0x0, true, b"lo"));
        frames.extend(server_frame(0x8, true, &[3, 232]));
        let mut ws = ws_with(frames);
        assert_eq!(ws.read_message(), Ok(Msg::Text("hello".into())));
        assert_eq!(ws.s.out[0], 0x8A, "a pong went back, masked");
        assert_eq!(ws.read_message(), Err(WsError::Closed));
        let mut idle = ws_with(Vec::new());
        assert_eq!(idle.read_message(), Ok(Msg::Idle));
    }

    #[test]
    fn the_handshake_checks_the_servers_proof_and_a_bad_one_is_refused() {
        // a server that answers with the wrong accept value
        let bad =
            b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: nope\r\n\r\n".to_vec();
        let p = Pipe {
            input: bad.into(),
            out: Vec::new(),
        };
        assert!(matches!(
            Ws::handshake(p, "h", "/x"),
            Err(WsError::Handshake(_))
        ));
        let refused = Pipe {
            input: b"HTTP/1.1 200 OK\r\n\r\n".to_vec().into(),
            out: Vec::new(),
        };
        assert!(Ws::handshake(refused, "h", "/x").is_err());
    }

    #[test]
    fn only_wss_to_public_addresses_is_connected_to() {
        assert!(connect("ws://example.com/x").is_err());
        assert!(connect("wss://127.0.0.1/x").is_err());
        assert!(connect("wss://10.0.0.5:443/x").is_err());
    }
}
