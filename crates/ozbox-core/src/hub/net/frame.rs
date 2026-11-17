//! The bytes on a connection: length-prefixed frames, and a reader that takes them from a stream with read timeouts.
//!
//! A frame is a 4-byte big-endian length, then one type byte, then the payload. The length counts the type byte and the payload.
//! A data frame carries one sealed envelope (as the channel's JSON) after an 8-byte transport number; nothing else is ever a body.

use std::io::{ErrorKind, Read};

use crate::channel::wire::Sealed;

/// The most one data frame may be: one envelope at the profile's body cap, written as hex, with room for its fields.
pub const MAX_FRAME: usize = 2 * 1024 * 1024;

/// The most a handshake frame may be. A peer that has not proved who it is gets no more than this read.
pub const MAX_HANDSHAKE_FRAME: usize = 4 * 1024;

pub const T_HELLO: u8 = 1;
pub const T_CHALLENGE: u8 = 2;
pub const T_PROOF: u8 = 3;
pub const T_ACCEPT: u8 = 4;
pub const T_DATA: u8 = 5;
pub const T_ACK: u8 = 6;
pub const T_PING: u8 = 7;
pub const T_PONG: u8 = 8;
/// First contact (ADR 0042 section 2): a worker that is not on the roster yet sends its enrolment request, once, on a connection
/// of its own. The reply is [`T_ENROLLED`]. Neither is ever a data frame.
pub const T_ENROL: u8 = 9;
pub const T_ENROLLED: u8 = 10;

/// The most an enrolment request may be (an attestation, four public keys and a proof). Read from a peer that has proved nothing.
pub const MAX_ENROL_FRAME: usize = 16 * 1024;

/// One frame, decoded as far as its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A handshake frame: its type and its JSON payload.
    Handshake(u8, Vec<u8>),
    Data(u64, Box<Sealed>),
    Ack(u64),
    Ping,
    Pong,
}

/// Encode a frame. A handshake payload is JSON the caller made.
pub fn encode(f: &Frame) -> Vec<u8> {
    let (t, payload): (u8, Vec<u8>) = match f {
        Frame::Handshake(t, p) => (*t, p.clone()),
        Frame::Data(n, s) => {
            let mut p = n.to_be_bytes().to_vec();
            // a Sealed always serialises: its fields are strings, numbers and bytes as hex
            p.extend(serde_json::to_vec(s.as_ref()).unwrap_or_default());
            (T_DATA, p)
        }
        Frame::Ack(n) => (T_ACK, n.to_be_bytes().to_vec()),
        Frame::Ping => (T_PING, Vec::new()),
        Frame::Pong => (T_PONG, Vec::new()),
    };
    let len = u32::try_from(payload.len() + 1).unwrap_or(u32::MAX);
    let mut out = len.to_be_bytes().to_vec();
    out.push(t);
    out.extend(payload);
    out
}

/// Why a stream was given up. Each is a word an operator can read and a count can be kept under; none carries a byte of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The peer closed the connection.
    Closed,
    /// The connection failed (reset, broken pipe).
    Io,
    /// A frame larger than this stage allows.
    TooBig,
    /// A frame that is not one of the known types, or whose payload does not parse.
    Malformed,
}

impl FrameError {
    pub fn code(self) -> &'static str {
        match self {
            FrameError::Closed => "closed",
            FrameError::Io => "io",
            FrameError::TooBig => "frame-too-big",
            FrameError::Malformed => "malformed-frame",
        }
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// Decode a frame's type and payload (the length is already taken off).
pub fn decode(t: u8, payload: &[u8]) -> Result<Frame, FrameError> {
    match t {
        T_HELLO | T_CHALLENGE | T_PROOF | T_ACCEPT | T_ENROL | T_ENROLLED => {
            Ok(Frame::Handshake(t, payload.to_vec()))
        }
        T_DATA => {
            let n = u64::from_be_bytes(
                payload
                    .get(..8)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(FrameError::Malformed)?,
            );
            let s: Sealed = serde_json::from_slice(payload.get(8..).unwrap_or_default())
                .map_err(|_| FrameError::Malformed)?;
            Ok(Frame::Data(n, Box::new(s)))
        }
        T_ACK => Ok(Frame::Ack(u64::from_be_bytes(
            payload.try_into().map_err(|_| FrameError::Malformed)?,
        ))),
        T_PING if payload.is_empty() => Ok(Frame::Ping),
        T_PONG if payload.is_empty() => Ok(Frame::Pong),
        _ => Err(FrameError::Malformed),
    }
}

/// Takes frames off a stream that has a read timeout: a timeout mid-frame keeps what was read, so the next call goes on.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    /// The next whole frame, `Ok(None)` when the read timed out before one was complete. `max` is the largest frame this stage
    /// accepts; a bigger length is refused before its bytes are read.
    pub fn next(&mut self, r: &mut dyn Read, max: usize) -> Result<Option<Frame>, FrameError> {
        loop {
            if let Some(f) = self.take(max)? {
                return Ok(Some(f));
            }
            let mut chunk = [0u8; 64 * 1024];
            match r.read(&mut chunk) {
                Ok(0) => return Err(FrameError::Closed),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Ok(None)
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => return Err(FrameError::Io),
            }
        }
    }

    /// A whole frame already in the buffer, if any.
    pub fn take(&mut self, max: usize) -> Result<Option<Frame>, FrameError> {
        let Some(len) = self
            .buf
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
        else {
            return Ok(None);
        };
        let len = usize::try_from(len).map_err(|_| FrameError::TooBig)?;
        if len == 0 {
            return Err(FrameError::Malformed);
        }
        if len > max {
            return Err(FrameError::TooBig);
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let t = self.buf[4];
        let f = decode(t, &self.buf[5..4 + len]);
        self.buf.drain(..4 + len);
        f.map(Some)
    }

    /// Bytes read and not yet a frame.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_survive_a_read_split_anywhere() {
        let frames = [
            Frame::Handshake(T_HELLO, b"{\"v\":1}".to_vec()),
            Frame::Ack(42),
            Frame::Ping,
            Frame::Pong,
        ];
        let mut all = Vec::new();
        for f in &frames {
            all.extend(encode(f));
        }
        for cut in 0..all.len() {
            let mut rd = FrameReader::default();
            let mut got = Vec::new();
            let mut a: &[u8] = &all[..cut];
            while let Ok(Some(f)) = rd.next(&mut a, MAX_FRAME) {
                got.push(f);
            }
            let mut b: &[u8] = &all[cut..];
            while let Ok(Some(f)) = rd.next(&mut b, MAX_FRAME) {
                got.push(f);
            }
            assert_eq!(got, frames, "cut at {cut}");
        }
    }

    #[test]
    fn a_length_past_the_stage_cap_is_refused_before_it_is_read() {
        let mut rd = FrameReader::default();
        let mut big = u32::try_from(MAX_HANDSHAKE_FRAME + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        big.push(T_HELLO);
        let mut s: &[u8] = &big;
        assert_eq!(
            rd.next(&mut s, MAX_HANDSHAKE_FRAME),
            Err(FrameError::TooBig)
        );
    }

    #[test]
    fn an_unknown_type_or_a_short_ack_is_malformed() {
        assert_eq!(decode(99, b""), Err(FrameError::Malformed));
        assert_eq!(decode(T_ACK, b"\x01"), Err(FrameError::Malformed));
        assert_eq!(decode(T_DATA, b"\x00\x00"), Err(FrameError::Malformed));
        assert_eq!(decode(T_PING, b"x"), Err(FrameError::Malformed));
    }
}
