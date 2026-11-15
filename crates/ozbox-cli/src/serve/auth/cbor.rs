//! A small CBOR reader: just what WebAuthn attestation objects and COSE keys use. Definite lengths only, bounded
//! depth, no tags, no floats.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_int(&self, key: i64) -> Option<&Value> {
        match self {
            Value::Map(m) => m
                .iter()
                .find(|(k, _)| matches!(k, Value::Int(i) if *i == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }
}

const MAX_DEPTH: usize = 8;
const MAX_ITEMS: usize = 256;

/// Decode one value from the front of `data`; returns the value and the bytes consumed.
pub fn decode(data: &[u8]) -> Option<(Value, usize)> {
    let mut pos = 0;
    let v = item(data, &mut pos, 0)?;
    Some((v, pos))
}

fn take<'a>(d: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(n)?;
    let s = d.get(*pos..end)?;
    *pos = end;
    Some(s)
}

fn arg(d: &[u8], pos: &mut usize, info: u8) -> Option<u64> {
    match info {
        0..=23 => Some(u64::from(info)),
        24 => Some(u64::from(take(d, pos, 1)?[0])),
        25 => Some(u64::from(u16::from_be_bytes(
            take(d, pos, 2)?.try_into().ok()?,
        ))),
        26 => Some(u64::from(u32::from_be_bytes(
            take(d, pos, 4)?.try_into().ok()?,
        ))),
        27 => Some(u64::from_be_bytes(take(d, pos, 8)?.try_into().ok()?)),
        _ => None,
    }
}

fn item(d: &[u8], pos: &mut usize, depth: usize) -> Option<Value> {
    if depth > MAX_DEPTH {
        return None;
    }
    let b = take(d, pos, 1)?[0];
    let (major, info) = (b >> 5, b & 31);
    match major {
        0 => Some(Value::Int(i64::try_from(arg(d, pos, info)?).ok()?)),
        1 => Some(Value::Int(-1 - i64::try_from(arg(d, pos, info)?).ok()?)),
        2 => {
            let n = usize::try_from(arg(d, pos, info)?).ok()?;
            Some(Value::Bytes(take(d, pos, n)?.to_vec()))
        }
        3 => {
            let n = usize::try_from(arg(d, pos, info)?).ok()?;
            Some(Value::Text(
                String::from_utf8(take(d, pos, n)?.to_vec()).ok()?,
            ))
        }
        4 => {
            let n = usize::try_from(arg(d, pos, info)?).ok()?;
            if n > MAX_ITEMS {
                return None;
            }
            (0..n)
                .map(|_| item(d, pos, depth + 1))
                .collect::<Option<Vec<_>>>()
                .map(Value::Array)
        }
        5 => {
            let n = usize::try_from(arg(d, pos, info)?).ok()?;
            if n > MAX_ITEMS {
                return None;
            }
            let mut m = Vec::with_capacity(n);
            for _ in 0..n {
                let k = item(d, pos, depth + 1)?;
                let v = item(d, pos, depth + 1)?;
                m.push((k, v));
            }
            Some(Value::Map(m))
        }
        7 => match info {
            20 => Some(Value::Bool(false)),
            21 => Some(Value::Bool(true)),
            22 => Some(Value::Null),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_shapes_webauthn_uses() {
        // {"fmt": "none", "authData": h'0102'}
        let d = [
            0xa2, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x68, b'a', b'u', b't',
            b'h', b'D', b'a', b't', b'a', 0x42, 1, 2,
        ];
        let (v, n) = decode(&d).unwrap();
        assert_eq!(n, d.len());
        assert_eq!(v.get_text("fmt").and_then(Value::as_text), Some("none"));
        assert_eq!(
            v.get_text("authData").and_then(Value::as_bytes),
            Some(&[1u8, 2][..])
        );
        // {1: 2, 3: -7}
        let (k, _) = decode(&[0xa2, 0x01, 0x02, 0x03, 0x26]).unwrap();
        assert_eq!(k.get_int(3).and_then(Value::as_int), Some(-7));
        assert!(decode(&[0x5f]).is_none()); // indefinite length
        assert!(decode(&[0x42, 1]).is_none()); // truncated
    }
}
