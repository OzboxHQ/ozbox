//! Base64 (standard and URL-safe) and base32, small and dependency-free.

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn enc(data: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(table[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

pub fn encode_std(data: &[u8]) -> String {
    enc(data, STD, true)
}

pub fn encode_url(data: &[u8]) -> String {
    enc(data, URL, false)
}

fn dec(s: &str, table: &[u8; 64]) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = table.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero padding and fewer than a byte plus one char.
    if bits >= 6 || acc != 0 {
        return None;
    }
    Some(out)
}

pub fn decode_url(s: &str) -> Option<Vec<u8>> {
    dec(s, URL)
}

pub fn decode_std(s: &str) -> Option<Vec<u8>> {
    dec(s, STD)
}

/// Equal bytes, compared without stopping at the first difference.
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode_base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn decode_base32(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| *c != b'=' && *c != b' ') {
        let v = B32.iter().position(|&t| t == c.to_ascii_uppercase())? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_std(i.as_bytes()), o);
            assert_eq!(decode_std(o).as_deref(), Some(i.as_bytes()));
        }
        assert_eq!(encode_url(&[0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(decode_url("-__-"), Some(vec![0xfb, 0xff, 0xfe]));
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(decode_base32("MZXW6YTBOI=="), Some(b"foobar".to_vec()));
        assert_eq!(decode_url("a$"), None);
        assert_eq!(decode_url("Zh"), None); // non-zero trailing bits
    }
}
