//! The checks that stand between a download and its use. All pure: they take bytes or text and answer yes or no.

/// SHA-256 (FIPS 180-4). Small and dependency-free on purpose; tested against the standard vectors.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

/// Constant-shape comparison of two hex digests (case-insensitive).
pub fn same_digest(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim().to_ascii_lowercase(), b.trim().to_ascii_lowercase());
    a.len() == 64
        && a.len() == b.len()
        && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The digest a `sha256sum`-style file lists for exactly this file name.
pub fn digest_for(sums: &str, file: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let digest = it.next()?;
        let name = it.next()?.trim_start_matches('*');
        (is_digest(digest) && name == file && it.next().is_none())
            .then(|| digest.to_ascii_lowercase())
    })
}

/// The file names in a `sha256sum`-style file that match `pattern` (one optional `*`).
pub fn names_matching(sums: &str, pattern: &str) -> Vec<String> {
    sums.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let digest = it.next()?;
            let name = it.next()?.trim_start_matches('*');
            (is_digest(digest) && wildcard_match(pattern, name)).then(|| name.to_string())
        })
        .collect()
}

/// A file holding just a digest (`kubectl.sha256` style); a trailing file name is tolerated.
pub fn single_digest(text: &str) -> Option<String> {
    let first = text.split_whitespace().next()?;
    is_digest(first).then(|| first.to_ascii_lowercase())
}

/// Match with at most one `*`.
pub fn wildcard_match(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((pre, post)) => {
            name.len() >= pre.len() + post.len() && name.starts_with(pre) && name.ends_with(post)
        }
    }
}

/// The part of `name` a single `*` stood for.
pub fn wildcard_capture<'a>(pattern: &str, name: &'a str) -> Option<&'a str> {
    let (pre, post) = pattern.split_once('*')?;
    if !wildcard_match(pattern, name) {
        return None;
    }
    name.get(pre.len()..name.len() - post.len())
}

/// The primary key fingerprints in `gpg --show-keys --with-colons` output. Only `fpr` records that follow a `pub`
/// record count; sub-keys are ignored, because a vendor publishes its primary fingerprint.
pub fn primary_fingerprints(colon_output: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut want = false;
    for l in colon_output.lines() {
        let f: Vec<&str> = l.split(':').collect();
        match f.first().copied() {
            Some("pub") => want = true,
            Some("sub") | Some("ssb") | Some("sec") => want = false,
            Some("fpr") if want => {
                if let Some(fp) = f.get(9) {
                    out.push(fp.to_ascii_uppercase());
                    want = false;
                }
            }
            _ => {}
        }
    }
    out
}

/// The key file is accepted only if it holds at least one primary key and every one of them is pinned. A file that
/// carries a key the vendor never published is refused whole.
pub fn fingerprints_match(colon_output: &str, pinned: &[String]) -> bool {
    let fps = primary_fingerprints(colon_output);
    !fps.is_empty()
        && fps
            .iter()
            .all(|f| pinned.iter().any(|p| p.eq_ignore_ascii_case(f)))
}

/// The first dotted version number in a program's output (`1.2`, `v22.4.1`, `NVIM v0.9.5`).
pub fn first_version(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let mut j = i;
            let mut dots = 0;
            while j < b.len()
                && (b[j].is_ascii_digit()
                    || (b[j] == b'.' && j + 1 < b.len() && b[j + 1].is_ascii_digit()))
            {
                if b[j] == b'.' {
                    dots += 1;
                }
                j += 1;
            }
            if dots >= 1 {
                return Some(text[i..j].to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_standard_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_hex(&million_a),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn digests_compare_case_insensitively_and_refuse_short_ones() {
        let d = sha256_hex(b"abc");
        assert!(same_digest(&d, &d.to_ascii_uppercase()));
        assert!(!same_digest(&d, &sha256_hex(b"abd")));
        assert!(!same_digest("abc", "abc"));
    }

    #[test]
    fn checksum_files_are_read_by_exact_name() {
        let h1 = sha256_hex(b"one");
        let h2 = sha256_hex(b"two");
        let sums = format!("{h1}  node-v22.1.0-linux-x64.tar.xz\n{h2} *node-v22.1.0-linux-arm64.tar.xz\nnot a line\n");
        assert_eq!(digest_for(&sums, "node-v22.1.0-linux-x64.tar.xz"), Some(h1));
        assert_eq!(
            digest_for(&sums, "node-v22.1.0-linux-arm64.tar.xz"),
            Some(h2)
        );
        assert_eq!(digest_for(&sums, "node-v22.1.0-linux-x64.tar.gz"), None);
        assert_eq!(digest_for(&sums, "node-v22.1.0-linux-x64"), None);
        assert_eq!(
            names_matching(&sums, "node-v22.*-linux-x64.tar.xz"),
            vec!["node-v22.1.0-linux-x64.tar.xz".to_string()]
        );
        assert_eq!(
            wildcard_capture(
                "node-v22.*-linux-x64.tar.xz",
                "node-v22.1.0-linux-x64.tar.xz"
            ),
            Some("1.0")
        );
    }

    #[test]
    fn a_single_digest_file_may_name_its_file() {
        let h = sha256_hex(b"k");
        assert_eq!(single_digest(&format!("{h}\n")), Some(h.clone()));
        assert_eq!(single_digest(&format!("{h}  kubectl")), Some(h));
        assert_eq!(single_digest("<html>"), None);
    }

    #[test]
    fn only_the_pinned_primary_key_is_accepted() {
        let good = "pub:-:4096:1:AAAA:1:::-:::scESC::::::23::0:\nfpr:::::::::2C6106201985B60E6C7AC87323F3D4EA75716059:\nuid:-::::1::HASH::GitHub CLI:::::::::0:\nsub:-:4096:1:BBBB:1::::::e::::::23:\nfpr:::::::::7F38BBB59D064DBCB3D84D725612B36462313325:\n";
        let pin = vec!["2C6106201985B60E6C7AC87323F3D4EA75716059".to_string()];
        assert!(fingerprints_match(good, &pin));
        // A sub-key's fingerprint is not a primary one: pinning only it does not match.
        let sub = vec!["7F38BBB59D064DBCB3D84D725612B36462313325".to_string()];
        assert!(!fingerprints_match(good, &sub));
        // A second primary key that was never pinned: the whole file is refused.
        let two = format!("{good}pub:-:4096:1:CCCC:1:::-:::scESC::::::23::0:\nfpr:::::::::0000000000000000000000000000000000000000:\n");
        assert!(!fingerprints_match(&two, &pin));
        let mut both = pin.clone();
        both.push("0000000000000000000000000000000000000000".into());
        assert!(fingerprints_match(&two, &both));
        assert!(!fingerprints_match("", &pin));
    }

    #[test]
    fn versions_are_found_in_typical_output() {
        assert_eq!(
            first_version("NVIM v0.9.5\nBuild type"),
            Some("0.9.5".into())
        );
        assert_eq!(first_version("v22.4.1"), Some("22.4.1".into()));
        assert_eq!(first_version("git version 2.43.0"), Some("2.43.0".into()));
        assert_eq!(
            first_version("go version go1.22.2 linux/amd64"),
            Some("1.22.2".into())
        );
        assert_eq!(first_version("no numbers"), None);
        assert_eq!(first_version("build 7"), None);
    }
}
