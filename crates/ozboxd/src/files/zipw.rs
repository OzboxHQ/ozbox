//! A tiny streaming ZIP writer (stored, no compression, sizes in data descriptors), enough to bundle a selection of
//! files for one download. No ZIP64: a bundle is capped well below 4 GiB by the caller.

use std::io::{self, Read, Write};

fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    for (i, slot) in t.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    t
}

pub struct Crc {
    table: [u32; 256],
    state: u32,
}

impl Default for Crc {
    fn default() -> Self {
        Self {
            table: crc_table(),
            state: 0xFFFF_FFFF,
        }
    }
}

impl Crc {
    pub fn update(&mut self, data: &[u8]) {
        for b in data {
            self.state =
                self.table[((self.state ^ u32::from(*b)) & 0xFF) as usize] ^ (self.state >> 8);
        }
    }
    pub fn value(&self) -> u32 {
        !self.state
    }
}

struct Entry {
    name: String,
    crc: u32,
    size: u32,
    offset: u32,
    dir: bool,
}

pub struct ZipWriter<W: Write> {
    out: W,
    pos: u64,
    entries: Vec<Entry>,
    dos_time: u16,
    dos_date: u16,
}

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// DOS date and time from a Unix time in seconds (UTC).
fn dos_stamp(secs: u64) -> (u16, u16) {
    let (y, mo, d, h, mi, s) = crate::timeutil::utc_parts(secs * 1000);
    let year = (y.clamp(1980, 2107) - 1980) as u16;
    (
        ((h as u16) << 11) | ((mi as u16) << 5) | (s as u16 / 2),
        (year << 9) | ((mo as u16) << 5) | d as u16,
    )
}

impl<W: Write> ZipWriter<W> {
    pub fn new(out: W, now_secs: u64) -> Self {
        let (t, d) = dos_stamp(now_secs);
        Self {
            out,
            pos: 0,
            entries: Vec::new(),
            dos_time: t,
            dos_date: d,
        }
    }

    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        self.out.write_all(b)?;
        self.pos += b.len() as u64;
        Ok(())
    }

    fn header(&mut self, name: &str, flags: u16) -> io::Result<()> {
        let mut h = Vec::with_capacity(30 + name.len());
        h.extend_from_slice(&le32(0x0403_4b50));
        h.extend_from_slice(&le16(20));
        h.extend_from_slice(&le16(flags));
        h.extend_from_slice(&le16(0)); // stored
        h.extend_from_slice(&le16(self.dos_time));
        h.extend_from_slice(&le16(self.dos_date));
        h.extend_from_slice(&le32(0)); // crc, in the descriptor
        h.extend_from_slice(&le32(0));
        h.extend_from_slice(&le32(0));
        h.extend_from_slice(&le16(name.len() as u16));
        h.extend_from_slice(&le16(0));
        h.extend_from_slice(name.as_bytes());
        self.put(&h)
    }

    pub fn add_dir(&mut self, name: &str) -> io::Result<()> {
        let name = format!("{}/", name.trim_end_matches('/'));
        let offset = u32::try_from(self.pos).map_err(|_| io::Error::other("zip too large"))?;
        self.header(&name, 0x0800)?;
        self.entries.push(Entry {
            name,
            crc: 0,
            size: 0,
            offset,
            dir: true,
        });
        Ok(())
    }

    /// Copy exactly the bytes `r` yields. `limit` bounds how many are accepted (a file that grew since it was measured).
    pub fn add_file(&mut self, name: &str, r: &mut dyn Read, limit: u64) -> io::Result<u64> {
        let offset = u32::try_from(self.pos).map_err(|_| io::Error::other("zip too large"))?;
        self.header(name, 0x0808)?;
        let mut crc = Crc::default();
        let mut total = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > limit {
                return Err(io::Error::other("file grew while it was being bundled"));
            }
            crc.update(&buf[..n]);
            self.put(&buf[..n])?;
        }
        let size =
            u32::try_from(total).map_err(|_| io::Error::other("file too large for a bundle"))?;
        let mut d = Vec::with_capacity(16);
        d.extend_from_slice(&le32(0x0807_4b50));
        d.extend_from_slice(&le32(crc.value()));
        d.extend_from_slice(&le32(size));
        d.extend_from_slice(&le32(size));
        self.put(&d)?;
        self.entries.push(Entry {
            name: name.to_string(),
            crc: crc.value(),
            size,
            offset,
            dir: false,
        });
        Ok(total)
    }

    pub fn finish(mut self) -> io::Result<W> {
        let cd_start = u32::try_from(self.pos).map_err(|_| io::Error::other("zip too large"))?;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            let mut c = Vec::with_capacity(46 + e.name.len());
            c.extend_from_slice(&le32(0x0201_4b50));
            c.extend_from_slice(&le16(0x031e)); // made by Unix, spec 3.0
            c.extend_from_slice(&le16(20));
            c.extend_from_slice(&le16(if e.dir { 0x0800 } else { 0x0808 }));
            c.extend_from_slice(&le16(0));
            c.extend_from_slice(&le16(self.dos_time));
            c.extend_from_slice(&le16(self.dos_date));
            c.extend_from_slice(&le32(e.crc));
            c.extend_from_slice(&le32(e.size));
            c.extend_from_slice(&le32(e.size));
            c.extend_from_slice(&le16(e.name.len() as u16));
            c.extend_from_slice(&le16(0));
            c.extend_from_slice(&le16(0));
            c.extend_from_slice(&le16(0));
            c.extend_from_slice(&le16(0));
            let mode: u32 = if e.dir {
                0o040_755 << 16 | 0x10
            } else {
                0o100_644 << 16
            };
            c.extend_from_slice(&le32(mode));
            c.extend_from_slice(&le32(e.offset));
            c.extend_from_slice(e.name.as_bytes());
            self.put(&c)?;
        }
        let cd_size =
            u32::try_from(self.pos).map_err(|_| io::Error::other("zip too large"))? - cd_start;
        let n = u16::try_from(entries.len()).map_err(|_| io::Error::other("too many files"))?;
        let mut e = Vec::with_capacity(22);
        e.extend_from_slice(&le32(0x0605_4b50));
        e.extend_from_slice(&le16(0));
        e.extend_from_slice(&le16(0));
        e.extend_from_slice(&le16(n));
        e.extend_from_slice(&le16(n));
        e.extend_from_slice(&le32(cd_size));
        e.extend_from_slice(&le32(cd_start));
        e.extend_from_slice(&le16(0));
        self.put(&e)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16at(b: &[u8], i: usize) -> usize {
        u16::from_le_bytes([b[i], b[i + 1]]) as usize
    }
    fn u32at(b: &[u8], i: usize) -> usize {
        u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize
    }

    #[test]
    fn crc_matches_the_standard_check_value() {
        let mut c = Crc::default();
        c.update(b"123456789");
        assert_eq!(c.value(), 0xCBF4_3926);
    }

    #[test]
    fn a_bundle_reads_back_through_its_central_directory() {
        let mut z = ZipWriter::new(Vec::new(), 1_800_000_000);
        z.add_dir("docs").unwrap();
        z.add_file("docs/a.txt", &mut &b"hello"[..], 100).unwrap();
        z.add_file("b.bin", &mut &[1u8, 2, 3][..], 100).unwrap();
        assert!(z.add_file("big", &mut &[0u8; 10][..], 5).is_err());
        let mut z2 = ZipWriter::new(Vec::new(), 1_800_000_000);
        z2.add_dir("docs").unwrap();
        z2.add_file("docs/a.txt", &mut &b"hello"[..], 100).unwrap();
        z2.add_file("b.bin", &mut &[1u8, 2, 3][..], 100).unwrap();
        let bytes = z2.finish().unwrap();

        let eocd = bytes.len() - 22;
        assert_eq!(u32at(&bytes, eocd), 0x0605_4b50);
        assert_eq!(u16at(&bytes, eocd + 10), 3);
        let mut at = u32at(&bytes, eocd + 16);
        let mut seen = Vec::new();
        for _ in 0..3 {
            assert_eq!(u32at(&bytes, at), 0x0201_4b50);
            let (crc, size, nlen) = (
                u32at(&bytes, at + 16),
                u32at(&bytes, at + 24),
                u16at(&bytes, at + 28),
            );
            let off = u32at(&bytes, at + 42);
            let name = String::from_utf8(bytes[at + 46..at + 46 + nlen].to_vec()).unwrap();
            if !name.ends_with('/') {
                let lnlen = u16at(&bytes, off + 26);
                let data = &bytes[off + 30 + lnlen..off + 30 + lnlen + size];
                let mut c = Crc::default();
                c.update(data);
                assert_eq!(c.value() as usize, crc, "{name}");
                seen.push((name, data.to_vec()));
            } else {
                seen.push((name, Vec::new()));
            }
            at += 46 + nlen;
        }
        assert_eq!(seen[0].0, "docs/");
        assert_eq!(seen[1], ("docs/a.txt".to_string(), b"hello".to_vec()));
        assert_eq!(seen[2], ("b.bin".to_string(), vec![1, 2, 3]));
    }
}
