//! Take one small file the box user left for the root helper (a tunnel token, a vault token), once and safely.
//!
//! The requests folder is the box user's to write, so a file in it is the box user's, and the box user can swap it for a
//! symbolic link between a check of its name and a read of it. Root would then read whatever the link names. So the file is
//! opened once, without following a link and without waiting on a pipe; the checks are made on the opened file itself (a
//! plain file, owned by the box user, small enough); the first line is read from that same descriptor; and the name is
//! removed whatever the outcome. The line is printed for the helper and the copy here is wiped.

use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

/// The first line of the file at `path`, if it is a plain file owned by `owner` of at most `max` bytes. The name is removed
/// in every case.
pub fn take(path: &Path, owner: u32, max: u64) -> Result<Zeroizing<String>, String> {
    let r = take_inner(path, owner, max);
    let _ = std::fs::remove_file(path);
    r
}

#[cfg(unix)]
fn take_inner(path: &Path, owner: u32, max: u64) -> Result<Zeroizing<String>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let refused = || "the file was not found, or is not a plain file of the box user's".to_string();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| refused())?;
    // fstat of the descriptor: what was opened, not what the name points at now
    let m = f.metadata().map_err(|_| refused())?;
    if !m.file_type().is_file() || m.uid() != owner || m.nlink() != 1 {
        return Err(refused());
    }
    if m.len() > max {
        return Err("the file is larger than this action takes".into());
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(m.len() as usize));
    f.by_ref()
        .take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|_| refused())?;
    if buf.len() as u64 > max {
        return Err("the file is larger than this action takes".into());
    }
    let end = buf.iter().position(|b| *b == b'\n').unwrap_or(buf.len());
    let line = std::str::from_utf8(&buf[..end]).map_err(|_| "the file is not text".to_string())?;
    Ok(Zeroizing::new(line.trim_end_matches('\r').to_string()))
}

#[cfg(not(unix))]
fn take_inner(_: &Path, _: u32, _: u64) -> Result<Zeroizing<String>, String> {
    Err("this runs on a box only".into())
}

/// The file a request named: `DIR/ID.tok`, where `DIR` is an absolute folder and `ID` is 16 lowercase hex digits. Nothing
/// else can be named, so this reader can never be pointed at another file, even by a request that reaches it. Pure.
pub fn token_path(dir: &str, id: &str) -> Result<std::path::PathBuf, String> {
    if !dir.starts_with('/') || dir.split('/').any(|seg| seg == "..") {
        return Err("--dir is an absolute folder".into());
    }
    if id.len() != 16
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("the token id must be 16 hex digits".into());
    }
    Ok(Path::new(dir).join(format!("{id}.tok")))
}

/// `take-file --dir DIR --id ID --owner UID [--max BYTES]`: print the first line of `DIR/ID.tok` on standard output, or say
/// why not and fail.
pub fn command(words: &[String]) -> Result<(), String> {
    let (mut dir, mut id, mut owner) = (None, None, None);
    let mut max = 4096u64;
    let mut it = words.iter();
    while let Some(flag) = it.next() {
        let v = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--dir" => dir = Some(v.clone()),
            "--id" => id = Some(v.clone()),
            "--owner" => owner = Some(v.parse::<u32>().map_err(|_| "--owner is a uid")?),
            "--max" => max = v.parse().map_err(|_| "--max is a number of bytes")?,
            other => return Err(format!("{other} is not an option of take-file")),
        }
    }
    let (Some(dir), Some(id), Some(owner)) = (dir, id, owner) else {
        return Err("take-file needs --dir, --id and --owner".into());
    };
    let line = take(&token_path(&dir, &id)?, owner, max)?;
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    out.write_all(line.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .map_err(|_| "could not write the answer".to_string())
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn me(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().uid()
    }

    #[test]
    fn a_plain_file_of_the_owner_is_read_once_from_the_descriptor_and_removed() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("a.tok");
        std::fs::write(&f, "first-line-of-the-token\nsecond\n").unwrap();
        let uid = me(&f);
        assert_eq!(&*take(&f, uid, 4096).unwrap(), "first-line-of-the-token");
        assert!(!f.exists(), "taken once");
        assert!(take(&f, uid, 4096).is_err());
    }

    #[test]
    fn a_symbolic_link_is_never_followed_and_its_target_is_left_alone() {
        let d = tempfile::tempdir().unwrap();
        let secret = d.path().join("root-only");
        std::fs::write(&secret, "SENTINEL-VALUE-NEVER-READ\n").unwrap();
        let link = d.path().join("b.tok");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        let e = take(&link, me(&secret), 4096).unwrap_err();
        assert!(!e.contains("SENTINEL"), "{e}");
        assert!(
            std::fs::symlink_metadata(&link).is_err(),
            "the link is removed"
        );
        assert!(secret.exists(), "the target is not");
    }

    #[test]
    fn another_owner_a_hard_link_a_large_file_or_a_folder_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("c.tok");
        std::fs::write(&f, "token\n").unwrap();
        let uid = me(&f);
        assert!(take(&f, uid.wrapping_add(1), 4096).is_err());
        assert!(!f.exists());
        std::fs::write(&f, "x".repeat(5000)).unwrap();
        assert!(take(&f, uid, 4096).unwrap_err().contains("larger"));
        let other = d.path().join("elsewhere");
        std::fs::write(&other, "token\n").unwrap();
        std::fs::hard_link(&other, &f).unwrap();
        assert!(
            take(&f, uid, 4096).is_err(),
            "a second name for another file"
        );
        std::fs::create_dir(&f).unwrap();
        assert!(take(&f, uid, 4096).is_err());
    }

    #[test]
    fn the_command_names_only_a_token_file_in_an_absolute_folder() {
        assert!(command(&[]).is_err());
        assert!(command(&["--owner".into(), "x".into()]).is_err());
        assert!(
            command(&["--path".into(), "/etc/shadow".into()]).is_err(),
            "no free path"
        );
        assert_eq!(
            token_path("/run/ozbox-admin/requests", "0123456789abcdef").unwrap(),
            Path::new("/run/ozbox-admin/requests/0123456789abcdef.tok")
        );
        for (dir, id) in [
            ("run/requests", "0123456789abcdef"),
            ("/run/../etc", "0123456789abcdef"),
            ("/run", "shadow"),
            ("/run", "0123456789ABCDEF"),
            ("/run", "0123456789abcde/"),
        ] {
            assert!(token_path(dir, id).is_err(), "{dir} {id}");
        }
    }
}
