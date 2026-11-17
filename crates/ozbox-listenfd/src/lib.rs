//! Socket activation, the receiving end (`sd_listen_fds(3)`).
//!
//! systemd binds a socket as root, in a folder root owns, and starts the service with the open descriptor as fd 3, naming
//! the process in `LISTEN_PID` and the count in `LISTEN_FDS`. The service never binds, creates or `chmod`s that path, so
//! nothing the service's own user can do to its folders changes who may connect. That is the point of using it for the
//! dashboard's socket (ADR 0040, decision 3).
//!
//! The descriptor is re-made close-on-exec at once and the original closed, and the two variables are removed: otherwise
//! every run the daemon starts would inherit a listening socket it could accept connections on.

#![cfg(unix)]

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;

/// The first descriptor systemd passes (`SD_LISTEN_FDS_START`).
const FIRST_FD: RawFd = 3;

/// The descriptor this process was handed, from the text of `LISTEN_PID` and `LISTEN_FDS`: `Some(fd)` only when the
/// variables name this process and at least one descriptor. Anything else (unset, another process, junk) is `None`.
pub fn parse(listen_pid: Option<&str>, listen_fds: Option<&str>, my_pid: u32) -> Option<RawFd> {
    let pid: u32 = listen_pid?.trim().parse().ok()?;
    let n: u32 = listen_fds?.trim().parse().ok()?;
    (pid == my_pid && n >= 1).then_some(FIRST_FD)
}

/// The name systemd gives the descriptor of `ozboxd-supervisor.socket` (`LISTEN_FDNAMES`), checked when it is set.
pub const SOCKET_NAME: &str = "ozboxd-supervisor.socket";

/// A marker a daemon that takes its socket from systemd carries in its binary (it is in the line the daemon logs when the
/// socket is up). The setup script writes the socket unit only for a daemon whose file contains it: an older daemon would
/// ignore `LISTEN_FDS` and leave a listening socket inheritable by every run it starts. Never reword it.
pub const DAEMON_MARKER: &str = "ozbox-listenfd-protocol-1";

/// Most descriptors one socket unit hands over; a larger count is not ours.
const MAX_FDS: u32 = 16;

/// Adopt `fd` as a listener, re-made close-on-exec, and close the original. The caller owns `fd` and must not use it again.
#[allow(unsafe_code)]
pub fn adopt(fd: RawFd) -> std::io::Result<UnixListener> {
    // SAFETY: the caller hands over a descriptor it owns and never touches again (systemd's, passed to this process).
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // `try_clone` is `F_DUPFD_CLOEXEC`; dropping `owned` closes the inheritable original
    let cloexec = owned.try_clone()?;
    drop(owned);
    Ok(UnixListener::from(cloexec))
}

#[allow(unsafe_code)]
fn sockopt_int(fd: RawFd, opt: libc::c_int) -> std::io::Result<libc::c_int> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v` and `len` are valid for the call; an invalid `fd` makes it fail, not misbehave.
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if r == 0 {
        Ok(v)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Is `fd` a listening `AF_UNIX` `SOCK_STREAM` socket? Anything else (a pipe, a file, a datagram or a connected socket, an
/// internet socket) is not what the socket unit passes and is refused.
#[allow(unsafe_code)]
fn is_listening_unix_stream(fd: RawFd) -> bool {
    if sockopt_int(fd, libc::SO_TYPE).ok() != Some(libc::SOCK_STREAM) {
        return false;
    }
    // Linux says whether it listens. (macOS has no such answer for a Unix socket; there a socket with a peer is refused,
    // which is all a development machine can tell. The daemon runs on Linux.)
    #[cfg(target_os = "linux")]
    if sockopt_int(fd, libc::SO_ACCEPTCONN).map_or(true, |v| v == 0) {
        return false;
    }
    // SAFETY: a zeroed address and its true size.
    let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut plen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: the pointer and length describe `peer`; a listener has no peer, so this fails with ENOTCONN.
    if unsafe {
        libc::getpeername(
            fd,
            (&mut peer as *mut libc::sockaddr_storage).cast(),
            &mut plen,
        )
    } == 0
    {
        return false;
    }
    // SAFETY: a zeroed `sockaddr_storage` and its true size are valid for `getsockname`.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: as above; the pointer and length describe `ss`.
    let r = unsafe {
        libc::getsockname(
            fd,
            (&mut ss as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    };
    r == 0 && libc::c_int::from(ss.ss_family) == libc::AF_UNIX
}

/// Is `fd` a listening `AF_INET` `SOCK_STREAM` socket? What a service's route (a TCP port held by PID 1) passes: a Unix socket, a
/// datagram socket, an IPv6 socket or a connected one is refused.
#[allow(unsafe_code)]
fn is_listening_inet_stream(fd: RawFd) -> bool {
    if sockopt_int(fd, libc::SO_TYPE).ok() != Some(libc::SOCK_STREAM) {
        return false;
    }
    #[cfg(target_os = "linux")]
    if sockopt_int(fd, libc::SO_ACCEPTCONN).map_or(true, |v| v == 0) {
        return false;
    }
    // SAFETY: a zeroed `sockaddr_storage` and its true size are valid for `getsockname`.
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: the pointer and length describe `ss`.
    let r = unsafe {
        libc::getsockname(
            fd,
            (&mut ss as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    };
    r == 0 && libc::c_int::from(ss.ss_family) == libc::AF_INET
}

#[allow(unsafe_code)]
fn close_fd(fd: RawFd) {
    // SAFETY: a passed descriptor this process owns and will not use again.
    unsafe {
        libc::close(fd);
    }
}

/// Take the listener out of the passed descriptors: the first must be a listening Unix stream socket (and, when systemd
/// named it, the socket unit's), it is returned close-on-exec; every other passed descriptor is closed, so none can leak
/// into a run. A descriptor that is not what the unit passes is closed and refused.
pub fn adopt_passed(fds: &[RawFd], names: Option<&str>) -> std::io::Result<UnixListener> {
    adopt_passed_named(fds, names, SOCKET_NAME)
}

/// [`adopt_passed`] for a socket unit of another name (`ozbox-hubd.socket`): the same checks, with `want` as the name systemd
/// must have given the first descriptor when it named them.
pub fn adopt_passed_named(
    fds: &[RawFd],
    names: Option<&str>,
    want: &str,
) -> std::io::Result<UnixListener> {
    let Some((&first, extra)) = fds.split_first() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no descriptor was passed",
        ));
    };
    for &fd in extra {
        close_fd(fd);
    }
    let name_ok = names.is_none_or(|n| n.split(':').next() == Some(want));
    if !name_ok || !is_listening_unix_stream(first) {
        close_fd(first);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the descriptor passed is not the listening socket this unit passes",
        ));
    }
    adopt(first)
}

/// Adopt every descriptor in `fds` as a TCP listener, in order, each re-made close-on-exec with the original closed. All of them
/// must be listening `AF_INET` stream sockets: if any is not, every one is closed and the call fails, so a proxy never serves on
/// part of its route. The caller owns the descriptors and must not use them again.
#[allow(unsafe_code)]
pub fn adopt_passed_tcp(fds: &[RawFd]) -> std::io::Result<Vec<std::net::TcpListener>> {
    if fds.is_empty() || !fds.iter().all(|&fd| is_listening_inet_stream(fd)) {
        for &fd in fds {
            close_fd(fd);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the descriptors passed are not all listening TCP sockets",
        ));
    }
    let mut out = Vec::with_capacity(fds.len());
    for &fd in fds {
        // SAFETY: the caller hands over a descriptor it owns and never touches again (systemd's, passed to this process).
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // `try_clone` is `F_DUPFD_CLOEXEC`; dropping `owned` closes the inheritable original
        let cloexec = owned.try_clone()?;
        drop(owned);
        out.push(std::net::TcpListener::from(cloexec));
    }
    Ok(out)
}

/// Every listening TCP socket systemd handed this process, in the order of the socket unit's `ListenStream=` lines, taken once.
/// `None`: none was passed (the program was not started from a socket unit): there is no fallback that binds, because a port the
/// program binds itself is a port nobody else holds. The environment variables are removed either way.
pub fn take_tcp_listeners() -> Option<std::io::Result<Vec<std::net::TcpListener>>> {
    let pid = std::env::var("LISTEN_PID").ok();
    let fds = std::env::var("LISTEN_FDS").ok();
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    let first = parse(pid.as_deref(), fds.as_deref(), std::process::id())?;
    let n: u32 = fds.as_deref()?.trim().parse().ok()?;
    if n > MAX_FDS {
        // not ours: close what was passed and refuse
        for fd in first..first + n as RawFd {
            close_fd(fd);
        }
        return Some(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "more descriptors were passed than a route can have",
        )));
    }
    let passed: Vec<RawFd> = (first..first + n as RawFd).collect();
    Some(adopt_passed_tcp(&passed))
}

/// The listening socket systemd handed this process, taken once. `None`: none was passed (the service was not started
/// from a socket unit, or it is an older host). The environment variables are removed either way.
pub fn take_unix_listener() -> Option<std::io::Result<UnixListener>> {
    take_unix_listener_named(SOCKET_NAME)
}

/// [`take_unix_listener`] for a socket unit of another name (`ozbox-hubd.socket`).
pub fn take_unix_listener_named(want: &str) -> Option<std::io::Result<UnixListener>> {
    let pid = std::env::var("LISTEN_PID").ok();
    let fds = std::env::var("LISTEN_FDS").ok();
    let names = std::env::var("LISTEN_FDNAMES").ok();
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    let first = parse(pid.as_deref(), fds.as_deref(), std::process::id())?;
    let n: u32 = fds.as_deref()?.trim().parse().ok()?;
    let n = n.min(MAX_FDS);
    let passed: Vec<RawFd> = (first..first + n as RawFd).collect();
    Some(adopt_passed_named(&passed, names.as_deref(), want))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn only_a_descriptor_named_for_this_process_is_taken() {
        assert_eq!(parse(Some("42"), Some("1"), 42), Some(3));
        assert_eq!(parse(Some("42"), Some("2"), 42), Some(3));
        assert_eq!(parse(Some("41"), Some("1"), 42), None, "another process's");
        assert_eq!(parse(Some("42"), Some("0"), 42), None);
        assert_eq!(parse(None, Some("1"), 42), None);
        assert_eq!(parse(Some("42"), None, 42), None);
        assert_eq!(parse(Some("x"), Some("1"), 42), None);
        assert_eq!(parse(Some("42"), Some("-1"), 42), None);
    }

    #[allow(unsafe_code)]
    fn cloexec(fd: RawFd) -> Option<bool> {
        let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        (r >= 0).then_some(r & libc::FD_CLOEXEC != 0)
    }

    #[allow(unsafe_code)]
    fn listener(d: &tempfile::TempDir, name: &str) -> RawFd {
        let fd = UnixListener::bind(d.path().join(name))
            .unwrap()
            .into_raw_fd();
        // std makes its sockets close-on-exec; systemd passes them without it
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
        fd
    }

    #[allow(unsafe_code)]
    fn inheritable(fd: RawFd) {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    }

    static FDS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn the_adopted_descriptor_is_close_on_exec_and_every_extra_one_is_closed() {
        let _g = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let d = tempfile::tempdir().unwrap();
        let (a, b, c) = (listener(&d, "a"), listener(&d, "b"), listener(&d, "c"));
        assert_eq!(cloexec(a), Some(false), "systemd passes it inheritable");
        let l = adopt_passed(&[a, b, c], Some("ozboxd-supervisor.socket")).unwrap();
        use std::os::fd::AsRawFd;
        assert_eq!(cloexec(l.as_raw_fd()), Some(true));
        // the new descriptor may reuse a closed one's number; every other passed number must be closed
        for (name, fd) in [("original", a), ("extra", b), ("extra", c)] {
            if fd != l.as_raw_fd() {
                assert_eq!(
                    cloexec(fd),
                    None,
                    "the {name} descriptor is closed, not left to leak into runs"
                );
            }
        }
    }

    #[test]
    fn only_a_listening_unix_stream_socket_with_the_right_name_is_taken() {
        let _g = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let d = tempfile::tempdir().unwrap();
        // the name systemd gave it names another socket unit
        let a = listener(&d, "a");
        assert!(adopt_passed(&[a], Some("other.socket")).is_err());
        assert_eq!(cloexec(a), None, "a refused descriptor is closed");
        let (r, w) = std::os::unix::net::UnixStream::pair().unwrap();
        // a connected socket is not a listening one
        assert!(adopt_passed(&[r.into_raw_fd()], None).is_err());
        drop(w);
        // a datagram socket is not a stream socket
        let dg = std::os::unix::net::UnixDatagram::bind(d.path().join("dg")).unwrap();
        assert!(adopt_passed(&[dg.into_raw_fd()], None).is_err());
        // a regular file
        let f = std::fs::File::open(d.path()).unwrap();
        assert!(adopt_passed(&[f.into_raw_fd()], None).is_err());
        // an internet listener is not a Unix socket
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(adopt_passed(&[tcp.into_raw_fd()], None).is_err());
        // nothing passed
        assert!(adopt_passed(&[], None).is_err());
        // the right one, with or without a name
        let ok = listener(&d, "ok");
        assert!(adopt_passed(&[ok], None).is_ok());
        let ok = listener(&d, "ok2");
        assert!(adopt_passed(&[ok], Some("ozboxd-supervisor.socket")).is_ok());
    }

    #[test]
    fn another_units_socket_is_taken_only_under_its_own_name() {
        let _g = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let d = tempfile::tempdir().unwrap();
        // the hub daemon's socket unit: the dashboard's name is not its name, and the reverse
        let a = listener(&d, "hub-a");
        assert!(adopt_passed_named(&[a], Some(SOCKET_NAME), "ozbox-hubd.socket").is_err());
        assert_eq!(cloexec(a), None, "a refused descriptor is closed");
        let b = listener(&d, "hub-b");
        assert!(adopt_passed(&[b], Some("ozbox-hubd.socket")).is_err());
        let ok = listener(&d, "hub-ok");
        assert!(adopt_passed_named(&[ok], Some("ozbox-hubd.socket"), "ozbox-hubd.socket").is_ok());
    }

    #[test]
    fn passed_tcp_listeners_are_adopted_in_order_close_on_exec_and_only_if_all_are_listening_inet_streams(
    ) {
        let _g = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let mk = || {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            let fd = l.into_raw_fd();
            // systemd passes it without close-on-exec
            inheritable(fd);
            (fd, port)
        };
        let ((a, pa), (b, pb)) = (mk(), mk());
        assert_eq!(cloexec(a), Some(false));
        let ls = adopt_passed_tcp(&[a, b]).unwrap();
        let ports: Vec<u16> = ls.iter().map(|l| l.local_addr().unwrap().port()).collect();
        assert_eq!(ports, [pa, pb], "in the order passed, each its own port");
        use std::os::fd::AsRawFd;
        for l in &ls {
            assert_eq!(cloexec(l.as_raw_fd()), Some(true));
        }
        for fd in [a, b] {
            if !ls.iter().any(|l| l.as_raw_fd() == fd) {
                assert_eq!(cloexec(fd), None, "the original is closed");
            }
        }
        // a connection is accepted on an adopted socket
        let _c = std::net::TcpStream::connect(("127.0.0.1", pa)).unwrap();
        assert!(ls[0].accept().is_ok());
        // one that is not a listening internet stream socket refuses the whole set, and every descriptor is closed
        let d = tempfile::tempdir().unwrap();
        let (good, _) = mk();
        let unix = listener(&d, "u");
        assert!(adopt_passed_tcp(&[good, unix]).is_err());
        assert_eq!(cloexec(good), None);
        assert_eq!(cloexec(unix), None);
        let dg = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .into_raw_fd();
        assert!(adopt_passed_tcp(&[dg]).is_err());
        assert!(adopt_passed_tcp(&[]).is_err());
    }

    #[test]
    fn an_adopted_socket_accepts_connections() {
        let _g = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("s.sock");
        let l = UnixListener::bind(&path).unwrap();
        let raw = l.into_raw_fd();
        let a = adopt(raw).unwrap();
        let mut c = UnixStream::connect(&path).unwrap();
        c.write_all(b"hi").unwrap();
        let (mut s, _) = a.accept().unwrap();
        let mut b = [0u8; 2];
        s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hi");
    }
}
