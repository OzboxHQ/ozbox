//! Who is on the other end of a loopback connection (ADR 0029 Amendment 12, the per-service egress proxy).
//!
//! The kernel rule that limits a service's proxy ports to the service's own user can be deleted under a running proxy (a
//! flushed ruleset, a restarted firewall), and the proxy has no password a unit's properties could keep secret. So the proxy asks
//! for itself: for every accepted connection it finds the **client's** socket in `/proc/net/tcp` or `/proc/net/tcp6` (the line
//! whose local address is the peer's address and whose remote address is the proxy's) and reads the owning uid from it. A uid that
//! is not the service's, no line, or two lines that disagree is a refusal. There is no `sock_diag` here: it needs a netlink socket
//! and this crate forbids `unsafe`.
//!
//! The parser is pure and runs on any machine; reading `/proc` is Linux only, and anywhere else every connection is refused (there
//! is no uid to be told, so there is no yes).
//!
//! Address text in `/proc/net/tcp*` is each 32-bit word of the address printed as a hexadecimal number from the machine's byte
//! order (so `127.0.0.1` is `0100007F` on a little-endian machine, which every Linux box we run on is), and the port as plain
//! hexadecimal. A v6 socket that connects to `127.0.0.1` shows in `tcp6` as the v4-mapped `::ffff:127.0.0.1`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;

/// One socket line of `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub uid: u32,
}

/// An address and port as `/proc/net/tcp*` prints them: `HHHHHHHH:PPPP` (v4) or 32 hex digits, a colon and the port (v6).
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => {
            let w = u32::from_str_radix(a, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(w.to_le_bytes()))
        }
        32 => {
            let mut b = [0u8; 16];
            for (i, chunk) in b.chunks_mut(4).enumerate() {
                let w = u32::from_str_radix(a.get(i * 8..i * 8 + 8)?, 16).ok()?;
                chunk.copy_from_slice(&w.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// A v4-mapped address as the plain v4 one, so a v6 client of `127.0.0.1` and a v4 one compare alike.
fn normal(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        IpAddr::V4(_) => a,
    }
}

/// Every well-formed socket line of one file's text. The header line and a line that does not parse are skipped.
pub fn parse_proc_net_tcp(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
            if f.len() < 8 {
                return None;
            }
            Some(Entry {
                local: normal(parse_addr(f[1])?),
                remote: normal(parse_addr(f[2])?),
                uid: f[7].parse().ok()?,
            })
        })
        .collect()
}

/// The uid that owns the client's socket: `peer` is the client's own address (what `accept` returned) and `server` is the proxy's
/// (the accepted socket's local address). `None` when no line matches or the matching lines disagree.
pub fn owner_of(entries: &[Entry], peer: SocketAddr, server: SocketAddr) -> Option<u32> {
    let (peer, server) = (normal(peer), normal(server));
    let mut uid = None;
    for e in entries
        .iter()
        .filter(|e| e.local == peer && e.remote == server)
    {
        match uid {
            None => uid = Some(e.uid),
            Some(u) if u == e.uid => {}
            Some(_) => return None,
        }
    }
    uid
}

/// Whether the client of `c` is a socket owned by `expected`. Always false off Linux, and false when `/proc` cannot be read.
pub fn peer_is(c: &TcpStream, expected: u32) -> bool {
    let (Ok(peer), Ok(server)) = (c.peer_addr(), c.local_addr()) else {
        return false;
    };
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let mut entries = parse_proc_net_tcp(&read("/proc/net/tcp"));
    entries.extend(parse_proc_net_tcp(&read("/proc/net/tcp6")));
    owner_of(&entries, peer, server) == Some(expected)
}

/// A connection check for the accept loops: true lets the connection through.
pub type PeerCheck = Arc<dyn Fn(&TcpStream) -> bool + Send + Sync>;

/// The check a service's proxy makes: only a socket owned by `uid`.
pub fn only_uid(uid: u32) -> PeerCheck {
    Arc::new(move |c| peer_is(c, uid))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // Written from the format in proc(5) and checked against the ones the kernel prints (`sl local rem st tx:rx tr:tm->when
    // retrnsmt uid timeout inode`); a capture from a real box is on the real-box list.
    const V4: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1234        0 55555 1 0000000000000000 20 4 30 10 -1\n\
   1: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 55556 1 0000000000000000 20 4 30 10 -1\n";
    const V6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0000000000000000FFFF00000100007F:9C41 0000000000000000FFFF00000100007F:1F90 01 00000000:00000000 00:00000000 00000000  5678        0 77777 1 0000000000000000 20 4 30 10 -1\n\
   1: 00000000000000000000000001000000:9C42 00000000000000000000000001000000:1F90 01 00000000:00000000 00:00000000 00000000  4242        0 77778 1 0000000000000000 20 4 30 10 -1\n";

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_v4_line_gives_its_address_port_and_owner() {
        let e = parse_proc_net_tcp(V4);
        assert_eq!(e.len(), 2, "the header is not a socket");
        assert_eq!(e[0].local, sa("127.0.0.1:40000"));
        assert_eq!(e[0].remote, sa("127.0.0.1:8080"));
        assert_eq!(e[0].uid, 1234);
        // the client's line is the one whose local side is the peer; the proxy's own accepted socket (uid 0 here) never answers
        assert_eq!(
            owner_of(&e, sa("127.0.0.1:40000"), sa("127.0.0.1:8080")),
            Some(1234)
        );
    }

    #[test]
    fn a_v6_client_of_the_v4_loopback_is_found_as_the_v4_mapped_address() {
        let e = parse_proc_net_tcp(V6);
        assert_eq!(
            e[0].local,
            sa("127.0.0.1:40001"),
            "::ffff:127.0.0.1 is 127.0.0.1"
        );
        assert_eq!(
            owner_of(&e, sa("127.0.0.1:40001"), sa("127.0.0.1:8080")),
            Some(5678)
        );
        // the peer may arrive already written as the mapped address
        assert_eq!(
            owner_of(
                &e,
                sa("[::ffff:127.0.0.1]:40001"),
                sa("[::ffff:127.0.0.1]:8080")
            ),
            Some(5678)
        );
        // a real v6 loopback client is a v6 address, not the v4 one
        assert_eq!(e[1].local, sa("[::1]:40002"));
        assert_eq!(
            owner_of(&e, sa("127.0.0.1:40002"), sa("127.0.0.1:8080")),
            None
        );
    }

    #[test]
    fn no_matching_line_is_no_owner_and_so_a_refusal() {
        let e = parse_proc_net_tcp(V4);
        // a port nobody has, another proxy port, and an empty table (a machine with no /proc)
        assert_eq!(
            owner_of(&e, sa("127.0.0.1:40009"), sa("127.0.0.1:8080")),
            None
        );
        assert_eq!(
            owner_of(&e, sa("127.0.0.1:40000"), sa("127.0.0.1:9999")),
            None
        );
        assert_eq!(
            owner_of(&[], sa("127.0.0.1:40000"), sa("127.0.0.1:8080")),
            None
        );
    }

    #[test]
    fn two_lines_that_disagree_are_a_refusal_and_two_that_agree_are_not() {
        let line = |uid: u32| {
            format!("   0: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 {uid:5} 0 1 1 0 20 4 30 10 -1\n")
        };
        let both = parse_proc_net_tcp(&format!("{}{}", line(1), line(2)));
        assert_eq!(
            owner_of(&both, sa("127.0.0.1:40000"), sa("127.0.0.1:8080")),
            None
        );
        let same = parse_proc_net_tcp(&format!("{}{}", line(7), line(7)));
        assert_eq!(
            owner_of(&same, sa("127.0.0.1:40000"), sa("127.0.0.1:8080")),
            Some(7)
        );
    }

    #[test]
    fn a_malformed_line_is_skipped_and_never_matches() {
        let junk = "garbage\n   0: ZZZZZZZZ:9C40 0100007F:1F90 01 0:0 0:0 0 1 0 1\n   1: 0100007F:9C40 0100007F:1F90 01 0:0 0:0 0 notauid 0 1\n   2: 0100007F:9C40\n";
        assert!(parse_proc_net_tcp(junk).is_empty());
    }

    #[test]
    fn a_socket_in_time_wait_has_uid_zero_and_is_never_the_service() {
        let tw = "   0: 0100007F:9C40 0100007F:1F90 06 00000000:00000000 03:00000000 00000000     0        0 0 1 0\n";
        let e = parse_proc_net_tcp(tw);
        assert_eq!(
            owner_of(&e, sa("127.0.0.1:40000"), sa("127.0.0.1:8080")),
            Some(0)
        );
        assert_ne!(
            owner_of(&e, sa("127.0.0.1:40000"), sa("127.0.0.1:8080")),
            Some(61234)
        );
    }

    #[test]
    fn the_addresses_round_trip_the_way_the_kernel_prints_them() {
        assert_eq!(parse_addr("0100007F:0050"), Some(sa("127.0.0.1:80")));
        assert_eq!(parse_addr("00000000:0000"), Some(sa("0.0.0.0:0")));
        assert_eq!(parse_addr("0100007F"), None);
        assert_eq!(parse_addr("0100007:0050"), None);
        assert_eq!(parse_addr("0100007F:12345"), None);
    }

    /// The real thing, on a Linux box: a connection from this process is owned by this process's uid, and by no other.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_is_seen_as_its_own_uid_on_a_real_loopback_connection() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let _client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (server_side, _) = l.accept().unwrap();
        let me = rustix::process::geteuid().as_raw();
        assert!(peer_is(&server_side, me));
        assert!(!peer_is(&server_side, me.wrapping_add(1)));
    }
}
