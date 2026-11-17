//! A service's route out (ADR 0029 Amendment 12, the per-service egress proxy).
//!
//! A secret-holding service (a test server with a Stripe TEST key) has `IPAddressDeny=any`, so it can reach this machine's
//! loopback and nothing else. What it may reach beyond is the project's declared hosts (`egress`), through a proxy that is a
//! **unit of its own** (`ozbox-egress-<project>_<command>`): the launcher exits after every request, so nothing of it could outlive
//! the call, and the unit is what makes the proxy live exactly as long as the service.
//!
//! **The invariant: the route's ports are held and guarded before any service process exists, and released only after the last
//! one is dead.** Three units make it so, and each does one job:
//!
//! * the **socket** (`<unit>.socket`, a transient socket unit made by `systemd-run --socket-property=`): PID 1 binds the ports and
//!   keeps them for as long as the socket is up, whatever happens to the proxy. Its privileged `ExecStartPre=` loads the firewall
//!   table before the ports listen and its `ExecStopPost=` removes the table after everything that used them has ended.
//! * the **proxy** (`<unit>.service`): takes the sockets from `LISTEN_FDS` and never binds. It is started explicitly, and
//!   `Type=notify` makes `systemctl start` return only once it has said READY, so the service is never started before it listens.
//!   It `BindsTo=` the socket, and ends (non-zero) if any listener is lost.
//! * the **service** (`ozbox-svc-<project>_<command>`): `BindsTo=` and `After=` both, and its `ExecStopPost=` stops the proxy and
//!   then the socket. The socket is `Before=` the service, so its stop job runs only after the service's has finished: the ports
//!   are released after the last service process is dead.
//!
//! Who may use the proxy: `HTTPS_PROXY` must be `http://127.0.0.1:<port>` for Node, curl and the SDKs (none takes a Unix socket, and
//! a relay in the service's own unit would let any user of the box inherit the service's identity). A kernel rule (`nftables`,
//! `meta skuid`) rejects every connection that does not come from the service's own `ozrc-` user, and the proxy checks the same for
//! itself (`peer_uid`), so a rule that is flushed does not open the proxy. There is no password: a unit's properties are readable
//! by every user of the box (`systemctl show`), so a password in `Environment=` would be no secret at all.
//!
//! **The same rules as a one-shot command.** The proxy is `egress::start_open_on`: the exact-host list (`egress::parse_rules`), the
//! public-address check and the TLS hello check are the one-shot proxy's own code. TLS passes through: the service is given no
//! certificate authority (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_*` stay unset, and stay reserved names).
//!
//! **Raw `tcp` destinations are not given to a service yet** ([`SERVICE_TCP_TUNNELS`]): the tunnel code is built and tested, and
//! switched on only after the port-squat check of the ADR's real-box list passes.
//!
//! The builders here are pure (argument lists, property text, firewall text), so a test on any machine reads them. What cannot be
//! shown off a Linux box is how systemd orders and ends the three units and that the kernel rule rejects another user: the ADR's
//! real-box list (Amendment 12, part 5) names each step.

use crate::egress::TcpDest;

/// Whether a service that receives secrets is given the project's `tcp` destinations. Held `false` until the real-box regression
/// of the ADR's list (the box user cannot take a route's port while the service runs, however the proxy ends) has passed: a tunnel
/// carries a wire protocol with no TLS check of ours, so a port that someone else could listen on would receive a database login.
/// Turning it on is this one constant, then removing the refusal's test.
pub const SERVICE_TCP_TUNNELS: bool = false;

/// A unit's name is `ozbox-egress-<project>_<command>`; setup stops `ozbox-egress-<project>_*` by name (`_` cannot be part of a
/// project or command name, so the glob never reaches another project's).
pub const UNIT_PREFIX: &str = "ozbox-egress-";
/// Where the launcher puts a start's firewall rules for the socket unit to load (root-owned, removed after the start).
pub const RULES_ROOT: &str = "/run/ozbox-egress-rules";
const NFT: &str = "/usr/sbin/nft";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
/// Longer than the service's own limit, so the service's limit is what ends a run and this one only catches a proxy left behind.
const EGRESS_MAX_SECS: u32 = crate::runner::SERVICE_MAX_SECS + 300;
/// Threads the proxy may have: each connection makes up to two, so the connection cap bites long before this does.
const PROXY_TASKS_MAX: u32 = 2 * crate::egress::MAX_CONNECTIONS as u32 + 64;
const PROXY_MEMORY_MAX: &str = "256M";
/// The proxy's own network floor: it talks to public hosts, never to this machine's neighbours. (A resolver that is a private
/// address would need an allowance; the stub resolver on loopback does not.)
const PROXY_IP_DENY: &str =
    "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 fc00::/7 fe80::/10";

pub fn egress_unit(project: &str, command: &str) -> String {
    format!("{UNIT_PREFIX}{project}_{command}")
}

/// The service a route's base name belongs to.
pub fn service_of_route_unit(route_unit: &str) -> Option<String> {
    route_unit
        .strip_prefix(UNIT_PREFIX)
        .filter(|r| !r.is_empty() && r.contains('_'))
        .map(|r| format!("ozbox-svc-{r}"))
}

/// What the launcher decided for one start: the route's unit (its socket and its proxy share the name), its port, and a loopback
/// port for each declared raw destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub unit: String,
    pub port: u16,
    pub tunnels: Vec<(TcpDest, u16)>,
}

impl Route {
    /// Every loopback port the route holds, in the order the socket unit lists them: the proxy's, then each tunnel's.
    pub fn ports(&self) -> Vec<u16> {
        let mut v = vec![self.port];
        v.extend(self.tunnels.iter().map(|(_, p)| *p));
        v
    }

    pub fn socket(&self) -> String {
        format!("{}.socket", self.unit)
    }

    pub fn proxy(&self) -> String {
        format!("{}.service", self.unit)
    }
}

/// The firewall table of one route, named by its UNIT (never by a port: a port is reused, so a table named by one can be replaced
/// or deleted by another route's start or stop). The name is a reversible encoding of the unit's part after `ozbox-egress-`
/// (`-` is `_h`, `_` is `_s`, so no two units share a table), which is what lets a sweep tell which unit a stale table belongs to.
pub fn nft_table(unit: &str) -> String {
    let rest = unit.strip_prefix(UNIT_PREFIX).unwrap_or(unit);
    let mut t = String::from("ozbox_egress_");
    for c in rest.chars() {
        match c {
            '-' => t.push_str("_h"),
            '_' => t.push_str("_s"),
            c => t.push(c),
        }
    }
    t
}

/// The unit a table name of [`nft_table`] belongs to. `None` for any other name.
pub fn unit_of_table(table: &str) -> Option<String> {
    let enc = table.strip_prefix("ozbox_egress_")?;
    let mut out = String::from(UNIT_PREFIX);
    let mut it = enc.chars();
    while let Some(c) = it.next() {
        match c {
            '_' => match it.next()? {
                'h' => out.push('-'),
                's' => out.push('_'),
                _ => return None,
            },
            c if c.is_ascii_lowercase() || c.is_ascii_digit() => out.push(c),
            _ => return None,
        }
    }
    (out.len() > UNIT_PREFIX.len()).then_some(out)
}

/// The ruleset: a connection to one of the route's loopback ports from any user but `uid` is refused. Loaded in one step (`add`,
/// `delete`, then the table), the way `metadata_guard` does, so a leftover of an earlier start never joins the new one. Pure.
pub fn render_nft(route: &Route, uid: u32) -> String {
    let t = nft_table(&route.unit);
    let ports = route
        .ports()
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "add table inet {t}\n\
         delete table inet {t}\n\
         table inet {t} {{\n\
         \x20 chain output {{\n\
         \x20   type filter hook output priority -5; policy accept;\n\
         \x20   ip daddr 127.0.0.1 tcp dport {{ {ports} }} meta skuid != {uid} counter reject with tcp reset\n\
         \x20 }}\n\
         }}\n"
    )
}

/// `host:port:ENV:localport`, the way a tunnel is passed to the proxy's command line.
pub fn tunnel_arg(d: &TcpDest, local: u16) -> String {
    format!("{}:{}:{}:{local}", d.host, d.port, d.env)
}

pub fn parse_tunnel_arg(s: &str) -> Result<(TcpDest, u16), String> {
    let bad = || "a tcp tunnel argument is host:port:ENV:localport".to_string();
    let p: Vec<&str> = s.split(':').collect();
    if p.len() != 4 {
        return Err(bad());
    }
    let d = TcpDest {
        host: p[0].to_string(),
        port: p[1].parse().map_err(|_| bad())?,
        env: p[2].to_string(),
    };
    let local: u16 = p[3].parse().map_err(|_| bad())?;
    crate::egress::validate_tcp(std::slice::from_ref(&d)).map_err(|e| e.to_string())?;
    if local == 0 {
        return Err(bad());
    }
    Ok((d, local))
}

/// The `systemd-run` call that makes a route's socket and proxy units, and starts the socket (PID 1 binds every port and loads the
/// firewall table first). It does **not** start the proxy: `systemctl start <proxy>` does, so the start can wait for READY.
/// The proxy runs as a user systemd makes for it (never the service's own, and not root), with a network floor and limits of
/// its own, and is `Type=notify`. `rules_file` is the ruleset ([`render_nft`]) the launcher wrote for this start. Holds no secret:
/// hosts, ports and a uid are public declarations.
pub fn systemd_run_route_argv(
    service_unit: &str,
    route: &Route,
    uid: u32,
    rules: &[String],
    rules_file: &str,
) -> Vec<String> {
    let mut v: Vec<String> = ["systemd-run", "--quiet", "--collect"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    v.push(format!("--unit={}", route.unit));
    let table = nft_table(&route.unit);
    let socket_props: Vec<String> = route
        .ports()
        .iter()
        .map(|p| format!("ListenStream=127.0.0.1:{p}"))
        // `+`: runs with full privileges, as the rule needs, and BEFORE the ports listen; the table is removed however the socket
        // ends (`-`: a table that is already gone is not a failure), which is after the last service process is dead
        .chain([
            format!("ExecStartPre=+{NFT} -f {rules_file}"),
            format!("ExecStopPost=-+{NFT} delete table inet {table}"),
        ])
        .collect();
    for p in socket_props {
        v.push(format!("--socket-property={p}"));
    }
    let props = [
        "Type=notify".to_string(),
        "NotifyAccess=main".to_string(),
        "DynamicUser=yes".to_string(),
        format!("RuntimeMaxSec={EGRESS_MAX_SECS}"),
        "Restart=no".to_string(),
        "StandardInput=null".to_string(),
        // the proxy needs the ports held: it ends with the socket and is not started without it
        format!("BindsTo={}", route.socket()),
        format!("After={}", route.socket()),
        // a stop or restart of the service takes the proxy with it
        format!("PartOf={service_unit}.service"),
        format!("TasksMax={PROXY_TASKS_MAX}"),
        format!("MemoryMax={PROXY_MEMORY_MAX}"),
        "IPAddressAllow=127.0.0.0/8 ::1/128".to_string(),
        format!("IPAddressDeny={PROXY_IP_DENY}"),
        "NoNewPrivileges=yes".to_string(),
        "PrivateTmp=yes".to_string(),
        "PrivateDevices=yes".to_string(),
        "ProtectSystem=strict".to_string(),
        "ProtectHome=yes".to_string(),
        "ProtectKernelTunables=yes".to_string(),
        "ProtectControlGroups=yes".to_string(),
        "RestrictSUIDSGID=yes".to_string(),
        "LockPersonality=yes".to_string(),
        "MemorySwapMax=0".to_string(),
        "LimitCORE=0".to_string(),
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6".to_string(),
    ];
    for p in props {
        v.push("-p".into());
        v.push(p);
    }
    v.push("--".into());
    v.extend(
        ["/usr/local/bin/ozbox", "secrets", "egress-serve", "--port"]
            .iter()
            .map(|s| s.to_string()),
    );
    v.push(route.port.to_string());
    v.push("--uid".into());
    v.push(uid.to_string());
    for r in rules {
        v.push("--rule".into());
        v.push(r.clone());
    }
    for (d, local) in &route.tunnels {
        v.push("--tcp".into());
        v.push(tunnel_arg(d, *local));
    }
    v
}

/// The properties a service with a route is given besides the usual ones: it needs the proxy and the socket to exist (`BindsTo=`,
/// `After=`), its end stops the proxy and then the socket, and the environment points at the proxy. Set by the launcher, as
/// `Environment=` properties (the addresses are public); a declaration cannot set any of these names
/// (`workload_policy::reserved_name`). Only `HTTPS_PROXY` is set: a plain `http://` request through the proxy is a 405 anyway, and
/// every client of an https destination reads `HTTPS_PROXY`.
pub fn route_props(route: &Route) -> Vec<String> {
    let mut v = vec![
        format!("BindsTo={} {}", route.proxy(), route.socket()),
        format!("After={} {}", route.proxy(), route.socket()),
        // whichever way the service ends (`--stop`, its limit, its own exit, a failed start, the proxy dying), the proxy is stopped
        // and then the socket, queued without waiting (a wait here would wait for this very job). systemd runs the socket's stop only
        // after the service's own (the service is After= the socket), so the ports are released after its last process is dead
        format!(
            "ExecStopPost=+{SYSTEMCTL} stop --no-block {}",
            route.proxy()
        ),
        format!(
            "ExecStopPost=+{SYSTEMCTL} stop --no-block {}",
            route.socket()
        ),
    ];
    let url = format!("http://127.0.0.1:{}", route.port);
    for k in ["HTTPS_PROXY", "https_proxy"] {
        v.push(format!("Environment={k}={url}"));
    }
    for k in ["NO_PROXY", "no_proxy"] {
        v.push(format!("Environment={k}=localhost,127.0.0.1,::1"));
    }
    // Node's fetch ignores HTTPS_PROXY without its opt-in (`egress::PROXY_OPT_INS`)
    for (k, val) in crate::egress::PROXY_OPT_INS {
        v.push(format!("Environment={k}={val}"));
    }
    for (d, port) in &route.tunnels {
        for (k, val) in crate::egress::tunnel_env(d, *port) {
            v.push(format!("Environment={k}={val}"));
        }
    }
    v
}

/// Tell systemd the proxy is listening (`Type=notify`).
#[cfg(target_os = "linux")]
fn notify_ready() -> Result<(), String> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let bad = || "the proxy could not tell systemd it is ready".to_string();
    let path = std::env::var_os("NOTIFY_SOCKET").ok_or_else(bad)?;
    let path = path.to_string_lossy().to_string();
    let sock = UnixDatagram::unbound().map_err(|_| bad())?;
    match path.strip_prefix('@') {
        Some(name) => {
            let addr = SocketAddr::from_abstract_name(name.as_bytes()).map_err(|_| bad())?;
            sock.send_to_addr(b"READY=1", &addr).map_err(|_| bad())?;
        }
        None => {
            sock.send_to(b"READY=1", &path).map_err(|_| bad())?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn notify_ready() -> Result<(), String> {
    Err("a service's egress proxy runs on a Linux box only".to_string())
}

/// The proxy unit's program: take the route's listening sockets from systemd (the proxy's, then one per tunnel, in the order of
/// `--port` and `--tcp`), serve only connections from `uid`, tell systemd, and serve until the unit is stopped. Anything wrong with
/// a rule or a socket ends it before it says ready, which fails the service's start. **A listener that ends later ends the
/// program**, non-zero: the service is bound to this unit, so it stops with it, and the ports stay held by systemd meanwhile.
/// There is no fallback that binds a port itself: a port this program binds is a port nobody else holds only while it lives.
pub fn serve_main(port: u16, uid: u32, rules: &[String], tunnels: &[String]) -> Result<(), String> {
    let parsed = crate::egress::parse_rules(rules).map_err(|e| e.to_string())?;
    if parsed.is_empty() && tunnels.is_empty() {
        return Err("a route with nothing declared is not started".to_string());
    }
    // in depth: a service's project cannot declare a wildcard, so a route that carries one was not made by the launcher
    if parsed.iter().any(|r| r.wildcard) {
        return Err("a service's route is exact hosts only".to_string());
    }
    let dests = tunnels
        .iter()
        .map(|t| parse_tunnel_arg(t))
        .collect::<Result<Vec<_>, _>>()?;
    let listeners = match ozbox_listenfd::take_tcp_listeners() {
        Some(Ok(l)) => l,
        _ => return Err("the route's ports were not handed over by systemd".to_string()),
    };
    let mut want = vec![port];
    want.extend(dests.iter().map(|(_, p)| *p));
    let got: Vec<Option<std::net::SocketAddr>> =
        listeners.iter().map(|l| l.local_addr().ok()).collect();
    let expected: Vec<Option<std::net::SocketAddr>> = want
        .iter()
        .map(|p| Some(std::net::SocketAddr::from(([127, 0, 0, 1], *p))))
        .collect();
    if got != expected {
        return Err("the sockets systemd handed over are not the route's ports".to_string());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let guard = crate::egress::Guard::with(
        Some(crate::peer_uid::only_uid(uid)),
        crate::egress::MAX_CONNECTIONS,
        Some(tx),
    );
    let mut it = listeners.into_iter();
    let (Some(first), rest) = (it.next(), it) else {
        return Err("the route has no listener".to_string());
    };
    let proxy = crate::egress::start_open_on(
        first,
        parsed,
        std::sync::Arc::new(crate::egress::SystemResolver),
        guard.clone(),
    )?;
    let mut held = Vec::new();
    for (l, (d, _)) in rest.zip(dests) {
        held.push(crate::egress::start_tunnel_on(
            l,
            d.host,
            d.port,
            std::sync::Arc::new(crate::egress::SystemResolver),
            crate::netguard::ip_is_public,
            guard.clone(),
        )?);
    }
    notify_ready()?;
    // served by the accept threads until systemd stops the unit; one that ends ends this
    let why = rx.recv().unwrap_or("the route's listeners ended");
    drop((proxy, held));
    Err(why.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn route() -> Route {
        Route {
            unit: egress_unit("app", "web"),
            port: 40123,
            tunnels: vec![(
                TcpDest {
                    host: "db.example.com".into(),
                    port: 5432,
                    env: "DATABASE".into(),
                },
                40124,
            )],
        }
    }

    #[test]
    fn the_rule_rejects_every_user_but_the_services_on_every_port_of_the_route() {
        let t = render_nft(&route(), 61234);
        // named by the unit, never by a port
        assert!(t.contains("table inet ozbox_egress_app_sweb"), "{t}");
        assert!(!t.contains("ozbox_egress_40123"));
        assert!(
            t.contains(
                "tcp dport { 40123, 40124 } meta skuid != 61234 counter reject with tcp reset"
            ),
            "{t}"
        );
        assert!(t.contains("ip daddr 127.0.0.1"));
        // loaded in one step: an earlier start's table of the same name is replaced, never joined
        let add = t.find("add table").unwrap();
        let del = t.find("delete table").unwrap();
        let def = t.find("table inet ozbox_egress_app_sweb {").unwrap();
        assert!(add < del && del < def, "{t}");
    }

    #[test]
    fn a_table_is_named_by_its_unit_and_two_units_never_share_one() {
        let a = nft_table(&egress_unit("a-b", "c"));
        let b = nft_table(&egress_unit("a", "b-c"));
        assert_ne!(a, b);
        assert_eq!(a, "ozbox_egress_a_hb_sc");
        // a table can be traced back to its unit, so a sweep knows whose it is
        for (p, c) in [("app", "web"), ("a-b", "c"), ("a", "b-c"), ("x1", "y-2-z")] {
            let u = egress_unit(p, c);
            assert_eq!(unit_of_table(&nft_table(&u)), Some(u.clone()), "{u}");
        }
        for bad in [
            "ozbox_egress_",
            "ozbox_egress_A",
            "ozbox_egress_a_x",
            "other",
            "ozbox_egress_a_",
        ] {
            assert_eq!(unit_of_table(bad), None, "{bad}");
        }
        // a route's unit gives its service's name
        assert_eq!(
            service_of_route_unit("ozbox-egress-app_web").as_deref(),
            Some("ozbox-svc-app_web")
        );
        assert_eq!(
            service_of_route_unit("ozbox-egress-app-web"),
            None,
            "a hyphen name is not a route of ours"
        );
    }

    fn run_argv() -> Vec<String> {
        systemd_run_route_argv(
            "ozbox-svc-app_web",
            &route(),
            61234,
            &[
                "api.stripe.com".to_string(),
                "files.example.org:8443".to_string(),
            ],
            "/run/ozbox-egress-rules/ozbox-egress-app_web.0123456789abcdef.nft",
        )
    }

    #[test]
    fn the_socket_unit_holds_every_port_and_loads_the_table_before_they_listen() {
        let v = run_argv();
        assert_eq!(v[0], "systemd-run");
        assert!(v.contains(&"--unit=ozbox-egress-app_web".to_string()));
        // blocking: the call returns once the socket is up, and it never starts the proxy
        assert!(!v.contains(&"--no-block".to_string()));
        let has = |p: &str| v.iter().any(|a| a == p);
        for p in [
            "--socket-property=ListenStream=127.0.0.1:40123",
            "--socket-property=ListenStream=127.0.0.1:40124",
            "--socket-property=ExecStartPre=+/usr/sbin/nft -f /run/ozbox-egress-rules/ozbox-egress-app_web.0123456789abcdef.nft",
            "--socket-property=ExecStopPost=-+/usr/sbin/nft delete table inet ozbox_egress_app_sweb",
        ] {
            assert!(has(p), "{p}: {v:?}");
        }
        // the ports are listed in the order the proxy takes its sockets: its own, then each tunnel's
        let l: Vec<&String> = v.iter().filter(|a| a.contains("ListenStream")).collect();
        assert!(l[0].ends_with(":40123") && l[1].ends_with(":40124"));
        // the table goes with the socket and not with the proxy: a proxy that dies does not take its rule away
        assert!(!v
            .iter()
            .any(|a| a.starts_with("ExecStartPre=") || a.starts_with("ExecStopPost=")));
    }

    #[test]
    fn the_proxy_unit_is_notify_bound_to_the_socket_limited_and_cut_off_from_the_neighbours() {
        let v = run_argv();
        let has = |p: &str| v.iter().any(|a| a == p);
        for p in [
            "Type=notify",
            "DynamicUser=yes",
            "BindsTo=ozbox-egress-app_web.socket",
            "After=ozbox-egress-app_web.socket",
            "PartOf=ozbox-svc-app_web.service",
            "Restart=no",
            "TasksMax=576",
            "MemoryMax=256M",
            "IPAddressAllow=127.0.0.0/8 ::1/128",
            "IPAddressDeny=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 fc00::/7 fe80::/10",
            "RuntimeMaxSec=14700",
        ] {
            assert!(has(p), "{p}: {v:?}");
        }
        // the connection cap bites before the task limit: two threads per connection, plus the accept loops
        assert!(PROXY_TASKS_MAX as usize > 2 * crate::egress::MAX_CONNECTIONS);
        // it is not the service's user
        assert!(!v.iter().any(|a| a.starts_with("--uid=")));
        let i = v.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            v[i + 1..],
            [
                "/usr/local/bin/ozbox",
                "secrets",
                "egress-serve",
                "--port",
                "40123",
                "--uid",
                "61234",
                "--rule",
                "api.stripe.com",
                "--rule",
                "files.example.org:8443",
                "--tcp",
                "db.example.com:5432:DATABASE:40124"
            ]
        );
    }

    #[test]
    fn the_service_needs_its_proxy_and_socket_ends_them_in_order_and_is_told_where_the_proxy_is() {
        let v = route_props(&route());
        for p in [
            "BindsTo=ozbox-egress-app_web.service ozbox-egress-app_web.socket",
            "After=ozbox-egress-app_web.service ozbox-egress-app_web.socket",
            "Environment=HTTPS_PROXY=http://127.0.0.1:40123",
            "Environment=https_proxy=http://127.0.0.1:40123",
            "Environment=NO_PROXY=localhost,127.0.0.1,::1",
            "Environment=NODE_USE_ENV_PROXY=1",
            "Environment=DATABASE_HOST=127.0.0.1",
            "Environment=DATABASE_PORT=40124",
            "Environment=DATABASE_REMOTE_HOST=db.example.com",
        ] {
            assert!(v.contains(&p.to_string()), "{p}: {v:?}");
        }
        // the proxy is stopped first and then the socket, and neither waits (a wait would wait for the stop that runs it)
        let stops: Vec<&String> = v
            .iter()
            .filter(|a| a.starts_with("ExecStopPost="))
            .collect();
        assert_eq!(
            stops,
            [
                "ExecStopPost=+/usr/bin/systemctl stop --no-block ozbox-egress-app_web.service",
                "ExecStopPost=+/usr/bin/systemctl stop --no-block ozbox-egress-app_web.socket"
            ]
        );
        // E11: a plain-http proxy variable is never set, and neither is the catch-all one
        let all = v.join("\n");
        for k in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
            assert!(!all.contains(&format!("Environment={k}=")), "{k}");
        }
        // no password, and no certificate authority: TLS goes through to the declared host untouched
        assert!(!all.contains("run:") && !all.contains('@'));
        assert!(!all.contains("NODE_EXTRA_CA_CERTS") && !all.contains("SSL_CERT"));
    }

    #[test]
    fn a_tunnel_argument_round_trips_and_refuses_what_a_declaration_would() {
        let (d, local) = parse_tunnel_arg("db.example.com:5432:DATABASE:40124").unwrap();
        assert_eq!(
            (d.host.as_str(), d.port, d.env.as_str(), local),
            ("db.example.com", 5432, "DATABASE", 40124)
        );
        assert_eq!(tunnel_arg(&d, local), "db.example.com:5432:DATABASE:40124");
        for bad in [
            "10.0.0.1:5432:DATABASE:40124",
            "db.example.com:5432:database:40124",
            "db.example.com:5432:DATABASE:0",
            "db.example.com:5432:DATABASE",
            "*.example.com:5432:DATABASE:1",
        ] {
            assert!(parse_tunnel_arg(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_proxy_with_nothing_declared_or_no_sockets_from_systemd_is_not_started() {
        assert!(serve_main(40999, 1, &[], &[]).is_err());
        assert!(serve_main(40999, 1, &["10.0.0.1".to_string()], &[]).is_err());
        // a wildcard never reaches a service's route
        let e = serve_main(40999, 1, &["*.example.com".to_string()], &[]).unwrap_err();
        assert!(e.contains("exact hosts"), "{e}");
        // nothing was handed over (no LISTEN_FDS): it does not bind a port of its own
        let e = serve_main(40999, 1, &["api.example.com".to_string()], &[]).unwrap_err();
        assert!(e.contains("handed over"), "{e}");
        assert!(
            std::net::TcpListener::bind(("127.0.0.1", 40999)).is_ok(),
            "and the port it was told of is still nobody's"
        );
    }

    #[test]
    fn raw_tcp_destinations_are_held_back_from_services_until_the_squat_check_passes() {
        // the switch the refusal reads; flipping it is the whole change, after the real-box check
        assert!(!std::hint::black_box(SERVICE_TCP_TUNNELS));
    }

    /// The `node` on this machine and its version, or why the Node test cannot run here.
    fn node_with_env_proxy() -> Result<(), String> {
        let out = std::process::Command::new("node")
            .arg("--version")
            .output()
            .map_err(|_| "no node on PATH".to_string())?;
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let n: Vec<u32> = v
            .trim_start_matches('v')
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        let ok = match n.as_slice() {
            [22, m, ..] => *m >= 21,
            [24, m, ..] => *m >= 5,
            [maj, ..] => *maj >= 25,
            _ => false,
        };
        if ok {
            Ok(())
        } else {
            Err(format!(
                "node {v} has no NODE_USE_ENV_PROXY (22.21+, 24.5+)"
            ))
        }
    }

    /// Run Node's built-in `fetch` to an `.invalid` https host with `env` only, behind a listener that plays the proxy:
    /// the request head it received, if Node came to it.
    fn node_fetch_through(
        env: &[(String, String)],
        port_holder: std::net::TcpListener,
    ) -> Option<String> {
        use std::io::{Read, Write};
        port_holder.set_nonblocking(true).unwrap();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done2 = done.clone();
        let seen = std::thread::spawn(move || {
            let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while std::time::Instant::now() < end {
                // node has exited: one last look for a connection it made, then stop
                let last = done2.load(std::sync::atomic::Ordering::SeqCst);
                match port_holder.accept() {
                    Ok((mut c, _)) => {
                        c.set_nonblocking(false).unwrap();
                        c.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                        let mut head = Vec::new();
                        let mut b = [0u8; 1024];
                        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                            match c.read(&mut b) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => head.extend_from_slice(&b[..n]),
                            }
                        }
                        let _ = c.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n");
                        return Some(String::from_utf8_lossy(&head).to_string());
                    }
                    Err(_) if last => return None,
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
            None
        });
        let script = "setTimeout(()=>process.exit(4),15000).unref();\
                      fetch('https://ozbox-test.invalid/').then(()=>process.exit(0),()=>process.exit(0))";
        let st = std::process::Command::new("node")
            .args(["-e", script])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_ne!(st.code(), Some(4), "node's fetch hung");
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        let head = seen.join().unwrap();
        head.filter(|h| !h.is_empty())
    }

    /// B4-30: the variables the launcher gives a service (and a one-shot command, whose proxy address carries a password)
    /// make Node's built-in `fetch` use the proxy. Without the opt-in it goes direct, which is the bug this pins.
    #[test]
    fn node_fetch_uses_the_proxy_with_the_variables_the_runner_sets() {
        if let Err(why) = node_with_env_proxy() {
            eprintln!("skipped: {why}");
            return;
        }
        // the service: exactly the Environment= lines of its unit
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut r = route();
        r.port = l.local_addr().unwrap().port();
        r.tunnels.clear();
        let env: Vec<(String, String)> = route_props(&r)
            .iter()
            .filter_map(|p| p.strip_prefix("Environment="))
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let Some(head) = node_fetch_through(&env, l) else {
            panic!("node's fetch did not use the proxy");
        };
        assert!(
            head.starts_with("CONNECT ozbox-test.invalid:443 "),
            "{head}"
        );

        // a one-shot command: the proxy address carries the run's password, and Node presents it
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://run:pw0123@127.0.0.1:{}",
            l.local_addr().unwrap().port()
        );
        let mut env = vec![
            ("HTTPS_PROXY".to_string(), url.clone()),
            ("https_proxy".to_string(), url),
            (
                "NO_PROXY".to_string(),
                "localhost,127.0.0.1,::1".to_string(),
            ),
        ];
        for (k, v) in crate::egress::PROXY_OPT_INS {
            env.push((k.to_string(), v.to_string()));
        }
        let Some(head) = node_fetch_through(&env, l) else {
            panic!("node's fetch did not use the proxy");
        };
        assert!(
            head.starts_with("CONNECT ozbox-test.invalid:443 "),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("proxy-authorization: basic "),
            "{head}"
        );

        // the control: the same address without the opt-in, and Node never comes to the proxy (it goes direct)
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let env = vec![("HTTPS_PROXY".to_string(), url)];
        assert_eq!(node_fetch_through(&env, l), None);
    }
}
