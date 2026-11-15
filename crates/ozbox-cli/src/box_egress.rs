//! The box-wide egress allow-list (ADR 0034): a declared list of places the whole machine may reach, enforced on the box
//! by the kernel's packet filter, off by default, and shown before it ever blocks anything.
//!
//! This is the *pure* half: what a declaration is and how it is validated, which destinations it comes to, how names and
//! their addresses are kept (an address stays allowed for a day after a name last gave it, because a name that rotates its
//! answers is otherwise blocked for the very program that resolved it), the packet-filter ruleset, and how a blocked
//! attempt is read back out of the kernel log. The root program that applies it is `egress_guard`.
//!
//! Three modes. `off`: nothing is installed. `log`: everything is allowed and what is *not* on the list is logged, so the
//! list can be built from what the box really does. `enforce`: what is not on the list is dropped, and logged.
//!
//! What this is, and is not: a name resolves to addresses, and the filter allows those addresses. An address shared with
//! other tenants (a content network, a cloud gateway) is therefore reachable by anything on the box, not only by the
//! host's name. The list is the coarse net for the whole machine; the per-command proxy of ADR 0023, which checks the
//! name in the TLS hello, stays the fine one for a project's commands.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

/// An address stays allowed this long after a name last returned it.
pub const ADDR_TTL_SECS: u64 = 24 * 3600;
/// The most presets and hosts a declaration may hold (the request that carries it is short on purpose).
pub const MAX_PRESETS: usize = 24;
pub const MAX_HOSTS: usize = 32;
/// The kernel-log prefixes the ruleset writes, and what the report looks for.
pub const PREFIX_WOULD: &str = "ozbox-egress-would-block";
pub const PREFIX_BLOCKED: &str = "ozbox-egress-blocked";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Off,
    Log,
    Enforce,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "log" => Some(Self::Log),
            "enforce" => Some(Self::Enforce),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Log => "log",
            Self::Enforce => "enforce",
        }
    }
}

/// Whether a change of declaration lets the box do or hide anything the one in force did not. Such a change needs a fresh
/// approval the box user cannot make (ADR 0034, amendment 1); a change that is not one may be made without, because asking
/// for less can only cost the asker.
///
/// - Anything from `off` is not: `off` lets everything out and notes nothing, so `log` or `enforce` of any list only adds.
/// - Turning the list `off`, or stepping `enforce` down to `log`, is.
/// - Within `log` or `enforce`, or from `log` to `enforce`, a change is one unless every destination it lists was listed
///   already. In `log` a wider list hides attempts from the report a person builds the `enforce` list from.
///
/// Pure.
pub fn loosens(current: &Declaration, new: &Declaration) -> bool {
    if current.mode == Mode::Off {
        return false;
    }
    if new.mode == Mode::Off || (current.mode == Mode::Enforce && new.mode == Mode::Log) {
        return true;
    }
    let had = current.destinations(&[]);
    new.destinations(&[]).iter().any(|d| !had.contains(d))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn nft(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One thing the box may reach: a name (or address), a protocol and a port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Dest {
    pub host: String,
    pub proto: Proto,
    pub port: u16,
}

struct P {
    host: &'static str,
    proto: Proto,
    ports: &'static [u16],
}

const fn tcp(host: &'static str, ports: &'static [u16]) -> P {
    P {
        host,
        proto: Proto::Tcp,
        ports,
    }
}

const fn udp(host: &'static str, ports: &'static [u16]) -> P {
    P {
        host,
        proto: Proto::Udp,
        ports,
    }
}

/// Named sets of destinations a declaration can ask for. Starting points: the names are the providers' own and drift, which
/// is what `log` mode is for. `{region}` is the box's own region.
const PRESETS: &[(&str, &str, &[P])] = &[
    (
        "aws-control",
        "what an AWS box needs to stay manageable: Session Manager, the object store its session logs go to, the key service",
        &[
            tcp("ssm.{region}.amazonaws.com", &[443]),
            tcp("ssmmessages.{region}.amazonaws.com", &[443]),
            tcp("ec2messages.{region}.amazonaws.com", &[443]),
            tcp("s3.{region}.amazonaws.com", &[443]),
            tcp("kms.{region}.amazonaws.com", &[443]),
        ],
    ),
    (
        "ubuntu-packages",
        "Ubuntu package mirrors and security updates",
        &[
            tcp("archive.ubuntu.com", &[80, 443]),
            tcp("security.ubuntu.com", &[80, 443]),
            tcp("{region}.ec2.archive.ubuntu.com", &[80, 443]),
            tcp("esm.ubuntu.com", &[443]),
            tcp("changelogs.ubuntu.com", &[443]),
            udp("ntp.ubuntu.com", &[123]),
        ],
    ),
    (
        "github",
        "GitHub: git over https and ssh, the API, release downloads",
        &[
            tcp("github.com", &[22, 443]),
            tcp("ssh.github.com", &[443]),
            tcp("api.github.com", &[443]),
            tcp("codeload.github.com", &[443]),
            tcp("objects.githubusercontent.com", &[443]),
            tcp("raw.githubusercontent.com", &[443]),
            tcp("release-assets.githubusercontent.com", &[443]),
        ],
    ),
    (
        "cloudflare-tunnel",
        "the Cloudflare tunnel connector",
        &[
            tcp("region1.v2.argotunnel.com", &[443, 7844]),
            udp("region1.v2.argotunnel.com", &[7844]),
            tcp("region2.v2.argotunnel.com", &[443, 7844]),
            udp("region2.v2.argotunnel.com", &[7844]),
            tcp("api.cloudflare.com", &[443]),
        ],
    ),
    ("anthropic", "the Anthropic API", &[tcp("api.anthropic.com", &[443])]),
    ("openai", "the OpenAI API", &[tcp("api.openai.com", &[443])]),
    (
        "google-ai",
        "the Google Gemini API",
        &[tcp("generativelanguage.googleapis.com", &[443])],
    ),
    (
        "bedrock",
        "Amazon Bedrock in the box's region",
        &[tcp("bedrock-runtime.{region}.amazonaws.com", &[443])],
    ),
    ("npm", "the npm registry", &[tcp("registry.npmjs.org", &[443])]),
    (
        "pypi",
        "the Python package index",
        &[tcp("pypi.org", &[443]), tcp("files.pythonhosted.org", &[443])],
    ),
    (
        "crates",
        "the Rust crate registry",
        &[
            tcp("crates.io", &[443]),
            tcp("index.crates.io", &[443]),
            tcp("static.crates.io", &[443]),
        ],
    ),
    (
        "containers",
        "Docker Hub and the GitHub container registry",
        &[
            tcp("registry-1.docker.io", &[443]),
            tcp("auth.docker.io", &[443]),
            tcp("production.cloudflare.docker.com", &[443]),
            tcp("ghcr.io", &[443]),
            tcp("pkg-containers.githubusercontent.com", &[443]),
        ],
    ),
];

/// The preset names and what each is for.
pub fn preset_catalogue() -> Vec<(&'static str, &'static str)> {
    PRESETS.iter().map(|(n, d, _)| (*n, *d)).collect()
}

/// A hostname or an IPv4 literal, in plain lowercase: no wildcard (an address filter cannot follow a wildcard name),
/// no port, nothing a command line could misread.
pub fn host_ok(h: &str) -> bool {
    if h.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !h.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

fn region_ok(r: &str) -> bool {
    r.is_empty()
        || (r.len() <= 20
            && r.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

/// What a person declared. Nothing in it is a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Declaration {
    pub mode: Mode,
    /// The box's region (AWS), for the names that carry one. Empty on a provider without one.
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub presets: Vec<String>,
    /// Extra names (https, port 443) beyond the presets.
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl Declaration {
    pub fn off() -> Self {
        Self {
            mode: Mode::Off,
            region: String::new(),
            presets: Vec::new(),
            hosts: Vec::new(),
        }
    }

    /// Check a declaration, wherever it came from (the request, the file on the box).
    pub fn validate(&self) -> Result<(), String> {
        if !region_ok(&self.region) {
            return Err("the region is not valid".into());
        }
        if self.presets.len() > MAX_PRESETS || self.hosts.len() > MAX_HOSTS {
            return Err(format!(
                "at most {MAX_PRESETS} presets and {MAX_HOSTS} hosts fit in a declaration"
            ));
        }
        for p in &self.presets {
            if !PRESETS.iter().any(|(n, _, _)| n == p) {
                let names: Vec<&str> = PRESETS.iter().map(|(n, _, _)| *n).collect();
                return Err(format!(
                    "{p} is not a preset (they are: {})",
                    names.join(", ")
                ));
            }
        }
        for h in &self.hosts {
            if !host_ok(h) {
                return Err(format!(
                    "{h} is not a plain host name (lowercase letters, digits, dashes and dots; no wildcard, no port)"
                ));
            }
        }
        let needs_region = self
            .presets
            .iter()
            .filter_map(|p| PRESETS.iter().find(|(n, _, _)| n == p))
            .any(|(_, _, ds)| ds.iter().any(|d| d.host.contains("{region}")));
        if needs_region && self.region.is_empty() {
            return Err("a preset names the box's region; pass --region".into());
        }
        Ok(())
    }

    /// Read the words after `host-guard egress set`: `MODE [--region R] [--preset P]... [--host H]...`.
    pub fn from_words(words: &[String]) -> Result<Self, String> {
        let (mode, rest) = words
            .split_first()
            .ok_or("say the mode: off, log or enforce")?;
        let mode = Mode::parse(mode).ok_or("the mode is off, log or enforce")?;
        let mut d = Declaration {
            mode,
            ..Declaration::off()
        };
        let mut it = rest.iter();
        while let Some(flag) = it.next() {
            let val = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
            match flag.as_str() {
                "--region" => d.region = val.clone(),
                "--preset" => d.presets.push(val.clone()),
                "--host" => d.hosts.push(val.clone()),
                other => return Err(format!("{other} is not an option of this action")),
            }
        }
        d.presets.sort();
        d.presets.dedup();
        d.hosts.sort();
        d.hosts.dedup();
        d.validate()?;
        Ok(d)
    }

    /// The words that carry it back to the box (the inverse of [`from_words`](Self::from_words)).
    pub fn to_words(&self) -> Vec<String> {
        let mut w = vec![self.mode.as_str().to_string()];
        if !self.region.is_empty() {
            w.extend(["--region".to_string(), self.region.clone()]);
        }
        for p in &self.presets {
            w.extend(["--preset".to_string(), p.clone()]);
        }
        for h in &self.hosts {
            w.extend(["--host".to_string(), h.clone()]);
        }
        w
    }

    /// Every destination the declaration comes to, sorted and without repeats. An AWS box (it has a region) always gets
    /// `aws-control`: without it, enforcing would cut the box off from the one management path it has.
    pub fn destinations(&self, fragments: &[Fragment]) -> Vec<Dest> {
        let mut out: BTreeSet<Dest> = BTreeSet::new();
        let mut names: Vec<&str> = self.presets.iter().map(String::as_str).collect();
        if !self.region.is_empty() && !names.contains(&"aws-control") {
            names.push("aws-control");
        }
        for n in names {
            if let Some((_, _, ds)) = PRESETS.iter().find(|(p, _, _)| *p == n) {
                for d in *ds {
                    for port in d.ports {
                        out.insert(Dest {
                            host: d.host.replace("{region}", &self.region),
                            proto: d.proto,
                            port: *port,
                        });
                    }
                }
            }
        }
        for h in &self.hosts {
            out.insert(Dest {
                host: h.clone(),
                proto: Proto::Tcp,
                port: 443,
            });
        }
        for f in fragments {
            out.extend(f.dests.iter().cloned());
        }
        out.into_iter().collect()
    }
}

/// The key service a box on the fleet's KMS key can never be cut off from: `kms.<region>` on https, for the region in the key's
/// ARN (the secrets settings' `OZBOX_KMS_KEY_ID`). Nothing for a box with no KMS key, or a value that is not a key ARN. Pure.
pub fn kms_always(key_arn: Option<&str>) -> Vec<Dest> {
    let Some(region) = key_arn.and_then(crate::secrets_adopt::arn_region) else {
        return Vec::new();
    };
    let host = format!("kms.{region}.amazonaws.com");
    if !host_ok(&host) {
        return Vec::new();
    }
    vec![Dest {
        host,
        proto: Proto::Tcp,
        port: 443,
    }]
}

/// A piece of the list another part of the box owns (the tunnel connector, the private mesh agent), dropped as a root-owned
/// JSON file in `/etc/ozbox/egress.d/`. The program that needs a destination declares it; this module hardcodes none of
/// them. `{"name":"mesh","hosts":[{"host":"control.example.com","proto":"tcp","ports":[443]}]}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub name: String,
    pub dests: Vec<Dest>,
}

#[derive(Deserialize)]
struct RawFragment {
    name: String,
    hosts: Vec<RawFragmentHost>,
}

#[derive(Deserialize)]
struct RawFragmentHost {
    host: String,
    proto: Proto,
    ports: Vec<u16>,
}

impl Fragment {
    pub fn parse(json: &str) -> Result<Self, String> {
        let raw: RawFragment =
            serde_json::from_str(json).map_err(|_| "not a fragment".to_string())?;
        if raw.name.is_empty()
            || raw.name.len() > 40
            || !raw
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("the fragment's name is not plain".into());
        }
        if raw.hosts.len() > 200 {
            return Err("a fragment holds at most 200 hosts".into());
        }
        let mut dests = Vec::new();
        for h in raw.hosts {
            if !host_ok(&h.host) || h.ports.is_empty() || h.ports.len() > 8 || h.ports.contains(&0)
            {
                return Err(format!("{} is not a valid destination", h.host));
            }
            for p in h.ports {
                dests.push(Dest {
                    host: h.host.clone(),
                    proto: h.proto,
                    port: p,
                });
            }
        }
        Ok(Self {
            name: raw.name,
            dests,
        })
    }
}

// ---------- names and their addresses ----------

/// What the last resolutions of one name found, and when each address was last seen.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostState {
    pub addrs: BTreeMap<String, u64>,
}

/// Fold fresh answers into what is already known. A name that answered: every address it gave is seen now, and the others
/// stay until they are a day old. A name that did not answer: nothing changes (an outage of the resolver must not shrink the
/// list), apart from the one-day expiry. Returns the names that have no address at all afterwards. Pure.
pub fn merge_resolution(
    prev: &BTreeMap<String, HostState>,
    fresh: &BTreeMap<String, Option<Vec<IpAddr>>>,
    now: u64,
) -> (BTreeMap<String, HostState>, Vec<String>) {
    let mut out: BTreeMap<String, HostState> = BTreeMap::new();
    let mut empty = Vec::new();
    for (host, answer) in fresh {
        let mut st = prev.get(host).cloned().unwrap_or_default();
        if let Some(ips) = answer {
            for ip in ips {
                st.addrs.insert(ip.to_string(), now);
            }
        }
        st.addrs
            .retain(|_, seen| now.saturating_sub(*seen) <= ADDR_TTL_SECS);
        if st.addrs.is_empty() {
            empty.push(host.clone());
        }
        out.insert(host.clone(), st);
    }
    (out, empty)
}

// ---------- the packet-filter ruleset ----------

/// Render the whole table. Applying it replaces the previous one in one step, so there is no moment with an open or a
/// half-built list. `resolvers` are the name servers the system really uses (never `127.0.0.53`, whose queries are the
/// stub's own).
pub fn render_ruleset(
    mode: Mode,
    dests: &[Dest],
    known: &BTreeMap<String, HostState>,
    resolvers: &[IpAddr],
) -> String {
    let mut v4: BTreeSet<(Ipv4Addr, Proto, u16)> = BTreeSet::new();
    let mut v6: BTreeSet<(std::net::Ipv6Addr, Proto, u16)> = BTreeSet::new();
    for d in dests {
        let mut ips: Vec<IpAddr> = Vec::new();
        if let Ok(ip) = d.host.parse::<IpAddr>() {
            ips.push(ip);
        } else if let Some(st) = known.get(&d.host) {
            ips.extend(st.addrs.keys().filter_map(|a| a.parse::<IpAddr>().ok()));
        }
        for ip in ips {
            match ip {
                IpAddr::V4(a) => {
                    v4.insert((a, d.proto, d.port));
                }
                IpAddr::V6(a) => {
                    v6.insert((a, d.proto, d.port));
                }
            }
        }
    }
    let elems4: Vec<String> = v4
        .iter()
        .map(|(a, p, n)| format!("{a} . {} . {n}", p.nft()))
        .collect();
    let elems6: Vec<String> = v6
        .iter()
        .map(|(a, p, n)| format!("{a} . {} . {n}", p.nft()))
        .collect();
    let set = |name: &str, ty: &str, elems: &[String]| {
        let mut s = format!("  set {name} {{\n    type {ty} . inet_proto . inet_service\n");
        if !elems.is_empty() {
            s.push_str(&format!("    elements = {{ {} }}\n", elems.join(", ")));
        }
        s.push_str("  }\n");
        s
    };
    let (r4, r6): (Vec<String>, Vec<String>) =
        resolvers.iter().fold((vec![], vec![]), |mut acc, ip| {
            match ip {
                IpAddr::V4(a) => acc.0.push(a.to_string()),
                IpAddr::V6(a) => acc.1.push(a.to_string()),
            }
            acc
        });
    let mut t = String::from(
        "add table inet ozbox_egress\ndelete table inet ozbox_egress\ntable inet ozbox_egress {\n",
    );
    t.push_str(&set("allow4", "ipv4_addr", &elems4));
    t.push_str(&set("allow6", "ipv6_addr", &elems6));
    t.push_str("  chain output {\n    type filter hook output priority 0; policy accept;\n");
    t.push_str("    oifname \"lo\" accept\n    ct state established,related accept\n");
    // the cloud's own plumbing, never subject to the list: the metadata service, the time service, DHCP, IPv6 neighbour discovery
    t.push_str("    ip daddr 169.254.169.254 accept\n");
    t.push_str("    ip daddr 169.254.169.123 udp dport 123 accept\n");
    t.push_str("    udp sport 68 udp dport 67 accept\n");
    t.push_str("    meta l4proto ipv6-icmp accept\n");
    if !r4.is_empty() {
        t.push_str(&format!(
            "    ip daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept\n",
            r4.join(", ")
        ));
    }
    if !r6.is_empty() {
        t.push_str(&format!(
            "    ip6 daddr {{ {} }} meta l4proto {{ tcp, udp }} th dport 53 accept\n",
            r6.join(", ")
        ));
    }
    t.push_str("    ip daddr . meta l4proto . th dport @allow4 accept\n");
    t.push_str("    ip6 daddr . meta l4proto . th dport @allow6 accept\n");
    match mode {
        Mode::Enforce => {
            t.push_str(&format!("    limit rate 30/minute burst 60 packets log prefix \"{PREFIX_BLOCKED}: \" level info\n"));
            t.push_str("    drop\n");
        }
        _ => {
            t.push_str(&format!("    limit rate 30/minute burst 60 packets log prefix \"{PREFIX_WOULD}: \" level info\n"));
            t.push_str("    accept\n");
        }
    }
    t.push_str("  }\n}\n");
    t
}

// ---------- reading back what was blocked ----------

/// One destination the box tried to reach that was not on the list, with how often and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedTally {
    pub count: u64,
    pub first: u64,
    pub last: u64,
    /// Whether it was dropped (`enforce`) or only noted (`log`).
    pub dropped: bool,
}

/// `(destination "ip:port/proto", dropped?, seconds)` from one kernel-log line the ruleset wrote, or `None`.
pub fn parse_blocked_line(line: &str, now: u64) -> Option<(String, bool, u64)> {
    let dropped = if line.contains(&format!("{PREFIX_BLOCKED}:")) {
        true
    } else if line.contains(&format!("{PREFIX_WOULD}:")) {
        false
    } else {
        return None;
    };
    let field = |k: &str| line.split_whitespace().find_map(|w| w.strip_prefix(k));
    let dst = field("DST=")?;
    let proto = field("PROTO=")?.to_ascii_lowercase();
    let port = field("DPT=").unwrap_or("0");
    if dst.parse::<IpAddr>().is_err()
        || !matches!(proto.as_str(), "tcp" | "udp")
        || port.parse::<u16>().is_err()
    {
        return None;
    }
    let when = line
        .split_whitespace()
        .next()
        .and_then(|w| w.split('.').next())
        .and_then(|w| w.parse::<u64>().ok())
        .unwrap_or(now);
    let shown = if dst.contains(':') {
        format!("[{dst}]")
    } else {
        dst.to_string()
    };
    Some((format!("{shown}:{port}/{proto}"), dropped, when))
}

/// Add the attempts in `lines` to the running tally. Keeps the busiest `keep` destinations. Pure.
pub fn merge_blocked(
    tally: &mut BTreeMap<String, BlockedTally>,
    lines: &str,
    now: u64,
    keep: usize,
) {
    for l in lines.lines() {
        if let Some((dest, dropped, when)) = parse_blocked_line(l, now) {
            let e = tally.entry(dest).or_insert(BlockedTally {
                count: 0,
                first: when,
                last: when,
                dropped,
            });
            e.count += 1;
            e.first = e.first.min(when);
            e.last = e.last.max(when);
            e.dropped = dropped;
        }
    }
    if tally.len() > keep {
        let mut by: Vec<(String, u64)> = tally.iter().map(|(k, v)| (k.clone(), v.count)).collect();
        by.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        for (k, _) in by.into_iter().skip(keep) {
            tally.remove(&k);
        }
    }
}

/// What the box keeps for a person to read: the mode it is in, what it resolved, and what was blocked. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct State {
    pub mode: Option<Mode>,
    pub refreshed_at: u64,
    /// When the box first entered `log` or `enforce` in the declaration now in force.
    pub since: u64,
    pub hosts: BTreeMap<String, HostState>,
    pub unresolved: Vec<String>,
    pub blocked: BTreeMap<String, BlockedTally>,
    /// Where the kernel-log read stopped, so no attempt is counted twice.
    pub journal_cursor: u64,
    pub declaration: Option<Declaration>,
    /// Why the last refresh did not use the declaration on disk (it could not be read or is not valid). The rules from the
    /// last good refresh stay loaded while this is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The report, in words. `now` is only used to say how long ago.
pub fn render_report(s: &State, now: u64) -> String {
    let mut out = String::new();
    if let Some(e) = &s.error {
        out.push_str(&format!(
            "PROBLEM: {e}. The rules from the last good refresh stay loaded; set the list again with `ozbox box-egress`.\n"
        ));
    }
    let Some(mode) = s.mode else {
        out.push_str("The box-wide egress list is not set up on this box (mode off).");
        return out;
    };
    out.push_str(&format!(
        "Egress list: {}. Last refreshed {} ago; {} names known.\n",
        mode.as_str(),
        ago(now.saturating_sub(s.refreshed_at)),
        s.hosts.len()
    ));
    if mode == Mode::Off {
        return out;
    }
    if !s.unresolved.is_empty() {
        out.push_str(&format!(
            "Names with no address yet: {}\n",
            s.unresolved.join(", ")
        ));
    }
    if s.blocked.is_empty() {
        out.push_str(if mode == Mode::Log {
            "Nothing outside the list has been attempted since this began.\n"
        } else {
            "Nothing has been blocked since this began.\n"
        });
    } else {
        out.push_str(if mode == Mode::Log {
            "Reached, but not on the list (these would be blocked by `enforce`):\n"
        } else {
            "Blocked (not on the list):\n"
        });
        let mut rows: Vec<(&String, &BlockedTally)> = s.blocked.iter().collect();
        rows.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(b.0)));
        for (d, t) in rows.into_iter().take(40) {
            out.push_str(&format!(
                "  {d}  x{}  last {} ago\n",
                t.count,
                ago(now.saturating_sub(t.last))
            ));
        }
    }
    out
}

fn ago(secs: u64) -> String {
    match secs {
        0..=89 => format!("{secs}s"),
        90..=5399 => format!("{}m", secs / 60),
        5400..=172_799 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn turning_the_list_off_or_widening_it_loosens_and_asking_for_less_does_not() {
        let d = |s: &str| Declaration::from_words(&w(s)).unwrap();
        let loose = [
            ("enforce --preset github", "off"),
            ("log --preset github", "off"),
            ("enforce --preset github", "log --preset github"),
            (
                "enforce --preset github",
                "enforce --preset github --host exfil.example.com",
            ),
            ("enforce --preset github", "enforce --preset npm"),
            ("log --preset github", "log --preset github --preset npm"),
            (
                "log --preset github",
                "enforce --preset github --host exfil.example.com",
            ),
            // another region's endpoints are other destinations
            ("enforce --region us-east-1", "enforce --region eu-west-1"),
        ];
        for (cur, new) in loose {
            assert!(loosens(&d(cur), &d(new)), "{cur} -> {new}");
        }
        let tight = [
            ("off", "off"),
            ("off", "log --preset github"),
            ("off", "enforce --host exfil.example.com"),
            ("log --preset github", "enforce --preset github"),
            ("log --preset github --preset npm", "log --preset github"),
            (
                "enforce --preset github --preset npm",
                "enforce --preset npm",
            ),
            ("enforce --preset github", "enforce --preset github"),
            (
                "enforce --region us-east-1 --preset github",
                "enforce --region us-east-1",
            ),
        ];
        for (cur, new) in tight {
            assert!(!loosens(&d(cur), &d(new)), "{cur} -> {new}");
        }
    }

    #[test]
    fn a_declaration_is_read_from_words_checked_and_written_back_the_same() {
        let d = Declaration::from_words(&w(
            "log --region us-east-1 --preset github --preset anthropic --host api.example.com",
        ))
        .unwrap();
        assert_eq!(d.mode, Mode::Log);
        assert_eq!(d.presets, ["anthropic", "github"]);
        assert_eq!(Declaration::from_words(&d.to_words()).unwrap(), d);
        for bad in [
            "maybe",
            "log --preset nope",
            "log --host *.example.com",
            "log --host Example.com",
            "log --host example.com:443",
            "log --host localhost",
            "log --host a_b.example.com",
            "log --host 1234",
            "log --wat x",
            "log --host",
            "log --preset bedrock", // needs a region
            "log --region UPPER",
        ] {
            assert!(Declaration::from_words(&w(bad)).is_err(), "{bad}");
        }
        assert!(Declaration::from_words(&[]).is_err());
        // an address literal is a host too
        assert!(Declaration::from_words(&w("log --host 203.0.113.9")).is_ok());
    }

    #[test]
    fn the_destinations_are_the_presets_the_hosts_and_the_fragments_and_an_aws_box_always_keeps_its_control_path(
    ) {
        let d = Declaration::from_words(&w(
            "enforce --region eu-west-1 --preset github --host api.example.com",
        ))
        .unwrap();
        let frag = Fragment::parse(r#"{"name":"mesh","hosts":[{"host":"control.example.net","proto":"udp","ports":[443,3478]}]}"#).unwrap();
        let dests = d.destinations(std::slice::from_ref(&frag));
        let has = |h: &str, p: Proto, port: u16| {
            dests
                .iter()
                .any(|x| x.host == h && x.proto == p && x.port == port)
        };
        assert!(
            has("ssm.eu-west-1.amazonaws.com", Proto::Tcp, 443),
            "aws-control is implied by a region"
        );
        assert!(has("github.com", Proto::Tcp, 22) && has("github.com", Proto::Tcp, 443));
        assert!(has("api.example.com", Proto::Tcp, 443));
        assert!(has("control.example.net", Proto::Udp, 3478));
        // no region: no AWS control names, and a name that wanted one was refused at validation
        let off_aws = Declaration::from_words(&w("log --preset github")).unwrap();
        assert!(!off_aws
            .destinations(&[])
            .iter()
            .any(|x| x.host.contains("amazonaws")));
        // sorted and without repeats
        let mut sorted = dests.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(dests, sorted);
    }

    #[test]
    fn the_key_service_of_a_box_on_kms_is_always_allowed_and_only_for_a_real_key() {
        let arn = "arn:aws:kms:eu-west-1:123456789012:key/0f0f0f0f-0000-4000-8000-000000000000";
        assert_eq!(
            kms_always(Some(arn)),
            vec![Dest {
                host: "kms.eu-west-1.amazonaws.com".into(),
                proto: Proto::Tcp,
                port: 443
            }]
        );
        // no key, no ARN, a made-up service: nothing is added to anyone's list
        assert!(kms_always(None).is_empty());
        assert!(kms_always(Some("")).is_empty());
        assert!(kms_always(Some("arn:aws:s3:::bucket")).is_empty());
        assert!(kms_always(Some("evil.example.com")).is_empty());
    }

    #[test]
    fn a_fragment_that_is_not_plain_is_refused() {
        assert!(Fragment::parse(r#"{"name":"a b","hosts":[]}"#).is_err());
        assert!(Fragment::parse(
            r#"{"name":"x","hosts":[{"host":"*.x.com","proto":"tcp","ports":[443]}]}"#
        )
        .is_err());
        assert!(Fragment::parse(
            r#"{"name":"x","hosts":[{"host":"x.com","proto":"tcp","ports":[0]}]}"#
        )
        .is_err());
        assert!(Fragment::parse(
            r#"{"name":"x","hosts":[{"host":"x.com","proto":"icmp","ports":[1]}]}"#
        )
        .is_err());
        assert!(Fragment::parse("nope").is_err());
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_address_stays_allowed_for_a_day_after_its_name_last_gave_it_and_an_outage_shrinks_nothing(
    ) {
        let mut fresh = BTreeMap::new();
        fresh.insert(
            "a.example.com".to_string(),
            Some(vec![ip("203.0.113.1"), ip("2001:db8::1")]),
        );
        fresh.insert("b.example.com".to_string(), None);
        let (s1, empty) = merge_resolution(&BTreeMap::new(), &fresh, 1_000);
        assert_eq!(empty, ["b.example.com"]);
        assert_eq!(s1["a.example.com"].addrs.len(), 2);
        // the name now answers with another address: both are kept
        let mut fresh2 = BTreeMap::new();
        fresh2.insert("a.example.com".to_string(), Some(vec![ip("203.0.113.2")]));
        fresh2.insert("b.example.com".to_string(), None);
        let (s2, _) = merge_resolution(&s1, &fresh2, 2_000);
        assert_eq!(s2["a.example.com"].addrs.len(), 3);
        // the resolver is down: nothing is dropped until a day has passed since each address was last seen
        let down = BTreeMap::from([("a.example.com".to_string(), None)]);
        let (s3, empty3) = merge_resolution(&s2, &down, 2_000 + 3_600);
        assert_eq!(s3["a.example.com"].addrs.len(), 3);
        assert!(empty3.is_empty());
        let (s4, empty4) = merge_resolution(&s3, &down, 2_000 + ADDR_TTL_SECS + 1);
        assert!(s4["a.example.com"].addrs.is_empty());
        assert_eq!(empty4, ["a.example.com"]);
    }

    fn known() -> BTreeMap<String, HostState> {
        BTreeMap::from([(
            "api.example.com".to_string(),
            HostState {
                addrs: BTreeMap::from([
                    ("203.0.113.7".to_string(), 1),
                    ("2001:db8::7".to_string(), 1),
                ]),
            },
        )])
    }

    fn dests() -> Vec<Dest> {
        vec![
            Dest {
                host: "api.example.com".into(),
                proto: Proto::Tcp,
                port: 443,
            },
            Dest {
                host: "198.51.100.4".into(),
                proto: Proto::Udp,
                port: 7844,
            },
        ]
    }

    #[test]
    fn the_ruleset_replaces_the_table_in_one_step_allows_the_plumbing_and_the_listed_addresses_and_logs_the_rest(
    ) {
        let r = render_ruleset(
            Mode::Enforce,
            &dests(),
            &known(),
            &[ip("10.0.0.2"), ip("2001:db8::53")],
        );
        // one transaction: add (so the delete cannot fail), delete, define
        assert!(r.starts_with("add table inet ozbox_egress\ndelete table inet ozbox_egress\ntable inet ozbox_egress {"));
        assert!(r.contains("203.0.113.7 . tcp . 443"));
        assert!(r.contains("198.51.100.4 . udp . 7844"));
        assert!(r.contains("2001:db8::7 . tcp . 443"));
        for plumbing in [
            "oifname \"lo\" accept",
            "ct state established,related accept",
            "ip daddr 169.254.169.254 accept",
            "udp sport 68 udp dport 67 accept",
            "meta l4proto ipv6-icmp accept",
            "ip daddr { 10.0.0.2 } meta l4proto { tcp, udp } th dport 53 accept",
            "ip6 daddr { 2001:db8::53 } meta l4proto { tcp, udp } th dport 53 accept",
        ] {
            assert!(r.contains(plumbing), "missing {plumbing}");
        }
        assert!(r.contains("ip daddr . meta l4proto . th dport @allow4 accept"));
        // enforce: log (rate limited) then drop, and the default is to accept what is not listed nowhere
        let tail = r.split("@allow6 accept").nth(1).unwrap();
        assert!(
            tail.contains("ozbox-egress-blocked: ")
                && tail.contains("drop")
                && !tail.contains("accept\n  }")
        );
        // log mode: the same list, but what falls through is noted and let through
        let l = render_ruleset(Mode::Log, &dests(), &known(), &[]);
        let ltail = l.split("@allow6 accept").nth(1).unwrap();
        assert!(
            ltail.contains("ozbox-egress-would-block: ")
                && ltail.contains("accept")
                && !ltail.contains("drop")
        );
        // a set with nothing in it has no empty elements list (nft refuses one)
        let e = render_ruleset(Mode::Log, &[], &BTreeMap::new(), &[]);
        assert!(!e.contains("elements"));
        // nothing the declaration holds can break out of the text
        assert!(!r.contains('$') && !r.contains(';') || r.contains("policy accept;"));
    }

    #[test]
    fn blocked_attempts_are_read_from_the_kernel_log_counted_and_the_busiest_kept() {
        let line = "1731234567.123456 box kernel: ozbox-egress-blocked: IN= OUT=ens5 SRC=10.0.0.5 DST=93.184.216.34 LEN=60 PROTO=TCP SPT=40000 DPT=443 WINDOW=64240";
        assert_eq!(
            parse_blocked_line(line, 9),
            Some(("93.184.216.34:443/tcp".to_string(), true, 1_731_234_567))
        );
        let would = "ozbox-egress-would-block: OUT=ens5 DST=2001:db8::9 PROTO=UDP SPT=1 DPT=7844";
        assert_eq!(
            parse_blocked_line(would, 77),
            Some(("[2001:db8::9]:7844/udp".to_string(), false, 77))
        );
        for junk in [
            "unrelated kernel line",
            "ozbox-egress-blocked: DST=not-an-ip PROTO=TCP DPT=1",
            "ozbox-egress-blocked: DST=1.2.3.4 PROTO=ICMP",
        ] {
            assert_eq!(parse_blocked_line(junk, 1), None, "{junk}");
        }
        let mut t = BTreeMap::new();
        let text = format!("{line}\n{line}\n{would}\nnoise\n");
        merge_blocked(&mut t, &text, 5, 10);
        assert_eq!(t["93.184.216.34:443/tcp"].count, 2);
        assert_eq!(t.len(), 2);
        merge_blocked(&mut t, &text, 5, 1);
        assert_eq!(t.len(), 1, "only the busiest destination is kept");
        assert!(t.contains_key("93.184.216.34:443/tcp"));
    }

    #[test]
    fn the_report_says_what_the_box_reached_that_was_not_on_the_list() {
        let mut s = State {
            mode: Some(Mode::Log),
            refreshed_at: 900,
            ..State::default()
        };
        assert!(render_report(&s, 1000).contains("Nothing outside the list"));
        s.blocked.insert(
            "1.2.3.4:443/tcp".into(),
            BlockedTally {
                count: 7,
                first: 10,
                last: 990,
                dropped: false,
            },
        );
        let r = render_report(&s, 1000);
        assert!(r.contains("would be blocked by `enforce`") && r.contains("1.2.3.4:443/tcp  x7"));
        s.mode = Some(Mode::Enforce);
        assert!(render_report(&s, 1000).contains("Blocked (not on the list)"));
        assert!(render_report(&State::default(), 1).contains("not set up"));
    }
}
