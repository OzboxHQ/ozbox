//! Pure parsers for `/proc` and cgroup v2 text. Each takes the file contents and returns numbers, so the logic is
//! tested on fixture text on any OS.

use std::collections::BTreeMap;

use ozbox_core::GpuSample;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("cannot parse {what}: {why}")]
pub struct ParseError {
    pub what: &'static str,
    pub why: String,
}

fn err<T>(what: &'static str, why: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError {
        what,
        why: why.into(),
    })
}

fn num<T: std::str::FromStr>(what: &'static str, s: &str) -> Result<T, ParseError> {
    s.trim().parse::<T>().map_err(|_| ParseError {
        what,
        why: format!("bad number {s:?}"),
    })
}

/// Cumulative CPU jiffies from the aggregate `cpu ` line of `/proc/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuTimes {
    pub busy: u64,
    pub total: u64,
}

pub fn parse_proc_stat(text: &str) -> Result<CpuTimes, ParseError> {
    let line = text
        .lines()
        .find(|l| l.starts_with("cpu "))
        .ok_or_else(|| ParseError {
            what: "/proc/stat",
            why: "no aggregate cpu line".into(),
        })?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .map(|s| num("/proc/stat", s))
        .collect::<Result<_, _>>()?;
    if v.len() < 4 {
        return err("/proc/stat", "fewer than 4 cpu fields");
    }
    let get = |i: usize| v.get(i).copied().unwrap_or(0);
    // user nice system idle iowait irq softirq steal
    let idle = get(3) + get(4);
    let total: u64 = v.iter().take(8).sum();
    let busy = total.saturating_sub(idle);
    Ok(CpuTimes { busy, total })
}

/// CPU percentage between two snapshots; 0 when no time passed.
pub fn cpu_pct(prev: CpuTimes, now: CpuTimes) -> f64 {
    let dt = now.total.saturating_sub(prev.total);
    if dt == 0 {
        return 0.0;
    }
    let db = now.busy.saturating_sub(prev.busy);
    (db as f64 / dt as f64 * 100.0).clamp(0.0, 100.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Meminfo {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

/// Values are returned in bytes (the file reports kB).
pub fn parse_meminfo(text: &str) -> Result<Meminfo, ParseError> {
    let mut m = Meminfo::default();
    let mut have_total = false;
    let mut have_avail = false;
    for line in text.lines() {
        let Some((k, rest)) = line.split_once(':') else {
            continue;
        };
        let val = |r: &str| -> Result<u64, ParseError> {
            let n = r.split_whitespace().next().unwrap_or("");
            Ok(num::<u64>("/proc/meminfo", n)? * 1024)
        };
        match k {
            "MemTotal" => {
                m.total = val(rest)?;
                have_total = true;
            }
            "MemFree" => m.free = val(rest)?,
            "MemAvailable" => {
                m.available = val(rest)?;
                have_avail = true;
            }
            "SwapTotal" => m.swap_total = val(rest)?,
            "SwapFree" => m.swap_free = val(rest)?,
            _ => {}
        }
    }
    if !have_total {
        return err("/proc/meminfo", "no MemTotal");
    }
    if !have_avail {
        m.available = m.free;
    }
    Ok(m)
}

/// One `some` / `full` line of a pressure file.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PressureLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Pressure {
    pub some: PressureLine,
    pub full: Option<PressureLine>,
}

/// `/proc/pressure/*` and cgroup `*.pressure`.
pub fn parse_pressure(text: &str) -> Result<Pressure, ParseError> {
    let mut p = Pressure::default();
    let mut have_some = false;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let kind = it.next().unwrap_or("");
        let mut pl = PressureLine::default();
        for kv in it {
            let Some((k, v)) = kv.split_once('=') else {
                continue;
            };
            match k {
                "avg10" => pl.avg10 = num("pressure", v)?,
                "avg60" => pl.avg60 = num("pressure", v)?,
                "avg300" => pl.avg300 = num("pressure", v)?,
                "total" => pl.total_us = num("pressure", v)?,
                _ => {}
            }
        }
        match kind {
            "some" => {
                p.some = pl;
                have_some = true;
            }
            "full" => p.full = Some(pl),
            _ => {}
        }
    }
    if !have_some {
        return err("pressure", "no `some` line");
    }
    Ok(p)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetDev {
    pub iface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// `/proc/net/dev`, loopback excluded.
pub fn parse_net_dev(text: &str) -> Result<Vec<NetDev>, ParseError> {
    let mut out = Vec::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name == "lo" {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        if f.len() < 9 {
            return err("/proc/net/dev", format!("short line for {name}"));
        }
        out.push(NetDev {
            iface: name.to_string(),
            rx_bytes: num("/proc/net/dev", f[0])?,
            tx_bytes: num("/proc/net/dev", f[8])?,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskStat {
    pub name: String,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

/// Whole disks only: loop, ram and device-mapper nodes and partitions are skipped so IO is not counted twice.
pub fn is_whole_disk(name: &str) -> bool {
    if name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("dm-")
        || name.starts_with("zram")
    {
        return false;
    }
    let ends_digit = name.ends_with(|c: char| c.is_ascii_digit());
    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        // nvme0n1 is a disk, nvme0n1p1 a partition.
        return match name.rfind('p') {
            Some(i) if i > 0 => {
                let tail = &name[i + 1..];
                let is_part = name[..i].ends_with(|c: char| c.is_ascii_digit())
                    && !tail.is_empty()
                    && tail.bytes().all(|b| b.is_ascii_digit());
                !is_part
            }
            _ => true,
        };
    }
    !ends_digit
}

/// `/proc/diskstats`; sectors are 512 bytes.
pub fn parse_diskstats(text: &str) -> Result<Vec<DiskStat>, ParseError> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let name = f[2];
        if !is_whole_disk(name) {
            continue;
        }
        out.push(DiskStat {
            name: name.to_string(),
            bytes_read: num::<u64>("/proc/diskstats", f[5])? * 512,
            bytes_written: num::<u64>("/proc/diskstats", f[9])? * 512,
        });
    }
    Ok(out)
}

/// A flat `key value` file such as cgroup `cpu.stat`.
pub fn parse_flat_keyed(text: &str) -> BTreeMap<String, u64> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let k = it.next()?;
            let v = it.next()?.parse().ok()?;
            Some((k.to_string(), v))
        })
        .collect()
}

/// `usage_usec` from cgroup v2 `cpu.stat`.
pub fn parse_cgroup_cpu_usage_usec(text: &str) -> Result<u64, ParseError> {
    parse_flat_keyed(text)
        .get("usage_usec")
        .copied()
        .ok_or_else(|| ParseError {
            what: "cpu.stat",
            why: "no usage_usec".into(),
        })
}

/// A single-number cgroup file (`memory.current`).
pub fn parse_cgroup_u64(text: &str) -> Result<u64, ParseError> {
    num("cgroup value", text)
}

/// `memory.max` / `memory.high`: the literal `max` means no limit.
pub fn parse_cgroup_limit(text: &str) -> Result<Option<u64>, ParseError> {
    let t = text.trim();
    if t == "max" {
        Ok(None)
    } else {
        Ok(Some(num("cgroup limit", t)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemoryEvents {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
}

pub fn parse_memory_events(text: &str) -> Result<MemoryEvents, ParseError> {
    let m = parse_flat_keyed(text);
    if m.is_empty() {
        return err("memory.events", "empty");
    }
    let g = |k: &str| m.get(k).copied().unwrap_or(0);
    Ok(MemoryEvents {
        low: g("low"),
        high: g("high"),
        max: g("max"),
        oom: g("oom"),
        oom_kill: g("oom_kill"),
    })
}

/// One connection from `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpEntry {
    pub local_loopback: bool,
    pub local_port: u16,
    pub remote_port: u16,
    /// Kernel state code; 1 = ESTABLISHED, 10 = LISTEN.
    pub state: u8,
}

pub const TCP_ESTABLISHED: u8 = 1;

fn is_loopback_hex(addr: &str) -> bool {
    match addr.len() {
        // IPv4, little-endian hex of the address: 127.x.y.z ends in 7F
        8 => addr.ends_with("7F"),
        32 => {
            // ::1 -> 00000000 00000000 00000000 01000000 ; ::ffff:127.x -> ...0000FFFF xxxxxx7F
            addr == "00000000000000000000000001000000"
                || (addr.starts_with("0000000000000000FFFF0000") && addr.ends_with("7F"))
        }
        _ => false,
    }
}

pub fn parse_proc_net_tcp(text: &str) -> Result<Vec<TcpEntry>, ParseError> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let (la, lp) = f[1].rsplit_once(':').ok_or_else(|| ParseError {
            what: "/proc/net/tcp",
            why: "bad local address".into(),
        })?;
        let (_, rp) = f[2].rsplit_once(':').ok_or_else(|| ParseError {
            what: "/proc/net/tcp",
            why: "bad remote address".into(),
        })?;
        let hex = |s: &str| {
            u32::from_str_radix(s, 16).map_err(|_| ParseError {
                what: "/proc/net/tcp",
                why: format!("bad hex {s:?}"),
            })
        };
        out.push(TcpEntry {
            local_loopback: is_loopback_hex(&la.to_ascii_uppercase()),
            local_port: hex(lp)? as u16,
            remote_port: hex(rp)? as u16,
            state: hex(f[3])? as u8,
        });
    }
    Ok(out)
}

/// `nvidia-smi --query-gpu=index,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits`
pub const NVIDIA_SMI_QUERY: &str = "--query-gpu=index,utilization.gpu,memory.used,memory.total";

pub fn parse_nvidia_smi_csv(text: &str) -> Result<Vec<GpuSample>, ParseError> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split(',').map(str::trim).collect();
        if f.len() < 4 {
            return err("nvidia-smi", "expected 4 columns");
        }
        out.push(GpuSample {
            index: num("nvidia-smi", f[0])?,
            util_pct: num("nvidia-smi", f[1])?,
            mem_used_bytes: num::<u64>("nvidia-smi", f[2])? * 1024 * 1024,
            mem_total_bytes: num::<u64>("nvidia-smi", f[3])? * 1024 * 1024,
        });
    }
    Ok(out)
}

/// The device mounted at `mountpoint` in `/proc/mounts`.
pub fn parse_mount_source(text: &str, mountpoint: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let dev = it.next()?;
        (it.next()? == mountpoint).then(|| dev.to_string())
    })
}

/// Mount points from `/proc/mounts`.
pub fn parse_mounts(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let _dev = it.next()?;
            let mp = it.next()?;
            let fs = it.next()?;
            Some((mp.to_string(), fs.to_string()))
        })
        .collect()
}
