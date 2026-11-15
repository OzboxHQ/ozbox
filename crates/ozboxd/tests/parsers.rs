#![allow(clippy::unwrap_used)]
use ozboxd::metrics::parse::*;

fn fx(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn proc_stat_and_cpu_pct() {
    let a = parse_proc_stat(&fx("proc_stat.txt")).unwrap();
    let b = parse_proc_stat(&fx("proc_stat_later.txt")).unwrap();
    assert_eq!((a.busy, a.total), (6060, 22830));
    let p = cpu_pct(a, b);
    assert!((p - 66.666).abs() < 0.01, "{p}");
    assert_eq!(cpu_pct(a, a), 0.0);
    assert!(parse_proc_stat("nope").is_err());
}

#[test]
fn meminfo_in_bytes() {
    let m = parse_meminfo(&fx("meminfo.txt")).unwrap();
    assert_eq!(m.total, 16_384_000 * 1024);
    assert_eq!(m.available, 8_192_000 * 1024);
    assert_eq!(m.swap_free, 1_048_576 * 1024);
    assert!(parse_meminfo("MemFree: 1 kB").is_err());
}

#[test]
fn pressure_some_and_full() {
    let c = parse_pressure(&fx("pressure_cpu.txt")).unwrap();
    assert_eq!(c.some.avg10, 1.5);
    assert!(c.full.is_none());
    let m = parse_pressure(&fx("pressure_mem.txt")).unwrap();
    assert_eq!(m.full.map(|f| f.total_us), Some(500));
    assert!(parse_pressure("").is_err());
}

#[test]
fn net_dev_skips_loopback() {
    let n = parse_net_dev(&fx("net_dev.txt")).unwrap();
    assert_eq!(n.len(), 1);
    assert_eq!((n[0].rx_bytes, n[0].tx_bytes), (5_000_000, 2_500_000));
}

#[test]
fn diskstats_whole_disks_only() {
    let d = parse_diskstats(&fx("diskstats.txt")).unwrap();
    let names: Vec<_> = d.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(names, ["nvme0n1", "sda"]);
    assert_eq!(d[0].bytes_read, 2000 * 512);
    assert_eq!(d[0].bytes_written, 4000 * 512);
    assert!(
        is_whole_disk("xvda")
            && !is_whole_disk("xvda1")
            && !is_whole_disk("mmcblk0p2")
            && is_whole_disk("mmcblk0")
    );
}

#[test]
fn cgroup_files() {
    assert_eq!(
        parse_cgroup_cpu_usage_usec(&fx("cpu_stat.txt")).unwrap(),
        5_000_000
    );
    assert!(parse_cgroup_cpu_usage_usec("user_usec 1").is_err());
    assert_eq!(parse_cgroup_u64("12345\n").unwrap(), 12345);
    assert_eq!(parse_cgroup_limit("max\n").unwrap(), None);
    assert_eq!(parse_cgroup_limit("1048576\n").unwrap(), Some(1_048_576));
    let e = parse_memory_events(&fx("memory_events.txt")).unwrap();
    assert_eq!((e.high, e.max, e.oom, e.oom_kill), (3, 2, 1, 1));
    assert!(parse_memory_events("").is_err());
}

#[test]
fn tcp_tables() {
    let t = parse_proc_net_tcp(&fx("net_tcp.txt")).unwrap();
    assert_eq!(t.len(), 4);
    assert!(t[0].local_loopback && t[0].local_port == 8080 && t[0].state == 10);
    assert!(t[1].state == TCP_ESTABLISHED && t[1].local_port == 8080 && t[1].remote_port == 50000);
    assert!(!t[3].local_loopback);
    let t6 = parse_proc_net_tcp(&fx("net_tcp6.txt")).unwrap();
    assert!(t6[0].local_loopback && t6[0].local_port == 0x17B8);
}

#[test]
fn nvidia_smi_and_mounts() {
    let g = parse_nvidia_smi_csv(&fx("nvidia_smi.txt")).unwrap();
    assert_eq!(g.len(), 2);
    assert_eq!(
        (g[0].util_pct, g[0].mem_used_bytes),
        (37.0, 1024 * 1024 * 1024)
    );
    assert!(parse_nvidia_smi_csv("0, x, 1, 2").is_err());
    let m = parse_mounts(&fx("mounts.txt"));
    assert!(m.iter().any(|(p, f)| p == "/work" && f == "ext4"));
}
