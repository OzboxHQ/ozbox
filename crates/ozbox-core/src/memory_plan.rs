//! How much memory a box sets aside for itself, and how much any one heavy job may take: the numbers of the box memory guard
//! (ADR 0045), derived from the box's own RAM so a resize never leaves a stale number behind.
//!
//! One module, because three programs must agree on them: the root helper that writes the box's units, the daemon that caps
//! every run it starts, and `ozbox capped` for a person or an agent in a terminal. Pure: nothing here reads the machine.

/// One GiB.
pub const GIB: u64 = 1 << 30;
/// One MiB.
pub const MIB: u64 = 1 << 20;

/// The compressed swap device is at most this much, however much RAM the box has. It is a ceiling on what may be swapped
/// out, not a reservation: zram takes RAM only for the pages it actually holds, about a third of their size with zstd.
pub const ZRAM_MAX_BYTES: u64 = 16 * GIB;
/// The share of RAM the compressed swap device may be as large as, in percent.
pub const ZRAM_PERCENT: u64 = 50;
/// The share of RAM the device may actually occupy, in percent, however badly its pages compress. Past it, a page-out simply
/// fails and the page stays where it was, so an incompressible load cannot make the device itself the thing that fills RAM.
pub const ZRAM_MEM_LIMIT_PERCENT: u64 = 40;
/// How eagerly the kernel swaps idle anonymous pages out. See the ADR for why 100: swapping to zram costs a compression, not a
/// disk wait, so an idle page is as cheap to reclaim as a cache page and the kernel should weigh them evenly.
pub const SWAPPINESS: u32 = 100;
/// No read-ahead on swap-in: a compressed page is a RAM copy, and read-ahead decompresses pages nobody asked for.
pub const PAGE_CLUSTER: u32 = 0;
/// The priority of the compressed device, above any other swap a person might add.
pub const ZRAM_PRIORITY: u32 = 100;

/// What stays out of any one job's reach, for the box itself: the daemon, the tunnels, the secrets service, the web IDE and the
/// kernel. A share of RAM, never under 1 GiB and never over 4 GiB.
pub const RESERVE_MIN_BYTES: u64 = GIB;
pub const RESERVE_MAX_BYTES: u64 = 4 * GIB;
/// The reserve is this many eighths of the box's RAM (one eighth, 12.5 %).
pub const RESERVE_EIGHTHS: u64 = 1;

/// A job's `memory.high` is this share of its `memory.max`, in percent: throttled well before it is killed.
pub const HIGH_PERCENT: u64 = 90;

/// The OOM score the kernel adds for the box's own services (strongly protected).
pub const PROTECTED_OOM_SCORE_ADJ: i32 = -900;
/// The web IDE's score: protected, but less, because its terminals inherit it (ADR 0045).
pub const IDE_OOM_SCORE_ADJ: i32 = -500;
/// What every run the daemon starts puts itself at, so the daemon's own protection is never inherited by a workload.
pub const RUN_OOM_SCORE_ADJ: i32 = 500;
/// What a terminal and a tool install put themselves at: killed after a run (which is capped and disposable) but before the
/// box's own services.
pub const TERMINAL_OOM_SCORE_ADJ: i32 = 200;
/// What `ozbox capped` puts a command at.
pub const CAPPED_OOM_SCORE_ADJ: i32 = 300;

/// The early-warning thresholds, in percent of the last ten seconds in which some (or every) task stalled on memory
/// (`/proc/pressure/memory`, `avg10`). A box in good order sits at 0; the 2026-11-13 incident stalled for about a minute
/// before the kernel killed anything.
pub const PSI_SOME_WARN: f64 = 10.0;
pub const PSI_FULL_WARN: f64 = 3.0;
/// A sustained 60-second average this high fails the self-test: the box is working, but starved.
pub const PSI_SOME_AVG60_FAIL: f64 = 25.0;

/// Everything derived from the box's RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizing {
    pub total_bytes: u64,
    /// The compressed swap device's size (`disksize`).
    pub zram_bytes: u64,
    /// The most RAM the device may hold (`mem_limit`).
    pub zram_mem_limit_bytes: u64,
    /// What stays out of any one job's reach.
    pub reserve_bytes: u64,
    /// One job's hard cap (`memory.max`): everything but the reserve. It is not divided by the number of runs, because the
    /// daemon's admission already shares memory by what each run asks for, and a division would starve the one big build.
    pub run_max_bytes: u64,
    /// One job's throttle point (`memory.high`).
    pub run_high_bytes: u64,
    /// How much of the compressed device one job may fill (`memory.swap.max`): a quarter of the box's RAM.
    pub run_swap_max_bytes: u64,
}

/// Round down to a whole MiB.
fn mib(v: u64) -> u64 {
    v / MIB * MIB
}

/// The numbers for a box with `total_bytes` of RAM. `total_bytes == 0` (unknown) gives all zeros, which every caller reads as
/// "no cap": never a guess.
pub fn sizing(total_bytes: u64) -> Sizing {
    if total_bytes == 0 {
        return Sizing {
            total_bytes: 0,
            zram_bytes: 0,
            zram_mem_limit_bytes: 0,
            reserve_bytes: 0,
            run_max_bytes: 0,
            run_high_bytes: 0,
            run_swap_max_bytes: 0,
        };
    }
    let reserve = (total_bytes / 8 * RESERVE_EIGHTHS).clamp(RESERVE_MIN_BYTES, RESERVE_MAX_BYTES);
    // a box too small to have a reserve gets a cap of half its RAM, never zero
    let run_max = mib(total_bytes.saturating_sub(reserve).max(total_bytes / 2));
    Sizing {
        total_bytes,
        zram_bytes: mib((total_bytes * ZRAM_PERCENT / 100).min(ZRAM_MAX_BYTES)),
        zram_mem_limit_bytes: mib(total_bytes * ZRAM_MEM_LIMIT_PERCENT / 100),
        reserve_bytes: reserve,
        run_max_bytes: run_max,
        run_high_bytes: high_for(run_max),
        run_swap_max_bytes: mib(total_bytes / 4),
    }
}

/// The throttle point for a hard cap of `max_bytes`: 90 %, to the MiB.
pub fn high_for(max_bytes: u64) -> u64 {
    mib(max_bytes * HIGH_PERCENT / 100)
}

/// Everything the daemon decides about one run's memory, from the box's RAM and the request: the single plan both run
/// backends read (a cgroup scope the daemon makes, and a unit of the box user's manager). Computing it twice is how a
/// backend ends up running without the guard, so there is exactly one function that does it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    /// The hard cap (`memory.max` / `MemoryMax=`). `None` only when the owner turned the default cap off and the run named
    /// none: then there is no throttle, swap bound or group kill either.
    pub memory_max: Option<u64>,
    /// The throttle point (`memory.high` / `MemoryHigh=`): [`high_for`] of the cap.
    pub memory_high: Option<u64>,
    /// A bounded share of the compressed swap (`memory.swap.max` / `MemorySwapMax=`), never above the cap.
    pub memory_swap_max: Option<u64>,
    /// One kill for the whole run (`memory.oom.group` / `OOMPolicy=kill`).
    pub oom_group: bool,
    /// The OOM score the run puts itself at (`oom_score_adj` / `OOMScoreAdjust=`), so the daemon's protection is never inherited.
    pub oom_score_adj: i32,
}

/// The plan for one run. A run that asked for more than the default cap is not given less than it asked for: the default is
/// the most a run gets when it names nothing, never a ceiling under its own request.
pub fn run_limits(
    total_bytes: u64,
    default_cap: bool,
    requested_max: Option<u64>,
    requested_memory: u64,
) -> RunLimits {
    let sizes = sizing(total_bytes);
    let max = requested_max.or_else(|| {
        (default_cap && sizes.run_max_bytes > 0).then(|| sizes.run_max_bytes.max(requested_memory))
    });
    RunLimits {
        memory_max: max,
        memory_high: max.map(high_for),
        memory_swap_max: max
            .filter(|_| sizes.run_swap_max_bytes > 0)
            .map(|m| sizes.run_swap_max_bytes.min(m)),
        oom_group: max.is_some(),
        oom_score_adj: RUN_OOM_SCORE_ADJ,
    }
}

/// `MemTotal` from the text of `/proc/meminfo`, in bytes.
pub fn mem_total_from_meminfo(text: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

/// One field of a pressure-stall line: `some avg10=1.23 avg60=…` gives `("some", "avg10")` 1.23.
pub fn psi_value(text: &str, kind: &str, field: &str) -> Option<f64> {
    let line = text
        .lines()
        .find(|l| l.split_whitespace().next() == Some(kind))?;
    line.split_whitespace()
        .find_map(|w| w.strip_prefix(field)?.strip_prefix('=')?.parse().ok())
}

/// The devices in the text of `/proc/swaps`: `(compressed-in-RAM, anything else)`. A device is the compressed kind only when
/// it is a `/dev/zram` one; a file, a partition or any other device is "anything else", which is a place secret pages could
/// reach a disk (ADR 0045), so the self-test fails on it.
pub fn swap_devices(text: &str) -> (Vec<String>, Vec<String>) {
    let (mut zram, mut other) = (Vec::new(), Vec::new());
    for l in text.lines().skip(1) {
        let Some(name) = l.split_whitespace().next() else {
            continue;
        };
        if name.starts_with("/dev/zram") {
            zram.push(name.to_string());
        } else {
            other.push(name.to_string());
        }
    }
    (zram, other)
}

/// The shell fragment a program puts at the top of a command's wrapper to take its own OOM score to `adj`. A process may
/// raise its own score without any privilege; it can never lower it, so this can never leak the daemon's protection onto
/// work it starts. The redirect's own error is silenced too (a shell prints that before it applies `2>`).
pub fn raise_score_snippet(adj: i32) -> String {
    format!("{{ echo {adj} >/proc/self/oom_score_adj; }} 2>/dev/null")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runs_plan_has_all_four_protections_or_none() {
        let s = sizing(16 * GIB);
        let p = run_limits(16 * GIB, true, None, GIB);
        assert_eq!(p.memory_max, Some(s.run_max_bytes));
        assert_eq!(p.memory_high, Some(s.run_high_bytes));
        assert_eq!(p.memory_swap_max, Some(s.run_swap_max_bytes));
        assert!(p.oom_group);
        assert_eq!(p.oom_score_adj, RUN_OOM_SCORE_ADJ);
        // its own request is kept, and the swap share never exceeds it
        let q = run_limits(16 * GIB, true, Some(2 * GIB), GIB);
        assert_eq!(q.memory_max, Some(2 * GIB));
        assert_eq!(q.memory_swap_max, Some(2 * GIB));
        // never a ceiling under what it asked for
        assert_eq!(
            run_limits(16 * GIB, true, None, 15 * GIB).memory_max,
            Some(15 * GIB)
        );
        // uncapped by choice: no cap, no throttle, no swap bound, no group kill; the score is still raised
        let off = run_limits(16 * GIB, false, None, GIB);
        assert_eq!(
            (
                off.memory_max,
                off.memory_high,
                off.memory_swap_max,
                off.oom_group
            ),
            (None, None, None, false)
        );
        assert_eq!(off.oom_score_adj, RUN_OOM_SCORE_ADJ);
    }

    #[test]
    fn the_numbers_for_the_benchmarks_shape_and_the_owners_box() {
        // 4 vCPU / 8 GiB: what the benchmark runs on
        let s = sizing(8 * GIB);
        assert_eq!(s.zram_bytes, 4 * GIB);
        assert_eq!(s.reserve_bytes, GIB);
        assert_eq!(s.run_max_bytes, 7 * GIB);
        assert_eq!(s.run_high_bytes, 6 * GIB + 307 * MIB);
        assert_eq!(s.run_swap_max_bytes, 2 * GIB);
        assert_eq!(s.zram_mem_limit_bytes, mib(8 * GIB * 40 / 100));
        // the box that ran out of memory on 2026-11-13: 15.7 GB
        let s = sizing(15_700_000_000);
        assert_eq!(s.reserve_bytes, 1_962_500_000);
        assert!(s.run_max_bytes < 15_700_000_000 - 1_900_000_000);
        assert!(s.run_high_bytes < s.run_max_bytes);
    }

    #[test]
    fn a_single_run_is_never_capped_below_what_the_box_can_spare() {
        for gib in [2u64, 4, 8, 16, 32, 64, 128, 512] {
            let s = sizing(gib * GIB);
            // the box keeps its reserve, nothing more is held back from one job
            assert!(
                s.run_max_bytes + s.reserve_bytes >= s.total_bytes - MIB,
                "{gib}"
            );
            assert!(s.run_max_bytes >= s.total_bytes / 2, "{gib}");
            assert!(s.run_high_bytes < s.run_max_bytes && s.run_high_bytes > s.run_max_bytes / 2);
            assert!(s.zram_bytes <= ZRAM_MAX_BYTES && s.zram_bytes <= s.total_bytes / 2);
            assert!(s.zram_mem_limit_bytes < s.total_bytes / 2);
            assert_eq!(s.zram_bytes % MIB, 0);
        }
        assert_eq!(sizing(512 * GIB).zram_bytes, ZRAM_MAX_BYTES, "capped");
        assert_eq!(sizing(512 * GIB).reserve_bytes, RESERVE_MAX_BYTES);
    }

    #[test]
    fn the_benchmarks_realworld_builds_fit_inside_the_cap_on_eight_gib() {
        // Mastra, Better-Auth and OpenClaw builds need a few GiB (measured on the 4/8/40 shape before release: the
        // real-box proof); the cap must leave them at least 6 GiB of an 8 GiB box before it throttles.
        assert!(sizing(8 * GIB).run_high_bytes >= 6 * GIB);
    }

    #[test]
    fn an_unknown_ram_is_no_cap_never_a_guess() {
        assert_eq!(sizing(0).run_max_bytes, 0);
        assert_eq!(sizing(0).zram_bytes, 0);
    }

    #[test]
    fn meminfo_and_pressure_lines_are_read() {
        assert_eq!(
            mem_total_from_meminfo("MemTotal:       16384 kB\nMemFree: 1 kB\n"),
            Some(16 * MIB)
        );
        assert_eq!(mem_total_from_meminfo("nothing"), None);
        let p = "some avg10=12.50 avg60=3.00 avg300=1.00 total=1\nfull avg10=4.25 avg60=0.00 avg300=0.00 total=2\n";
        assert_eq!(psi_value(p, "some", "avg10"), Some(12.5));
        assert_eq!(psi_value(p, "full", "avg10"), Some(4.25));
        assert_eq!(psi_value(p, "some", "avg60"), Some(3.0));
        assert_eq!(psi_value(p, "cpu", "avg10"), None);
    }

    #[test]
    fn the_score_snippet_only_raises_and_hides_a_failed_redirect() {
        let s = raise_score_snippet(RUN_OOM_SCORE_ADJ);
        assert_eq!(s, "{ echo 500 >/proc/self/oom_score_adj; } 2>/dev/null");
        const {
            assert!(
                RUN_OOM_SCORE_ADJ > 0 && TERMINAL_OOM_SCORE_ADJ > 0 && CAPPED_OOM_SCORE_ADJ > 0
            );
            assert!(PROTECTED_OOM_SCORE_ADJ < IDE_OOM_SCORE_ADJ && IDE_OOM_SCORE_ADJ < 0);
        }
    }
    #[test]
    fn swap_is_zram_or_it_is_a_finding() {
        let head = "Filename\tType\tSize\tUsed\tPriority\n";
        assert_eq!(swap_devices(head), (vec![], vec![]));
        let t = format!("{head}/dev/zram0 partition 4194300 0 100\n/swapfile file 1024 0 -2\n/dev/nvme0n1p3 partition 1 0 -3\n");
        let (z, o) = swap_devices(&t);
        assert_eq!(z, ["/dev/zram0"]);
        assert_eq!(o, ["/swapfile", "/dev/nvme0n1p3"]);
    }
}
