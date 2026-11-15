//! Synthetic usage for the fake provider, so the dashboard has something to draw without a real box.
//!
//! Deterministic: a sample is a pure function of the box and the timestamp, so repeated requests agree and tests
//! are stable. Every response that carries these says `"source": "simulated"`.

use ozbox_core::{BoxRecord, MetricsSample, RunUsage};

const GIB: u64 = 1024 * 1024 * 1024;

/// Round a time down to a whole step.
pub fn bucket(ts_ms: u64, step_ms: u64) -> u64 {
    ts_ms - ts_ms % step_ms
}

fn fnv(data: &[u8], seed: u64) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Uniform in [0, 1) from a hash.
fn unit(h: u64) -> f64 {
    (h >> 11) as f64 / (1u64 << 53) as f64
}

pub fn sample(rec: &BoxRecord, ts_ms: u64) -> MetricsSample {
    let seed = fnv(rec.spec.name.as_str().as_bytes(), 0);
    let phase = unit(seed) * std::f64::consts::TAU;
    let t = ts_ms as f64 / 1000.0;
    let noise = unit(fnv(&ts_ms.to_le_bytes(), seed)) - 0.5;

    let busy = (38.0 + 24.0 * (t / 900.0 + phase).sin() + 9.0 * (t / 37.0).sin() + 8.0 * noise)
        .clamp(1.0, 99.0);
    let busy_mem = (0.52 + 0.14 * (t / 3600.0 + phase).sin() + 0.02 * noise).clamp(0.05, 0.97);
    // The label `sim_profile` makes a demo box light or idle, so the suggestions have something to find.
    let (cpu, mem_frac) = match rec.spec.labels.get("sim_profile").map(String::as_str) {
        Some("light") => (busy * 0.25, busy_mem * 0.45),
        Some("idle") => (1.0 + 3.0 * (noise + 0.5), 0.2),
        _ => (busy, busy_mem),
    };

    let spec = rec.spec.size.spec();
    let mem_total = u64::from(spec.memory_gb) * GIB;
    let mem_used = (mem_total as f64 * mem_frac) as u64;
    let disk_total = u64::from(rec.spec.work_disk_gb) * GIB;
    let disk_free = disk_total - (disk_total as f64 * (0.30 + 0.05 * (phase.sin() + 1.0))) as u64;

    let share = 0.6 + 0.2 * (t / 120.0 + phase).sin();
    let runs = vec![
        RunUsage {
            id: "run-1".into(),
            cpu_pct: cpu * share,
            mem_bytes: (mem_used as f64 * 0.5) as u64,
            mem_max_bytes: Some(mem_total / 2),
        },
        RunUsage {
            id: "run-2".into(),
            cpu_pct: cpu * (1.0 - share) * 0.5,
            mem_bytes: (mem_used as f64 * 0.2) as u64,
            mem_max_bytes: Some(mem_total / 4),
        },
    ];

    MetricsSample {
        ts_ms,
        cpu_pct: cpu,
        mem_total_bytes: mem_total,
        mem_available_bytes: mem_total - mem_used,
        swap_total_bytes: 0,
        swap_free_bytes: 0,
        psi_cpu_some_avg10: (cpu - 60.0).max(0.0) / 8.0,
        psi_mem_some_avg10: (mem_frac - 0.85).max(0.0) * 20.0,
        psi_io_some_avg10: unit(fnv(&ts_ms.to_le_bytes(), seed ^ 7)) * 2.0,
        disk_total_bytes: disk_total,
        disk_free_bytes: disk_free,
        disk_read_bps: 2.0e6 * (1.0 + noise),
        disk_write_bps: 1.0e6 * (1.0 + (t / 60.0).sin()),
        net_rx_bps: 5.0e5 * (1.0 + noise),
        net_tx_bps: 2.5e5 * (1.0 - noise),
        gpus: Vec::new(),
        runs,
    }
}

/// Simulated runs for a running box: two running (the ones the sample reports), one queued, one finished.
pub fn runs(rec: &BoxRecord, now_ms: u64) -> Vec<serde_json::Value> {
    use serde_json::json;
    let name = rec.spec.name.as_str();
    let s = sample(rec, now_ms);
    let mut out = Vec::new();
    for (i, r) in s.runs.iter().enumerate() {
        out.push(json!({
            "id": format!("{name}-{}", r.id),
            "box": name,
            "label": if i == 0 { "agent session" } else { "test job" },
            "status": "running",
            "cpu_pct": r.cpu_pct,
            "mem_bytes": r.mem_bytes,
            "started_ms": now_ms.saturating_sub(25 * 60_000 + i as u64 * 7 * 60_000),
        }));
    }
    out.push(json!({
        "id": format!("{name}-run-3"),
        "box": name,
        "label": "build job",
        "status": "queued",
        "cpu_pct": null,
        "mem_bytes": null,
        "started_ms": null,
    }));
    out.push(json!({
        "id": format!("{name}-run-0"),
        "box": name,
        "label": "lint job",
        "status": "finished",
        "cpu_pct": null,
        "mem_bytes": null,
        "started_ms": now_ms.saturating_sub(3 * 3_600_000),
    }));
    out
}

/// Fixed, obviously synthetic log lines for a simulated run id (`<box>-run-<n>`).
pub fn run_logs(id: &str) -> Option<Vec<String>> {
    let (name, n) = id.rsplit_once("-run-")?;
    ozbox_core::BoxName::new(name).ok()?;
    let n: u32 = n.parse().ok().filter(|n| *n <= 3)?;
    let tail = match n {
        3 => "waiting for free memory before starting",
        0 => "finished with exit code 0",
        _ => "still running",
    };
    Some(vec![
        "[simulated] this log is generated for the demo provider".to_string(),
        format!("[simulated] {name}: starting run {n}"),
        "[simulated] checking out the repository".to_string(),
        format!("[simulated] {tail}"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozbox_core::{BoxName, BoxSpec, BoxState, Size};

    fn rec(name: &str) -> Result<BoxRecord, Box<dyn std::error::Error>> {
        Ok(BoxRecord {
            spec: BoxSpec::new(BoxName::new(name)?, Size::M),
            state: BoxState::Running,
            provider: "fake".into(),
            provider_id: None,
            machine_type: None,
            snapshots: vec![],
            created_at: None,
            last_activity_at: None,
        })
    }

    #[test]
    fn deterministic_and_in_range() -> Result<(), Box<dyn std::error::Error>> {
        let a = rec("alpha")?;
        let b = rec("beta")?;
        let t = 1_800_000_000_000u64;
        assert_eq!(sample(&a, t), sample(&a, t));
        assert_ne!(sample(&a, t), sample(&b, t));
        for i in 0..500 {
            let s = sample(&a, t + i * 5_000);
            assert!((0.0..=100.0).contains(&s.cpu_pct));
            assert!(s.mem_available_bytes <= s.mem_total_bytes);
            assert!(s.disk_free_bytes <= s.disk_total_bytes);
        }
        Ok(())
    }
}
