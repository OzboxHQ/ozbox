//! Metric sample types shared by the box daemon and anything that reads its API.
//!
//! A sample carries numbers, ids and labels only - never arguments, file contents or secrets.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One GPU, from the vendor tool's CSV output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpuSample {
    pub index: u32,
    pub util_pct: f64,
    pub mem_used_bytes: u64,
    pub mem_total_bytes: u64,
}

/// What one run (its own cgroup) is using right now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunUsage {
    pub id: String,
    pub cpu_pct: f64,
    pub mem_bytes: u64,
    pub mem_max_bytes: Option<u64>,
}

/// Box-wide totals at one instant. Rates are computed from deltas by the sampler.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct MetricsSample {
    /// Unix time, milliseconds.
    pub ts_ms: u64,
    pub cpu_pct: f64,
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    /// PSI `some avg10` percentages.
    pub psi_cpu_some_avg10: f64,
    pub psi_mem_some_avg10: f64,
    pub psi_io_some_avg10: f64,
    pub disk_total_bytes: u64,
    pub disk_free_bytes: u64,
    pub disk_read_bps: f64,
    pub disk_write_bps: f64,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    #[serde(default)]
    pub gpus: Vec<GpuSample>,
    #[serde(default)]
    pub runs: Vec<RunUsage>,
}

impl MetricsSample {
    /// The scalar fields the time-series store rolls up (min / max / mean / last), by stable name.
    pub fn fields(&self) -> BTreeMap<String, f64> {
        let mut m = BTreeMap::new();
        let mut put = |k: &str, v: f64| {
            m.insert(k.to_string(), v);
        };
        put("cpu_pct", self.cpu_pct);
        put("mem_total_bytes", self.mem_total_bytes as f64);
        put("mem_available_bytes", self.mem_available_bytes as f64);
        put("swap_total_bytes", self.swap_total_bytes as f64);
        put("swap_free_bytes", self.swap_free_bytes as f64);
        put("psi_cpu_some_avg10", self.psi_cpu_some_avg10);
        put("psi_mem_some_avg10", self.psi_mem_some_avg10);
        put("psi_io_some_avg10", self.psi_io_some_avg10);
        put("disk_total_bytes", self.disk_total_bytes as f64);
        put("disk_free_bytes", self.disk_free_bytes as f64);
        put("disk_read_bps", self.disk_read_bps);
        put("disk_write_bps", self.disk_write_bps);
        put("net_rx_bps", self.net_rx_bps);
        put("net_tx_bps", self.net_tx_bps);
        if let Some(g) = self.gpus.first() {
            put("gpu_util_pct", g.util_pct);
            put("gpu_mem_used_bytes", g.mem_used_bytes as f64);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_flat_and_stable() {
        let s = MetricsSample {
            cpu_pct: 12.5,
            ..MetricsSample::default()
        };
        let f = s.fields();
        assert_eq!(f.get("cpu_pct"), Some(&12.5));
        assert!(!f.contains_key("gpu_util_pct"));
    }
}
