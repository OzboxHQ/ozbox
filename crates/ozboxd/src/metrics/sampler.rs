//! Reads the host every tick and computes rates from deltas.

use std::path::PathBuf;
use std::sync::Arc;

use ozbox_core::{CommandRunner, CommandSpec, GpuSample, MetricsSample, RunUsage};

use crate::host::HostSource;
use crate::metrics::parse::{self, CpuTimes};

#[derive(Debug, Clone, Copy)]
struct Prev {
    ts_ms: u64,
    cpu: CpuTimes,
    net_rx: u64,
    net_tx: u64,
    disk_r: u64,
    disk_w: u64,
}

pub struct Sampler {
    host: Arc<dyn HostSource>,
    runner: Arc<dyn CommandRunner>,
    work_path: PathBuf,
    gpu_enabled: bool,
    prev: Option<Prev>,
}

impl Sampler {
    pub fn new(
        host: Arc<dyn HostSource>,
        runner: Arc<dyn CommandRunner>,
        work_path: PathBuf,
        gpu_enabled: bool,
    ) -> Self {
        Self {
            host,
            runner,
            work_path,
            gpu_enabled,
            prev: None,
        }
    }

    /// Take one sample. A file that is missing or malformed leaves its fields at zero rather than failing the tick
    /// (a degraded sample beats no sample); only a missing `/proc/stat` or `/proc/meminfo` is an error.
    pub fn sample(
        &mut self,
        now_ms: u64,
        runs: Vec<RunUsage>,
    ) -> Result<MetricsSample, parse::ParseError> {
        let stat = self.host.read("/proc/stat").map_err(io_err("/proc/stat"))?;
        let cpu = parse::parse_proc_stat(&stat)?;
        let mem_text = self
            .host
            .read("/proc/meminfo")
            .map_err(io_err("/proc/meminfo"))?;
        let mem = parse::parse_meminfo(&mem_text)?;

        let psi = |name: &str| -> f64 {
            self.host
                .read(&format!("/proc/pressure/{name}"))
                .ok()
                .and_then(|t| parse::parse_pressure(&t).ok())
                .map(|p| p.some.avg10)
                .unwrap_or(0.0)
        };
        let (net_rx, net_tx) = self
            .host
            .read("/proc/net/dev")
            .ok()
            .and_then(|t| parse::parse_net_dev(&t).ok())
            .map(|v| {
                v.iter()
                    .fold((0u64, 0u64), |a, d| (a.0 + d.rx_bytes, a.1 + d.tx_bytes))
            })
            .unwrap_or((0, 0));
        let (disk_r, disk_w) = self
            .host
            .read("/proc/diskstats")
            .ok()
            .and_then(|t| parse::parse_diskstats(&t).ok())
            .map(|v| {
                v.iter().fold((0u64, 0u64), |a, d| {
                    (a.0 + d.bytes_read, a.1 + d.bytes_written)
                })
            })
            .unwrap_or((0, 0));
        let space = self.host.disk_space(&self.work_path).ok();

        let mut s = MetricsSample {
            ts_ms: now_ms,
            mem_total_bytes: mem.total,
            mem_available_bytes: mem.available,
            swap_total_bytes: mem.swap_total,
            swap_free_bytes: mem.swap_free,
            psi_cpu_some_avg10: psi("cpu"),
            psi_mem_some_avg10: psi("memory"),
            psi_io_some_avg10: psi("io"),
            disk_total_bytes: space.map(|d| d.total_bytes).unwrap_or(0),
            disk_free_bytes: space.map(|d| d.free_bytes).unwrap_or(0),
            gpus: self.gpus(),
            runs,
            ..MetricsSample::default()
        };
        if let Some(p) = self.prev {
            let dt_s = now_ms.saturating_sub(p.ts_ms) as f64 / 1000.0;
            s.cpu_pct = parse::cpu_pct(p.cpu, cpu);
            if dt_s > 0.0 {
                let rate = |now: u64, before: u64| now.saturating_sub(before) as f64 / dt_s;
                s.net_rx_bps = rate(net_rx, p.net_rx);
                s.net_tx_bps = rate(net_tx, p.net_tx);
                s.disk_read_bps = rate(disk_r, p.disk_r);
                s.disk_write_bps = rate(disk_w, p.disk_w);
            }
        }
        self.prev = Some(Prev {
            ts_ms: now_ms,
            cpu,
            net_rx,
            net_tx,
            disk_r,
            disk_w,
        });
        Ok(s)
    }

    fn gpus(&mut self) -> Vec<GpuSample> {
        if !self.gpu_enabled {
            return Vec::new();
        }
        let cmd = CommandSpec::new("nvidia-smi")
            .arg(parse::NVIDIA_SMI_QUERY)
            .arg("--format=csv,noheader,nounits");
        match self.runner.run_ok(&cmd) {
            Ok(out) => parse::parse_nvidia_smi_csv(&out.stdout).unwrap_or_default(),
            Err(_) => {
                // Absent tool or no driver: no GPU, and do not ask again.
                self.gpu_enabled = false;
                Vec::new()
            }
        }
    }
}

fn io_err(what: &'static str) -> impl Fn(std::io::Error) -> parse::ParseError {
    move |e| parse::ParseError {
        what,
        why: e.kind().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::FakeHost;
    use ozbox_core::{Output, RecordingRunner};

    fn fx(n: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/{n}", env!("CARGO_MANIFEST_DIR")))
            .unwrap()
    }

    #[test]
    fn computes_rates_from_deltas() {
        let host = Arc::new(FakeHost::default());
        host.set("/proc/stat", &fx("proc_stat.txt"));
        host.set("/proc/meminfo", &fx("meminfo.txt"));
        host.set("/proc/net/dev", &fx("net_dev.txt"));
        host.set("/proc/diskstats", &fx("diskstats.txt"));
        host.set("/proc/pressure/cpu", &fx("pressure_cpu.txt"));
        host.set_disk(1000, 400);
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(Output {
            status: Some(0),
            stdout: fx("nvidia_smi.txt"),
            stderr: String::new(),
        });
        let mut s = Sampler::new(host.clone(), runner.clone(), "/work".into(), true);

        let first = s.sample(10_000, vec![]).unwrap();
        assert_eq!((first.cpu_pct, first.net_rx_bps), (0.0, 0.0)); // no previous sample yet
        assert_eq!(first.mem_available_bytes, 8_192_000 * 1024);
        assert_eq!((first.disk_total_bytes, first.disk_free_bytes), (1000, 400));
        assert_eq!(first.psi_cpu_some_avg10, 1.5);
        assert_eq!(first.gpus.len(), 2);

        // 5 s later: +300 jiffies (200 busy), +5 MB rx, +2.5 MB tx
        host.set("/proc/stat", &fx("proc_stat_later.txt"));
        host.set(
            "/proc/net/dev",
            &fx("net_dev.txt")
                .replace("5000000", "10000000")
                .replace("2500000", "5000000"),
        );
        let second = s.sample(15_000, vec![]).unwrap();
        assert!((second.cpu_pct - 66.67).abs() < 0.01);
        assert_eq!(
            (second.net_rx_bps, second.net_tx_bps),
            (1_000_000.0, 500_000.0)
        );
        // GPU tool is asked for on each sample while it works
        assert_eq!(runner.calls().len(), 2);
        assert_eq!(runner.calls()[0].program, "nvidia-smi");
    }

    #[test]
    fn missing_gpu_tool_is_not_asked_twice_and_missing_proc_is_an_error() {
        let host = Arc::new(FakeHost::default());
        host.set("/proc/stat", &fx("proc_stat.txt"));
        host.set("/proc/meminfo", &fx("meminfo.txt"));
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(Output {
            status: Some(127),
            ..Default::default()
        });
        let mut s = Sampler::new(host, runner.clone(), "/work".into(), true);
        assert!(s.sample(1, vec![]).unwrap().gpus.is_empty());
        assert!(s.sample(2, vec![]).unwrap().gpus.is_empty());
        assert_eq!(runner.calls().len(), 1);
        let mut bare = Sampler::new(Arc::new(FakeHost::default()), runner, "/work".into(), false);
        assert!(bare.sample(1, vec![]).is_err());
    }
}
