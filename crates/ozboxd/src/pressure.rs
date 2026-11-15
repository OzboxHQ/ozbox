//! Memory pressure as an early warning (ADR 0045). The kernel says how much of the last ten seconds some, or every, task stalled
//! waiting for memory (`/proc/pressure/memory`). A healthy box sits at zero. The box that ran out of memory on 2026-11-13
//! stalled for about a minute before the kernel killed anything, and nothing said so: this watcher turns that minute into one
//! incident, which the alert path sends to chat, while there is still time to stop the job.
//!
//! Pure: the daemon reads the file and calls [`Watch::observe`]; nothing here touches the machine.

use ozbox_core::memory_plan::{psi_value, PSI_FULL_WARN, PSI_SOME_WARN};

/// How often the daemon samples, in seconds.
pub const SAMPLE_EVERY_S: u64 = 5;
/// Pressured samples in a row before one incident: a ten-second average already smooths a blip, and two samples make it
/// real without making the warning late.
const SUSTAIN: u32 = 2;
/// Calm samples in a row (30 s) before the watcher can warn again, and the least time between two warnings.
const CALM_SAMPLES: u32 = 6;
const COOLDOWN_MS: u64 = 5 * 60_000;

#[derive(Debug, Default)]
pub struct Watch {
    hot: u32,
    calm: u32,
    armed_after_ms: u64,
    fired: bool,
}

/// The two numbers a sample carries, from the text of `/proc/pressure/memory`.
pub fn read(text: &str) -> Option<(f64, f64)> {
    Some((
        psi_value(text, "some", "avg10")?,
        psi_value(text, "full", "avg10").unwrap_or(0.0),
    ))
}

impl Watch {
    /// One sample. `Some(detail)` is the incident to record, once per episode: ids and numbers only.
    pub fn observe(&mut self, now_ms: u64, some: f64, full: f64) -> Option<String> {
        let pressured = some >= PSI_SOME_WARN || full >= PSI_FULL_WARN;
        let calm = some < PSI_SOME_WARN / 2.0 && full < PSI_FULL_WARN / 2.0;
        if pressured {
            self.hot += 1;
            self.calm = 0;
        } else {
            self.hot = 0;
            // "calm for 30 s in a row" is literal: a sample between calm and pressured (5 to 10 %) breaks the run
            if calm {
                self.calm += 1;
            } else {
                self.calm = 0;
            }
        }
        if self.fired && self.calm >= CALM_SAMPLES {
            self.fired = false;
        }
        if pressured && self.hot >= SUSTAIN && !self.fired && now_ms >= self.armed_after_ms {
            self.fired = true;
            self.armed_after_ms = now_ms + COOLDOWN_MS;
            return Some(format!(
                "memory stalls: some {some:.0}% and full {full:.0}% of the last 10 s; the box is short of memory, and a job may be killed (ADR 0045)"
            ));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 5_000;

    #[test]
    fn a_stall_that_lasts_is_one_warning_a_blip_is_none() {
        let mut w = Watch::default();
        // a blip: one pressured sample, then calm
        assert!(w.observe(T, 30.0, 8.0).is_none());
        assert!(w.observe(2 * T, 0.0, 0.0).is_none());
        // a stall: the second pressured sample in a row warns, once
        assert!(w.observe(3 * T, 12.0, 0.0).is_none());
        let said = w.observe(4 * T, 14.0, 1.0).unwrap();
        assert!(said.contains("14%") && said.contains("ADR 0045"), "{said}");
        for i in 5..40 {
            assert!(
                w.observe(i * T, 40.0, 20.0).is_none(),
                "still the same episode at {i}"
            );
        }
    }

    #[test]
    fn a_sample_between_calm_and_pressured_breaks_the_calm_run() {
        let mut w = Watch::default();
        let t = |i: u64| i * T + COOLDOWN_MS;
        // an episode
        assert!(w.observe(t(0), 40.0, 5.0).is_none());
        assert!(w.observe(t(1), 40.0, 5.0).is_some());
        // five calm samples, then one in between (7 % some is neither calm nor pressured), then five more calm: 5 + 5 is not 6 in
        // a row, so it is still the same episode
        for i in 2..7 {
            assert!(w.observe(t(i), 0.0, 0.0).is_none());
        }
        assert!(w.observe(t(7), 7.0, 0.0).is_none());
        for i in 8..13 {
            assert!(w.observe(t(i), 0.0, 0.0).is_none());
        }
        assert!(w.fired, "not calm for 30 s in a row yet");
        assert!(w.observe(t(13), 0.0, 0.0).is_none());
        assert!(!w.fired, "now it was");
    }

    #[test]
    fn it_warns_again_only_after_the_box_was_calm_and_the_cooldown_passed() {
        let mut w = Watch::default();
        w.observe(T, 20.0, 0.0);
        assert!(w.observe(2 * T, 20.0, 0.0).is_some());
        // calm for 30 s, pressured again within the cooldown: quiet
        for i in 3..10 {
            w.observe(i * T, 0.0, 0.0);
        }
        w.observe(10 * T, 20.0, 0.0);
        assert!(
            w.observe(11 * T, 20.0, 0.0).is_none(),
            "inside five minutes"
        );
        // five minutes on, calm again, then another stall
        for i in 12..90 {
            w.observe(i * T, 0.0, 0.0);
        }
        w.observe(90 * T, 20.0, 0.0);
        assert!(w.observe(91 * T, 20.0, 0.0).is_some());
    }

    #[test]
    fn full_stalls_alone_warn_and_the_file_is_read() {
        let mut w = Watch::default();
        w.observe(T, 2.0, 5.0);
        assert!(w.observe(2 * T, 2.0, 5.0).is_some());
        let p = "some avg10=1.50 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert_eq!(read(p), Some((1.5, 0.0)));
        assert_eq!(read("garbage"), None);
    }
}
