//! The sampler's OOM watch (Z20): a run in a unit that is killed whole leaves its kill only in the box user's app slice.

use ozboxd::health::{oom_step, prime_oom_slices, OomSlice, OomWatcher};
use ozboxd::host::FakeHost;

const DAEMON: &str = "/cg/system.slice/ozboxd.service/memory.events";
const APP: &str = "/cg/user.slice/user-1500.slice/user@1500.service/app.slice/memory.events";

fn events(n: u64) -> String {
    format!("low 0\nhigh 0\nmax 0\noom {n}\noom_kill {n}\noom_group_kill 0\n")
}

fn slices() -> Vec<OomSlice> {
    vec![
        OomSlice {
            key: "slice".into(),
            path: DAEMON.into(),
            label: "the box slice".into(),
            holds_units: false,
        },
        OomSlice {
            key: "app-slice".into(),
            path: APP.into(),
            label: "the box user's app slice".into(),
            holds_units: true,
        },
    ]
}

fn no_run(_: &str) -> Option<String> {
    None
}

#[test]
fn a_unit_run_killed_whole_is_one_incident_from_the_app_slice_even_though_its_cgroup_is_gone() {
    let host = FakeHost::default();
    host.set(DAEMON, &events(0));
    host.set(APP, &events(0));
    let mut w = OomWatcher::default();
    prime_oom_slices(&host, &mut w, &slices());
    // the run's cgroup was removed with the unit; only the app slice's counter moved
    host.set(APP, &events(2));
    let runs = vec![("r1".to_string(), "ozbox-run-r1.service".to_string())];
    let step = oom_step(&host, &mut w, &runs, &no_run, &slices());
    assert_eq!(step.kills, 2);
    assert_eq!(
        step.incidents,
        vec!["2 process(es) killed under the box user's app slice".to_string()]
    );
    // and it is said once
    assert_eq!(oom_step(&host, &mut w, &[], &no_run, &slices()).kills, 0);
}

#[test]
fn a_live_unit_run_that_is_killed_is_not_counted_twice() {
    let host = FakeHost::default();
    host.set(DAEMON, &events(0));
    host.set(APP, &events(0));
    let mut w = OomWatcher::default();
    prime_oom_slices(&host, &mut w, &slices());
    host.set(APP, &events(1));
    let runs = vec![("r1".to_string(), "ozbox-run-r1.service".to_string())];
    let read = |_: &str| Some(events(1));
    let step = oom_step(&host, &mut w, &runs, &read, &slices());
    assert_eq!(step.kills, 1);
    assert_eq!(
        step.incidents,
        vec!["run r1: 1 process(es) killed for memory".to_string()]
    );
}

#[test]
fn a_kill_in_the_app_slice_beyond_the_runs_is_still_reported() {
    let host = FakeHost::default();
    host.set(DAEMON, &events(0));
    host.set(APP, &events(0));
    let mut w = OomWatcher::default();
    prime_oom_slices(&host, &mut w, &slices());
    host.set(APP, &events(3));
    let runs = vec![("r1".to_string(), "ozbox-run-r1.service".to_string())];
    let read = |_: &str| Some(events(1));
    let step = oom_step(&host, &mut w, &runs, &read, &slices());
    assert_eq!(step.kills, 3);
    assert_eq!(step.incidents.len(), 2);
}

#[test]
fn counters_that_were_already_high_when_the_daemon_started_report_nothing() {
    let host = FakeHost::default();
    host.set(DAEMON, &events(7));
    host.set(APP, &events(5));
    let mut w = OomWatcher::default();
    prime_oom_slices(&host, &mut w, &slices());
    let step = oom_step(&host, &mut w, &[], &no_run, &slices());
    assert_eq!(step, Default::default());
}

#[test]
fn a_slice_unreadable_at_start_is_baselined_on_its_first_read_and_a_missing_file_stays_silent() {
    let host = FakeHost::default();
    host.set(DAEMON, &events(0));
    let mut w = OomWatcher::default();
    prime_oom_slices(&host, &mut w, &slices());
    // the manager's slice does not exist yet: nothing, and no complaint
    assert_eq!(
        oom_step(&host, &mut w, &[], &no_run, &slices()),
        Default::default()
    );
    // it appears with history in it: that is the baseline, not a finding
    host.set(APP, &events(4));
    assert_eq!(
        oom_step(&host, &mut w, &[], &no_run, &slices()),
        Default::default()
    );
    host.set(APP, &events(5));
    assert_eq!(oom_step(&host, &mut w, &[], &no_run, &slices()).kills, 1);
}

#[test]
fn a_scope_run_is_still_counted_once_against_the_daemons_slice() {
    let host = FakeHost::default();
    host.set(DAEMON, &events(0));
    host.set(APP, &events(0));
    let mut w = OomWatcher::default();
    prime_oom_slices(&host, &mut w, &slices());
    host.set(DAEMON, &events(1));
    let runs = vec![("r2".to_string(), "run-r2.scope".to_string())];
    let read = |_: &str| Some(events(1));
    let step = oom_step(&host, &mut w, &runs, &read, &slices());
    assert_eq!(step.kills, 1);
}
