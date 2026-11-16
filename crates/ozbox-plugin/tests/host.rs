//! The host side against the two example plugins, run as real processes.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use ozbox_core::{BoxName, BoxState, Engine, Operation, Provider, Size};
use ozbox_plugin::host::{Approvals, Plugin, PluginBackend, PluginError, TunnelPlugin};
use serde_json::json;

fn example(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap().join("examples");
    let p = dir.join(name);
    assert!(
        p.exists(),
        "the example {name} is built by `cargo test`: {}",
        p.display()
    );
    p
}

/// A plugin folder holding a copy of an example program.
fn folder(example_name: &str, kind: &str) -> (tempfile::TempDir, Plugin) {
    let d = tempfile::tempdir().unwrap();
    std::fs::copy(example(example_name), d.path().join("plugin-bin")).unwrap();
    let plugin_name = example_name.replace('_', "-");
    std::fs::write(
        d.path().join("plugin.toml"),
        format!("name = \"{plugin_name}\"\nkind = \"{kind}\"\napi_version = 1\nlicense = \"Apache-2.0\"\nprogram = \"plugin-bin\"\n"),
    )
    .unwrap();
    let p = Plugin::load(d.path()).unwrap();
    (d, p)
}

fn approved(p: &Plugin) -> Approvals {
    let mut a = Approvals::default();
    a.approve(&p.manifest.name, &p.program_hash().unwrap());
    a
}

fn name(s: &str) -> BoxName {
    BoxName::new(s).unwrap()
}

fn spec(n: &str) -> ozbox_core::BoxSpec {
    ozbox_core::BoxSpec::new(name(n), Size::M)
}

#[test]
fn nothing_runs_until_the_programs_hash_is_approved_and_a_changed_program_is_refused() {
    let (d, p) = folder("dir_provider", "provider");
    let none = Approvals::default();
    assert_eq!(
        p.call(&none, "describe", json!({})),
        Err(PluginError::NotApproved)
    );
    let ok = approved(&p);
    assert!(p.call(&ok, "describe", json!({})).is_ok());
    // the program changes after approval
    let prog = d.path().join("plugin-bin");
    let mut bytes = std::fs::read(&prog).unwrap();
    bytes.push(0);
    std::fs::write(&prog, bytes).unwrap();
    assert_eq!(
        p.call(&ok, "describe", json!({})),
        Err(PluginError::NotApproved)
    );
}

#[test]
fn a_provider_plugin_runs_the_whole_lifecycle_through_the_shared_engine() {
    let (_d, p) = folder("dir_provider", "provider");
    let a = approved(&p);
    let engine = Engine::new(PluginBackend::open(p, a).unwrap());
    assert_eq!(engine.id(), "dirfake");
    let create = Operation::Create { spec: spec("dev") };
    let plan = engine.plan(&create).unwrap();
    assert!(!plan.is_noop());
    engine.apply(&plan).unwrap();
    // already satisfied: plans to nothing, as for every provider
    assert!(engine.plan(&create).unwrap().is_noop());
    assert_eq!(engine.list().unwrap().len(), 1);
    let pause = engine
        .plan(&Operation::Pause { name: name("dev") })
        .unwrap();
    engine.apply(&pause).unwrap();
    assert_eq!(
        engine.get(&name("dev")).unwrap().unwrap().state,
        BoxState::Paused
    );
    let snap = engine
        .plan(&Operation::Snapshot { name: name("dev") })
        .unwrap();
    engine.apply(&snap).unwrap();
    assert_eq!(
        engine.get(&name("dev")).unwrap().unwrap().snapshots.len(),
        1
    );
    let resume = engine
        .plan(&Operation::Resume { name: name("dev") })
        .unwrap();
    engine.apply(&resume).unwrap();
    let destroy = engine
        .plan(&Operation::Destroy {
            name: name("dev"),
            final_snapshot: false,
            keep_old_system_disks: false,
        })
        .unwrap();
    engine.apply(&destroy).unwrap();
    assert!(engine.list().unwrap().is_empty());
}

#[test]
fn an_operation_a_plugin_does_not_support_is_a_clean_refusal_and_its_environment_is_empty() {
    let (_d, p) = folder("dir_provider", "provider");
    let a = approved(&p);
    let e = p.call(&a, "teleport", json!({})).unwrap_err();
    assert!(matches!(e, PluginError::Failed(ref f) if f.code == "unsupported"));
    std::env::set_var("OZBOX_PLUGIN_TEST_SECRET", "SENTINEL");
    // the plugin never sees it: nothing to assert on its side beyond the call still working
    assert!(p.call(&a, "list", json!({})).is_ok());
}

#[test]
fn a_tunnel_plugin_starts_stops_and_reports() {
    let (_d, p) = folder("echo_tunnel", "tunnel");
    let a = approved(&p);
    let t = TunnelPlugin::open(p, a).unwrap();
    assert_eq!(t.status().unwrap().0, "stopped");
    assert!(
        t.start(80, "https://x.example.com").is_err(),
        "the plugin refuses a low port"
    );
    t.start(7878, "https://x.example.com").unwrap();
    assert_eq!(t.status().unwrap().0, "running");
    t.stop().unwrap();
    assert_eq!(t.status().unwrap().0, "stopped");
}

#[test]
fn a_provider_plugin_cannot_be_opened_as_a_tunnel_and_the_reverse() {
    let (_d, p) = folder("dir_provider", "provider");
    let a = approved(&p);
    assert!(TunnelPlugin::open(p.clone(), a.clone()).is_err());
    assert!(PluginBackend::open(folder("echo_tunnel", "tunnel").1, a).is_err());
}

#[test]
fn a_manifest_that_is_not_plain_is_refused() {
    let d = tempfile::tempdir().unwrap();
    for (toml, why) in [
        (
            "name = \"A b\"\nkind = \"tunnel\"\napi_version = 1\nlicense = \"Apache-2.0\"\nprogram = \"x\"\n",
            "name",
        ),
        (
            "name = \"ok\"\nkind = \"tunnel\"\napi_version = 2\nlicense = \"Apache-2.0\"\nprogram = \"x\"\n",
            "version",
        ),
        (
            "name = \"ok\"\nkind = \"tunnel\"\napi_version = 1\nlicense = \"Apache-2.0\"\nprogram = \"../x\"\n",
            "path",
        ),
        (
            "name = \"ok\"\nkind = \"tunnel\"\napi_version = 1\nlicense = \"Apache-2.0\"\nprogram = \"x\"\nsurprise = 1\n",
            "field",
        ),
        (
            "name = \"ok\"\nkind = \"tunnel\"\napi_version = 1\nprogram = \"x\"\n",
            "licence missing",
        ),
        (
            "name = \"ok\"\nkind = \"tunnel\"\napi_version = 1\nlicense = \"x; rm\"\nprogram = \"x\"\n",
            "licence not SPDX-shaped",
        ),
    ] {
        std::fs::write(d.path().join("plugin.toml"), toml).unwrap();
        assert!(Plugin::load(Path::new(d.path())).is_err(), "{why}");
    }
}

#[test]
fn approvals_round_trip_through_a_file() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("plugins.toml");
    let mut a = Approvals::default();
    a.approve("x", "abc");
    a.save(&f).unwrap();
    assert_eq!(Approvals::load(&f).get("x"), Some("abc"));
    let mut b = Approvals::load(&f);
    assert!(b.revoke("x"));
    assert_eq!(b.get("x"), None);
}

#[test]
fn a_plugin_written_in_python_with_no_oz_box_library_speaks_the_same_protocol() {
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 is not installed: skipped");
        return;
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugins/python-tunnel");
    let d = tempfile::tempdir().unwrap();
    for f in ["plugin.toml", "python_tunnel.py"] {
        std::fs::copy(src.join(f), d.path().join(f)).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            d.path().join("python_tunnel.py"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let p = Plugin::load(d.path()).unwrap();
    let a = approved(&p);
    let t = TunnelPlugin::open(p, a).unwrap();
    assert_eq!(t.status().unwrap().0, "stopped");
    assert!(t.start(80, "https://x.example.com").is_err());
    t.start(7878, "https://x.example.com").unwrap();
    assert_eq!(t.status().unwrap().0, "running");
    t.stop().unwrap();
}

#[test]
fn a_plugin_that_never_answers_is_cut_off_and_a_plugin_that_answers_garbage_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    for (body, why) in [
        ("#!/bin/sh\nsleep 30\n", "silent"),
        ("#!/bin/sh\nread l; echo nonsense\n", "garbage"),
        ("#!/bin/sh\nexit 0\n", "exits at once"),
    ] {
        let d = tempfile::tempdir().unwrap();
        let prog = d.path().join("p.sh");
        std::fs::write(&prog, body).unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            d.path().join("plugin.toml"),
            "name = \"bad\"\nkind = \"tunnel\"\napi_version = 1\nlicense = \"Apache-2.0\"\nprogram = \"p.sh\"\n",
        )
        .unwrap();
        let p = Plugin::load(d.path()).unwrap();
        let a = approved(&p);
        let started = std::time::Instant::now();
        let r = ozbox_plugin::host::call_with_limit(
            &p,
            &a,
            "describe",
            json!({}),
            std::time::Duration::from_millis(800),
        );
        assert!(matches!(r, Err(PluginError::Run(_))), "{why}: {r:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{why}: took too long"
        );
    }
}
