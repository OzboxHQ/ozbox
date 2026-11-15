#![allow(clippy::unwrap_used)]
//! Every systemd property and `systemd-run` option Oz Box emits is a real one.
//!
//! A real box found `TimeoutRunSec=1800` in the one-shot unit: not a systemd property, so `systemd-run` refused the whole unit
//! ("Unknown assignment") and every one-shot `ozbox env run` failed. No test could see it, because every test read the argument list
//! as text. This one reads it against a list of the names systemd documents (`systemd.exec`, `systemd.resource-control`,
//! `systemd.service`, `systemd.kill`), for every unit the program builds: a one-shot, a secret command, a browser command, a service
//! (with and without credentials), and the browser worker.
//!
//! A list of names proves SPELLING only. That systemd 255's `systemd-run` accepts each VALUE is only shown by running it on a real box (the real-box proof scripts in `scripts/` do); a name added here must be one a systemd man page defines.

use crate::runner::{self, Host};
use crate::runner_pins::Mount;
use crate::workload_policy::Policy;

/// The property names systemd defines, that Oz Box uses.
const KNOWN_PROPERTIES: &[&str] = &[
    "After",
    "BindPaths",
    "BindReadOnlyPaths",
    "BindsTo",
    "DynamicUser",
    "Environment",
    "ExecStartPre",
    "ExecStopPost",
    "InaccessiblePaths",
    "IPAddressAllow",
    "IPAddressDeny",
    "LimitCORE",
    "LoadCredential",
    "LockPersonality",
    "MemoryMax",
    "MemorySwapMax",
    "NoNewPrivileges",
    "NotifyAccess",
    "PartOf",
    "PrivateDevices",
    "PrivatePIDs",
    "PrivateTmp",
    "ProcSubset",
    "ProtectControlGroups",
    "ProtectHome",
    "ProtectKernelLogs",
    "ProtectKernelModules",
    "ProtectKernelTunables",
    "ProtectProc",
    "ProtectSystem",
    "ReadWritePaths",
    "Restart",
    "RestrictAddressFamilies",
    "RestrictSUIDSGID",
    "RuntimeMaxSec",
    "StandardInput",
    "TasksMax",
    "TemporaryFileSystem",
    "Type",
    "UMask",
];

/// The `systemd-run` options Oz Box uses, with `=` values cut off.
const KNOWN_OPTIONS: &[&str] = &[
    "--quiet",
    "--pipe",
    "--wait",
    "--collect",
    "--no-block",
    "--unit",
    "--uid",
    "--gid",
    "--slice",
    "--working-directory",
    "-p",
    "--",
];

/// The names `--socket-property=` may set on a transient socket unit (`systemd.socket`, `systemd.exec`).
const KNOWN_SOCKET_PROPERTIES: &[&str] = &["ExecStartPre", "ExecStopPost", "ListenStream"];

/// Names that look right and are not systemd properties: every one was written by hand at some point.
const NOT_PROPERTIES: &[&str] = &["TimeoutRunSec", "TimeoutSec", "MaxRuntimeSec", "RuntimeMax"];

/// Panics unless every option and every `-p NAME=VALUE` of the `systemd-run` call before its `--` is a known one.
pub fn assert_known(argv: &[String], what: &str) {
    assert_eq!(argv[0], "systemd-run", "{what}");
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            return;
        }
        if a == "-p" {
            let p = argv
                .get(i + 1)
                .unwrap_or_else(|| panic!("{what}: -p with no property"));
            let (name, value) = p
                .split_once('=')
                .unwrap_or_else(|| panic!("{what}: property {p:?} is not NAME=VALUE"));
            assert!(
                !NOT_PROPERTIES.contains(&name),
                "{what}: {name} is not a systemd property"
            );
            assert!(
                KNOWN_PROPERTIES.contains(&name),
                "{what}: {name} is not in the list of systemd properties Oz Box may emit (spelled wrong, or add it here with the man page that defines it)"
            );
            assert!(!value.is_empty(), "{what}: {name} has no value");
            i += 2;
            continue;
        }
        if let Some(p) = a.strip_prefix("--socket-property=") {
            let (name, value) = p
                .split_once('=')
                .unwrap_or_else(|| panic!("{what}: socket property {p:?} is not NAME=VALUE"));
            assert!(
                KNOWN_SOCKET_PROPERTIES.contains(&name),
                "{what}: {name} is not in the list of socket properties Oz Box may emit (spelled wrong, or add it here with the man page that defines it)"
            );
            assert!(!value.is_empty(), "{what}: {name} has no value");
            i += 1;
            continue;
        }
        let opt = a.split('=').next().unwrap();
        assert!(
            KNOWN_OPTIONS.contains(&opt),
            "{what}: {a} is not a systemd-run option Oz Box uses"
        );
        i += 1;
    }
    panic!("{what}: no `--` before the command");
}

fn policy() -> Policy {
    Policy::parse(
        r#"{"dir":"/work/projects/app","writable":[".next"],"commands":{"a":{"allow":[]}}}"#,
    )
    .unwrap()
}

fn cp(json: &str) -> crate::workload_policy::CommandPolicy {
    serde_json::from_str(json).unwrap()
}

fn mounts() -> Vec<Mount> {
    vec![Mount {
        blob: "/var/lib/ozbox-run/.pins/blob".into(),
        dest: "/work/projects/app/x.mjs".into(),
    }]
}

#[test]
fn every_property_the_runner_emits_is_a_systemd_property() {
    let p = policy();
    let argv = ["node".to_string(), "x.mjs".to_string()];
    for private_pids in [false, true] {
        let host = Host { private_pids };
        for (what, c) in [
            ("plain", r#"{"allow":[]}"#),
            ("browser", r#"{"allow":[],"browser":true}"#),
            // a command with a secret gets the private view of /work: TemporaryFileSystem and BindPaths
            ("secret", r#"{"allow":["K"],"env":["K"]}"#),
        ] {
            let v = runner::systemd_run_argv_with(
                "app",
                "ozrc-app",
                "id1",
                &p,
                &cp(c),
                &argv,
                &mounts(),
                host,
            );
            assert_known(&v, what);
            let limit = v.iter().find(|x| x.starts_with("RuntimeMaxSec=")).unwrap();
            assert_eq!(
                limit, "RuntimeMaxSec=1800",
                "{what}: a run ends after 30 minutes"
            );
        }
    }
}

#[test]
fn every_property_a_service_emits_is_a_systemd_property() {
    let p = policy();
    for host in [
        Host {
            private_pids: false,
        },
        Host { private_pids: true },
    ] {
        let c = cp(
            r#"{"allow":[],"service":true,"port":3100,"argv":["node","x.mjs"],"vars":{"PORT":"3100"}}"#,
        );
        let v = runner::systemd_run_service_argv(
            "app",
            "web",
            &p,
            &c,
            &mounts(),
            host,
            &runner::ServiceInputs::default(),
        );
        assert_known(&v, "service");
        // with credentials and public values: Type, LoadCredential and a plain Environment
        let secret = cp(
            r#"{"allow":["K"],"env":["K"],"service":true,"port":3100,"argv":["node","x.mjs"],"credential_env":true}"#,
        );
        let names = vec!["K".to_string()];
        let public = vec![(
            "NEXT_PUBLIC_APP_URL".to_string(),
            "https://staging.example.com".to_string(),
        )];
        let v = runner::systemd_run_service_argv(
            "app",
            "web",
            &p,
            &secret,
            &mounts(),
            host,
            &runner::ServiceInputs {
                credentials: &names,
                stage: "00ff00ff00ff00ff",
                public: &public,
                route: None,
            },
        );
        assert_known(&v, "service with credentials");
        assert!(v.iter().any(|a| a.starts_with("LoadCredential=K:")));
    }
}

#[test]
fn every_property_a_services_proxy_and_a_service_with_a_route_emit_is_a_systemd_property() {
    use crate::egress::TcpDest;
    let route = crate::runner_egress::Route {
        unit: crate::runner_egress::egress_unit("app", "web"),
        port: 40123,
        tunnels: vec![(
            TcpDest {
                host: "db.example.com".into(),
                port: 5432,
                env: "DATABASE".into(),
            },
            40124,
        )],
    };
    // the proxy's own unit
    let v = crate::runner_egress::systemd_run_route_argv(
        &runner::service_unit("app", "web"),
        &route,
        61234,
        &["api.stripe.com".to_string()],
        "/run/ozbox-egress-rules/ozbox-egress-app_web.nft",
    );
    assert_known(&v, "egress route (socket and proxy)");
    // the service that uses it
    let secret =
        cp(r#"{"allow":["K"],"env":["K"],"service":true,"port":3100,"argv":["node","x.mjs"]}"#);
    let names = vec!["K".to_string()];
    let v = runner::systemd_run_service_argv(
        "app",
        "web",
        &policy(),
        &secret,
        &mounts(),
        Host { private_pids: true },
        &runner::ServiceInputs {
            credentials: &names,
            stage: "00ff00ff00ff00ff",
            public: &[],
            route: Some(&route),
        },
    );
    assert_known(&v, "service with a route");
    for p in [
        "BindsTo=",
        "After=",
        "ExecStopPost=",
        "Environment=HTTPS_PROXY=",
    ] {
        assert!(v.iter().any(|a| a.starts_with(p)), "{p}");
    }
    // the service keeps its closed network: the route is a loopback port, nothing else
    assert!(v.iter().any(|a| a == "IPAddressDeny=any"));
}

#[test]
fn the_guard_itself_refuses_the_property_that_broke_every_run() {
    let bad: Vec<String> = [
        "systemd-run",
        "--quiet",
        "-p",
        "TimeoutRunSec=1800",
        "--",
        "x",
    ]
    .map(String::from)
    .to_vec();
    assert!(std::panic::catch_unwind(|| assert_known(&bad, "bad")).is_err());
    let misspelt: Vec<String> = ["systemd-run", "-p", "PrivateTemp=yes", "--", "x"]
        .map(String::from)
        .to_vec();
    assert!(std::panic::catch_unwind(|| assert_known(&misspelt, "bad")).is_err());
    let option: Vec<String> = ["systemd-run", "--timeout=5", "--", "x"]
        .map(String::from)
        .to_vec();
    assert!(std::panic::catch_unwind(|| assert_known(&option, "bad")).is_err());
}
