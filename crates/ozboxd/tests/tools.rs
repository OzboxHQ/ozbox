#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ozbox_catalog::verify::sha256_hex;
use ozbox_catalog::{embedded, Action, Arch, PlanRequest};
use ozbox_core::RecordingRunner;
use ozboxd::http::Request;
use ozboxd::runs::testing::{FakeCgroup, FakeMemory, FakeSpawner};
use ozboxd::runs::{RunConfig, RunManager};
use ozboxd::timeutil::FakeClock;
use ozboxd::tools::exec::{run_root_action, run_user_action, Ctx, RootPaths};
use ozboxd::tools::job::{run_job, JobSpec, JobState, JobStatus, RootBridge};
use ozboxd::tools::root::serve_requests;
use ozboxd::tools::sys::{Log, RealSys, Sys};
use ozboxd::tools::{ToolsConfig, ToolsService};

/// Real files in a temp directory; commands are answered by a script and recorded.
struct FakeSys {
    urls: BTreeMap<String, Vec<u8>>,
    calls: Mutex<Vec<Vec<String>>>,
    gpg: Mutex<String>,
    present: Mutex<BTreeSet<PathBuf>>,
    fail_on: Mutex<Option<String>>,
    /// An `apt-get` that does not carry `APT::Sandbox::User=root` says apt could not change to its download user, and fails.
    apt_refuses_user_switch: Mutex<bool>,
}

impl FakeSys {
    fn new() -> FakeSys {
        FakeSys {
            urls: BTreeMap::new(),
            calls: Mutex::new(vec![]),
            gpg: Mutex::new(String::new()),
            present: Mutex::new(BTreeSet::new()),
            fail_on: Mutex::new(None),
            apt_refuses_user_switch: Mutex::new(false),
        }
    }
    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

impl Sys for FakeSys {
    fn exec(&self, argv: &[String], _env: &[(String, String)], _log: &Log) -> Result<i32, String> {
        self.calls.lock().unwrap().push(argv.to_vec());
        if argv[0] == "apt-get"
            && *self.apt_refuses_user_switch.lock().unwrap()
            && !argv.contains(&"APT::Sandbox::User=root".to_string())
        {
            _log.line("E: seteuid 42 failed - seteuid (1: Operation not permitted)");
            return Ok(100);
        }
        if self.fail_on.lock().unwrap().as_deref() == Some(argv[0].as_str()) {
            return Ok(1);
        }
        match argv[0].as_str() {
            "curl" => {
                let out = argv
                    .iter()
                    .position(|a| a == "--output")
                    .map(|i| argv[i + 1].clone())
                    .unwrap();
                match self.urls.get(argv.last().unwrap()) {
                    Some(b) => {
                        std::fs::write(out, b).unwrap();
                        Ok(0)
                    }
                    None => Ok(22),
                }
            }
            "tar" => {
                let dir = argv[argv.iter().position(|a| a == "-C").unwrap() + 1].clone();
                std::fs::create_dir_all(format!("{dir}/bin")).unwrap();
                for f in ["node", "npm", "npx"] {
                    std::fs::write(format!("{dir}/bin/{f}"), "x").unwrap();
                }
                Ok(0)
            }
            _ => Ok(0),
        }
    }
    fn capture(
        &self,
        _argv: &[String],
        _env: &[(String, String)],
    ) -> Result<(i32, String), String> {
        Ok((0, self.gpg.lock().unwrap().clone()))
    }
    fn read_file(&self, p: &Path) -> std::io::Result<Vec<u8>> {
        RealSys.read_file(p)
    }
    fn write_file(&self, p: &Path, d: &[u8], m: u32) -> std::io::Result<()> {
        RealSys.write_file(p, d, m)
    }
    fn create_dir_all(&self, p: &Path) -> std::io::Result<()> {
        RealSys.create_dir_all(p)
    }
    fn remove_path(&self, p: &Path) -> std::io::Result<()> {
        RealSys.remove_path(p)
    }
    fn symlink(&self, t: &Path, l: &Path) -> std::io::Result<()> {
        RealSys.symlink(t, l)
    }
    fn exists(&self, p: &Path) -> bool {
        RealSys.exists(p)
    }
    fn is_executable(&self, p: &Path) -> bool {
        self.present.lock().unwrap().contains(p)
    }
}

fn ctx<'a>(sys: &'a dyn Sys, log: &'a Log, dir: &Path) -> Ctx<'a> {
    Ctx {
        sys,
        log,
        home: dir.join("home"),
        tmp: {
            let t = dir.join("tmp");
            std::fs::create_dir_all(&t).unwrap();
            t
        },
        root: RootPaths {
            keyrings: dir.join("keyrings"),
            sources: dir.join("sources"),
            apt_conf: dir.join("conf"),
        },
    }
}

fn node_action(arch: &str) -> Action {
    let c = embedded().unwrap();
    let p = ozbox_catalog::plan::build_plan(
        &c,
        if arch == "x64" {
            Arch::Amd64
        } else {
            Arch::Arm64
        },
        &BTreeSet::new(),
        &PlanRequest {
            install: vec!["node".into()],
            remove: vec![],
        },
    )
    .unwrap();
    p.steps
        .into_iter()
        .find(|s| matches!(s.action, Action::Release { .. }))
        .unwrap()
        .action
}

#[test]
fn a_release_is_used_only_after_its_checksum_matches() {
    let dir = tempfile::tempdir().unwrap();
    let archive = b"the tarball bytes".to_vec();
    let name = "node-v22.5.0-linux-x64.tar.xz";
    let sums = format!(
        "{}  {name}\n{}  node-v22.5.0-linux-arm64.tar.xz\n",
        sha256_hex(&archive),
        sha256_hex(b"other")
    );
    let mut sys = FakeSys::new();
    sys.urls.insert(
        "https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt".into(),
        sums.into_bytes(),
    );
    sys.urls.insert(
        format!("https://nodejs.org/dist/latest-v22.x/{name}"),
        archive.clone(),
    );
    let log = Log::open(&dir.path().join("log"), 1 << 20).unwrap();
    let c = ctx(&sys, &log, dir.path());
    run_user_action(&c, &node_action("x64")).unwrap();
    let calls = sys.calls();
    assert!(calls
        .iter()
        .any(|a| a[0] == "tar" && a.contains(&"--strip-components=1".to_string())));
    // The download is https only, also across redirects, and size-capped.
    let curl = calls.iter().find(|a| a[0] == "curl").unwrap();
    assert!(
        curl.windows(2).any(|w| w == ["--proto", "=https"])
            && curl.contains(&"--max-filesize".to_string())
    );
    assert!(std::fs::symlink_metadata(c.home.join(".local/bin/node"))
        .unwrap()
        .file_type()
        .is_symlink());

    // A tampered download is discarded and nothing is unpacked or linked.
    let dir2 = tempfile::tempdir().unwrap();
    let mut bad = FakeSys::new();
    bad.urls.insert(
        "https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt".into(),
        format!("{}  {name}\n", sha256_hex(&archive)).into_bytes(),
    );
    bad.urls.insert(
        format!("https://nodejs.org/dist/latest-v22.x/{name}"),
        b"tampered".to_vec(),
    );
    let log2 = Log::open(&dir2.path().join("log"), 1 << 20).unwrap();
    let c2 = ctx(&bad, &log2, dir2.path());
    let e = run_user_action(&c2, &node_action("x64")).unwrap_err();
    assert!(e.contains("does not match"), "{e}");
    assert!(bad.calls().iter().all(|a| a[0] != "tar"));
    assert!(!c2.home.join(".local/bin/node").exists());

    // A checksum list that does not cover the asset is a refusal too.
    let dir3 = tempfile::tempdir().unwrap();
    let mut none = FakeSys::new();
    none.urls.insert(
        "https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt".into(),
        b"nothing here\n".to_vec(),
    );
    let log3 = Log::open(&dir3.path().join("log"), 1 << 20).unwrap();
    assert!(
        run_user_action(&ctx(&none, &log3, dir3.path()), &node_action("x64"))
            .unwrap_err()
            .contains("no file matching")
    );
}

fn repo_action() -> Action {
    Action::AptRepo {
        name: "github-cli".into(),
        key_url: "https://cli.github.com/packages/key.gpg".into(),
        fingerprints: vec!["2C6106201985B60E6C7AC87323F3D4EA75716059".into()],
        uri: "https://cli.github.com/packages".into(),
        suite: "stable".into(),
        components: vec!["main".into()],
    }
}

#[test]
fn a_package_source_is_added_only_for_the_published_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut sys = FakeSys::new();
    sys.urls.insert(
        "https://cli.github.com/packages/key.gpg".into(),
        b"BINARYKEY".to_vec(),
    );
    *sys.gpg.lock().unwrap() = "pub:-:4096:1:AA:1:::-:::scESC::::::23::0:\nfpr:::::::::2C6106201985B60E6C7AC87323F3D4EA75716059:\n".into();
    let log = Log::open(&dir.path().join("log"), 1 << 20).unwrap();
    let c = ctx(&sys, &log, dir.path());
    run_root_action(&c, &repo_action()).unwrap();
    let src = std::fs::read_to_string(dir.path().join("sources/ozbox-github-cli.sources")).unwrap();
    assert!(
        src.contains("Signed-By:")
            && src.contains("ozbox-github-cli.gpg")
            && src.contains("URIs: https://cli.github.com/packages")
    );
    let conf = std::fs::read_to_string(dir.path().join("conf/52ozbox-github-cli")).unwrap();
    assert!(conf.contains("site=cli.github.com"));
    assert!(sys
        .calls()
        .last()
        .unwrap()
        .ends_with(&["update".to_string()]));

    // A different key: refused, nothing written, no update.
    let dir2 = tempfile::tempdir().unwrap();
    let mut other = FakeSys::new();
    other.urls.insert(
        "https://cli.github.com/packages/key.gpg".into(),
        b"EVIL".to_vec(),
    );
    *other.gpg.lock().unwrap() = "pub:-:4096:1:AA:1:::-:::scESC::::::23::0:\nfpr:::::::::0000000000000000000000000000000000000000:\n".into();
    let log2 = Log::open(&dir2.path().join("log"), 1 << 20).unwrap();
    let c2 = ctx(&other, &log2, dir2.path());
    let e = run_root_action(&c2, &repo_action()).unwrap_err();
    assert!(e.contains("not the one its vendor publishes"));
    assert!(!dir2.path().join("sources").exists());
    assert!(other.calls().iter().all(|a| a[0] != "apt-get"));
}

#[test]
fn root_steps_and_user_steps_stay_apart() {
    let dir = tempfile::tempdir().unwrap();
    let sys = FakeSys::new();
    let log = Log::open(&dir.path().join("log"), 1 << 20).unwrap();
    let c = ctx(&sys, &log, dir.path());
    assert!(run_user_action(&c, &Action::AptUpdate).is_err());
    assert!(run_root_action(
        &c,
        &Action::Exec {
            argv: vec!["id".into()]
        }
    )
    .is_err());
    // Removing paths never leaves the home.
    assert!(run_user_action(
        &c,
        &Action::UserRemove {
            paths: vec!["../etc".into()]
        }
    )
    .is_err());
    // The home placeholder is filled in, argv stays an array.
    run_user_action(
        &c,
        &Action::Exec {
            argv: vec!["npm".into(), "--prefix".into(), "{home}/.local".into()],
        },
    )
    .unwrap();
    assert_eq!(sys.calls()[0][2], format!("{}/.local", c.home.display()));
    // apt install is always non-interactive and never pulls recommended packages.
    run_root_action(
        &c,
        &Action::AptInstall {
            packages: vec!["jq".into()],
        },
    )
    .unwrap();
    let apt = sys.calls().last().unwrap().clone();
    assert!(apt.contains(&"--no-install-recommends".to_string()) && apt.last().unwrap() == "jq");
}

/// Release-gate T1 (2026-11-12): on a real box every apt step failed with `seteuid 42 failed`, because apt could not drop
/// to its `_apt` user inside the root helper. A box where that works keeps apt's own user switch: the first run of every
/// step carries no sandbox option, and nothing is retried when the step succeeds.
#[test]
fn every_root_apt_step_runs_apt_with_its_own_user_switch_first() {
    let dir = tempfile::tempdir().unwrap();
    let sys = FakeSys::new();
    let log = Log::open(&dir.path().join("log"), 1 << 20).unwrap();
    let c = ctx(&sys, &log, dir.path());
    for action in [
        Action::AptUpdate,
        Action::AptInstall {
            packages: vec!["jq".into()],
        },
        Action::AptRemove {
            packages: vec!["jq".into()],
        },
    ] {
        let before = sys.calls().len();
        run_root_action(&c, &action).unwrap();
        let new = &sys.calls()[before..];
        assert_eq!(new.len(), 1, "no retry when the step worked: {new:?}");
        assert_eq!(new[0][0], "apt-get");
        assert!(
            !new[0].contains(&"APT::Sandbox::User=root".to_string()),
            "{new:?}"
        );
    }
    run_root_action(&c, &repo_action()).ok();
    for call in sys.calls().iter().filter(|a| a[0] == "apt-get") {
        assert!(
            !call.contains(&"APT::Sandbox::User=root".to_string()),
            "{call:?}"
        );
    }
}

/// The stop-gap: only when the output says the user switch was refused does the step run once more with downloads as root,
/// and the log says so. A failure for any other reason is not retried, and a box where the switch is refused for a second
/// time fails honestly.
#[test]
fn apt_runs_without_its_user_switch_only_after_that_switch_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let sys = FakeSys::new();
    *sys.apt_refuses_user_switch.lock().unwrap() = true;
    let log = Log::open(&dir.path().join("log"), 1 << 20).unwrap();
    let c = ctx(&sys, &log, dir.path());
    for action in [
        Action::AptUpdate,
        Action::AptInstall {
            packages: vec!["jq".into()],
        },
        Action::AptRemove {
            packages: vec!["jq".into()],
        },
    ] {
        let before = sys.calls().len();
        run_root_action(&c, &action).unwrap();
        let new = &sys.calls()[before..];
        assert_eq!(new.len(), 2, "{new:?}");
        assert!(!new[0].contains(&"APT::Sandbox::User=root".to_string()));
        assert_eq!(&new[1][..3], ["apt-get", "-o", "APT::Sandbox::User=root"]);
        assert_eq!(
            new[0][1..],
            new[1][3..],
            "the same step, nothing else changed"
        );
    }
    let said = std::fs::read_to_string(dir.path().join("log")).unwrap();
    assert!(
        said.contains("trying once more with downloads run as root"),
        "{said}"
    );
    // any other failure is not retried
    let sys = FakeSys::new();
    *sys.fail_on.lock().unwrap() = Some("apt-get".into());
    let c = ctx(&sys, &log, dir.path());
    assert!(run_root_action(&c, &Action::AptUpdate).is_err());
    assert_eq!(sys.calls().len(), 1);
}

#[test]
fn only_a_refused_user_switch_counts_as_the_trigger() {
    use ozboxd::tools::sys::is_privilege_drop_refusal as t;
    assert!(t(
        "E: seteuid 42 failed - seteuid (1: Operation not permitted)"
    ));
    assert!(t(
        "E: setresuid 42 failed - setresuid (1: Operation not permitted)"
    ));
    assert!(!t("E: Unable to locate package nothere"));
    assert!(!t("E: Failed to fetch http://x  Connection failed"));
    assert!(!t("seteuid ok"));
}

struct Bridge {
    steps: Mutex<Vec<usize>>,
    fail: bool,
}
impl RootBridge for Bridge {
    fn run_step(&self, _s: &JobSpec, i: usize, _l: &Log) -> Result<(), String> {
        self.steps.lock().unwrap().push(i);
        if self.fail {
            Err("apt said no".into())
        } else {
            Ok(())
        }
    }
}

fn job_spec(ids: &[&str]) -> JobSpec {
    let c = embedded().unwrap();
    let req = PlanRequest {
        install: ids.iter().map(|s| s.to_string()).collect(),
        remove: vec![],
    };
    let plan = ozbox_catalog::plan::build_plan(&c, Arch::Amd64, &BTreeSet::new(), &req).unwrap();
    JobSpec {
        id: "abc1".into(),
        requested_by: "owner".into(),
        request: req,
        installed: vec![],
        plan,
        created_ms: 1,
    }
}

fn write_job(root: &Path, spec: &JobSpec) -> PathBuf {
    let dir = root.join("jobs").join(&spec.id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("job.json"), serde_json::to_vec(spec).unwrap()).unwrap();
    dir
}

#[test]
fn a_job_runs_root_steps_through_the_helper_then_verifies_and_audits() {
    let root = tempfile::tempdir().unwrap();
    let spec = job_spec(&["neovim"]);
    let dir = write_job(root.path(), &spec);
    let sys = FakeSys::new();
    let home = root.path().join("home");
    sys.present
        .lock()
        .unwrap()
        .insert(PathBuf::from("/usr/bin/nvim"));
    let bridge = Bridge {
        steps: Mutex::new(vec![]),
        fail: false,
    };
    let st = run_job(&dir, &embedded().unwrap(), &sys, &bridge, &home, &|| 7).unwrap();
    assert_eq!(st.state, JobState::Succeeded, "{:?}", st.error);
    assert_eq!(*bridge.steps.lock().unwrap(), vec![0, 1]);
    let log = std::fs::read_to_string(dir.join("log")).unwrap();
    assert!(log.contains("verified neovim") && log.contains("done"));
    let audit = std::fs::read_to_string(root.path().join("audit.jsonl")).unwrap();
    assert!(
        audit.contains("tools.job_finished")
            && audit.contains("\"succeeded\"")
            && audit.contains("neovim")
    );

    // Installed but not found afterwards: the job fails and says which program.
    let root2 = tempfile::tempdir().unwrap();
    let dir2 = write_job(root2.path(), &spec);
    let sys2 = FakeSys::new();
    let st2 = run_job(
        &dir2,
        &embedded().unwrap(),
        &sys2,
        &bridge,
        &root2.path().join("home"),
        &|| 7,
    )
    .unwrap();
    assert_eq!(st2.state, JobState::Failed);
    assert!(st2.error.unwrap().contains("nvim"));

    // A failing step stops the job; later steps never run, and the status names the step.
    let root3 = tempfile::tempdir().unwrap();
    let dir3 = write_job(root3.path(), &spec);
    let bad = Bridge {
        steps: Mutex::new(vec![]),
        fail: true,
    };
    let st3 = run_job(
        &dir3,
        &embedded().unwrap(),
        &FakeSys::new(),
        &bad,
        &root3.path().join("home"),
        &|| 7,
    )
    .unwrap();
    assert_eq!(st3.state, JobState::Failed);
    assert_eq!(*bad.steps.lock().unwrap(), vec![0]);
    assert!(st3.error.unwrap().contains("apt said no"));
    let status: JobStatus =
        serde_json::from_slice(&std::fs::read(dir3.join("status.json")).unwrap()).unwrap();
    assert_eq!(status.steps.len(), spec.plan.steps.len());
}

#[test]
fn the_helper_runs_only_what_the_catalog_plans() {
    let c = embedded().unwrap();
    let rd = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(rd.path().join("requests")).unwrap();
    std::fs::create_dir_all(rd.path().join("results")).unwrap();
    let spec = job_spec(&["jq"]);
    let good = serde_json::json!({ "job": "abc1", "index": 1, "plan_hash": spec.plan.hash, "request": spec.request, "installed": [] });
    let wrong_hash = serde_json::json!({ "job": "abc1", "index": 1, "plan_hash": "0000", "request": spec.request, "installed": [] });
    let user_step = serde_json::json!({ "job": "abc1", "index": 9, "plan_hash": spec.plan.hash, "request": spec.request, "installed": [] });
    let mismatched_name = serde_json::json!({ "job": "zzz9", "index": 1, "plan_hash": spec.plan.hash, "request": spec.request, "installed": [] });
    let put = |name: &str, v: &serde_json::Value| {
        std::fs::write(
            rd.path().join("requests").join(name),
            serde_json::to_vec(v).unwrap(),
        )
        .unwrap()
    };
    put("abc1-1.json", &good);
    put("abc1-2.json", &wrong_hash);
    put("abc1-9.json", &user_step);
    put("abc1-3.json", &mismatched_name);
    put("not-a-request.json", &good);
    std::fs::write(
        rd.path().join("requests/abc1-4.json"),
        b"{\"job\": \"x\", \"surprise\": 1}",
    )
    .unwrap();
    std::fs::write(rd.path().join("requests/half.tmp"), b"being written").unwrap();
    let sys = FakeSys::new();
    let paths = RootPaths {
        keyrings: rd.path().join("k"),
        sources: rd.path().join("s"),
        apt_conf: rd.path().join("c"),
    };
    let n = serve_requests(rd.path(), &c, Arch::Amd64, &sys, &paths, 1 << 20);
    assert_eq!(n, 6);
    // The one good request ran its apt step; nothing else ran.
    let calls = sys.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0][0], "apt-get");
    assert!(calls[0].contains(&"install".to_string()));
    let result = |n: &str| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(rd.path().join("results").join(n)).unwrap()).unwrap()
    };
    assert_eq!(result("abc1-1.result")["ok"], true);
    for bad in [
        "abc1-2.result",
        "abc1-9.result",
        "abc1-3.result",
        "abc1-4.result",
    ] {
        assert_eq!(result(bad)["ok"], false, "{bad}");
    }
    // A request is taken off the queue before it runs; a file being written is left alone.
    assert!(!rd.path().join("requests/abc1-1.json").exists());
    assert!(rd.path().join("requests/half.tmp").exists());
    // Errors never echo the request's contents.
    assert!(!result("abc1-4.result").to_string().contains("surprise"));
}

fn service(dir: &Path) -> (Arc<ToolsService>, Arc<Mutex<RunManager>>, Arc<FakeSys>) {
    let clock = Arc::new(FakeClock::new(1_794_182_400_000));
    let runs = Arc::new(Mutex::new(RunManager::new(
        RunConfig::default(),
        Arc::new(FakeCgroup::default()),
        Arc::new(FakeMemory::new(16 << 30, 8 << 30)),
        Arc::new(FakeSpawner::default()),
        clock.clone(),
    )));
    let sys = Arc::new(FakeSys::new());
    let svc = ToolsService::new(
        ToolsConfig {
            state: dir.join("tools"),
            home: dir.join("home"),
            exe: PathBuf::from("/usr/local/bin/ozboxd"),
            job_memory_bytes: 1 << 30,
            arch: Arch::Amd64,
        },
        embedded().unwrap(),
        runs.clone(),
        sys.clone(),
        Arc::new(RecordingRunner::new()),
        clock,
    );
    (Arc::new(svc), runs, sys)
}

fn call(
    svc: &ToolsService,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let r = svc.route(&Request {
        method: method.into(),
        path: path.into(),
        query: BTreeMap::new(),
        body: if body.is_null() {
            vec![]
        } else {
            serde_json::to_vec(&body).unwrap()
        },
        capability: None,
    });
    (
        r.status,
        serde_json::from_slice(&r.body).unwrap_or_default(),
    )
}

#[test]
fn plan_never_mutates_and_apply_needs_the_plan_that_was_shown() {
    let dir = tempfile::tempdir().unwrap();
    let (svc, runs, _) = service(dir.path());
    let (s, v) = call(&svc, "GET", "/v1/tools", serde_json::Value::Null);
    assert_eq!(s, 200);
    assert!(v["tools"].as_array().unwrap().len() >= 40);
    let (s, p) = call(
        &svc,
        "POST",
        "/v1/tools/plan",
        serde_json::json!({ "install": ["bundle:ai-agents"] }),
    );
    assert_eq!(s, 200);
    assert!(p["plan"]["steps"].as_array().unwrap().len() > 5);
    assert!(runs.lock().unwrap().list().is_empty());
    assert!(!dir
        .path()
        .join("tools/jobs")
        .read_dir()
        .unwrap()
        .any(|_| true));

    // Apply without the hash, or with a stale one, is refused and starts nothing.
    let (s, e) = call(
        &svc,
        "POST",
        "/v1/tools/apply",
        serde_json::json!({ "install": ["jq"] }),
    );
    assert_eq!((s, e["code"].as_str().unwrap()), (400, "bad_request"));
    let (s, e) = call(
        &svc,
        "POST",
        "/v1/tools/apply",
        serde_json::json!({ "install": ["jq"], "plan_hash": "stale" }),
    );
    assert_eq!((s, e["code"].as_str().unwrap()), (409, "stale_plan"));
    assert!(runs.lock().unwrap().list().is_empty());

    let (_, p) = call(
        &svc,
        "POST",
        "/v1/tools/plan",
        serde_json::json!({ "install": ["jq"] }),
    );
    let hash = p["plan"]["hash"].as_str().unwrap().to_string();
    let (s, a) = call(
        &svc,
        "POST",
        "/v1/tools/apply",
        serde_json::json!({ "install": ["jq"], "plan_hash": hash }),
    );
    assert_eq!(s, 202, "{a}");
    let job = a["job_id"].as_str().unwrap().to_string();
    // It runs as a capped run of the daemon's own binary, with an argv array.
    let list = runs.lock().unwrap().list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].memory_max_bytes, Some(1 << 30));
    assert_eq!(list[0].program, "ozboxd");
    // One job at a time.
    let (s, e) = call(
        &svc,
        "POST",
        "/v1/tools/apply",
        serde_json::json!({ "install": ["jq"], "plan_hash": hash }),
    );
    assert_eq!((s, e["code"].as_str().unwrap()), (409, "busy"));
    let (s, j) = call(
        &svc,
        "GET",
        &format!("/v1/tools/jobs/{job}"),
        serde_json::Value::Null,
    );
    assert_eq!(s, 200);
    assert_eq!(j["job"]["state"], "queued");
    assert_eq!(
        call(
            &svc,
            "GET",
            "/v1/tools/jobs/../etc",
            serde_json::Value::Null
        )
        .0,
        404
    );
    let (_, audit) = call(&svc, "GET", "/v1/tools/audit", serde_json::Value::Null);
    assert_eq!(audit["events"][0]["event"], "tools.install_started");
}

#[test]
fn unverified_and_unknown_tools_are_refused_with_codes() {
    let dir = tempfile::tempdir().unwrap();
    let (svc, _, _) = service(dir.path());
    let plan = |t: &str| {
        call(
            &svc,
            "POST",
            "/v1/tools/plan",
            serde_json::json!({ "install": [t] }),
        )
    };
    let (s, e) = plan("docker");
    assert_eq!((s, e["code"].as_str().unwrap()), (422, "unverified_tool"));
    assert!(e["message"].as_str().unwrap().contains("fingerprint"));
    assert_eq!(plan("nope").0, 404);
    assert_eq!(
        call(&svc, "POST", "/v1/tools/plan", serde_json::json!({})).0,
        400
    );
    assert_eq!(
        call(&svc, "DELETE", "/v1/tools/plan", serde_json::Value::Null).0,
        405
    );
    assert_eq!(
        call(&svc, "GET", "/v1/tools/zzz", serde_json::Value::Null).0,
        404
    );
}

#[test]
fn an_agent_can_ask_but_only_the_owner_can_approve() {
    let dir = tempfile::tempdir().unwrap();
    let (svc, runs, _) = service(dir.path());
    let ask = |tool: &str| {
        call(
            &svc,
            "POST",
            "/v1/tools/requests",
            serde_json::json!({ "tool": tool, "reason": "need it\u{7} to build", "agent": "claude-1" }),
        )
    };
    let (s, r) = ask("jq");
    assert_eq!(s, 201);
    assert_eq!(r["request"]["state"], "pending");
    assert_eq!(r["request"]["reason"], "need it to build");
    // Asking is not installing.
    assert!(runs.lock().unwrap().list().is_empty());
    // Asking again returns the same request.
    assert_eq!(ask("jq").1["request"]["id"], r["request"]["id"]);
    assert_eq!(ask("docker").0, 422);
    assert_eq!(ask("nope").0, 404);
    let id = r["request"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        call(
            &svc,
            "POST",
            &format!("/v1/tools/requests/{id}/decision"),
            serde_json::json!({ "decision": "maybe" })
        )
        .0,
        400
    );
    let (s, d) = call(
        &svc,
        "POST",
        &format!("/v1/tools/requests/{id}/decision"),
        serde_json::json!({ "decision": "approve_always" }),
    );
    assert_eq!(s, 200, "{d}");
    assert_eq!(d["request"]["state"], "approved");
    assert!(d["request"]["job_id"].is_string());
    assert_eq!(runs.lock().unwrap().list().len(), 1);
    assert_eq!(
        call(
            &svc,
            "POST",
            &format!("/v1/tools/requests/{id}/decision"),
            serde_json::json!({ "decision": "deny" })
        )
        .0,
        409
    );
    let (_, list) = call(&svc, "GET", "/v1/tools/requests", serde_json::Value::Null);
    assert_eq!(list["always_allowed"], serde_json::json!(["jq"]));
    let (_, audit) = call(&svc, "GET", "/v1/tools/audit", serde_json::Value::Null);
    let events: Vec<&str> = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert!(events.contains(&"tools.requested") && events.contains(&"tools.request_approved"));

    // A denial installs nothing.
    let (_, r2) = ask("htop");
    let id2 = r2["request"]["id"].as_str().unwrap().to_string();
    let (s, d2) = call(
        &svc,
        "POST",
        &format!("/v1/tools/requests/{id2}/decision"),
        serde_json::json!({ "decision": "deny" }),
    );
    assert_eq!(
        (s, d2["request"]["state"].as_str().unwrap()),
        (200, "denied")
    );
}

// ---- a zstd archive, unpacked for real ------------------------------------------------------------------------------

/// Downloads are answered from a fixture file; everything else (`tar`, `zstd`) really runs, so the unpack is the real one.
struct FixtureSys {
    archive: Vec<u8>,
    calls: Mutex<Vec<Vec<String>>>,
}

impl Sys for FixtureSys {
    fn exec(&self, argv: &[String], env: &[(String, String)], log: &Log) -> Result<i32, String> {
        self.calls.lock().unwrap().push(argv.to_vec());
        if argv[0] == "curl" {
            let out = argv
                .iter()
                .position(|a| a == "--output")
                .map(|i| argv[i + 1].clone())
                .unwrap();
            std::fs::write(out, &self.archive).unwrap();
            return Ok(0);
        }
        RealSys.exec(argv, env, log)
    }
    fn capture(&self, argv: &[String], env: &[(String, String)]) -> Result<(i32, String), String> {
        RealSys.capture(argv, env)
    }
    fn read_file(&self, p: &Path) -> std::io::Result<Vec<u8>> {
        RealSys.read_file(p)
    }
    fn sha256_file(&self, p: &Path) -> std::io::Result<String> {
        RealSys.sha256_file(p)
    }
    fn write_file(&self, p: &Path, d: &[u8], m: u32) -> std::io::Result<()> {
        RealSys.write_file(p, d, m)
    }
    fn create_dir_all(&self, p: &Path) -> std::io::Result<()> {
        RealSys.create_dir_all(p)
    }
    fn remove_path(&self, p: &Path) -> std::io::Result<()> {
        RealSys.remove_path(p)
    }
    fn symlink(&self, t: &Path, l: &Path) -> std::io::Result<()> {
        RealSys.symlink(t, l)
    }
    fn exists(&self, p: &Path) -> bool {
        RealSys.exists(p)
    }
    fn is_executable(&self, p: &Path) -> bool {
        RealSys.is_executable(p)
    }
}

/// A small `.tar.zst` shaped like the vendor's (`bin/ollama`, `lib/ollama/...`), made with the machine's own `tar` and
/// `zstd`. `None` when this machine has no zstd to make it with (the test then has nothing to check).
fn zstd_fixture(dir: &Path) -> Option<Vec<u8>> {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("bin")).unwrap();
    std::fs::create_dir_all(src.join("lib/ollama")).unwrap();
    std::fs::write(
        src.join("bin/ollama"),
        "#!/bin/sh\necho ollama version 0.40.15\n",
    )
    .unwrap();
    std::fs::write(src.join("lib/ollama/libggml.so"), "not really a library").unwrap();
    let out = dir.join("fixture.tar.zst");
    let ok = std::process::Command::new("tar")
        .args(["--zstd", "-cf"])
        .arg(&out)
        .arg("-C")
        .arg(&src)
        .args(["bin", "lib"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then(|| std::fs::read(&out).unwrap())
}

fn ollama_release(pin: &str) -> Action {
    use ozbox_catalog::model::{Bin, ChecksumFormat, Extract};
    Action::Release {
        tool: "ollama".into(),
        version_url: None,
        base_url: "https://github.com/ollama/ollama/releases/download/v0.40.15/".into(),
        asset: "ollama-linux-{arch}.tar.zst".into(),
        checksum_url: String::new(),
        checksum_format: ChecksumFormat::Sums,
        pinned_sha256: Some(pin.into()),
        extract: Extract::TarZst,
        strip: 0,
        arch_name: "amd64".into(),
        bins: vec![Bin {
            name: "ollama".into(),
            path: "bin/ollama".into(),
        }],
    }
}

#[test]
fn a_zstd_archive_is_checked_against_its_pinned_digest_then_unpacked_and_linked() {
    let dir = tempfile::tempdir().unwrap();
    let Some(archive) = zstd_fixture(dir.path()) else {
        eprintln!("skipped: this machine's tar cannot make a zstd archive");
        return;
    };
    let digest = sha256_hex(&archive);
    let sys = FixtureSys {
        archive: archive.clone(),
        calls: Mutex::new(vec![]),
    };
    let work = tempfile::tempdir().unwrap();
    let log = Log::open(&work.path().join("log"), 1 << 20).unwrap();
    let c = ctx(&sys, &log, work.path());
    run_user_action(&c, &ollama_release(&digest)).unwrap();

    // unpacked by the real tar with the zstd filter, into the tool's own folder, and linked into the box user's bin
    let opt = c.home.join(".local/opt/ollama");
    assert!(opt.join("bin/ollama").is_file());
    assert_eq!(
        std::fs::read_to_string(opt.join("lib/ollama/libggml.so")).unwrap(),
        "not really a library"
    );
    let link = c.home.join(".local/bin/ollama");
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read_link(&link).unwrap(), opt.join("bin/ollama"));
    let calls = sys.calls.lock().unwrap().clone();
    let tar = calls.iter().find(|a| a[0] == "tar").unwrap();
    assert!(
        tar.contains(&"--zstd".to_string()) && tar.contains(&"--strip-components=0".to_string())
    );
    // the download is https only and size-capped, and no checksum file was fetched: the digest is the pinned one
    let curls: Vec<&Vec<String>> = calls.iter().filter(|a| a[0] == "curl").collect();
    assert_eq!(curls.len(), 1, "{curls:?}");
    assert!(
        curls[0].windows(2).any(|w| w == ["--proto", "=https"])
            && curls[0].contains(&"--max-filesize".to_string())
    );
    assert_eq!(
        curls[0].last().unwrap(),
        "https://github.com/ollama/ollama/releases/download/v0.40.15/ollama-linux-amd64.tar.zst"
    );
}

#[test]
fn a_zstd_archive_that_is_not_the_pinned_file_is_discarded_and_nothing_is_unpacked() {
    let dir = tempfile::tempdir().unwrap();
    let Some(archive) = zstd_fixture(dir.path()) else {
        eprintln!("skipped: this machine's tar cannot make a zstd archive");
        return;
    };
    let pin = sha256_hex(&archive);
    let mut tampered = archive.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let sys = FixtureSys {
        archive: tampered,
        calls: Mutex::new(vec![]),
    };
    let work = tempfile::tempdir().unwrap();
    let log = Log::open(&work.path().join("log"), 1 << 20).unwrap();
    let c = ctx(&sys, &log, work.path());
    let e = run_user_action(&c, &ollama_release(&pin)).unwrap_err();
    assert!(e.contains("does not match"), "{e}");
    assert!(sys.calls.lock().unwrap().iter().all(|a| a[0] != "tar"));
    assert!(!c.home.join(".local/opt/ollama").exists());
    assert!(!c.home.join(".local/bin/ollama").exists());
    assert!(!c.tmp.join("asset").exists(), "the bad download is removed");
    // a digest that is the right one in capitals is still the same digest
    let ok = FixtureSys {
        archive,
        calls: Mutex::new(vec![]),
    };
    run_user_action(
        &ctx(&ok, &log, work.path()),
        &ollama_release(&pin.to_ascii_uppercase()),
    )
    .unwrap();
}
