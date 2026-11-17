#![allow(clippy::unwrap_used)]
use super::*;
use crate::approval_key as ak;
use crate::fleet_holder::{Holder, HolderConfig, ReadSessionSource};
use crate::secrets::MemorySecrets;
use ozbox_core::{BoxName, BoxSpec, Operation, Output, Provider, Size};
use std::sync::Mutex;

const SENTINEL: &str = "SENTINEL-CLI-SESSION-SECRET";

struct Capture(Mutex<Vec<CommandSpec>>);
impl CommandRunner for Capture {
    fn run(&self, c: &CommandSpec) -> ozbox_core::Result<Output> {
        self.0.lock().unwrap().push(c.clone());
        let secret = SENTINEL;
        Ok(Output {
            status: Some(0),
            stdout: format!(
                r#"{{"Credentials":{{"AccessKeyId":"ASIA","SecretAccessKey":"{secret}","SessionToken":"tok","Expiration":"2099-01-15T08:00:00Z"}}}}"#
            ),
            stderr: String::new(),
        })
    }
}

struct Yes(bool);
impl Ask for Yes {
    fn interactive(&self) -> bool {
        self.0
    }
    fn line(&mut self, _: &str) -> Option<String> {
        Some("yes".into())
    }
}

struct NoRead;
impl ReadSessionSource for NoRead {
    fn assume_read(&self, _: u64) -> Result<SessionCreds, String> {
        Err("no".into())
    }
}

struct Fx {
    dir: tempfile::TempDir,
    keys: MemorySecrets,
    holder: Holder,
    pins: FleetPins,
}

fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let (seed, public) = ak::generate().unwrap();
    let keys = MemorySecrets::default();
    keys.set("approval-key-laptop", &seed).unwrap();
    let key = ozbox_seal::ServiceKey::generate().unwrap();
    let holder_public = ozbox_seal::public_to_hex(&key.public());
    let holder = Holder::new(
        HolderConfig {
            box_id: "box-1".into(),
            store_id: "store-1".into(),
            this_box: "main".into(),
            laptop_public_hex: public,
            dir: dir.path().join("holder"),
        },
        key,
        Box::new(NoRead),
    )
    .unwrap();
    Fx {
        pins: FleetPins {
            box_id: "box-1".into(),
            store_id: "store-1".into(),
            fleet_box: "main".into(),
            holder_public,
            account_id: "123456789012".into(),
            person: "owner".into(),
            key_id: "laptop".into(),
        },
        dir,
        keys,
        holder,
    }
}

fn plan_file(f: &Fx, op: Operation) -> PathBuf {
    let plan = ozbox_provider_fake::open(f.dir.path().join("fake"))
        .plan(&op)
        .unwrap();
    let p = f.dir.path().join("plan.json");
    std::fs::write(&p, serde_json::to_vec(&plan).unwrap()).unwrap();
    p
}

fn args(f: &Fx, plan: PathBuf) -> WindowArgs {
    WindowArgs {
        plan_id: "p1".into(),
        plan_file: plan,
        window_secs: 1800,
        profile: Some("fleet-window".into()),
        region: None,
        machine_type: None,
        out: f.dir.path().join("window.json"),
    }
}

fn create(name: &str) -> Operation {
    Operation::Create {
        spec: BoxSpec::new(BoxName::new(name).unwrap(), Size::S),
    }
}

const NOW: u64 = 1_800_000_000;
const YES: Flags = Flags {
    yes: true,
    dry_run: false,
    json: false,
};

#[test]
fn a_window_asks_for_the_plans_session_only_and_seals_it_so_the_holder_opens_it() {
    let mut f = fx();
    let a = args(&f, plan_file(&f, create("dev")));
    let r = Capture(Mutex::default());
    let mut out = Vec::new();
    let v = window(
        &a,
        &f.pins,
        &r,
        &f.keys,
        &mut Yes(false),
        &YES,
        NOW,
        &mut out,
    )
    .unwrap();
    assert_eq!(v["opened"], true);
    let c = r.0.lock().unwrap()[0].clone();
    // what was asked: the change role, a plan session, the owner's identity, the box tag, the plan-scoped policy
    let joined = c.args.join(" ");
    assert!(joined.contains("role/obx/obx-fleet-change"), "{joined}");
    assert!(c.args.contains(&"plan-p1".to_string()));
    assert!(c.args.contains(&"ozbox-owner".to_string()));
    assert!(c
        .args
        .contains(&"Key=ozbox-window-box,Value=dev".to_string()));
    assert!(c.args.contains(&"fleet-window".to_string()));
    let policy = &c.args[c.args.iter().position(|x| x == "--policy").unwrap() + 1];
    assert!(policy.contains("DateGreaterThan") && policy.contains("RunInstances"));
    assert!(
        !policy.contains("TerminateInstances"),
        "a create's session cannot terminate"
    );
    // the session is never in argv, the environment, the file on disk or the printed text
    assert!(c.env.is_empty());
    let sealed = std::fs::read_to_string(&a.out).unwrap();
    assert!(!sealed.contains(SENTINEL));
    assert!(!String::from_utf8_lossy(&out).contains(SENTINEL));
    assert!(!v.to_string().contains(SENTINEL));
    // the holder opens it: the owner's signature, the plan and the box all check
    let m: Value = serde_json::from_str(&sealed).unwrap();
    let enc = ozbox_core::approval_subject::from_hex(m["enc"].as_str().unwrap()).unwrap();
    let ct = ozbox_core::approval_subject::from_hex(m["ct"].as_str().unwrap()).unwrap();
    let now_ms = NOW * 1000;
    f.holder
        .receive_window("p1", m["plan_hash"].as_str().unwrap(), &enc, &ct, now_ms)
        .unwrap();
    assert!(f.holder.window_for("p1", now_ms + 1000).is_some());
    // the window ends at its own expiry, whatever the cloud's session says
    assert!(f.holder.window_for("p1", now_ms + 1_900_000).is_none());
}

#[test]
fn nothing_is_asked_or_sent_without_a_yes_a_terminal_or_for_a_change_a_dashboard_may_not_make() {
    let f = fx();
    let r = Capture(Mutex::default());
    let a = args(&f, plan_file(&f, create("dev")));
    let mut out = Vec::new();
    // a script without --yes
    let err = window(
        &a,
        &f.pins,
        &r,
        &f.keys,
        &mut Yes(false),
        &Flags {
            yes: false,
            dry_run: false,
            json: false,
        },
        NOW,
        &mut out,
    )
    .unwrap_err();
    assert!(err.to_string().contains("--yes"));
    // dry run: shown, nothing asked of the cloud
    let v = window(
        &a,
        &f.pins,
        &r,
        &f.keys,
        &mut Yes(true),
        &Flags {
            yes: false,
            dry_run: true,
            json: false,
        },
        NOW,
        &mut out,
    )
    .unwrap();
    assert_eq!(v["opened"], false);
    assert!(r.0.lock().unwrap().is_empty());
    assert!(!a.out.exists());
    // the fleet manager's own box is changed from this computer, not from its dashboard
    let own = plan_file(&f, create("main"));
    let err = window(
        &args(&f, own),
        &f.pins,
        &r,
        &f.keys,
        &mut Yes(true),
        &YES,
        NOW,
        &mut out,
    )
    .unwrap_err();
    assert!(err.to_string().contains("main"));
    // an upgrade is not a dashboard change
    let up_plan = Plan {
        operation: Operation::Upgrade {
            name: BoxName::new("dev").unwrap(),
            image: "ami-0123456789abcdef0".into(),
            reprovision: false,
            keep_old_system_disk: false,
        },
        provider: "fake".into(),
        changes: vec![ozbox_core::Change::new(
            "instance",
            "x",
            ozbox_core::Risk::Low,
        )],
        notes: vec![],
        based_on: "s".into(),
    };
    let up = f.dir.path().join("up.json");
    std::fs::write(&up, serde_json::to_vec(&up_plan).unwrap()).unwrap();
    assert!(window(
        &args(&f, up),
        &f.pins,
        &r,
        &f.keys,
        &mut Yes(true),
        &YES,
        NOW,
        &mut out
    )
    .is_err());
    assert!(r.0.lock().unwrap().is_empty());
}

#[test]
fn the_cloud_refusing_a_session_sends_nothing() {
    struct Refuse;
    impl CommandRunner for Refuse {
        fn run(&self, _: &CommandSpec) -> ozbox_core::Result<Output> {
            Ok(Output {
                status: Some(254),
                stdout: String::new(),
                stderr: "AccessDenied".into(),
            })
        }
    }
    let f = fx();
    let a = args(&f, plan_file(&f, create("dev")));
    let err = window(
        &a,
        &f.pins,
        &Refuse,
        &f.keys,
        &mut Yes(true),
        &YES,
        NOW,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("did not give"));
    assert!(!a.out.exists());
}

#[test]
fn a_signed_approver_list_is_accepted_by_the_holder_and_a_changed_one_is_not() {
    let mut f = fx();
    let creds = f.dir.path().join("creds.json");
    std::fs::write(
        &creds,
        r#"{"approvers":[{"credential_id":"c1","person":"owner","role":"owner","public_key":"04aa","rp":{"rp_id":"x.test","origin":"https://x.test"}}]}"#,
    )
    .unwrap();
    let out = f.dir.path().join("approvers.json");
    let v = approvers_sign(&f.pins, &f.keys, &creds, 3, &out, 1).unwrap();
    assert_eq!(v["people"], 1);
    let m: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    let signed: SignedApproverSet = serde_json::from_value(m["signed"].clone()).unwrap();
    assert_eq!(f.holder.accept_approvers(&signed).unwrap(), 3);
    let mut forged = signed.clone();
    forged.set = forged.set.replace("\"version\":3", "\"version\":9");
    assert!(f.holder.accept_approvers(&forged).is_err());
    // nothing to vouch for
    std::fs::write(&creds, r#"{"approvers":[]}"#).unwrap();
    assert!(approvers_sign(&f.pins, &f.keys, &creds, 4, &out, 1).is_err());
}

#[test]
fn durations_and_pins_round_trip() {
    assert_eq!(parse_duration("30m"), Some(1800));
    assert_eq!(parse_duration("90s"), Some(90));
    assert_eq!(parse_duration("1h"), Some(3600));
    assert_eq!(parse_duration("45"), Some(45));
    assert_eq!(parse_duration("soon"), None);
    let f = fx();
    let p = f.dir.path().join("sub/fleet.json");
    save_pins(&p, &f.pins).unwrap();
    assert_eq!(load_pins(&p).unwrap(), f.pins);
    assert!(load_pins(&f.dir.path().join("none.json")).is_err());
}
