//! What stands between a box's dashboard and a change to the fleet (ADR 0040 §2, §8).
//!
//! A dashboard on a box plans a fleet change with the same engine as the laptop (`Provider::plan`), shows it, and applies it
//! with the same `apply`. Before that apply, this gate says yes only when ALL of these hold:
//!
//! 1. the change is one a box's dashboard may make (create, resize, pause, resume, snapshot, clone, destroy) and it does not
//!    name the box the dashboard runs on (§8 layers 2 and 3: "this box" is changed from your own computer);
//! 2. the plan id has not been spent (one assertion applies one plan once);
//! 3. a change window for exactly this plan is open (§2: the owner opened it from their own computer; the dashboard never
//!    holds a change credential, it only learns that the window is open and until when);
//! 4. a passkey assertion, with user verification, was made over THIS plan's challenge ([`challenge`]: the box, the store,
//!    the plan id and the plan's hash), by a person whose dashboard role is owner. An authenticator code or a laptop key is
//!    never accepted for a fleet change (ADR 0041 §3, and B4's rule that a software key never decides Production).
//!
//! The credentials themselves are never here. [`FleetCredentials`] is the credential holder's side (ADR 0040 §1: a uid of its
//! own, not the dashboard's), and it answers only "is a window open for this plan, and until when". Nothing in this module
//! can return, print or serialize a session.

use std::collections::VecDeque;

use ozbox_core::approval_subject::Encoder;
use ozbox_core::roles::Role;
use ozbox_core::{Operation, Plan};

use crate::messages::t;

/// The challenge's domain tag (ADR 0040 §2), encoded the way ADR 0041 §4 encodes a digest.
pub const FLEET_APPLY_TAG: &str = "ozbox-fleet-apply-v1";
/// How many spent plan ids are remembered; an id past this many is long past its plan's time to live.
const SPENT_KEPT: usize = 4096;

/// The hash of a plan as issued: its canonical JSON (the operation, the changes, the notes and the state it was based on).
pub fn plan_hash(plan: &Plan) -> [u8; 32] {
    let bytes = serde_json::to_vec(plan).unwrap_or_default();
    let mut e = Encoder::new("ozbox-fleet-plan-v1");
    e.field(&bytes);
    e.digest()
}

/// What a passkey signs for one fleet plan: `H("ozbox-fleet-apply-v1", box id, store id, "plan", plan id, plan hash)`.
pub fn challenge(box_id: &str, store_id: &str, plan_id: &str, plan_hash: &[u8; 32]) -> [u8; 32] {
    let mut e = Encoder::new(FLEET_APPLY_TAG);
    e.text(box_id)
        .text(store_id)
        .text("plan")
        .text(plan_id)
        .field(plan_hash);
    e.digest()
}

/// An open change window, as the credential holder reports it: a name and an expiry, never a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowStatus {
    /// The role session name the laptop chose (`plan-<plan id>`).
    pub session_name: String,
    pub expires_at_ms: u64,
}

/// The credential holder's side of the gate (ADR 0040 §1). The real one is a uid of its own reached over a socket only the
/// dashboard may open; it holds the read session and, inside a window, hands the change session to the apply unit. Neither
/// session is ever returned here.
pub trait FleetCredentials: Send + Sync {
    /// The open window for this plan id, if any.
    fn window_for(&self, plan_id: &str) -> Option<WindowStatus>;
}

/// What the person showed for this plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Factor {
    /// A passkey assertion the dashboard checked (relying party, origin, user presence and verification, signature) over
    /// `challenge`, by `person` with dashboard role `role`.
    Passkey {
        person: String,
        role: Role,
        challenge: [u8; 32],
    },
    /// A six-digit authenticator code: never enough for a fleet change.
    AuthenticatorCode,
    /// A laptop's software key: never decides from a box's dashboard.
    LaptopKey,
    /// Nothing was shown.
    None,
}

/// Why a fleet change was refused: a stable code and the sentence to show. Never carries a credential or an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

fn refuse(status: u16, code: &'static str, key: &str, args: &[(&str, &str)]) -> Refusal {
    Refusal {
        status,
        code,
        message: t(key, args),
    }
}

/// The gate. One per dashboard; it remembers which plans were spent.
pub struct FleetGate {
    this_box: String,
    store_id: String,
    creds: Box<dyn FleetCredentials>,
    spent: VecDeque<String>,
}

impl std::fmt::Debug for FleetGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetGate")
            .field("this_box", &self.this_box)
            .field("spent", &self.spent.len())
            .finish_non_exhaustive()
    }
}

/// The boxes an operation names, the one it changes first.
fn named(op: &Operation) -> Vec<&str> {
    match op {
        Operation::Clone { from, to, .. } | Operation::RestoreToNewBox { from, to, .. } => {
            vec![to.as_str(), from.as_str()]
        }
        other => vec![other.box_name().as_str()],
    }
}

impl FleetGate {
    pub fn new(this_box: &str, store_id: &str, creds: Box<dyn FleetCredentials>) -> Self {
        FleetGate {
            this_box: this_box.to_string(),
            store_id: store_id.to_string(),
            creds,
            spent: VecDeque::new(),
        }
    }

    /// The challenge a passkey must sign for this plan.
    pub fn challenge_for(&self, plan_id: &str, plan: &Plan) -> [u8; 32] {
        challenge(&self.this_box, &self.store_id, plan_id, &plan_hash(plan))
    }

    /// Everything that does not need the person: the operation, "this box", a spent plan, the window. Checked before a
    /// passkey is asked for, so nobody is asked to confirm a change that would be refused anyway.
    pub fn precheck(&self, plan_id: &str, plan: &Plan, now_ms: u64) -> Result<(), Refusal> {
        let op = &plan.operation;
        let verb = op.verb();
        if !matches!(
            op,
            Operation::Create { .. }
                | Operation::Resize { .. }
                | Operation::Pause { .. }
                | Operation::Resume { .. }
                | Operation::Snapshot { .. }
                | Operation::Clone { .. }
                | Operation::Destroy { .. }
        ) {
            return Err(refuse(
                422,
                "fleet_from_your_computer",
                "fleet.from_your_computer",
                &[("verb", verb)],
            ));
        }
        if named(op).contains(&self.this_box.as_str()) {
            return Err(refuse(
                409,
                "fleet_this_box",
                "fleet.this_box",
                &[("box", &self.this_box)],
            ));
        }
        if self.spent.iter().any(|p| p == plan_id) {
            return Err(refuse(409, "fleet_plan_spent", "fleet.plan_spent", &[]));
        }
        match self.creds.window_for(plan_id) {
            None => Err(refuse(
                409,
                "change_window_required",
                "fleet.window_required",
                &[],
            )),
            Some(w) if w.session_name != format!("plan-{plan_id}") => Err(refuse(
                409,
                "change_window_required",
                "fleet.window_required",
                &[],
            )),
            Some(w) if w.expires_at_ms <= now_ms => Err(refuse(
                409,
                "change_window_expired",
                "fleet.window_expired",
                &[],
            )),
            Some(_) => Ok(()),
        }
    }

    /// The whole gate. On success the plan id is spent, so the same assertion cannot apply it again.
    pub fn authorize(
        &mut self,
        plan_id: &str,
        plan: &Plan,
        factor: &Factor,
        now_ms: u64,
    ) -> Result<(), Refusal> {
        self.precheck(plan_id, plan, now_ms)?;
        match factor {
            Factor::Passkey {
                role, challenge, ..
            } => {
                if *challenge != self.challenge_for(plan_id, plan) {
                    return Err(refuse(
                        403,
                        "fleet_passkey_required",
                        "fleet.passkey_other_plan",
                        &[],
                    ));
                }
                if *role != Role::Owner {
                    return Err(refuse(403, "role_forbidden", "fleet.owner_only", &[]));
                }
            }
            Factor::AuthenticatorCode | Factor::LaptopKey | Factor::None => {
                return Err(refuse(
                    403,
                    "fleet_passkey_required",
                    "fleet.passkey_required",
                    &[],
                ));
            }
        }
        if self.spent.len() >= SPENT_KEPT {
            self.spent.pop_front();
        }
        self.spent.push_back(plan_id.to_string());
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// A credential holder with windows a test opens. It holds a made-up session value, so a test can prove the value never
    /// reaches anything the dashboard says.
    #[derive(Clone, Default)]
    pub struct FakeCreds {
        pub windows: Arc<Mutex<HashMap<String, u64>>>,
        pub session_value: String,
    }

    impl FakeCreds {
        pub fn with_sentinel(v: &str) -> Self {
            FakeCreds {
                windows: Arc::default(),
                session_value: v.to_string(),
            }
        }
        pub fn open(&self, plan_id: &str, until_ms: u64) {
            if let Ok(mut w) = self.windows.lock() {
                w.insert(plan_id.to_string(), until_ms);
            }
        }
    }

    impl FleetCredentials for FakeCreds {
        fn window_for(&self, plan_id: &str) -> Option<WindowStatus> {
            // the session value stays here: only the name and the expiry go out
            let _held = &self.session_value;
            self.windows
                .lock()
                .ok()?
                .get(plan_id)
                .map(|&expires_at_ms| WindowStatus {
                    session_name: format!("plan-{plan_id}"),
                    expires_at_ms,
                })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::testing::FakeCreds;
    use super::*;
    use ozbox_core::{BoxName, BoxSpec, Size};

    fn plan(op: Operation) -> Plan {
        Plan {
            operation: op,
            provider: "fake".into(),
            changes: vec![ozbox_core::Change::new(
                "instance.x",
                "x",
                ozbox_core::Risk::Low,
            )],
            notes: vec![],
            based_on: "s1".into(),
        }
    }

    fn create(name: &str) -> Plan {
        plan(Operation::Create {
            spec: BoxSpec::new(BoxName::new(name).unwrap(), Size::S),
        })
    }

    fn gate() -> (FleetGate, FakeCreds) {
        let c = FakeCreds::with_sentinel("SENTINEL-SESSION-TOKEN");
        (FleetGate::new("main", "store-1", Box::new(c.clone())), c)
    }

    fn owner(g: &FleetGate, id: &str, p: &Plan) -> Factor {
        Factor::Passkey {
            person: "owner".into(),
            role: Role::Owner,
            challenge: g.challenge_for(id, p),
        }
    }

    #[test]
    fn the_challenge_is_bound_to_the_box_the_store_the_plan_id_and_the_plan() {
        let p = create("dev");
        let h = plan_hash(&p);
        let base = challenge("main", "store-1", "p1", &h);
        assert_ne!(base, challenge("other", "store-1", "p1", &h));
        assert_ne!(base, challenge("main", "store-2", "p1", &h));
        assert_ne!(base, challenge("main", "store-1", "p2", &h));
        assert_ne!(
            base,
            challenge("main", "store-1", "p1", &plan_hash(&create("dev2")))
        );
        // a golden vector: the laptop and the credential holder must compute the same bytes
        assert_eq!(
            ozbox_core::audit::hex(&challenge("main", "store-1", "p1", &[0u8; 32])),
            ozbox_core::audit::hex(&{
                let mut e = Encoder::new("ozbox-fleet-apply-v1");
                e.text("main")
                    .text("store-1")
                    .text("plan")
                    .text("p1")
                    .field(&[0u8; 32]);
                e.digest()
            })
        );
    }

    #[test]
    fn plan_then_window_then_owners_passkey_applies_once() {
        let (mut g, c) = gate();
        let p = create("dev");
        assert_eq!(
            g.precheck("p1", &p, 10).unwrap_err().code,
            "change_window_required"
        );
        c.open("p1", 1_000);
        g.precheck("p1", &p, 10).unwrap();
        let f = owner(&g, "p1", &p);
        g.authorize("p1", &p, &f, 10).unwrap();
        // the same assertion cannot apply the plan again
        assert_eq!(
            g.authorize("p1", &p, &f, 11).unwrap_err().code,
            "fleet_plan_spent"
        );
    }

    #[test]
    fn without_a_passkey_for_this_exact_plan_nothing_is_applied() {
        let (mut g, c) = gate();
        let p = create("dev");
        c.open("p1", 1_000);
        for f in [Factor::None, Factor::AuthenticatorCode, Factor::LaptopKey] {
            assert_eq!(
                g.authorize("p1", &p, &f, 10).unwrap_err().code,
                "fleet_passkey_required",
                "{f:?}"
            );
        }
        // a passkey over another plan's challenge
        let other = create("other");
        let f = owner(&g, "p1", &other);
        assert_eq!(
            g.authorize("p1", &p, &f, 10).unwrap_err().code,
            "fleet_passkey_required"
        );
        // a member's passkey
        let f = Factor::Passkey {
            person: "friend".into(),
            role: Role::Member,
            challenge: g.challenge_for("p1", &p),
        };
        assert_eq!(
            g.authorize("p1", &p, &f, 10).unwrap_err().code,
            "role_forbidden"
        );
        // none of those spent the plan
        let f = owner(&g, "p1", &p);
        g.authorize("p1", &p, &f, 10).unwrap();
    }

    #[test]
    fn a_window_for_another_plan_or_an_expired_one_is_no_window() {
        let (mut g, c) = gate();
        let p = create("dev");
        c.open("p2", 1_000);
        let f = owner(&g, "p1", &p);
        assert_eq!(
            g.authorize("p1", &p, &f, 10).unwrap_err().code,
            "change_window_required"
        );
        c.open("p1", 100);
        assert_eq!(
            g.authorize("p1", &p, &f, 100).unwrap_err().code,
            "change_window_expired"
        );
    }

    #[test]
    fn this_box_is_never_changed_from_its_own_dashboard() {
        let (mut g, c) = gate();
        let main = BoxName::new("main").unwrap();
        for op in [
            Operation::Destroy {
                name: main.clone(),
                final_snapshot: true,
                keep_old_system_disks: false,
            },
            Operation::Pause { name: main.clone() },
            Operation::Resize {
                name: main.clone(),
                size: Some(Size::L),
                work_disk_gb: None,
            },
            Operation::Snapshot { name: main.clone() },
            Operation::Clone {
                from: main.clone(),
                to: BoxName::new("copy").unwrap(),
                snapshot: None,
            },
        ] {
            let p = plan(op);
            c.open("p1", 1_000);
            let f = owner(&g, "p1", &p);
            let r = g.authorize("p1", &p, &f, 10).unwrap_err();
            assert_eq!(r.code, "fleet_this_box", "{:?}", p.operation);
            assert!(r.message.contains("main"));
        }
    }

    #[test]
    fn changes_a_box_dashboard_does_not_make_are_sent_to_your_computer() {
        let (g, c) = gate();
        c.open("p1", 1_000);
        let p = plan(Operation::Upgrade {
            name: BoxName::new("dev").unwrap(),
            image: "ami-0123456789abcdef0".into(),
            reprovision: false,
            keep_old_system_disk: false,
        });
        assert_eq!(
            g.precheck("p1", &p, 10).unwrap_err().code,
            "fleet_from_your_computer"
        );
    }

    #[test]
    fn the_session_never_leaves_the_credential_holder() {
        let (mut g, c) = gate();
        let p = create("dev");
        c.open("p1", 1_000);
        let mut said = format!("{g:?} {:?}", c.window_for("p1"));
        for f in [Factor::None, owner(&g, "p1", &p)] {
            match g.authorize("p1", &p, &f, 10) {
                Ok(()) => said.push_str("ok"),
                Err(r) => said.push_str(&format!("{r:?}")),
            }
        }
        assert!(!said.contains("SENTINEL-SESSION-TOKEN"), "{said}");
    }
}
