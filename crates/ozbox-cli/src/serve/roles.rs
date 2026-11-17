//! Who may do what at the dashboard (ADR 0039).
//!
//! Two decisions are made here, each in one place, for every route:
//!
//! * **Roles.** [`classify`] says what a request needs (nothing but a sign-in, or one [`Action`]); [`App::role_gate`]
//!   asks the permission engine (`ozbox_core::roles`, which calls `permissions::decide`) whether the signed-in person's
//!   role may. It runs inside [`App::guard`], which every request to the API, the file transfers and the terminal streams
//!   goes through, so no route has a check of its own to forget. A request that is not in the table needs an owner if it
//!   changes anything, so a new route is closed to members and viewers until somebody opens it.
//! * **The second factor.** [`step_up_gate`] says whether a request counts as coming from a person who just proved it:
//!   behind a sign-in, a passkey shown a moment ago; on the person's own computer with no sign-in, the access token; on a
//!   box with no sign-in, never, because another process may hold that token. Every route that asks for a second factor
//!   uses [`App::step_up_state`] and [`step_up_refusal`], so the answer and the words are the same everywhere.
//!
//! A dashboard with no sign-in has one person, its operator, who is treated as an owner.

use ozbox_core::permissions::Action;
use ozbox_core::roles::{self, Role};
use serde_json::{json, Value};

use super::{App, Req, Resp};

/// What a request needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Need {
    /// Anyone signed in.
    Read,
    /// A role whose rules allow this action.
    Act(Action),
}

fn is_get(method: &str) -> bool {
    matches!(method, "GET" | "HEAD")
}

/// What `method path` needs. The path is the request's, with or without its `/v1` prefix. A route the table does not name
/// needs a sign-in to look at and an owner to change.
pub(super) fn classify(method: &str, path: &str) -> Need {
    classify_named(method, path).unwrap_or(if is_get(method) {
        Need::Read
    } else {
        Need::Act(Action::SettingsChange)
    })
}

/// What `method path` needs when the table names the route, `None` when it falls to the default.
pub(super) fn classify_named(method: &str, path: &str) -> Option<Need> {
    let all: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let segs: &[&str] = if all.first() == Some(&"v1") {
        &all[1..]
    } else {
        &all
    };
    let get = is_get(method);
    use Action::*;
    let read_or = |a: Action| if get { Need::Read } else { Need::Act(a) };
    Some(match segs {
        // the browser: its pictures are what is on a person's screen, so even looking is for members and owners
        ["agent-mcp"] => read_or(SettingsChange),
        ["browser", "settings"] => read_or(SettingsChange),
        ["browser", ..] if get => Need::Act(BrowserWatch),
        ["browser", ..] => Need::Act(BrowserControl),
        // a box's files, terminal and IDE
        ["boxes", _, "files", ..] => Need::Act(if get { FileRead } else { FileWrite }),
        ["boxes", _, "terminal"] | ["terminal", ..] => Need::Act(CommandRun),
        // a box's SSH details name the way in (a POST makes the key), so it is an act on the box, not a look
        ["boxes", _, "ssh"] => Need::Act(CommandRun),
        ["boxes", _, "code", ..] => read_or(CommandRun),
        ["boxes", _, "tools", "requests", _, "decision"] => Need::Act(ApprovalDecide),
        ["boxes", _, "backups", "credentials"] => read_or(SecretWrite),
        ["boxes", _, "tools" | "backups" | "local-ai", ..] => read_or(BoxChange),
        // where a change to a box stands: a look
        ["jobs", ..] => Need::Read,
        // plans and applying them: a change to a box
        ["plans", ..] | ["apply"] => read_or(BoxChange),
        // runs and what starts them
        ["tasks", ..] | ["chat", ..] | ["schedules", ..] | ["triggers", ..] => read_or(RunStart),
        ["orchestrations", "settings"] => read_or(SettingsChange),
        ["orchestrations", "rules", "check"] => Need::Read,
        ["orchestrations", ..] => read_or(RunStart),
        ["approval-requests", ..] => read_or(ApprovalDecide),
        ["approval-policy"] => read_or(SettingsChange),
        // Telegram links (ADR 0050): looking is for anyone signed in; making a link or a delegation is working, and the passkey is
        // asked inside. What only makes Telegram less able (lock, unlink, revoke) is open to anyone for their own link, and the
        // handler checks whose it is.
        ["telegram"] if get => Need::Read,
        ["telegram", "window" | "link", ..] => Need::Act(RunStart),
        ["telegram", "links", _, "lock" | "unlock", ..] | ["telegram", "links", _] if !get => {
            Need::Read
        }
        ["telegram", "links", _, "transcript"] => Need::Act(SettingsChange),
        ["telegram", "links", _, "renew" | "delegations", ..] => Need::Act(RunStart),
        ["telegram", "delegations", _] if !get => Need::Read,
        ["telegram", "delegations", _, "cosign", ..] => Need::Act(SettingsChange),
        ["telegram", "lock-all" | "resume" | "marks"] => Need::Act(SettingsChange),
        // anything else under here that changes something is an owner's
        ["telegram", ..] => read_or(SettingsChange),
        // memory is the agents' notes; a skill is code an agent may run, so reviewing one is the owner's
        ["memory", ..] => read_or(FileWrite),
        ["skills", ..] => read_or(SettingsChange),
        // a skill put on a box's own disk is guidance its agents will follow: an owner's act, like approving one
        ["boxes", _, "skills", ..] => read_or(SettingsChange),
        // permissions, secrets, costs, settings and people
        ["permissions", "check"] => Need::Read,
        ["permissions", "grants", ..] => read_or(GrantCreate),
        ["permissions", ..] => read_or(SettingsChange),
        ["secrets", "approvals"] => read_or(SecretUse),
        ["secrets", ..] => read_or(SecretWrite),
        ["cost", "orphans", "plan" | "apply"] => Need::Act(ResourceTouch),
        // looking at costs is open; asking a provider's billing service for fresh figures is a use of the account
        ["cost", rest @ ..] if !get && matches!(rest.last(), Some(&("refresh" | "scan"))) => {
            Need::Act(RunStart)
        }
        ["cost", ..] => Need::Read,
        ["spend-caps"] => read_or(Spend),
        ["settings"] => read_or(SettingsChange),
        ["people", ..] => read_or(PeopleManage),
        ["setup", ..] | ["dashboard-access", ..] | ["profiles", ..] | ["apps", ..] => {
            read_or(SettingsChange)
        }
        ["backups", ..] => read_or(SettingsChange),
        // asking the provider whether it answers is a look; nothing under here changes anything
        ["provider", ..] => read_or(SettingsChange),
        ["audit", "verify"] => Need::Read,
        ["audit", ..] => read_or(SettingsChange),
        // messages out: a test message, a phone that is to receive alerts
        ["alerts", "test"] | ["push", "devices", ..] => Need::Act(MessageSend),
        ["models", _, "list" | "test"] => Need::Act(ToolCall),
        // not named here: the default applies (see `classify`)
        _ => return None,
    })
}

/// What a role cannot do, in the words of the refusal ("a viewer cannot watch a browser session").
pub(super) fn act_words(a: Action) -> &'static str {
    match a {
        Action::BrowserWatch => "watch a browser session",
        Action::BrowserControl => "take over or control a browser",
        Action::ApprovalDecide => "decide approvals",
        Action::RunStart | Action::RunStop => "start or stop runs",
        Action::CommandRun => "use a terminal or an IDE on a box",
        Action::FileRead | Action::FileWrite => "open or change the files on a box",
        Action::BoxCreate | Action::BoxChange | Action::BoxDestroy => "change a box",
        Action::SettingsChange => "change settings",
        Action::GrantCreate => "change permissions",
        Action::SecretWrite | Action::SecretUse => "change the secrets policy",
        Action::Spend | Action::ResourceTouch => "manage costs",
        Action::PeopleManage => "change who can do what",
        Action::MessageSend => "send messages",
        Action::ToolCall => "use a model",
        _ => "do this",
    }
}

/// What a request may do about a second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StepUp {
    /// A passkey was shown a moment ago, or there is no sign-in and the server is on the person's own computer.
    Fresh,
    /// Behind a sign-in, and no passkey was shown a moment ago.
    Needed,
    /// No sign-in, and the server runs on a box: refused, whatever the request says.
    LocalOnly,
}

/// Decide a fresh second factor. `signed_in` is `Some(fresh)` behind a sign-in. Without one, the server's operator is
/// whoever holds the access token it printed, which is the person only on their own computer: on a box (a security review,
/// 2026-11-11) any process that read the token from the server's log, or that runs as the same user, would pass, so the
/// routes that ask for a second factor are refused there.
pub(super) fn step_up_gate(signed_in: Option<bool>, on_a_box: bool) -> StepUp {
    match (signed_in, on_a_box) {
        (Some(true), _) => StepUp::Fresh,
        (Some(false), _) => StepUp::Needed,
        (None, false) => StepUp::Fresh,
        (None, true) => StepUp::LocalOnly,
    }
}

/// Why a route that needs a second factor is refused on a box without a sign-in. `what` finishes "so ... needs a sign-in".
pub(super) fn local_only_message(what: &str) -> String {
    format!("this dashboard has no sign-in and runs on a box, where another process could hold its access token, so {what} needs a sign-in with a passkey. Turn on sign-in (`ozbox dashboard install` with --person), or run the dashboard on your own computer")
}

/// The refusal for a request that did not show a second factor, or `None` when it did. `what` names the act for the
/// no-sign-in case ("granting access to production").
pub(super) fn step_up_refusal(state: StepUp, what: &str) -> Option<Resp> {
    match state {
        StepUp::Fresh => None,
        StepUp::Needed => Some(Resp::error(
            403,
            "step_up_required",
            "confirm with your passkey to continue",
        )),
        StepUp::LocalOnly => Some(Resp::error(
            403,
            "sign_in_required",
            &local_only_message(what),
        )),
    }
}

impl App {
    /// The refusal for a loosening that did not show a fresh second factor, written to the audit chain like a role refusal
    /// (a refused change is recorded; the detail names the act and why, never a value).
    pub(super) fn step_up_denied(&self, who: &str, state: StepUp, what: &str) -> Resp {
        let why = match state {
            StepUp::LocalOnly => "sign_in_required",
            _ => "step_up_required",
        };
        self.chain_event(
            &format!("person:{who}"),
            "permission.deny",
            None,
            &format!("{what} rule={why}"),
        );
        step_up_refusal(state, what).unwrap_or_else(|| {
            Resp::error(
                403,
                "step_up_required",
                "confirm with your passkey to continue",
            )
        })
    }

    /// Whether this request counts as one from a person who just proved who they are.
    pub(super) fn step_up_state(&self, req: &Req) -> StepUp {
        step_up_gate(
            self.auth.as_ref().map(|a| a.step_up_fresh(req)),
            self.on_a_box,
        )
    }

    /// `Some` refuses the request: the person's role may not do what it asks. A dashboard with no sign-in has one
    /// person, who may do anything.
    pub(super) fn role_gate(&self, req: &Req) -> Option<Resp> {
        let auth = self.auth.as_ref()?;
        // a person who is no longer on the list has no role, so not even a look
        let Some((person, role)) = auth.who_and_role(req) else {
            return Some(Resp::error(401, "unauthorized", "sign in to continue"));
        };
        let Need::Act(action) = classify(&req.method, &req.path) else {
            return None;
        };
        let d = roles::decide(role, &person, action, super::unix_ms());
        if d.effect != ozbox_core::permissions::Effect::Deny {
            return None;
        }
        if !is_get(&req.method) {
            // a refused change is recorded; a refused look is not, so polling cannot fill the chain
            self.chain_event(
                &format!("person:{person}"),
                "permission.deny",
                None,
                &format!(
                    "{} role={} rule={}",
                    action.name(),
                    role.name(),
                    d.rule.as_deref().unwrap_or("-")
                ),
            );
        }
        Some(Resp::error(
            403,
            "role_forbidden",
            &format!(
                "you are signed in as a {}, and a {} cannot {}. Ask an owner",
                role.name(),
                role.name(),
                act_words(action)
            ),
        ))
    }

    /// `GET /v1/people` and `PUT /v1/people/<id>/role`.
    pub(super) fn people_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let who = self.who(req);
        let Some(auth) = self.auth.clone() else {
            // one person, the operator: everything is theirs
            return match (req.method.as_str(), rest) {
                ("GET", []) => Resp::json(
                    200,
                    &json!({
                        "mode": "token",
                        "me": { "id": who, "role": "owner" },
                        "people": [],
                        "roles": Role::ALL.iter().map(|r| r.name()).collect::<Vec<_>>(),
                        "can": roles::capabilities(Role::Owner),
                    }),
                ),
                _ => Resp::error(
                    409,
                    "no_sign_in",
                    "roles belong to a dashboard with a sign-in; this one has a single operator",
                ),
            };
        };
        match (req.method.as_str(), rest) {
            ("GET", []) => {
                let current = roles_with_labels(&auth);
                let my = auth.role_of(&who);
                Resp::json(
                    200,
                    &json!({
                        "mode": "session",
                        "me": { "id": who, "role": my.name() },
                        "people": current,
                        "roles": Role::ALL.iter().map(|r| r.name()).collect::<Vec<_>>(),
                        "can": roles::capabilities(my),
                    }),
                )
            }
            ("PUT", [id, "role"]) => {
                if let Some(r) =
                    step_up_refusal(self.step_up_state(req), "changing who can do what")
                {
                    return r;
                }
                let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                let Some(role) = body
                    .get("role")
                    .and_then(Value::as_str)
                    .and_then(Role::parse)
                else {
                    return Resp::error(400, "bad_request", "the role is owner, member or viewer");
                };
                match auth.set_role(id, role) {
                    Ok(from) => {
                        if from != role {
                            self.chain_event(
                                &format!("person:{who}"),
                                "person.role",
                                Some(id),
                                &format!("{}->{}", from.name(), role.name()),
                            );
                        }
                        Resp::json(
                            200,
                            &json!({ "id": id, "role": role.name(), "was": from.name() }),
                        )
                    }
                    Err(super::auth::roles::RoleError::Unknown) => {
                        Resp::error(404, "not_found", "there is no such person on this dashboard")
                    }
                    Err(super::auth::roles::RoleError::Save) => Resp::error(
                        500,
                        "not_saved",
                        "the change could not be written to the dashboard's state file, so nothing was changed",
                    ),
                    Err(super::auth::roles::RoleError::LastOwner) => Resp::error(
                        409,
                        "last_owner",
                        "this dashboard must keep at least one owner: make someone else an owner first",
                    ),
                }
            }
            (_, [] | [_, "role"]) => Resp::error(405, "method_not_allowed", "method not allowed"),
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }
}

/// Everyone on the list with their role, for the people screen.
fn roles_with_labels(auth: &super::auth::Auth) -> Vec<Value> {
    let current = auth.roles();
    auth.cfg
        .file
        .users
        .iter()
        .map(|u| {
            json!({
                "id": u.id,
                "label": u.label,
                "role": current.get(&u.id).copied().unwrap_or(Role::Viewer).name(),
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use Action::*;

    #[test]
    fn the_second_factor_gate_decides_by_sign_in_and_where_the_server_runs() {
        assert_eq!(step_up_gate(None, false), StepUp::Fresh);
        assert_eq!(step_up_gate(None, true), StepUp::LocalOnly);
        assert_eq!(step_up_gate(Some(false), false), StepUp::Needed);
        assert_eq!(step_up_gate(Some(false), true), StepUp::Needed);
        assert_eq!(step_up_gate(Some(true), true), StepUp::Fresh);
        assert!(step_up_refusal(StepUp::Fresh, "x").is_none());
        let local = step_up_refusal(StepUp::LocalOnly, "granting access").map(|r| r.body);
        let body = String::from_utf8_lossy(&local.unwrap_or_default()).to_string();
        assert!(body.contains("sign_in_required") && body.contains("granting access"));
    }

    #[test]
    fn the_table_names_what_each_route_needs() {
        let cases: &[(&str, &str, Need)] = &[
            ("GET", "/v1/boxes", Need::Read),
            ("GET", "/v1/runs", Need::Read),
            ("GET", "/v1/cost/bill", Need::Read),
            ("GET", "/v1/audit", Need::Read),
            ("GET", "/v1/people", Need::Read),
            ("GET", "/v1/browser/sessions", Need::Act(BrowserWatch)),
            (
                "GET",
                "/v1/browser/sessions/x/frame",
                Need::Act(BrowserWatch),
            ),
            (
                "GET",
                "/v1/browser/recordings/b/x/shots/1.jpg",
                Need::Act(BrowserWatch),
            ),
            (
                "POST",
                "/v1/browser/sessions/x/takeover",
                Need::Act(BrowserControl),
            ),
            (
                "POST",
                "/v1/browser/sessions/x/input",
                Need::Act(BrowserControl),
            ),
            (
                "POST",
                "/v1/browser/sessions/x/resume",
                Need::Act(BrowserControl),
            ),
            ("GET", "/v1/browser/settings", Need::Read),
            ("PUT", "/v1/browser/settings", Need::Act(SettingsChange)),
            ("POST", "/v1/tasks", Need::Act(RunStart)),
            ("POST", "/v1/orchestrations", Need::Act(RunStart)),
            ("POST", "/v1/chat/messages", Need::Act(RunStart)),
            (
                "POST",
                "/v1/approval-requests/a/approve",
                Need::Act(ApprovalDecide),
            ),
            ("GET", "/v1/approval-requests", Need::Read),
            ("PUT", "/v1/approval-policy", Need::Act(SettingsChange)),
            ("PUT", "/v1/settings", Need::Act(SettingsChange)),
            ("PUT", "/v1/permissions", Need::Act(SettingsChange)),
            ("POST", "/v1/permissions/grants", Need::Act(GrantCreate)),
            (
                "POST",
                "/v1/permissions/grants/g1/revoke",
                Need::Act(GrantCreate),
            ),
            ("POST", "/v1/permissions/check", Need::Read),
            ("PUT", "/v1/secrets/api-key", Need::Act(SecretWrite)),
            ("DELETE", "/v1/secrets/api-key", Need::Act(SecretWrite)),
            ("POST", "/v1/secrets/approvals", Need::Act(SecretUse)),
            ("POST", "/v1/cost/orphans/apply", Need::Act(ResourceTouch)),
            ("POST", "/v1/cost/orphans/scan", Need::Act(RunStart)),
            ("POST", "/v1/cost/refresh", Need::Act(RunStart)),
            ("POST", "/v1/cost/bill/refresh", Need::Act(RunStart)),
            ("GET", "/v1/cost/bill", Need::Read),
            ("GET", "/v1/boxes/dev/ssh", Need::Act(CommandRun)),
            ("POST", "/v1/boxes/dev/ssh", Need::Act(CommandRun)),
            ("PUT", "/v1/spend-caps", Need::Act(Spend)),
            ("PUT", "/v1/people/ann/role", Need::Act(PeopleManage)),
            ("POST", "/v1/apply", Need::Act(BoxChange)),
            ("GET", "/v1/jobs/abc", Need::Read),
            ("POST", "/v1/plans", Need::Act(BoxChange)),
            ("POST", "/v1/boxes/dev/terminal", Need::Act(CommandRun)),
            ("GET", "/v1/terminal/abc/output", Need::Act(CommandRun)),
            ("GET", "/v1/boxes/dev/files/list", Need::Act(FileRead)),
            ("PUT", "/v1/boxes/dev/files/x", Need::Act(FileWrite)),
            ("GET", "/v1/boxes/dev/code", Need::Read),
            ("POST", "/v1/boxes/dev/code/open", Need::Act(CommandRun)),
            (
                "POST",
                "/v1/boxes/dev/backups/credentials",
                Need::Act(SecretWrite),
            ),
            ("PUT", "/v1/backups/settings", Need::Act(SettingsChange)),
            ("GET", "/v1/provider/check", Need::Read),
            ("POST", "/v1/alerts/test", Need::Act(MessageSend)),
            ("POST", "/v1/apps/webhooks", Need::Act(SettingsChange)),
            ("POST", "/v1/skills/x/approve", Need::Act(SettingsChange)),
            ("POST", "/v1/memory", Need::Act(FileWrite)),
            ("POST", "/v1/skills", Need::Act(SettingsChange)),
            ("DELETE", "/v1/skills/demo", Need::Act(SettingsChange)),
            ("GET", "/v1/skills/holdings", Need::Read),
            ("GET", "/v1/boxes/dev/skills", Need::Read),
            (
                "PUT",
                "/v1/boxes/dev/skills/demo",
                Need::Act(SettingsChange),
            ),
            (
                "DELETE",
                "/v1/boxes/dev/skills/demo",
                Need::Act(SettingsChange),
            ),
            // not in the table: reading is open to anyone signed in, a change is an owner's
            ("GET", "/v1/something-new", Need::Read),
            ("POST", "/v1/something-new", Need::Act(SettingsChange)),
        ];
        for (m, p, want) in cases {
            assert_eq!(classify(m, p), *want, "{m} {p}");
        }
    }

    /// The table is checked against every route the server answers: each `/v1` route in the source's dispatch has to
    /// classify as something other than the owner-only catch-all by accident. Here, the catch-all is the answer for
    /// exactly the routes that are meant to be an owner's (a settings change), so this pins the ones that must not be.
    #[test]
    fn what_a_member_does_all_day_is_not_caught_by_the_owners_catch_all() {
        for (m, p) in [
            ("POST", "/v1/tasks"),
            ("POST", "/v1/tasks/t1/cancel"),
            ("POST", "/v1/tasks/bulk"),
            ("POST", "/v1/orchestrations/o1/stop"),
            ("POST", "/v1/schedules"),
            ("POST", "/v1/schedules/s1/run-now"),
            ("POST", "/v1/triggers"),
            ("POST", "/v1/chat/messages"),
            ("POST", "/v1/boxes/dev/terminal"),
            ("POST", "/v1/terminal/t/input"),
            ("DELETE", "/v1/terminal/t"),
            ("POST", "/v1/approval-requests/a/deny"),
            ("POST", "/v1/boxes/dev/code/plan"),
            ("POST", "/v1/boxes/dev/tools/apply"),
            ("POST", "/v1/boxes/dev/local-ai/apply"),
            ("PUT", "/v1/memory/m1"),
            ("DELETE", "/v1/memory/m1"),
            ("POST", "/v1/push/devices"),
            ("POST", "/v1/models/x/test"),
        ] {
            assert!(
                roles::allowed(
                    Role::Member,
                    match classify(m, p) {
                        Need::Act(a) => a,
                        Need::Read => continue,
                    }
                ),
                "{m} {p}"
            );
        }
    }

    /// Every first path segment `App::api` answers has been decided: either the table names it, or it is in the list of
    /// roots whose writes knowingly fall to the owner-only default. A new route root that is neither fails here, so adding
    /// a route is a decision about who may use it, not an accident of the default.
    #[test]
    fn every_route_root_the_server_answers_has_been_decided() {
        const OWNER_BY_DEFAULT: &[&str] = &[
            // reads only (their writes, if any are added, are an owner's until somebody names them)
            "info",
            "catalog",
            "usage",
            "suggestions",
            "runs",
            "host-tools",
            "approvals",
            "activity",
            "events",
            "demo",
            "code",
            // a box's dashboard that manages the fleet: the plan-bound passkey challenge is an owner's (ADR 0040)
            "fleet",
            "boxes",
            // named by sub-route in the table (a test message, a model's list or test, a push device); anything else under
            // them is an owner's
            "alerts",
            "models",
            "push",
        ];
        const BOX_OWNER_BY_DEFAULT: &[&str] = &["image", "selftest", "incidents", "metrics"];
        let src = include_str!("../serve.rs");
        let from = src.find("    fn api(&mut self").expect("api");
        let rest = &src[from..];
        let to = rest[10..]
            .find("\n    fn ")
            .map(|i| i + 10)
            .unwrap_or(rest.len());
        let body = &rest[..to];
        let mut roots = std::collections::BTreeSet::new();
        let mut box_subs = std::collections::BTreeSet::new();
        for line in body.lines() {
            let t = line.trim_start().trim_start_matches('|').trim_start();
            let Some(inner) = t.strip_prefix('[') else {
                continue;
            };
            let items: Vec<&str> = inner
                .split(']')
                .next()
                .unwrap_or("")
                .split(',')
                .map(str::trim)
                .collect();
            let lit = |x: &str| {
                x.strip_prefix('"')
                    .and_then(|y| y.strip_suffix('"'))
                    .map(str::to_string)
            };
            if let Some(r) = items.first().and_then(|x| lit(x)) {
                if r == "boxes" {
                    if let Some(sub) = items.get(2).and_then(|x| lit(x)) {
                        box_subs.insert(sub);
                    }
                }
                roots.insert(r);
            }
        }
        assert!(roots.len() > 25, "the scan found too few routes: {roots:?}");
        let undecided: Vec<&String> = roots
            .iter()
            .filter(|r| {
                let named = classify_named("POST", &format!("/v1/{r}/x/y")).is_some()
                    || classify_named("POST", &format!("/v1/{r}")).is_some()
                    || classify_named("PUT", &format!("/v1/{r}/x")).is_some()
                    || classify_named("DELETE", &format!("/v1/{r}/x")).is_some();
                !named && !OWNER_BY_DEFAULT.contains(&r.as_str())
            })
            .collect();
        assert!(
            undecided.is_empty(),
            "/v1/{undecided:?} are answered by the server but nobody decided who may use them: name them in `classify` (or list them here as roots whose writes are an owner's)"
        );
        for sub in &box_subs {
            let named = classify_named("POST", &format!("/v1/boxes/dev/{sub}/y")).is_some()
                || classify_named("POST", &format!("/v1/boxes/dev/{sub}")).is_some();
            assert!(
                named || BOX_OWNER_BY_DEFAULT.contains(&sub.as_str()),
                "/v1/boxes/<name>/{sub} is answered by the server but nobody decided who may use it"
            );
        }
    }

    /// Everything `App::handle` answers before the request guard is on this list, and each has a reason. A route that
    /// skips the guard has to be added here on purpose; one that is added to `handle` by accident fails this test.
    #[test]
    fn what_skips_the_request_guard_is_a_short_list_with_reasons() {
        // "/auth/session": the page asks which way in this server uses (the sign-in router checks its own routes against
        //   `AUTH_ROUTES`, owner-only ones included); "/hooks/*": signed by the sender, not by a person;
        // "/code/enter": the IDE hosts' own check. `/v1` and the files are behind the guard, which comes next.
        const BEFORE_THE_GUARD: &[&str] = &[
            "/auth/session",
            "/hooks/chat/whatsapp",
            "/hooks/",
            "/code/enter",
        ];
        let src = include_str!("../serve.rs");
        let from = src.find("    pub fn handle(&mut self").expect("handle");
        let rest = &src[from..];
        let to = rest.find("\n    fn api(").expect("end of handle");
        let body = &rest[..to];
        let guard_at = body.find("self.guard(req").expect("guard");
        let before = &body[..guard_at];
        let mut seen = std::collections::BTreeSet::new();
        let mut cur = before;
        while let Some(i) = cur.find("\"/") {
            let tail = &cur[i + 1..];
            let end = tail.find('"').unwrap_or(0);
            seen.insert(tail[..end].to_string());
            cur = &tail[end..];
        }
        let want: std::collections::BTreeSet<String> =
            BEFORE_THE_GUARD.iter().map(|x| x.to_string()).collect();
        assert_eq!(seen, want, "a route is answered before the request guard: add it to the list with its reason, or move it behind the guard");
        // the file transfers check the guard themselves
        assert!(
            include_str!("../serve/files.rs").contains("guard("),
            "file transfers must pass the guard"
        );
    }
}
