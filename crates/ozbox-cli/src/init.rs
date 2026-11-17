//! First-run setup, shared by `ozbox init` and the dashboard's "Set up your fleet": sign-in check, permission probes,
//! region suggestion, the encrypted state bucket, the network, the plugin cache, the budget and alert guard rail and the
//! security baseline.
//!
//! Rules this module keeps:
//!
//! * **Every mutating step is planned first.** `plan_*` only reads (or writes this program's own scratch files); the
//!   returned [`Prepared`] lists every change, and `apply` runs exactly those commands.
//! * **What is done is read from reality**, not from a progress file: the bucket exists, the config has a subnet. That
//!   makes every step idempotent and the whole run resumable.
//! * **Short-lived credentials only.** A root identity, or an IAM user that has long-lived access keys, is refused.
//! * **Probes cannot mutate.** Permissions are checked with `--dry-run` calls (an answer of `DryRunOperation` means the
//!   call would have been allowed) and read-only listings.
//! * Commands are argv arrays through [`CommandRunner`]; no secret is ever put in one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ozbox_core::{Change, CommandRunner, CommandSpec, Output, Risk, Size};
use ozbox_provider_aws::operator_policy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod adopt;

use crate::messages::t;
use crate::netguard::{Guard, HttpClient, HttpRequest};
use crate::secrets::SecretStore;
use crate::settings::Settings;

/// Providers `init` knows. `fake` is the free sandbox.
pub const PROVIDERS: [&str; 3] = ["fake", "aws", "hcloud"];

/// A refusal or failure with a stable machine code, a sentence a person can act on, and (when there is one) the fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Finding {
    pub fn new(code: &str, message: String) -> Self {
        Finding {
            code: code.into(),
            message,
            fix: None,
        }
    }

    pub fn with_fix(mut self, fix: String) -> Self {
        self.fix = Some(fix);
        self
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;
        if let Some(fix) = &self.fix {
            write!(f, " {fix}")?;
        }
        Ok(())
    }
}

type Res<T> = std::result::Result<T, Finding>;

// ---------- the target ----------

/// Which provider, with which sign-in profile, in which region.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Target {
    pub provider: String,
    pub profile: Option<String>,
    pub region: Option<String>,
}

pub fn valid_region(r: &str) -> bool {
    // us-east-1, eu-central-1, ap-southeast-2, us-gov-west-1
    let parts: Vec<&str> = r.split('-').collect();
    parts.len() >= 3
        && parts.len() <= 4
        && parts[0].len() == 2
        && parts[0].bytes().all(|b| b.is_ascii_lowercase())
        && parts[1..parts.len() - 1]
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase()))
        && parts
            .last()
            .is_some_and(|l| l.len() == 1 && l.bytes().all(|b| b.is_ascii_digit()))
}

pub fn valid_profile(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 128
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.@+=,".contains(&b))
}

impl Target {
    pub fn validate(&self) -> Res<()> {
        if !PROVIDERS.contains(&self.provider.as_str()) {
            return Err(Finding::new(
                "bad_provider",
                t("init.bad_provider", &[("provider", &self.provider)]),
            ));
        }
        if let Some(p) = &self.profile {
            if !valid_profile(p) {
                return Err(Finding::new("bad_profile", t("init.bad_profile", &[])));
            }
        }
        if let Some(r) = &self.region {
            if self.provider == "aws" && !valid_region(r) {
                return Err(Finding::new(
                    "bad_region",
                    t("init.bad_region", &[("region", r)]),
                ));
            }
            if self.provider == "hcloud"
                && !(r.len() <= 8
                    && r.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
            {
                return Err(Finding::new(
                    "bad_region",
                    t("init.bad_region", &[("region", r)]),
                ));
            }
        }
        Ok(())
    }

    fn region_or_err(&self) -> Res<&str> {
        self.region
            .as_deref()
            .ok_or_else(|| Finding::new("region_missing", t("init.region_missing", &[])))
    }
}

// ---------- the identity ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    Root,
    IamUser,
    SsoRole,
    AssumedRole,
    Federated,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identity {
    pub account: String,
    pub arn: String,
    pub kind: IdentityKind,
    /// The IAM user name, for an IAM user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

/// Classify an ARN from `sts get-caller-identity`.
pub fn classify_arn(arn: &str) -> (IdentityKind, Option<String>) {
    let resource = arn.splitn(6, ':').nth(5).unwrap_or("");
    if resource == "root" {
        (IdentityKind::Root, None)
    } else if let Some(user) = resource.strip_prefix("user/") {
        let name = user.rsplit('/').next().unwrap_or(user);
        (IdentityKind::IamUser, Some(name.to_string()))
    } else if let Some(role) = resource.strip_prefix("assumed-role/") {
        if role.starts_with("AWSReservedSSO_") {
            (IdentityKind::SsoRole, None)
        } else {
            (IdentityKind::AssumedRole, None)
        }
    } else if resource.starts_with("federated-user/") {
        (IdentityKind::Federated, None)
    } else {
        (IdentityKind::Other, None)
    }
}

pub fn parse_identity(json: &str) -> Res<Identity> {
    let v: Value = serde_json::from_str(json)
        .map_err(|_| Finding::new("bad_answer", t("init.bad_answer", &[])))?;
    let arn = v
        .get("Arn")
        .and_then(Value::as_str)
        .ok_or_else(|| Finding::new("bad_answer", t("init.bad_answer", &[])))?;
    let account = v.get("Account").and_then(Value::as_str).unwrap_or("");
    let (kind, user) = classify_arn(arn);
    Ok(Identity {
        account: account.to_string(),
        arn: arn.to_string(),
        kind,
        user,
    })
}

// ---------- probes ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeState {
    Allowed,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub id: String,
    pub label: String,
    pub state: ProbeState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermissionReport {
    pub probes: Vec<Probe>,
    /// No probe was denied.
    pub ok: bool,
}

/// What a probe's answer means. A `--dry-run` call that would have succeeded answers `DryRunOperation`; a caller who
/// may not make the call is refused before the parameters are even checked, so a later "invalid parameter" error still
/// means the permission is there.
pub fn classify_probe(dry: bool, out: &Output) -> (ProbeState, Option<String>) {
    let err = out.stderr.as_str();
    if out.status == Some(0) {
        return (ProbeState::Allowed, None);
    }
    if err.contains("DryRunOperation") {
        return (ProbeState::Allowed, None);
    }
    // a named-bucket probe: the bucket not being there is not a refusal (a 403 or AccessDenied still is one, never a 404)
    if err.contains("NoSuchBucket") || err.contains("(404)") {
        return (ProbeState::Allowed, None);
    }
    if err.contains("UnauthorizedOperation")
        || err.contains("AccessDenied")
        || err.contains("not authorized")
    {
        return (ProbeState::Denied, None);
    }
    if dry
        && (err.contains("InvalidAMIID")
            || err.contains("InvalidParameter")
            || err.contains("InvalidVolume")
            || err.contains("InvalidZone")
            || err.contains("InvalidAvailabilityZone")
            || err.contains("Malformed"))
    {
        return (ProbeState::Allowed, None);
    }
    let first = err.lines().next().unwrap_or("").trim();
    let detail: String = first.chars().take(160).collect();
    (
        ProbeState::Unknown,
        if detail.is_empty() {
            None
        } else {
            Some(detail)
        },
    )
}

/// Whether the daily operator sign-in already holds the statements the adopt commands need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorCheck {
    /// Systems Manager answered "not found" to a read of a command that does not exist: the sign-in may ask.
    Allowed,
    /// The sign-in was refused: it was set up before the adopt statements existed.
    Denied,
    /// The answer was neither (not signed in, a network error).
    Unknown,
    /// No daily profile is recorded in the config, so there is no sign-in to ask.
    NotChecked,
}

/// What `ozbox init` leaves for the administrator who applies the operator policy.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OperatorPolicyReport {
    /// The complete policy, ready to apply (one file; replaces the daily permission set's policy).
    pub file: String,
    pub region: String,
    pub fleet: String,
    /// The statements an operator policy from before 0.2.0 does not have.
    pub added_statements: Vec<String>,
    /// Those statements as rendered for this account, region and fleet.
    pub adopt_statements: Vec<Value>,
    pub operator_check: OperatorCheck,
}

/// The meaning of the one read the operator check makes.
pub fn classify_operator_check(out: &Output) -> OperatorCheck {
    let err = out.stderr.as_str();
    if err.contains("AccessDenied") || err.contains("not authorized") {
        return OperatorCheck::Denied;
    }
    if out.status == Some(0)
        || err.contains("InvocationDoesNotExist")
        || err.contains("InvalidCommandId")
        || err.contains("InvalidInstanceId")
    {
        return OperatorCheck::Allowed;
    }
    OperatorCheck::Unknown
}

/// Who grants a probe's permission. The operator policy (`infra/aws/operator-policy.json`) is the daily role; the state
/// bucket belongs to the setup identity, which no operator statement reaches (README, "AWS: the network and the operator's
/// permissions"). Only an operator probe can stop setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grant {
    /// `infra/aws/operator-policy.json`, by the named statement.
    Operator(&'static str),
    /// The setup identity (or an administrator), not the operator policy.
    SetupIdentity,
}

/// One permission probe: the call it makes, and the IAM action and tag it stands for, so a test can hold it to the policy.
pub(crate) struct ProbeDef {
    pub id: &'static str,
    pub label: &'static str,
    pub dry: bool,
    pub args: Vec<String>,
    /// The IAM action the call needs.
    pub action: &'static str,
    /// The EC2 resource type the call tags on creation (`ozbox-managed=true`, as the OpenTofu modules do), if it creates one.
    pub tag_resource: Option<&'static str>,
    pub grant: Grant,
}

/// The tag every Oz Box resource carries, and the only shape of create the operator policy allows.
pub(crate) const MANAGED_TAG: &str = "ozbox-managed";

fn tag_spec(resource: &str) -> String {
    format!("ResourceType={resource},Tags=[{{Key={MANAGED_TAG},Value=true}}]")
}

pub(crate) fn probe_defs(region: &str, account: Option<&str>) -> Vec<ProbeDef> {
    let az = format!("{region}a");
    let v = |a: &[&str]| a.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    let mut defs = vec![
        ProbeDef {
            id: "ec2_run_instances",
            label: "init.probe_run_instances",
            dry: true,
            args: {
                let mut a = v(&[
                    "ec2",
                    "run-instances",
                    "--dry-run",
                    "--image-id",
                    "ami-0123456789abcdef0",
                    "--instance-type",
                    "t3.nano",
                    "--count",
                    "1",
                    "--tag-specifications",
                ]);
                a.push(tag_spec("instance"));
                a
            },
            action: "ec2:RunInstances",
            tag_resource: Some("instance"),
            grant: Grant::Operator("RunTaggedInstances"),
        },
        ProbeDef {
            id: "ec2_create_volume",
            label: "init.probe_create_volume",
            dry: true,
            args: {
                let mut a = v(&[
                    "ec2",
                    "create-volume",
                    "--dry-run",
                    "--availability-zone",
                    &az,
                    "--size",
                    "1",
                    "--tag-specifications",
                ]);
                a.push(tag_spec("volume"));
                a
            },
            action: "ec2:CreateVolume",
            tag_resource: Some("volume"),
            grant: Grant::Operator("CreateTaggedResources"),
        },
        ProbeDef {
            id: "ec2_create_snapshot",
            label: "init.probe_create_snapshot",
            dry: true,
            args: {
                let mut a = v(&[
                    "ec2",
                    "create-snapshot",
                    "--dry-run",
                    "--volume-id",
                    "vol-0123456789abcdef0",
                    "--tag-specifications",
                ]);
                a.push(tag_spec("snapshot"));
                a
            },
            action: "ec2:CreateSnapshot",
            tag_resource: Some("snapshot"),
            grant: Grant::Operator("CreateTaggedResources"),
        },
        ProbeDef {
            id: "ec2_create_vpc",
            label: "init.probe_create_vpc",
            dry: true,
            args: {
                let mut a = v(&[
                    "ec2",
                    "create-vpc",
                    "--dry-run",
                    "--cidr-block",
                    "10.255.0.0/16",
                    "--tag-specifications",
                ]);
                a.push(tag_spec("vpc"));
                a
            },
            action: "ec2:CreateVpc",
            tag_resource: Some("vpc"),
            grant: Grant::Operator("CreateTaggedResources"),
        },
        ProbeDef {
            id: "ssm_describe",
            label: "init.probe_ssm",
            dry: false,
            args: v(&["ssm", "describe-instance-information", "--max-results", "5"]),
            action: "ssm:DescribeInstanceInformation",
            tag_resource: None,
            grant: Grant::Operator("ReadOnly"),
        },
    ];
    // The state bucket init keeps its plans in, by name: never a listing of every bucket in the account. "Not found" means
    // the permission is there and the bucket is still to be made. It is the setup identity's bucket, so it never stops setup.
    if let Some(account) = account {
        defs.push(ProbeDef {
            id: "s3_state_bucket",
            label: "init.probe_s3",
            dry: false,
            args: v(&[
                "s3api",
                "head-bucket",
                "--bucket",
                &Init::bucket_name(account, region),
            ]),
            action: "s3:ListBucket",
            tag_resource: None,
            grant: Grant::SetupIdentity,
        });
    }
    defs
}

/// Which grant to name when a probe is refused, so the person knows who to ask and for what.
fn grant_hint(def: &ProbeDef) -> String {
    match def.grant {
        Grant::Operator(sid) => t(
            if def.tag_resource.is_some() {
                "init.grant_operator_tagged"
            } else {
                "init.grant_operator"
            },
            &[("action", def.action), ("sid", sid), ("tag", MANAGED_TAG)],
        ),
        Grant::SetupIdentity => t("init.grant_setup_identity", &[("action", def.action)]),
    }
}

// ---------- regions ----------

/// Round-trip time to a URL, or `None` when it cannot be reached. Separate from [`HttpClient`] so tests need no clock.
pub trait Latency: Send + Sync {
    fn rtt(&self, url: &str) -> Option<Duration>;
}

/// The real thing: the median of three HTTPS requests, each on a fresh connection.
pub struct HttpLatency<'a>(pub &'a dyn HttpClient);

impl Latency for HttpLatency<'_> {
    fn rtt(&self, url: &str) -> Option<Duration> {
        let mut samples = Vec::new();
        for _ in 0..3 {
            let mut req = HttpRequest::new("GET", url, Guard::Public);
            req.timeout = Duration::from_secs(3);
            let started = Instant::now();
            if self.0.send(&req).is_ok() {
                samples.push(started.elapsed());
            }
        }
        samples.sort();
        samples.get(samples.len() / 2).copied()
    }
}

/// Regions measured. Not hard-coded as an answer: only as the list to measure.
pub const AWS_REGIONS: [(&str, &str); 12] = [
    ("us-east-1", "N. Virginia"),
    ("us-east-2", "Ohio"),
    ("us-west-1", "N. California"),
    ("us-west-2", "Oregon"),
    ("ca-central-1", "Canada"),
    ("eu-west-1", "Ireland"),
    ("eu-west-2", "London"),
    ("eu-central-1", "Frankfurt"),
    ("ap-south-1", "Mumbai"),
    ("ap-southeast-1", "Singapore"),
    ("ap-northeast-1", "Tokyo"),
    ("sa-east-1", "Sao Paulo"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegionCandidate {
    pub region: String,
    pub name: String,
    pub ms: Option<u64>,
    /// Whether the box sizes exist there; `None` = not checked.
    pub offers_sizes: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegionReport {
    pub candidates: Vec<RegionCandidate>,
    pub suggested: Option<String>,
}

/// Fastest first, unreachable last; the suggestion is the fastest region where the sizes are offered (or not known to
/// be missing).
pub fn rank_regions(mut c: Vec<RegionCandidate>) -> RegionReport {
    c.sort_by(|a, b| match (a.ms, b.ms) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.region.cmp(&b.region),
    });
    let suggested = c
        .iter()
        .find(|r| r.ms.is_some() && r.offers_sizes != Some(false))
        .map(|r| r.region.clone());
    RegionReport {
        candidates: c,
        suggested,
    }
}

// ---------- security ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Pass,
    Fail,
    /// Cannot be checked from here; the person confirms it.
    Reminder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityItem {
    pub id: String,
    pub state: CheckState,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityReport {
    pub items: Vec<SecurityItem>,
    /// A failed item stops setup.
    pub blocking: bool,
    /// A reminder must be acknowledged before setup finishes.
    pub needs_ack: bool,
}

// ---------- plans ----------

/// What one setup step would do. The changes are what is shown; `run` is what is executed, nothing else.
#[derive(Debug, Clone, Serialize)]
pub struct Prepared {
    pub step: String,
    pub summary: String,
    pub changes: Vec<Change>,
    pub notes: Vec<String>,
    /// Monthly cost in US dollars, when it can be said; `None` is shown as an em dash.
    pub estimate_usd_month: Option<f64>,
    pub noop: bool,
    #[serde(skip)]
    run: Vec<CommandSpec>,
    #[serde(skip)]
    after: After,
}

/// What a look at the configured subnet found.
#[derive(Debug, PartialEq, Eq)]
pub enum SubnetState {
    Found,
    Missing,
    /// The answer could not be read (often a missing `ec2:DescribeSubnets` permission); the reason is short.
    Unknown(String),
}

#[derive(Debug, Clone, Default)]
enum After {
    #[default]
    Nothing,
    Bucket(String),
    Network(PathBuf),
    /// The security services' working directory: after applying, the bucket and patch group are recorded.
    Security(PathBuf),
    /// The fleet's secrets key: after applying, its ARN and the fleet name are recorded.
    Key(PathBuf),
    /// The off-box issuer: after applying, its address and function are recorded.
    Issuer(PathBuf),
    /// The adopt command's document: after applying, the operator policy it outputs is written to a file next to the plan.
    Adopt(PathBuf),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Applied {
    pub step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_log_bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_key_arn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fleet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,
    /// Where the policy for whoever runs `ozbox adopt-fleet-key` was written (the adopt step).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_adopt_policy_file: Option<String>,
}

impl Prepared {
    /// A plan whose only change is writing this program's own configuration (the free sandbox).
    pub fn config_only(summary: &str, change: &str) -> Prepared {
        Prepared {
            step: "sandbox".into(),
            summary: summary.into(),
            changes: vec![Change::new("config.write", change.to_string(), Risk::Low)],
            notes: Vec::new(),
            estimate_usd_month: Some(0.0),
            noop: false,
            run: Vec::new(),
            after: After::Nothing,
        }
    }
}

// ---------- the setup file ----------

/// What setup records next to the settings. No secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SetupFile {
    pub completed: bool,
    pub provider: Option<String>,
    /// A real cloud needs a budget and an alert channel before a box can be created.
    pub require_guardrails: bool,
    pub mfa_ack: bool,
    pub completed_ms: Option<u64>,
}

impl SetupFile {
    pub fn load(path: &Path) -> SetupFile {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)
    }
}

// ---------- guard rails: budget and alert channel ----------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Guardrails {
    pub budget_set: bool,
    pub monthly_usd: Option<f64>,
    /// The channels that can really deliver: enabled and with their key or address saved.
    pub channels: Vec<String>,
    pub alert_ready: bool,
    pub ok: bool,
}

pub fn guardrails(
    settings: &Settings,
    secrets: &dyn SecretStore,
    paired_chats: usize,
) -> Guardrails {
    let has = |n: &str| secrets.exists(n).unwrap_or(false);
    let a = &settings.apps;
    let mut channels = Vec::new();
    if a.email.enabled && has("email-api-key") && !a.email.from.is_empty() && !a.email.to.is_empty()
    {
        channels.push("email".to_string());
    }
    if a.telegram.enabled && has("telegram-bot-token") && paired_chats > 0 {
        channels.push("telegram".to_string());
    }
    if a.slack.enabled && has("slack-webhook-url") {
        channels.push("slack".to_string());
    }
    if a.webhooks.iter().any(|w| {
        w.enabled
            && has(&format!("webhook-url-{}", w.id))
            && has(&format!("webhook-secret-{}", w.id))
    }) {
        channels.push("webhook".to_string());
    }
    let monthly = settings.budget.monthly_usd.filter(|b| *b > 0.0);
    let (budget_set, alert_ready) = (monthly.is_some(), !channels.is_empty());
    Guardrails {
        budget_set,
        monthly_usd: monthly,
        channels,
        alert_ready,
        ok: budget_set && alert_ready,
    }
}

/// A box that costs money cannot be created (or cloned) until a budget and an alert channel exist, once setup has
/// asked for it. The free sandbox, and a fleet that was set up before this existed, are not held to it.
pub fn require_guardrails(
    setup: &SetupFile,
    g: &Guardrails,
    provider_id: &str,
    op: &ozbox_core::Operation,
) -> Res<()> {
    let adds_box = matches!(
        op,
        ozbox_core::Operation::Create { .. }
            | ozbox_core::Operation::Clone { .. }
            | ozbox_core::Operation::RestoreToNewBox { .. }
    );
    if !adds_box || !setup.require_guardrails || provider_id == "fake" || g.ok {
        return Ok(());
    }
    let what = match (g.budget_set, g.alert_ready) {
        (false, false) => t("init.need_both", &[]),
        (false, true) => t("init.need_budget", &[]),
        _ => t("init.need_alert", &[]),
    };
    Err(Finding::new("guardrails_missing", what).with_fix(t("init.need_fix", &[])))
}

// ---------- the engine ----------

#[derive(Debug, Clone)]
pub struct InitPaths {
    pub config: PathBuf,
    pub setup: PathBuf,
    /// Where OpenTofu keeps downloaded plugins, so a second create does not download them again.
    pub plugin_cache: PathBuf,
    /// This program's own scratch directory for the generated network configuration.
    pub work: PathBuf,
    /// The directory that holds `aws-box` and `aws-network`.
    pub modules: PathBuf,
}

impl InitPaths {
    /// Only where the setup record is (`setup.json` beside the configuration file): what the guard rails read, without
    /// finding (and extracting) the box modules.
    pub fn setup_path() -> Option<PathBuf> {
        Some(crate::config::Config::path()?.parent()?.join("setup.json"))
    }

    /// The directory next to the configuration file (`OZBOX_CONFIG`, else `~/.config/ozbox`).
    pub fn detect() -> Option<InitPaths> {
        // the file the loader reads (`fleet.toml` on an older layout), never a second one beside it
        let config = crate::config::Config::active_path()?;
        let base = config.parent()?.to_path_buf();
        let cache = std::env::var_os("OZBOX_PLUGIN_CACHE_DIR")
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".cache/ozbox/tofu-plugins")))?;
        let loaded = crate::config::Config::load().ok();
        // The modules this program renders (its own copy, or a developer folder; see `infra_cli`).
        let sec = loaded.as_ref().and_then(|c| c.aws.as_ref());
        let box_dir = crate::infra_cli::resolve(&crate::infra_cli::Wanted {
            section: "aws",
            module: "aws-box",
            module_dir: sec.and_then(|a| a.module_dir.clone()),
            dev: crate::infra_cli::dev_flag() || sec.and_then(|a| a.dev_modules).unwrap_or(false),
            state_root: None,
        })
        .map(|r| r.module_dir)
        .unwrap_or_else(|_| PathBuf::from(ozbox_provider_aws::DEFAULT_MODULE_DIR));
        let modules = box_dir
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("infra/tofu/modules"));
        Some(InitPaths {
            setup: base.join("setup.json"),
            work: base.join("init"),
            config,
            plugin_cache: cache,
            modules,
        })
    }

    fn box_dir(&self) -> PathBuf {
        self.modules.join("aws-box")
    }

    fn network_dir(&self) -> PathBuf {
        self.modules.join("aws-network")
    }

    fn security_dir(&self) -> PathBuf {
        self.modules.join("aws-security-baseline")
    }

    fn key_dir(&self) -> PathBuf {
        self.modules.join("aws-secrets-key")
    }

    fn adopt_dir(&self) -> PathBuf {
        self.modules.join("aws-adopt-command")
    }

    fn box_policy_dir(&self) -> PathBuf {
        self.modules.join("aws-box-policy")
    }

    fn fleet_manager_dir(&self) -> PathBuf {
        self.modules.join("aws-fleet-manager")
    }

    fn issuer_dir(&self) -> PathBuf {
        self.modules.join("aws-issuer")
    }
}

/// The actions the fleet key's creation needs: what `infra/aws/key-admin-policy.json` (`OzBoxKeyAdmin`) grants. This is
/// exactly the create and read-back set of the key module: the `aws_kms_key` row of `ozbox_provider_aws::init_actions` without
/// its update and destroy actions (`UpdateKeyDescription`, `ScheduleKeyDeletion`), plus `kms:CreateAlias` from the alias row
/// (a test holds the equality).
pub const KEY_ACTIONS: [&str; 9] = [
    "kms:CreateKey",
    "kms:CreateAlias",
    "kms:PutKeyPolicy",
    "kms:EnableKeyRotation",
    "kms:TagResource",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
    "kms:GetKeyPolicy",
    "kms:ListResourceTags",
];

/// One policy simulation: some actions, asked against the resources they act on, under the request context the apply sends.
/// A simulation takes one resource list for all its actions, so each resource type is its own request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimRequest {
    pub actions: Vec<&'static str>,
    pub resources: Vec<String>,
    /// `(name, type, values)`, as `--context-entries` takes them.
    pub context: Vec<(&'static str, &'static str, &'static str)>,
}

/// What the real apply sends: the Oz Box tag on every create and tag call, and only Oz Box tag keys. Without these the policy's
/// tag conditions evaluate false and the simulation says "denied" to an identity that is allowed.
const KEY_CONTEXT: [(&str, &str, &str); 3] = [
    ("aws:RequestTag/ozbox-managed", "string", "true"),
    ("aws:ResourceTag/ozbox-managed", "string", "true"),
    ("aws:TagKeys", "stringList", "ozbox-managed"),
];

/// The simulations that ask whether an identity may create the fleet key, each action against its own resource type:
/// `CreateKey` against `*` (a key has no ARN yet), `CreateAlias` against the alias and the key it points at, and every other
/// key action against keys. Pure.
pub fn key_sim_requests(region: &str, account: &str, fleet: &str) -> Vec<SimRequest> {
    let key = format!("arn:aws:kms:{region}:{account}:key/*");
    let alias = format!("arn:aws:kms:{region}:{account}:alias/ozbox-{fleet}-secrets");
    let req = |actions: Vec<&'static str>, resources: Vec<String>| SimRequest {
        actions,
        resources,
        context: KEY_CONTEXT.to_vec(),
    };
    let on_keys: Vec<&'static str> = KEY_ACTIONS
        .iter()
        .copied()
        .filter(|a| *a != "kms:CreateKey" && *a != "kms:CreateAlias")
        .collect();
    vec![
        req(vec!["kms:CreateKey"], vec!["*".into()]),
        req(vec!["kms:CreateAlias"], vec![alias, key.clone()]),
        req(on_keys, vec![key]),
    ]
}

/// The actions the adopt command's document needs: what `infra/aws/adopt-admin-policy.json` (`OzBoxAdoptAdmin`) grants, and
/// exactly the `aws_ssm_document` row of `ozbox_provider_aws::init_actions` (a test holds the two equal, so the check asks for
/// what the apply calls).
/// Systems Manager document actions only; the key's identity (`OzBoxKeyAdmin`) is KMS-only and is never asked for these.
pub const ADOPT_ACTIONS: [&str; 10] = [
    "ssm:CreateDocument",
    "ssm:UpdateDocument",
    "ssm:UpdateDocumentDefaultVersion",
    "ssm:DeleteDocument",
    "ssm:DescribeDocument",
    "ssm:GetDocument",
    "ssm:DescribeDocumentPermission",
    "ssm:AddTagsToResource",
    "ssm:RemoveTagsFromResource",
    "ssm:ListTagsForResource",
];

/// The ARN of the fleet's adopt document in a region and account (`document/ozbox-adopt-<fleet>`).
pub fn adopt_document_arn(region: &str, account: &str, fleet: &str) -> String {
    format!(
        "arn:aws:ssm:{region}:{account}:document/{}",
        ozbox_provider_aws::adopt_document_name(fleet)
    )
}

/// Whether the identity that runs `init` may create the fleet key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPermission {
    Allowed,
    /// These actions are not allowed.
    Denied(Vec<String>),
    /// It could not be checked (the check itself needs `iam:GetRole` and `iam:SimulatePrincipalPolicy`).
    Unknown,
}

/// Read the answer of `iam simulate-principal-policy`: every action must be `allowed`. Pure.
pub fn classify_simulation(json: &str) -> KeyPermission {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return KeyPermission::Unknown;
    };
    let Some(rows) = v.get("EvaluationResults").and_then(Value::as_array) else {
        return KeyPermission::Unknown;
    };
    let denied: Vec<String> = rows
        .iter()
        .filter(|r| r.get("EvalDecision").and_then(Value::as_str) != Some("allowed"))
        .filter_map(|r| r.get("EvalActionName").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    if rows.is_empty() {
        KeyPermission::Unknown
    } else if denied.is_empty() {
        KeyPermission::Allowed
    } else {
        KeyPermission::Denied(denied)
    }
}

/// The role a session of `identity` runs as, as a name, or `None` for anything that is not a role session.
fn session_role_name(arn: &str) -> Option<String> {
    let resource = arn.splitn(6, ':').nth(5)?;
    let role = resource.strip_prefix("assumed-role/")?;
    role.split('/').next().map(str::to_string)
}

/// What the security module already manages, read from its own state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecurityManaged {
    /// The region's GuardDuty detector was made by this module.
    pub detector: bool,
    /// The account's Session Manager preferences were written by this module.
    pub preferences: bool,
}

impl SecurityManaged {
    /// From `tofu state pull`. Pure: an empty or unreadable answer manages nothing.
    pub fn of(state_json: &str) -> Self {
        let v: Value = serde_json::from_str(state_json).unwrap_or(Value::Null);
        let has = |ty: &str, name: &str| {
            v["resources"].as_array().is_some_and(|rs| {
                rs.iter().any(|r| {
                    r["module"] == "module.security"
                        && r["mode"] == "managed"
                        && r["type"] == ty
                        && r["name"] == name
                        && r["instances"].as_array().is_some_and(|i| !i.is_empty())
                })
            })
        };
        Self {
            detector: has("aws_guardduty_detector", "this"),
            preferences: has("aws_ssm_document", "session_preferences"),
        }
    }
}

/// What `ozbox fleet enable` asks of the fleet manager's roles (ADR 0040 §3).
#[derive(Debug, Clone)]
pub struct FleetOpts {
    pub regions: Vec<String>,
    pub machine_types: Vec<String>,
    pub image_ids: Vec<String>,
    pub subnet_ids: Vec<String>,
    pub window_permission_set: String,
    pub fleet_manager_box: String,
    pub max_volume_gb: u32,
    pub max_iops: u32,
    pub max_throughput: u32,
    pub read_costs: bool,
}

/// Which opt-in security services to have on (ADR 0035). The set is the whole desired state: leaving one out plans its
/// removal, which the plan shows.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityOpts {
    pub guardduty_runtime: bool,
    pub session_logs: bool,
    pub patching: bool,
    pub retention_days: u32,
    /// `GOVERNANCE` or `COMPLIANCE` (the one nobody, not even the account root, can undo).
    pub lock_mode: String,
}

impl Default for SecurityOpts {
    fn default() -> Self {
        Self {
            guardduty_runtime: false,
            session_logs: false,
            patching: false,
            retention_days: 365,
            lock_mode: "GOVERNANCE".into(),
        }
    }
}

pub struct Init<'a> {
    pub runner: &'a dyn CommandRunner,
    pub http: &'a dyn HttpClient,
    pub latency: &'a dyn Latency,
    pub paths: InitPaths,
    /// Pause between attempts to download plugins (GitHub's release downloads fail now and then).
    pub retry_delay: Duration,
}

const NAT_USD_MONTH: f64 = 32.85;

impl Init<'_> {
    // ----- running things -----

    fn exec(&self, cmd: &CommandSpec) -> Res<Output> {
        self.runner.run(cmd).map_err(|e| match e {
            ozbox_core::Error::Io(io) if io.kind() == std::io::ErrorKind::NotFound => Finding::new(
                "tool_missing",
                t("init.tool_missing", &[("tool", &cmd.program)]),
            ),
            other => Finding::new("command_failed", other.to_string()),
        })
    }

    fn aws(&self, target: &Target, args: &[&str]) -> CommandSpec {
        let mut c = CommandSpec::new("aws").args(args.iter().copied());
        if let Some(p) = &target.profile {
            c = c.arg("--profile").arg(p);
        }
        if let Some(r) = &target.region {
            c = c.arg("--region").arg(r);
        }
        c.arg("--output").arg("json").arg("--no-cli-pager")
    }

    fn tofu_env(&self, target: &Target, c: CommandSpec) -> CommandSpec {
        let mut c = c
            .env("TF_IN_AUTOMATION", "1")
            .env(
                "TF_PLUGIN_CACHE_DIR",
                self.paths.plugin_cache.display().to_string(),
            )
            .env("AWS_PAGER", "");
        if let Some(p) = &target.profile {
            c = c.env("AWS_PROFILE", p);
        }
        if let Some(r) = &target.region {
            c = c.env("AWS_REGION", r).env("AWS_DEFAULT_REGION", r);
        }
        c
    }

    // ----- sign-in -----

    /// Who is signed in, and whether that is an acceptable identity for daily use. Refuses root and long-lived keys.
    pub fn sign_in(&self, target: &Target) -> Res<Identity> {
        target.validate()?;
        match target.provider.as_str() {
            "aws" => self.aws_sign_in(target),
            "hcloud" => Err(Finding::new("use_hcloud_check", t("init.use_hcloud", &[]))),
            _ => Err(Finding::new("no_sign_in", t("init.fake_no_sign_in", &[]))),
        }
    }

    fn aws_sign_in(&self, target: &Target) -> Res<Identity> {
        let out = self.exec(&self.aws(target, &["sts", "get-caller-identity"]))?;
        if out.status != Some(0) {
            // a version 1 CLI fails here for a reason that has nothing to do with signing in: say so first
            if let Some((v, at)) =
                crate::awscli::v1_in_the_way(self.runner, std::env::var("PATH").ok().as_deref())
            {
                return Err(Finding::new(
                    "aws_cli_v1",
                    crate::awscli::v1_message(&v, at.as_ref()),
                ));
            }
            let profile = target.profile.clone().unwrap_or_else(|| "default".into());
            return Err(Finding::new("not_signed_in", t("init.not_signed_in", &[]))
                .with_fix(t("init.sign_in_fix", &[("profile", &profile)])));
        }
        let id = parse_identity(&out.stdout)?;
        match id.kind {
            IdentityKind::Root => Err(Finding::new("root_refused", t("init.root_refused", &[]))
                .with_fix(t("init.root_fix", &[]))),
            IdentityKind::IamUser => {
                let user = id.user.clone().unwrap_or_default();
                let keys = self
                    .exec(&self.aws(target, &["iam", "list-access-keys", "--user-name", &user]))?;
                let has_keys = keys.status != Some(0)
                    || serde_json::from_str::<Value>(&keys.stdout)
                        .ok()
                        .and_then(|v| {
                            v.get("AccessKeyMetadata")
                                .and_then(Value::as_array)
                                .map(|a| !a.is_empty())
                        })
                        .unwrap_or(true);
                if has_keys {
                    Err(
                        Finding::new("long_lived_keys_refused", t("init.keys_refused", &[]))
                            .with_fix(t("init.keys_fix", &[])),
                    )
                } else {
                    Ok(id)
                }
            }
            _ => Ok(id),
        }
    }

    /// Hetzner: the token is read at call time from the environment and checked with one read-only request.
    pub fn hcloud_sign_in(&self, token: Option<&str>) -> Res<()> {
        let Some(token) = token.filter(|t| !t.is_empty()) else {
            return Err(
                Finding::new("not_signed_in", t("init.hcloud_no_token", &[]))
                    .with_fix(t("init.hcloud_token_fix", &[])),
            );
        };
        let req = HttpRequest::new(
            "GET",
            "https://api.hetzner.cloud/v1/locations",
            Guard::Public,
        )
        .header("Authorization", format!("Bearer {token}"));
        match self.http.send(&req) {
            Ok(r) if r.ok() => Ok(()),
            Ok(r) if r.status == 401 || r.status == 403 => Err(Finding::new(
                "not_signed_in",
                t("init.hcloud_bad_token", &[]),
            )
            .with_fix(t("init.hcloud_token_fix", &[]))),
            _ => Err(Finding::new("unreachable", t("init.unreachable", &[]))),
        }
    }

    /// The Hetzner locations the account can use (names only).
    pub fn hcloud_locations(&self, token: &str) -> Vec<String> {
        let req = HttpRequest::new(
            "GET",
            "https://api.hetzner.cloud/v1/locations",
            Guard::Public,
        )
        .header("Authorization", format!("Bearer {token}"));
        let Ok(r) = self.http.send(&req) else {
            return Vec::new();
        };
        serde_json::from_str::<Value>(&r.body)
            .ok()
            .and_then(|v| {
                v.get("locations").and_then(Value::as_array).map(|a| {
                    a.iter()
                        .filter_map(|l| l.get("name").and_then(Value::as_str).map(str::to_string))
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    // ----- permissions -----

    pub fn permissions(&self, target: &Target) -> Res<PermissionReport> {
        target.validate()?;
        // EC2 permissions are the same in every region, so before a region is chosen a default is used to ask.
        let region = target.region.clone().unwrap_or_else(|| "us-east-1".into());
        let mut target = target.clone();
        target.region = Some(region.clone());
        let target = &target;
        let mut probes = Vec::new();
        // The account names the state bucket. No answer, no bucket probe.
        let who = self.exec(&self.aws(target, &["sts", "get-caller-identity"]))?;
        if who.stderr.contains("ExpiredToken")
            || who.stderr.contains("Unable to locate credentials")
        {
            return Err(Finding::new("not_signed_in", t("init.not_signed_in", &[])));
        }
        let account = parse_identity(&who.stdout)
            .ok()
            .map(|i| i.account)
            .filter(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()));
        for def in probe_defs(&region, account.as_deref()) {
            let argv: Vec<&str> = def.args.iter().map(String::as_str).collect();
            let out = self.exec(&self.aws(target, &argv))?;
            if out.stderr.contains("ExpiredToken")
                || out.stderr.contains("Unable to locate credentials")
            {
                return Err(Finding::new("not_signed_in", t("init.not_signed_in", &[])));
            }
            let (mut state, mut detail) = classify_probe(def.dry, &out);
            if state == ProbeState::Denied {
                detail = Some(grant_hint(&def));
                // a refusal on something the operator policy does not govern is reported, never a stop
                if def.grant == Grant::SetupIdentity {
                    state = ProbeState::Unknown;
                }
            }
            probes.push(Probe {
                id: def.id.into(),
                label: t(def.label, &[]),
                state,
                detail,
            });
        }
        let ok = probes.iter().all(|p| p.state != ProbeState::Denied);
        Ok(PermissionReport { probes, ok })
    }

    // ----- regions -----

    pub fn regions(&self, target: &Target) -> Res<RegionReport> {
        target.validate()?;
        let measured: Vec<(usize, Option<Duration>)> = std::thread::scope(|s| {
            let handles: Vec<_> = AWS_REGIONS
                .iter()
                .enumerate()
                .map(|(i, (r, _))| {
                    let url = format!("https://ec2.{r}.amazonaws.com/");
                    s.spawn(move || (i, self.latency.rtt(&url)))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or((usize::MAX, None)))
                .collect()
        });
        let mut cands: Vec<RegionCandidate> = measured
            .into_iter()
            .filter_map(|(i, d)| {
                AWS_REGIONS.get(i).map(|(r, n)| RegionCandidate {
                    region: (*r).into(),
                    name: (*n).into(),
                    ms: d.map(|d| d.as_millis() as u64),
                    offers_sizes: None,
                })
            })
            .collect();
        // Ask the three fastest whether the sizes exist there (a read-only listing).
        let mut order: Vec<usize> = (0..cands.len()).collect();
        order.sort_by_key(|i| cands[*i].ms.unwrap_or(u64::MAX));
        let types: Vec<String> = [Size::S, Size::M, Size::L, Size::XL]
            .iter()
            .filter_map(|s| ozbox_provider_aws::machine_choice(*s).ok())
            .map(|m| m.machine_type)
            .collect();
        for i in order.into_iter().take(3) {
            if cands[i].ms.is_none() {
                continue;
            }
            let mut t2 = target.clone();
            t2.region = Some(cands[i].region.clone());
            let filter = format!("Name=instance-type,Values={}", types.join(","));
            let out = self.exec(&self.aws(
                &t2,
                &[
                    "ec2",
                    "describe-instance-type-offerings",
                    "--location-type",
                    "region",
                    "--filters",
                    &filter,
                ],
            ))?;
            if out.status == Some(0) {
                let offered: Vec<String> = serde_json::from_str::<Value>(&out.stdout)
                    .ok()
                    .and_then(|v| {
                        v.get("InstanceTypeOfferings")
                            .and_then(Value::as_array)
                            .map(|a| {
                                a.iter()
                                    .filter_map(|o| {
                                        o.get("InstanceType")
                                            .and_then(Value::as_str)
                                            .map(str::to_string)
                                    })
                                    .collect()
                            })
                    })
                    .unwrap_or_default();
                cands[i].offers_sizes = Some(types.iter().all(|t| offered.contains(t)));
            }
        }
        Ok(rank_regions(cands))
    }

    // ----- security -----

    pub fn security(&self, target: &Target, identity: &Identity) -> Res<SecurityReport> {
        let mut items = Vec::new();
        let pass = |id: &str, key: &str| SecurityItem {
            id: id.into(),
            state: CheckState::Pass,
            message: t(key, &[]),
        };
        items.push(if identity.kind == IdentityKind::Root {
            SecurityItem {
                id: "not_root".into(),
                state: CheckState::Fail,
                message: t("init.root_refused", &[]),
            }
        } else {
            pass("not_root", "init.sec_not_root")
        });
        let short = matches!(
            identity.kind,
            IdentityKind::SsoRole | IdentityKind::AssumedRole | IdentityKind::Federated
        );
        items.push(if short {
            pass("short_lived", "init.sec_short_lived")
        } else {
            SecurityItem {
                id: "short_lived".into(),
                state: CheckState::Fail,
                message: t("init.keys_refused", &[]),
            }
        });
        // Two-factor: an IAM user's devices can be listed; for everyone else the sign-in provider decides, which this
        // program cannot see, so the person confirms it.
        let mfa_known = if let (IdentityKind::IamUser, Some(user)) =
            (identity.kind, identity.user.as_deref())
        {
            let out =
                self.exec(&self.aws(target, &["iam", "list-mfa-devices", "--user-name", user]))?;
            (out.status == Some(0))
                .then(|| {
                    serde_json::from_str::<Value>(&out.stdout)
                        .ok()
                        .and_then(|v| {
                            v.get("MFADevices")
                                .and_then(Value::as_array)
                                .map(|a| !a.is_empty())
                        })
                })
                .flatten()
        } else {
            None
        };
        items.push(match mfa_known {
            Some(true) => pass("two_factor", "init.sec_two_factor_ok"),
            _ => SecurityItem {
                id: "two_factor".into(),
                state: CheckState::Reminder,
                message: t("init.sec_two_factor_remind", &[]),
            },
        });
        let blocking = items.iter().any(|i| i.state == CheckState::Fail);
        let needs_ack = items.iter().any(|i| i.state == CheckState::Reminder);
        Ok(SecurityReport {
            items,
            blocking,
            needs_ack,
        })
    }

    // ----- the state bucket -----

    pub fn bucket_name(account: &str, region: &str) -> String {
        format!("ozbox-state-{account}-{region}")
    }

    fn bucket_probe(&self, target: &Target, bucket: &str) -> Res<bool> {
        let out = self.exec(&self.aws(target, &["s3api", "head-bucket", "--bucket", bucket]))?;
        if out.status == Some(0) {
            return Ok(true);
        }
        let e = &out.stderr;
        if e.contains("404") || e.contains("Not Found") || e.contains("NoSuchBucket") {
            return Ok(false);
        }
        if e.contains("403") || e.contains("Forbidden") {
            return Err(Finding::new(
                "bucket_not_ours",
                t("init.bucket_not_ours", &[("bucket", bucket)]),
            ));
        }
        Err(Finding::new(
            "command_failed",
            t("init.bucket_probe_failed", &[]),
        ))
    }

    /// What it takes to have the encrypted, versioned, private bucket that holds the OpenTofu state.
    pub fn plan_bucket(&self, target: &Target, account: &str) -> Res<Prepared> {
        target.validate()?;
        let region = target.region_or_err()?.to_string();
        if account.is_empty() || !account.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Finding::new("bad_answer", t("init.bad_answer", &[])));
        }
        let bucket = Self::bucket_name(account, &region);
        let exists = self.bucket_probe(target, &bucket)?;
        let mut changes = Vec::new();
        let mut run = Vec::new();
        let mut need = |kind: &str, key: &str, cmd: CommandSpec, risk: Risk| {
            changes.push(Change::new(
                kind,
                t(key, &[("bucket", &bucket), ("region", &region)]),
                risk,
            ));
            run.push(cmd);
        };
        let b = bucket.as_str();
        let versioning_on = exists
            && self
                .exec(&self.aws(target, &["s3api", "get-bucket-versioning", "--bucket", b]))?
                .stdout
                .contains("\"Enabled\"");
        let encrypted = exists
            && self
                .exec(&self.aws(target, &["s3api", "get-bucket-encryption", "--bucket", b]))?
                .status
                == Some(0);
        let blocked = exists && {
            let out =
                self.exec(&self.aws(target, &["s3api", "get-public-access-block", "--bucket", b]))?;
            out.status == Some(0)
                && serde_json::from_str::<Value>(&out.stdout)
                    .ok()
                    .and_then(|v| v.get("PublicAccessBlockConfiguration").cloned())
                    .is_some_and(|c| {
                        [
                            "BlockPublicAcls",
                            "IgnorePublicAcls",
                            "BlockPublicPolicy",
                            "RestrictPublicBuckets",
                        ]
                        .iter()
                        .all(|k| c.get(*k).and_then(Value::as_bool) == Some(true))
                    })
        };
        if !exists {
            let mut c = self.aws(target, &["s3api", "create-bucket", "--bucket", b]);
            if region != "us-east-1" {
                let at = c.args.len() - 3;
                c.args.insert(at, format!("LocationConstraint={region}"));
                c.args.insert(at, "--create-bucket-configuration".into());
            }
            need("bucket.create", "init.chg_bucket_create", c, Risk::Medium);
        }
        if !versioning_on {
            need(
                "bucket.versioning",
                "init.chg_bucket_versioning",
                self.aws(
                    target,
                    &[
                        "s3api",
                        "put-bucket-versioning",
                        "--bucket",
                        b,
                        "--versioning-configuration",
                        "Status=Enabled",
                    ],
                ),
                Risk::Low,
            );
        }
        if !encrypted {
            need(
                "bucket.encryption",
                "init.chg_bucket_encryption",
                self.aws(
                    target,
                    &[
                        "s3api",
                        "put-bucket-encryption",
                        "--bucket",
                        b,
                        "--server-side-encryption-configuration",
                        r#"{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}"#,
                    ],
                ),
                Risk::Low,
            );
        }
        if !blocked {
            need(
                "bucket.public_access_block",
                "init.chg_bucket_block",
                self.aws(
                    target,
                    &[
                        "s3api",
                        "put-public-access-block",
                        "--bucket",
                        b,
                        "--public-access-block-configuration",
                        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    ],
                ),
                Risk::Low,
            );
        }
        if !exists {
            let policy = format!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"TlsOnly","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::{bucket}","arn:aws:s3:::{bucket}/*"],"Condition":{{"Bool":{{"aws:SecureTransport":"false"}}}}}}]}}"#
            );
            need(
                "bucket.tls_only",
                "init.chg_bucket_tls",
                self.aws(
                    target,
                    &[
                        "s3api",
                        "put-bucket-policy",
                        "--bucket",
                        b,
                        "--policy",
                        &policy,
                    ],
                ),
                Risk::Low,
            );
        }
        let noop = changes.is_empty();
        Ok(Prepared {
            step: "state_bucket".into(),
            summary: t("init.sum_bucket", &[("bucket", &bucket)]),
            changes,
            notes: vec![t("init.note_bucket_cost", &[])],
            estimate_usd_month: Some(0.0),
            noop,
            run,
            after: After::Bucket(bucket),
        })
    }

    // ----- the plugin cache and the network -----

    fn version_ok(&self, target: &Target) -> Res<()> {
        let out = self.exec(&CommandSpec::new("tofu").args(["version", "-json"]))?;
        let v = serde_json::from_str::<Value>(&out.stdout)
            .ok()
            .and_then(|v| {
                v.get("terraform_version")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .or_else(|| {
                // Older versions print `OpenTofu v1.10.1`.
                out.stdout
                    .split_whitespace()
                    .find_map(|w| w.strip_prefix('v').map(str::to_string))
            })
            .unwrap_or_default();
        let mut it = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
        let (major, minor) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
        let _ = target;
        if (major, minor) < (1, 10) {
            return Err(Finding::new(
                "tofu_too_old",
                t("init.tofu_too_old", &[("version", &v)]),
            ));
        }
        Ok(())
    }

    /// `init` with the plugin cache, retried: GitHub's release downloads fail now and then, and a failed download
    /// should cost a retry, not a failed setup. Writes the lock file next to the module so a later create can verify
    /// the plugin without asking the registry.
    fn init_with_retry(&self, target: &Target, cmd: &CommandSpec) -> Res<()> {
        let _ = std::fs::create_dir_all(&self.paths.plugin_cache);
        let mut last = String::new();
        for attempt in 0..3 {
            if attempt > 0 && !self.retry_delay.is_zero() {
                std::thread::sleep(self.retry_delay * attempt);
            }
            let out = self.exec(&self.tofu_env(target, cmd.clone()))?;
            if out.status == Some(0) {
                return Ok(());
            }
            last = out
                .stderr
                .lines()
                .find(|l| l.contains("rror"))
                .unwrap_or("")
                .trim()
                .chars()
                .take(200)
                .collect();
        }
        Err(Finding::new(
            "plugin_download_failed",
            t("init.plugin_failed", &[("why", &last)]),
        ))
    }

    /// Download the AWS plugin once into the cache and record its checksum beside the box module and the network
    /// module. Local files only.
    pub fn seed_plugins(&self, target: &Target) -> Res<()> {
        for dir in [self.paths.box_dir(), self.paths.network_dir()] {
            if !dir.is_dir() {
                return Err(Finding::new(
                    "module_not_found",
                    t(
                        "init.module_not_found",
                        &[("dir", &dir.display().to_string())],
                    ),
                ));
            }
            let cmd = CommandSpec::new("tofu").args([
                format!("-chdir={}", dir.display()),
                "init".into(),
                "-backend=false".into(),
                "-input=false".into(),
                "-no-color".into(),
            ]);
            self.init_with_retry(target, &cmd)?;
        }
        Ok(())
    }

    fn network_workdir(&self, region: &str) -> PathBuf {
        self.paths.work.join("network").join(region)
    }

    fn write_network_files(&self, bucket: &str, region: &str) -> Res<PathBuf> {
        let module = self.paths.network_dir();
        let module = module.canonicalize().map_err(|_| {
            Finding::new(
                "module_not_found",
                t(
                    "init.module_not_found",
                    &[("dir", &module.display().to_string())],
                ),
            )
        })?;
        let module_s = module.display().to_string();
        if module_s.contains(['"', '\\', '$', '%', '\n', '\r']) {
            return Err(Finding::new("bad_path", t("init.bad_path", &[])));
        }
        let main = format!(
            "terraform {{\n  required_version = \">= 1.10.0\"\n  backend \"s3\" {{}}\n}}\n\nprovider \"aws\" {{\n  region = \"{region}\"\n}}\n\nmodule \"network\" {{\n  source = \"{module_s}\"\n  name   = \"ozbox\"\n  region = \"{region}\"\n}}\n\noutput \"private_subnet_id\" {{\n  value = module.network.private_subnet_id\n}}\n\noutput \"vpc_id\" {{\n  value = module.network.vpc_id\n}}\n"
        );
        let _ = bucket;
        let dir = self.network_workdir(region);
        std::fs::create_dir_all(&dir).map_err(|e| Finding::new("command_failed", e.to_string()))?;
        std::fs::write(dir.join("main.tf"), main)
            .map_err(|e| Finding::new("command_failed", e.to_string()))?;
        Ok(dir)
    }

    /// The private subnet the configuration already names (`[aws] subnet_id`), if it looks like one. When there is one, setup
    /// uses it and plans no network: a second, empty network would cost a NAT gateway for nothing.
    pub fn configured_subnet(&self) -> Option<String> {
        self.recorded("aws")
            .remove("subnet_id")
            .map(|s| s.trim().to_string())
            .filter(|s| s.starts_with("subnet-") && s.len() > "subnet-".len())
    }

    /// Whether the configured subnet exists and this identity can see it (a read-only `describe-subnets`).
    pub fn check_subnet(&self, target: &Target, subnet: &str) -> Res<SubnetState> {
        target.validate()?;
        let out =
            self.exec(&self.aws(target, &["ec2", "describe-subnets", "--subnet-ids", subnet]))?;
        if out.status == Some(0) {
            let listed = serde_json::from_str::<Value>(&out.stdout)
                .ok()
                .and_then(|v| {
                    v.get("Subnets")
                        .and_then(Value::as_array)
                        .map(|a| !a.is_empty())
                })
                .unwrap_or(false);
            return Ok(if listed {
                SubnetState::Found
            } else {
                SubnetState::Missing
            });
        }
        if out.stderr.contains("InvalidSubnetID.NotFound") {
            return Ok(SubnetState::Missing);
        }
        let why: String = out
            .stderr
            .lines()
            .find(|l| l.contains("rror"))
            .unwrap_or("")
            .trim()
            .chars()
            .take(200)
            .collect();
        Ok(SubnetState::Unknown(why))
    }

    /// What it takes to have the private network boxes live in. Needs the state bucket first (the state is kept there).
    pub fn plan_network(&self, target: &Target, account: &str) -> Res<Prepared> {
        target.validate()?;
        let region = target.region_or_err()?.to_string();
        let bucket = Self::bucket_name(account, &region);
        if !self.bucket_probe(target, &bucket)? {
            return Err(Finding::new(
                "bucket_missing",
                t("init.bucket_missing", &[]),
            ));
        }
        self.version_ok(target)?;
        self.seed_plugins(target)?;
        let dir = self.write_network_files(&bucket, &region)?;
        let chdir = format!("-chdir={}", dir.display());
        let key = format!("ozbox/network/{region}.tfstate");
        let init = CommandSpec::new("tofu").args([
            chdir.clone(),
            "init".into(),
            "-input=false".into(),
            "-no-color".into(),
            "-reconfigure".into(),
            format!("-backend-config=bucket={bucket}"),
            format!("-backend-config=key={key}"),
            format!("-backend-config=region={region}"),
            "-backend-config=encrypt=true".into(),
            "-backend-config=use_lockfile=true".into(),
        ]);
        self.init_with_retry(target, &init)?;
        let plan_cmd = CommandSpec::new("tofu").args([
            chdir.clone(),
            "plan".into(),
            "-input=false".into(),
            "-no-color".into(),
            "-detailed-exitcode".into(),
            "-out=ozbox.tfplan".into(),
        ]);
        let out = self.exec(&self.tofu_env(target, plan_cmd))?;
        let changes = match out.status {
            Some(0) => Vec::new(),
            Some(2) => parse_tofu_plan(&out.stdout),
            _ => {
                let why: String = out
                    .stderr
                    .lines()
                    .find(|l| l.contains("rror"))
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .take(200)
                    .collect();
                return Err(Finding::new(
                    "plan_failed",
                    t("init.plan_failed", &[("why", &why)]),
                ));
            }
        };
        let noop = changes.is_empty();
        let apply = self.tofu_env(
            target,
            CommandSpec::new("tofu").args([
                chdir,
                "apply".into(),
                "-input=false".into(),
                "-no-color".into(),
                "ozbox.tfplan".into(),
            ]),
        );
        Ok(Prepared {
            step: "network".into(),
            summary: t("init.sum_network", &[("region", &region)]),
            changes,
            notes: vec![
                t("init.note_network_cost", &[]),
                t("init.note_plugins", &[]),
            ],
            estimate_usd_month: Some(NAT_USD_MONTH),
            noop,
            run: if noop { Vec::new() } else { vec![apply] },
            after: After::Network(dir),
        })
    }

    /// Whether this identity may create the fleet key, asked without changing anything: the role's own ARN, then a policy
    /// simulation for the key's actions. Neither call can create or change a resource.
    pub fn key_permission(&self, target: &Target, identity: &Identity) -> KeyPermission {
        let requests = match target.region_or_err() {
            Ok(region) => key_sim_requests(region, &identity.account, &self.fleet_name()),
            Err(_) => return KeyPermission::Unknown,
        };
        self.permission_for(target, identity, &requests)
    }

    /// Whether this identity may make the adopt command's document (the same two read-only calls, for `ADOPT_ACTIONS`).
    pub fn adopt_permission(&self, target: &Target, identity: &Identity) -> KeyPermission {
        let resources = match target.region_or_err() {
            Ok(region) => vec![adopt_document_arn(
                region,
                &identity.account,
                &self.fleet_name(),
            )],
            Err(_) => return KeyPermission::Unknown,
        };
        let request = SimRequest {
            actions: ADOPT_ACTIONS.to_vec(),
            resources,
            context: Vec::new(),
        };
        self.permission_for(target, identity, &[request])
    }

    /// The complete operator policy for this account, region and fleet, written next to the other plans for an administrator to
    /// apply, and a read-only check of whether the daily sign-in already has the statements the adopt commands need.
    ///
    /// Setup never applies it: the setup identity has no right over the operator's permissions (it could otherwise widen
    /// them), and the daily role is usually a permission set that only an administrator edits. So the file is written on EVERY
    /// run, not only when the adopt step changed something, and a daily sign-in that lacks the statements is named.
    pub fn operator_policy(&self, target: &Target, account: &str) -> Res<OperatorPolicyReport> {
        let region = target.region_or_err()?.to_string();
        let fleet = self.fleet_name();
        let policy = operator_policy::render(account, &region, &fleet)
            .map_err(|e| Finding::new("operator_policy", e))?;
        let dir = self.paths.work.join("operator-policy").join(&region);
        std::fs::create_dir_all(&dir).map_err(|e| Finding::new("command_failed", e.to_string()))?;
        let file = dir.join("operator-policy.json");
        let text = serde_json::to_string_pretty(&policy)
            .map_err(|e| Finding::new("operator_policy", e.to_string()))?;
        std::fs::write(&file, format!("{text}\n"))
            .map_err(|e| Finding::new("command_failed", e.to_string()))?;
        let adopt = operator_policy::statements_named(&policy, &operator_policy::ADOPT_STATEMENTS);
        let operator_check = match self.recorded("aws").get("profile") {
            None => OperatorCheck::NotChecked,
            Some(profile) => {
                let as_operator = Target {
                    provider: target.provider.clone(),
                    profile: Some(profile.clone()),
                    region: target.region.clone(),
                };
                // A read of a command that does not exist: the answer is "not found" when the sign-in may ask and a refusal
                // when it may not, and nothing is sent or changed either way.
                match self.exec(&self.aws(
                    &as_operator,
                    &[
                        "ssm",
                        "get-command-invocation",
                        "--command-id",
                        "00000000-0000-0000-0000-000000000000",
                        "--instance-id",
                        "i-00000000000000000",
                    ],
                )) {
                    Ok(out) => classify_operator_check(&out),
                    Err(_) => OperatorCheck::Unknown,
                }
            }
        };
        Ok(OperatorPolicyReport {
            file: file.display().to_string(),
            region,
            fleet,
            added_statements: operator_policy::ADOPT_STATEMENTS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            adopt_statements: adopt,
            operator_check,
        })
    }

    /// The fleet's name as recorded in the config (`ozbox` until one is chosen), the same way the plans read it.
    fn fleet_name(&self) -> String {
        self.recorded("aws")
            .get("fleet")
            .cloned()
            .unwrap_or_else(|| "ozbox".into())
    }

    /// Read-only calls: the role's own ARN, then one policy simulation per request. A simulation with no resource ARN is run
    /// against `*`, which a statement scoped to a resource does not match, so the resources are always given. Any action
    /// denied is denied; a request that could not run makes the answer unknown unless something was already denied.
    fn permission_for(
        &self,
        target: &Target,
        identity: &Identity,
        requests: &[SimRequest],
    ) -> KeyPermission {
        let Some(role) = session_role_name(&identity.arn) else {
            return KeyPermission::Unknown;
        };
        let get = self.aws(
            target,
            &[
                "iam",
                "get-role",
                "--role-name",
                &role,
                "--query",
                "Role.Arn",
                "--output",
                "text",
            ],
        );
        let Ok(o) = self.exec(&get) else {
            return KeyPermission::Unknown;
        };
        let arn = o.stdout.trim().to_string();
        if o.status != Some(0) || !arn.starts_with("arn:") {
            return KeyPermission::Unknown;
        }
        let mut denied: Vec<String> = Vec::new();
        let mut unknown = false;
        for r in requests {
            let entries: Vec<String> = r
                .context
                .iter()
                .map(|(n, ty, v)| {
                    format!("ContextKeyName={n},ContextKeyValues={v},ContextKeyType={ty}")
                })
                .collect();
            let mut args = vec![
                "iam",
                "simulate-principal-policy",
                "--policy-source-arn",
                arn.as_str(),
                "--action-names",
            ];
            args.extend(r.actions.iter().copied());
            args.push("--resource-arns");
            args.extend(r.resources.iter().map(String::as_str));
            if !entries.is_empty() {
                args.push("--context-entries");
                args.extend(entries.iter().map(String::as_str));
            }
            args.extend(["--output", "json"]);
            match self.exec(&self.aws(target, &args)) {
                Ok(o) if o.status == Some(0) => match classify_simulation(&o.stdout) {
                    KeyPermission::Allowed => {}
                    KeyPermission::Denied(d) => {
                        for a in d {
                            if !denied.contains(&a) {
                                denied.push(a);
                            }
                        }
                    }
                    KeyPermission::Unknown => unknown = true,
                },
                _ => unknown = true,
            }
        }
        if !denied.is_empty() {
            KeyPermission::Denied(denied)
        } else if unknown || requests.is_empty() {
            KeyPermission::Unknown
        } else {
            KeyPermission::Allowed
        }
    }

    fn module_root(&self, module: &Path, dir: &Path, body: &str) -> Res<()> {
        let module = module.canonicalize().map_err(|_| {
            Finding::new(
                "module_not_found",
                t(
                    "init.module_not_found",
                    &[("dir", &module.display().to_string())],
                ),
            )
        })?;
        let module_s = module.display().to_string();
        if module_s.contains(['"', '\\', '$', '%', '\n', '\r']) {
            return Err(Finding::new("bad_path", t("init.bad_path", &[])));
        }
        let region = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let text = format!(
            "terraform {{\n  required_version = \">= 1.10.0\"\n  backend \"s3\" {{}}\n}}\n\nprovider \"aws\" {{\n  region = \"{region}\"\n}}\n\n{}",
            body.replace("@MODULE@", &module_s)
        );
        std::fs::create_dir_all(dir).map_err(|e| Finding::new("command_failed", e.to_string()))?;
        std::fs::write(dir.join("main.tf"), text)
            .map_err(|e| Finding::new("command_failed", e.to_string()))
    }

    /// Plan one more module into the state bucket: the same steps as the network's (init with the bucket as backend, plan,
    /// nothing applied until the person agrees).
    #[allow(clippy::too_many_arguments)]
    fn plan_state_module(
        &self,
        target: &Target,
        account: &str,
        step: &str,
        dir: PathBuf,
        state_key: &str,
        summary: String,
        mut notes: Vec<String>,
        after: After,
        adoptables: Vec<adopt::Adoptable>,
    ) -> Res<Prepared> {
        let region = target.region_or_err()?.to_string();
        let bucket = Self::bucket_name(account, &region);
        if !self.bucket_probe(target, &bucket)? {
            return Err(Finding::new(
                "bucket_missing",
                t("init.bucket_missing", &[]),
            ));
        }
        self.version_ok(target)?;
        let chdir = format!("-chdir={}", dir.display());
        let init = CommandSpec::new("tofu").args([
            chdir.clone(),
            "init".into(),
            "-input=false".into(),
            "-no-color".into(),
            "-reconfigure".into(),
            format!("-backend-config=bucket={bucket}"),
            format!("-backend-config=key={state_key}"),
            format!("-backend-config=region={region}"),
            "-backend-config=encrypt=true".into(),
            "-backend-config=use_lockfile=true".into(),
        ]);
        self.init_with_retry(target, &init)?;
        // What already exists in the account and is not in this step's state is adopted, not re-created (ADR 0053).
        let adopted = if adoptables.is_empty() {
            Vec::new()
        } else {
            let in_state = self.state_addresses(target, &chdir)?;
            self.find_adoptions(target, account, &adoptables, &in_state)?
        };
        adopt::write_imports(&dir, &adopted)?;
        let plan_cmd = CommandSpec::new("tofu").args([
            chdir.clone(),
            "plan".into(),
            "-input=false".into(),
            "-no-color".into(),
            "-detailed-exitcode".into(),
            "-out=ozbox.tfplan".into(),
        ]);
        let out = self.exec(&self.tofu_env(target, plan_cmd))?;
        let mut changes: Vec<Change> = adopted.iter().map(adopt::Adopted::change).collect();
        match out.status {
            Some(0) => {}
            Some(2) => {
                adopt::refuse_replacing(&adopted, &plan_entries(&out.stdout))?;
                changes.extend(parse_tofu_plan(&out.stdout));
            }
            _ => {
                let why: String = out
                    .stderr
                    .lines()
                    .find(|l| l.contains("rror"))
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .take(200)
                    .collect();
                return Err(Finding::new(
                    "plan_failed",
                    t("init.plan_failed", &[("why", &why)]),
                ));
            }
        }
        if !adopted.is_empty() {
            notes.push(t("init.note_adopted", &[]));
        }
        // an import is a change even when nothing else differs: applying is what records the resource in the state
        let noop = changes.is_empty();
        let apply = self.tofu_env(
            target,
            CommandSpec::new("tofu").args([
                chdir,
                "apply".into(),
                "-input=false".into(),
                "-no-color".into(),
                "ozbox.tfplan".into(),
            ]),
        );
        Ok(Prepared {
            step: step.into(),
            summary,
            changes,
            notes,
            estimate_usd_month: Some(1.0),
            noop,
            run: if noop { Vec::new() } else { vec![apply] },
            after,
        })
    }

    /// The fleet manager's two roles (`aws-fleet-manager`, ADR 0040), made ONCE with an administrator's sign-in: the module
    /// creates roles and policies under `/obx/`, which the daily operator is denied on purpose. Every value is checked by the
    /// same renderer the policy tests use before it is written into the module's root (so a value cannot carry a quote or a
    /// placeholder into the file). Nothing here changes a box, opens a port or makes a key.
    pub fn plan_fleet_manager(
        &self,
        target: &Target,
        account: &str,
        o: &FleetOpts,
    ) -> Res<Prepared> {
        target.validate()?;
        let region = target.region_or_err()?.to_string();
        let vars = ozbox_provider_aws::fleet_policy::FleetVars {
            account_id: account.to_string(),
            regions: o.regions.clone(),
            sizes: o.machine_types.clone(),
            image_ids: o.image_ids.clone(),
            max_volume_gb: o.max_volume_gb,
            max_iops: o.max_iops,
            max_throughput: o.max_throughput,
            window_principal_arn: format!(
                "arn:aws:iam::{account}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_{}_*",
                o.window_permission_set
            ),
            subnet_ids: o.subnet_ids.clone(),
            fleet_manager_box: o.fleet_manager_box.clone(),
        };
        for d in ozbox_provider_aws::fleet_policy::Doc::ALL {
            ozbox_provider_aws::fleet_policy::render(d, &vars)
                .map_err(|m| Finding::new("fleet_bad_value", m))?;
        }
        let list = |v: &[String]| serde_json::to_string(v).unwrap_or_else(|_| "[]".into());
        let dir = self.paths.work.join("fleet-manager").join(&region);
        self.module_root(
            &self.paths.fleet_manager_dir(),
            &dir,
            &format!(
                "module \"fleet\" {{\n  source                = \"@MODULE@\"\n  regions               = {}\n  machine_types         = {}\n  image_ids             = {}\n  subnet_ids            = {}\n  max_volume_gb         = {}\n  max_iops              = {}\n  max_throughput        = {}\n  window_permission_set = \"{}\"\n  read_costs            = {}\n  fleet_manager_box     = \"{}\"\n}}\n\noutput \"change_role_arn\" {{\n  value = module.fleet.change_role_arn\n}}\n",
                list(&o.regions),
                list(&o.machine_types),
                list(&o.image_ids),
                list(&o.subnet_ids),
                o.max_volume_gb,
                o.max_iops,
                o.max_throughput,
                o.window_permission_set,
                o.read_costs,
                o.fleet_manager_box,
            ),
        )?;
        let mut p = self.plan_state_module(
            target,
            account,
            "fleet_manager",
            dir,
            // one pair of roles for the account, so one state, whatever the region
            "ozbox/fleet-manager/account.tfstate",
            t("init.sum_fleet_manager", &[]),
            vec![t("init.note_fleet_manager", &[])],
            After::Nothing,
            Vec::new(),
        )?;
        p.estimate_usd_month = Some(0.0);
        Ok(p)
    }

    /// The account's Session Manager policy for boxes (the `aws-box-policy` module), made ONCE with the setup identity: the
    /// operator role may attach it to a box's role by its ARN and cannot create or change a policy, so a box's role is never
    /// widened from the daily role. It replaces AWS's AmazonSSMManagedInstanceCore, which reads every parameter in the
    /// account (ADR 0029, Amendment 9). Needs `OzBoxPolicyAdmin` (`infra/aws/box-policy-admin-policy.json`).
    pub fn plan_box_policy(&self, target: &Target, account: &str) -> Res<Prepared> {
        target.validate()?;
        let region = target.region_or_err()?.to_string();
        // what is recorded so far: the fleet's key (`ozbox init` makes it first) and the session-log bucket (`ozbox harden`). A
        // policy for a key or a bucket that does not exist yet is not made; running `ozbox init` again adds it.
        let rec = self.recorded("aws");
        let mut extra = String::new();
        // what the module makes for this configuration, so only those policies are looked for in the account
        let mut adoptables = vec![
            adopt::Adoptable {
                address: "module.policy.aws_iam_policy.session".into(),
                what: "IAM policy",
                find: adopt::Find::IamPolicy {
                    name: "ozbox-box-session-manager".into(),
                },
            },
            adopt::Adoptable {
                address: "module.policy.aws_iam_policy.parameters".into(),
                what: "IAM policy",
                find: adopt::Find::IamPolicy {
                    name: "ozbox-box-parameters".into(),
                },
            },
        ];
        let ok_word = |v: &str| !v.is_empty() && !v.contains(['"', '\\', '$', '%', '\n', '\r']);
        if let (Some(arn), Some(fleet)) = (rec.get("secrets_key_arn"), rec.get("fleet")) {
            if ok_word(arn) && ok_word(fleet) {
                extra.push_str(&format!(
                    "  fleet_key_arn = \"{arn}\"\n  fleet         = \"{fleet}\"\n"
                ));
                // a counted resource: its address carries the index
                adoptables.push(adopt::Adoptable {
                    address: "module.policy.aws_iam_policy.fleet_key[0]".into(),
                    what: "IAM policy",
                    find: adopt::Find::IamPolicy {
                        name: format!("ozbox-box-fleet-key-{fleet}"),
                    },
                });
            }
        }
        if let Some(b) = rec.get("session_log_bucket").filter(|b| ok_word(b)) {
            extra.push_str(&format!("  session_log_bucket = \"{b}\"\n"));
            adoptables.push(adopt::Adoptable {
                address: "module.policy.aws_iam_policy.session_logs[0]".into(),
                what: "IAM policy",
                find: adopt::Find::IamPolicy {
                    name: "ozbox-box-session-logs".into(),
                },
            });
        }
        let dir = self.paths.work.join("box-policy").join(&region);
        self.module_root(
            &self.paths.box_policy_dir(),
            &dir,
            &format!(
                "module \"policy\" {{\n  source = \"@MODULE@\"\n{extra}}}\n\noutput \"policy_arn\" {{\n  value = module.policy.policy_arn\n}}\n"
            ),
        )?;
        let mut p = self.plan_state_module(
            target,
            account,
            "box_policy",
            dir.clone(),
            // one policy for the account, so one state, whatever the region
            "ozbox/box-policy/account.tfstate",
            t("init.sum_box_policy", &[]),
            vec![t("init.note_box_policy", &[])],
            After::Nothing,
            adoptables,
        )?;
        p.estimate_usd_month = Some(0.0);
        Ok(p)
    }

    /// The fleet's secrets key (the `aws-secrets-key` module): one key, its alias `alias/ozbox-<fleet>-secrets`, rotation on.
    /// No operator role is given any right to it, so nothing here widens what the daily role can do. Created with the identity
    /// that runs `init`, with its state in the encrypted bucket like the other steps.
    pub fn plan_key(&self, target: &Target, account: &str) -> Res<Prepared> {
        target.validate()?;
        let region = target.region_or_err()?.to_string();
        let fleet = self
            .recorded("aws")
            .get("fleet")
            .cloned()
            .unwrap_or_else(|| "ozbox".into());
        let alias = format!("alias/ozbox-{fleet}-secrets");
        let dir = self.paths.work.join("secrets-key").join(&region);
        self.module_root(
            &self.paths.key_dir(),
            &dir,
            &format!(
                "module \"key\" {{\n  source     = \"@MODULE@\"\n  name       = \"{fleet}\"\n  account_id = \"{account}\"\n}}\n\noutput \"key_arn\" {{\n  value = module.key.key_arn\n}}\n\noutput \"fleet\" {{\n  value = module.key.fleet\n}}\n"
            ),
        )?;
        self.plan_state_module(
            target,
            account,
            "secrets_key",
            dir,
            &format!("ozbox/secrets-key/{region}.tfstate"),
            t("init.sum_key", &[("fleet", &fleet), ("region", &region)]),
            vec![t("init.note_key", &[("fleet", &fleet)])],
            After::Key(self.paths.work.join("secrets-key").join(&region)),
            vec![
                adopt::Adoptable {
                    address: "module.key.aws_kms_key.secrets".into(),
                    what: "KMS key",
                    find: adopt::Find::KmsKey {
                        alias: alias.clone(),
                        recorded_arn: self.recorded("aws").get("secrets_key_arn").cloned(),
                    },
                },
                adopt::Adoptable {
                    address: "module.key.aws_kms_alias.secrets".into(),
                    what: "KMS alias",
                    find: adopt::Find::KmsAlias { alias },
                },
            ],
        )
    }

    /// The adopt command's Systems Manager document and the operator policy for it (the `aws-adopt-command` module), a step of
    /// its own: it needs the `OzBoxAdoptAdmin` permission set, not the key's KMS-only one. Its state is its own too.
    pub fn plan_adopt(&self, target: &Target, account: &str) -> Res<Prepared> {
        target.validate()?;
        let region = target.region_or_err()?.to_string();
        let fleet = self.fleet_name();
        let dir = self.paths.work.join("adopt-command").join(&region);
        self.module_root(
            &self.paths.adopt_dir(),
            &dir,
            &format!(
                "module \"adopt\" {{\n  source     = \"@MODULE@\"\n  name       = \"{fleet}\"\n  account_id = \"{account}\"\n}}\n\noutput \"operator_adopt_policy_json\" {{\n  value = module.adopt.operator_adopt_policy_json\n}}\n"
            ),
        )?;
        self.plan_state_module(
            target,
            account,
            "adopt_command",
            dir.clone(),
            &format!("ozbox/adopt-command/{region}.tfstate"),
            t("init.sum_adopt", &[("fleet", &fleet), ("region", &region)]),
            vec![t("init.note_adopt", &[("fleet", &fleet)])],
            After::Adopt(dir),
            vec![adopt::Adoptable {
                address: "module.adopt.aws_ssm_document.adopt".into(),
                what: "Systems Manager document",
                find: adopt::Find::SsmDocument {
                    name: format!("ozbox-adopt-{fleet}"),
                },
            }],
        )
    }

    /// The off-box issuer (the `aws-issuer` module) for Production secrets, from a package the person built and named. Shown,
    /// approved and recorded the same way. Needs the fleet's name; nothing is created without the person's approval.
    pub fn plan_issuer(
        &self,
        target: &Target,
        account: &str,
        package: &Path,
        expected_sha256: &str,
    ) -> Res<Prepared> {
        target.validate()?;
        let region = target.region_or_err()?.to_string();
        let fleet = self
            .recorded("aws")
            .get("fleet")
            .cloned()
            .unwrap_or_else(|| "ozbox".into());
        let bytes = std::fs::read(package).map_err(|_| {
            Finding::new(
                "issuer_package",
                t(
                    "init.issuer_package",
                    &[("path", &package.display().to_string())],
                ),
            )
        })?;
        // The hash the person gave (from the signed release's manifest or a reproducible build), never one made from this file:
        // a hash of the file itself proves nothing about the file. A mismatch refuses before anything is planned.
        let given = expected_sha256.trim().to_ascii_lowercase();
        let given_raw: Vec<u8> =
            if given.len() == 64 && given.bytes().all(|b| b.is_ascii_hexdigit()) {
                (0..32)
                    .filter_map(|i| u8::from_str_radix(&given[2 * i..2 * i + 2], 16).ok())
                    .collect()
            } else {
                Vec::new()
            };
        if given_raw.len() != 32 {
            return Err(Finding::new(
                "issuer_hash",
                t("init.issuer_hash_needed", &[]),
            ));
        }
        let actual = ring::digest::digest(&ring::digest::SHA256, &bytes);
        if actual.as_ref() != given_raw.as_slice() {
            return Err(Finding::new(
                "issuer_hash",
                t("init.issuer_hash_mismatch", &[]),
            ));
        }
        let sha = crate::serve::auth::b64::encode_std(&given_raw);
        let package_s = package
            .canonicalize()
            .unwrap_or_else(|_| package.to_path_buf())
            .display()
            .to_string();
        if package_s.contains(['"', '\\', '$', '%', '\n', '\r']) {
            return Err(Finding::new("bad_path", t("init.bad_path", &[])));
        }
        let dir = self.paths.work.join("issuer").join(&region);
        self.module_root(
            &self.paths.issuer_dir(),
            &dir,
            &format!(
                "module \"issuer\" {{\n  source         = \"@MODULE@\"\n  name           = \"{fleet}\"\n  account_id     = \"{account}\"\n  region         = \"{region}\"\n  package_path   = \"{package_s}\"\n  package_sha256 = \"{sha}\"\n}}\n\noutput \"function_url\" {{\n  value = module.issuer.function_url\n}}\n\noutput \"function_arn\" {{\n  value = module.issuer.function_arn\n}}\n"
            ),
        )?;
        self.plan_state_module(
            target,
            account,
            "issuer",
            dir.clone(),
            &format!("ozbox/issuer/{region}.tfstate"),
            t("init.sum_issuer", &[("fleet", &fleet), ("region", &region)]),
            vec![t("init.note_issuer", &[])],
            After::Issuer(dir),
            // the issuer is not adopted yet (ADR 0053: its roles live in the reserved namespace and need an administrator)
            Vec::new(),
        )
    }

    // ----- the opt-in security services -----

    fn security_workdir(&self, region: &str) -> PathBuf {
        self.paths.work.join("security").join(region)
    }

    /// The GuardDuty detector this region already has, if any (there is at most one). Read-only.
    fn guardduty_detector(&self, target: &Target) -> Res<Option<String>> {
        let out = self.exec(&self.aws(target, &["guardduty", "list-detectors"]))?;
        if out.status != Some(0) {
            return Ok(None);
        }
        Ok(serde_json::from_str::<Value>(&out.stdout)
            .ok()
            .and_then(|v| {
                v["DetectorIds"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }))
    }

    /// Whether the account's Session Manager preferences document exists already. Read-only.
    fn session_preferences_exist(&self, target: &Target) -> Res<bool> {
        let out = self.exec(&self.aws(
            target,
            &[
                "ssm",
                "describe-document",
                "--name",
                "SSM-SessionManagerRunShell",
            ],
        ))?;
        Ok(out.status == Some(0))
    }

    /// What the security module's own state (in the bucket) already holds: a detector and preferences it created stay its
    /// own. An empty answer (no state yet) holds nothing. Read-only (`tofu state pull`).
    fn security_managed(&self, target: &Target, chdir: &str) -> Res<SecurityManaged> {
        let out = self.exec(&self.tofu_env(
            target,
            CommandSpec::new("tofu").args([chdir, "state", "pull"]),
        ))?;
        if out.status != Some(0) {
            return Err(Finding::new(
                "plan_failed",
                t(
                    "init.security_plan_failed",
                    &[("why", "the module's state could not be read")],
                ),
            ));
        }
        Ok(SecurityManaged::of(&out.stdout))
    }

    fn write_security_files(
        &self,
        region: &str,
        account: &str,
        o: &SecurityOpts,
        detector: Option<&str>,
        manage_prefs: bool,
    ) -> Res<PathBuf> {
        let module = self.paths.security_dir();
        let module = module.canonicalize().map_err(|_| {
            Finding::new(
                "module_not_found",
                t(
                    "init.module_not_found",
                    &[("dir", &module.display().to_string())],
                ),
            )
        })?;
        let module_s = module.display().to_string();
        if module_s.contains(['"', '\\', '$', '%', '\n', '\r']) {
            return Err(Finding::new("bad_path", t("init.bad_path", &[])));
        }
        if !matches!(o.lock_mode.as_str(), "GOVERNANCE" | "COMPLIANCE")
            || !(1..=3650).contains(&o.retention_days)
        {
            return Err(Finding::new(
                "bad_security_option",
                t("init.bad_security_option", &[]),
            ));
        }
        let detector_line = detector.map_or(String::new(), |d| {
            if d.bytes().all(|b| b.is_ascii_alphanumeric()) {
                format!("  existing_guardduty_detector_id = \"{d}\"\n")
            } else {
                String::new()
            }
        });
        let main = format!(
            "terraform {{\n  required_version = \">= 1.10.0\"\n  backend \"s3\" {{}}\n}}\n\nprovider \"aws\" {{\n  region = \"{region}\"\n}}\n\nmodule \"security\" {{\n  source = \"{module_s}\"\n  account_id = \"{account}\"\n  region = \"{region}\"\n  enable_guardduty_runtime = {gd}\n{detector_line}  enable_session_logs = {sl}\n  session_log_retention_days = {days}\n  session_log_retention_mode = \"{mode}\"\n  manage_session_preferences = {prefs}\n  enable_patching = {pt}\n}}\n\noutput \"session_log_bucket\" {{\n  value = module.security.session_log_bucket\n}}\n\noutput \"patch_group\" {{\n  value = module.security.patch_group\n}}\n",
            gd = o.guardduty_runtime,
            sl = o.session_logs,
            days = o.retention_days,
            mode = o.lock_mode,
            prefs = manage_prefs,
            pt = o.patching,
        );
        let dir = self.security_workdir(region);
        std::fs::create_dir_all(&dir).map_err(|e| Finding::new("command_failed", e.to_string()))?;
        std::fs::write(dir.join("main.tf"), main)
            .map_err(|e| Finding::new("command_failed", e.to_string()))?;
        Ok(dir)
    }

    /// What it takes to have the chosen security services: GuardDuty Runtime Monitoring, the locked session-log bucket with
    /// Session Manager logging to it, and Patch Manager. Plan first, like the network: nothing is created until the plan is
    /// confirmed, and the plan shows what each costs. Needs the state bucket (the state is kept there).
    pub fn plan_security(&self, target: &Target, account: &str, o: &SecurityOpts) -> Res<Prepared> {
        target.validate()?;
        let region = target.region_or_err()?.to_string();
        let bucket = Self::bucket_name(account, &region);
        if !self.bucket_probe(target, &bucket)? {
            return Err(Finding::new(
                "bucket_missing",
                t("init.bucket_missing", &[]),
            ));
        }
        self.version_ok(target)?;
        let seed = self.paths.security_dir();
        if !seed.is_dir() {
            return Err(Finding::new(
                "module_not_found",
                t(
                    "init.module_not_found",
                    &[("dir", &seed.display().to_string())],
                ),
            ));
        }
        self.init_with_retry(
            target,
            &CommandSpec::new("tofu").args([
                format!("-chdir={}", seed.display()),
                "init".into(),
                "-backend=false".into(),
                "-input=false".into(),
                "-no-color".into(),
            ]),
        )?;
        // The root is written once with no answers yet, so its backend can be opened and the module's own state read: what
        // this module already manages decides the inputs before any live API is asked. Asking first is what made a second
        // run plan to destroy what the first created (its detector looked like "an existing one", its preferences like
        // "someone else's").
        let dir = self.write_security_files(&region, account, o, None, true)?;
        let chdir = format!("-chdir={}", dir.display());
        let init = CommandSpec::new("tofu").args([
            chdir.clone(),
            "init".into(),
            "-input=false".into(),
            "-no-color".into(),
            "-reconfigure".into(),
            format!("-backend-config=bucket={bucket}"),
            format!("-backend-config=key=ozbox/security/{region}.tfstate"),
            format!("-backend-config=region={region}"),
            "-backend-config=encrypt=true".into(),
            "-backend-config=use_lockfile=true".into(),
        ]);
        self.init_with_retry(target, &init)?;
        let managed = self.security_managed(target, &chdir)?;
        let detector = if o.guardduty_runtime && !managed.detector {
            self.guardduty_detector(target)?
        } else {
            None
        };
        // The account's Session Manager preferences are one document. An existing one is left alone (and said so): writing
        // over what is there would change how every session in the account behaves, not only an Oz Box's. One this module
        // made is its own, and stays managed.
        let prefs_exist =
            o.session_logs && !managed.preferences && self.session_preferences_exist(target)?;
        self.write_security_files(&region, account, o, detector.as_deref(), !prefs_exist)?;
        let out = self.exec(&self.tofu_env(
            target,
            CommandSpec::new("tofu").args([
                chdir.clone(),
                "plan".into(),
                "-input=false".into(),
                "-no-color".into(),
                "-detailed-exitcode".into(),
                "-out=ozbox.tfplan".into(),
            ]),
        ))?;
        let changes = match out.status {
            Some(0) => Vec::new(),
            Some(2) => parse_tofu_plan(&out.stdout),
            _ => {
                let why: String = out
                    .stderr
                    .lines()
                    .find(|l| l.contains("rror"))
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .take(200)
                    .collect();
                return Err(Finding::new(
                    "plan_failed",
                    t("init.security_plan_failed", &[("why", &why)]),
                ));
            }
        };
        let noop = changes.is_empty();
        let mut notes = vec![t("init.note_security_plugins", &[])];
        if o.guardduty_runtime {
            notes.push(t("init.note_guardduty_cost", &[]));
            if detector.is_some() {
                notes.push(t("init.note_guardduty_existing", &[]));
            }
        }
        if o.session_logs {
            notes.push(t(
                if o.lock_mode == "COMPLIANCE" {
                    "init.note_logs_compliance"
                } else {
                    "init.note_logs_governance"
                },
                &[("days", &o.retention_days.to_string())],
            ));
            if prefs_exist {
                notes.push(t(
                    "init.note_prefs_exist",
                    &[("bucket", &format!("ozbox-sessionlogs-{account}-{region}"))],
                ));
            }
        }
        if o.patching {
            notes.push(t("init.note_patching", &[]));
        }
        if changes.iter().any(|c| c.risk == Risk::High) {
            notes.push(t("init.note_security_removal", &[]));
        }
        let apply = self.tofu_env(
            target,
            CommandSpec::new("tofu").args([
                chdir,
                "apply".into(),
                "-input=false".into(),
                "-no-color".into(),
                "ozbox.tfplan".into(),
            ]),
        );
        Ok(Prepared {
            step: "security".into(),
            summary: t("init.sum_security", &[("region", &region)]),
            changes,
            notes,
            // GuardDuty bills per vCPU of monitored machines and the bucket by what is stored: neither is a fixed figure
            estimate_usd_month: None,
            noop,
            run: if noop { Vec::new() } else { vec![apply] },
            after: After::Security(dir),
        })
    }

    // ----- applying -----

    /// Run exactly what the plan listed, then record the result in the configuration.
    pub fn apply(&self, target: &Target, prepared: &Prepared) -> Res<Applied> {
        target.validate()?;
        let mut applied = Applied {
            step: prepared.step.clone(),
            ..Applied::default()
        };
        for cmd in &prepared.run {
            let out = self.exec(cmd)?;
            if out.status != Some(0) {
                let why: String = out.stderr.trim().chars().take(300).collect();
                return Err(Finding::new(
                    "apply_failed",
                    t("init.apply_failed", &[("why", &why)]),
                ));
            }
        }
        match &prepared.after {
            After::Nothing => {}
            After::Bucket(b) => {
                self.persist(target, &[("state_bucket", b)])?;
                applied.bucket = Some(b.clone());
            }
            After::Network(dir) => {
                let out = self.exec(&self.tofu_env(
                    target,
                    CommandSpec::new("tofu").args([
                        format!("-chdir={}", dir.display()),
                        "output".into(),
                        "-json".into(),
                    ]),
                ))?;
                let subnet = serde_json::from_str::<Value>(&out.stdout)
                    .ok()
                    .and_then(|v| {
                        v.pointer("/private_subnet_id/value")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .ok_or_else(|| Finding::new("bad_answer", t("init.bad_answer", &[])))?;
                if !subnet.starts_with("subnet-") {
                    return Err(Finding::new("bad_answer", t("init.bad_answer", &[])));
                }
                self.persist(target, &[("subnet_id", &subnet)])?;
                applied.subnet_id = Some(subnet);
            }
            After::Key(dir) | After::Issuer(dir) => {
                let out = self.exec(&self.tofu_env(
                    target,
                    CommandSpec::new("tofu").args([
                        format!("-chdir={}", dir.display()),
                        "output".into(),
                        "-json".into(),
                    ]),
                ))?;
                let v: Value = serde_json::from_str(&out.stdout).unwrap_or(Value::Null);
                let get = |k: &str| {
                    v.pointer(&format!("/{k}/value"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                };
                let bad = || Finding::new("bad_answer", t("init.bad_answer", &[]));
                if matches!(prepared.after, After::Key(_)) {
                    let (arn, fleet) = (
                        get("key_arn").ok_or_else(bad)?,
                        get("fleet").ok_or_else(bad)?,
                    );
                    if !arn.starts_with("arn:") {
                        return Err(bad());
                    }
                    self.persist(target, &[("secrets_key_arn", &arn), ("fleet", &fleet)])?;
                    applied.secrets_key_arn = Some(arn);
                    applied.fleet = Some(fleet);
                } else {
                    let url = get("function_url").ok_or_else(bad)?;
                    if !url.starts_with("https://") {
                        return Err(bad());
                    }
                    let arn = get("function_arn").unwrap_or_default();
                    self.persist(
                        target,
                        &[("issuer_url", &url), ("issuer_function_arn", &arn)],
                    )?;
                    applied.issuer_url = Some(url);
                }
            }
            After::Adopt(dir) => {
                let out = self.exec(&self.tofu_env(
                    target,
                    CommandSpec::new("tofu").args([
                        format!("-chdir={}", dir.display()),
                        "output".into(),
                        "-raw".into(),
                        "operator_adopt_policy_json".into(),
                    ]),
                ))?;
                let doc: Value = serde_json::from_str(&out.stdout)
                    .map_err(|_| Finding::new("bad_answer", t("init.bad_answer", &[])))?;
                if out.status != Some(0) || doc.get("Statement").is_none() {
                    return Err(Finding::new("bad_answer", t("init.bad_answer", &[])));
                }
                let file = dir.join("operator-adopt-policy.json");
                std::fs::write(&file, out.stdout.as_bytes()).map_err(|e| {
                    Finding::new("bad_answer", format!("{}: {e}", t("init.bad_answer", &[])))
                })?;
                applied.operator_adopt_policy_file = Some(file.display().to_string());
            }
            After::Security(dir) => {
                let out = self.exec(&self.tofu_env(
                    target,
                    CommandSpec::new("tofu").args([
                        format!("-chdir={}", dir.display()),
                        "output".into(),
                        "-json".into(),
                    ]),
                ))?;
                let v: Value = serde_json::from_str(&out.stdout).unwrap_or(Value::Null);
                let get = |k: &str| {
                    v.pointer(&format!("/{k}/value"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                };
                let (bucket, group) = (get("session_log_bucket"), get("patch_group"));
                // Recorded so boxes made or rebuilt from now on join them; turned off, the keys are cleared.
                self.persist_keys(
                    target,
                    &[
                        ("session_log_bucket", bucket.as_deref()),
                        ("patch_group", group.as_deref()),
                    ],
                )?;
                applied.session_log_bucket = bucket;
                applied.patch_group = group;
            }
        }
        Ok(applied)
    }

    // ----- the configuration file -----

    /// Set the provider and the given keys under its section, keeping everything else in the file: comments, order and keys
    /// this program does not know (a backup is made the first time). It edits the file the loader reads, so a layout that
    /// keeps its settings in `fleet.toml` is updated in place and no second file shadows it. The profile init was run with is
    /// the SETUP identity: it is recorded as `setup_profile` and never written over `profile`, which daily commands use.
    pub fn persist(&self, target: &Target, extra: &[(&str, &str)]) -> Res<()> {
        self.persist_keys_in(target, extra, &[])
    }

    fn persist_keys_in(&self, target: &Target, set: &[(&str, &str)], remove: &[&str]) -> Res<()> {
        let path = &self.paths.config;
        let mut keys: Vec<(&str, &str)> = Vec::new();
        if target.provider != "fake" {
            if let Some(r) = &target.region {
                keys.push(("region", r));
            }
            if let Some(p) = &target.profile {
                keys.push(("setup_profile", p));
            }
        }
        keys.extend_from_slice(set);
        let section = (target.provider != "fake").then_some(target.provider.as_str());
        crate::config::edit_config_file(
            path,
            &[("provider", target.provider.as_str())],
            section,
            &keys,
            remove,
        )
        .map_err(|e| match e {
            crate::config::EditError::Invalid | crate::config::EditError::NotTable(_) => {
                Finding::new(
                    "bad_config",
                    t("init.bad_config", &[("path", &path.display().to_string())]),
                )
            }
            crate::config::EditError::Io(e) => Finding::new("command_failed", e.to_string()),
        })
    }

    /// Like [`persist`](Self::persist) for keys that may also be cleared: `None` removes the key.
    pub fn persist_keys(&self, target: &Target, keys: &[(&str, Option<&str>)]) -> Res<()> {
        let set: Vec<(&str, &str)> = keys
            .iter()
            .filter_map(|(k, v)| v.map(|v| (*k, v)))
            .collect();
        let removed: Vec<&str> = keys
            .iter()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| *k)
            .collect();
        self.persist_keys_in(target, &set, &removed)
    }

    /// The values setup has recorded for a provider (`state_bucket`, `subnet_id`, ...).
    pub fn recorded(&self, provider: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let Ok(text) = std::fs::read_to_string(&self.paths.config) else {
            return out;
        };
        let Ok(table) = text.parse::<toml::Table>() else {
            return out;
        };
        if let Some(toml::Value::Table(s)) = table.get(provider) {
            for (k, v) in s {
                if let toml::Value::String(v) = v {
                    out.insert(k.clone(), v.clone());
                }
            }
        }
        out
    }

    /// Finish setup: nothing is written as "done" unless everything a real cloud needs is in place.
    pub fn finish(
        &self,
        target: &Target,
        mfa_ack: bool,
        g: &Guardrails,
        now_ms: u64,
    ) -> Res<SetupFile> {
        target.validate()?;
        let real = target.provider != "fake";
        if real {
            if !mfa_ack {
                return Err(Finding::new("ack_required", t("init.ack_required", &[])));
            }
            if !g.ok {
                return Err(Finding::new("guardrails_missing", t("init.need_both", &[]))
                    .with_fix(t("init.need_fix", &[])));
            }
            if target.provider == "aws" {
                let rec = self.recorded("aws");
                if !rec.contains_key("state_bucket") || !rec.contains_key("subnet_id") {
                    return Err(Finding::new(
                        "foundation_missing",
                        t("init.foundation_missing", &[]),
                    ));
                }
            }
        }
        self.persist(target, &[])?;
        let file = SetupFile {
            completed: true,
            provider: Some(target.provider.clone()),
            require_guardrails: real,
            mfa_ack: real && mfa_ack,
            completed_ms: Some(now_ms),
        };
        file.save(&self.paths.setup)
            .map_err(|e| Finding::new("command_failed", e.to_string()))?;
        Ok(file)
    }
}

/// The (address, verb) of every resource a `tofu plan` says it will create, change or destroy, in the order shown. The verb
/// is one of `create`, `destroy`, `update`, `replace`.
pub fn plan_entries(stdout: &str) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let l = line.trim_start();
        let Some(rest) = l.strip_prefix("# ") else {
            continue;
        };
        let (addr, verb) = if let Some(a) = rest.strip_suffix(" will be created") {
            (a, "create")
        } else if let Some(a) = rest.strip_suffix(" will be destroyed") {
            (a, "destroy")
        } else if let Some(a) = rest.strip_suffix(" will be updated in-place") {
            (a, "update")
        } else if let Some(a) = rest.strip_suffix(" must be replaced") {
            (a, "replace")
        } else if let Some(a) = rest.strip_suffix(" will be replaced, as requested") {
            (a, "replace")
        } else {
            continue;
        };
        out.push((addr.to_string(), verb));
    }
    out
}

/// The resources a `tofu plan` says it will create, change or destroy, in the order shown.
pub fn parse_tofu_plan(stdout: &str) -> Vec<Change> {
    plan_entries(stdout)
        .into_iter()
        .map(|(addr, verb)| {
            let kind = addr
                .rsplit('.')
                .nth(1)
                .unwrap_or("resource")
                .trim_start_matches("aws_");
            let risk = if verb == "destroy" || verb == "replace" {
                Risk::High
            } else {
                Risk::Medium
            };
            Change::new(
                format!("network.{verb}"),
                t(
                    &format!("init.net_{verb}"),
                    &[("what", &kind.replace('_', " ")), ("address", &addr)],
                ),
                risk,
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::netguard::FakeHttp;
    use crate::secrets::MemorySecrets;
    use ozbox_core::RecordingRunner;

    struct FakeLatency(Vec<(&'static str, Option<u64>)>);
    impl Latency for FakeLatency {
        fn rtt(&self, url: &str) -> Option<Duration> {
            self.0
                .iter()
                .find(|(r, _)| url.contains(&format!("ec2.{r}.")))
                .and_then(|(_, ms)| ms.map(Duration::from_millis))
        }
    }

    fn out(status: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: Some(status),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    fn target() -> Target {
        Target {
            provider: "aws".into(),
            profile: Some("work".into()),
            region: Some("us-east-1".into()),
        }
    }

    struct Env {
        dir: tempfile::TempDir,
        runner: RecordingRunner,
        http: FakeHttp,
        latency: FakeLatency,
    }

    impl Env {
        fn new() -> Env {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("modules/aws-box")).unwrap();
            std::fs::create_dir_all(dir.path().join("modules/aws-network")).unwrap();
            Env {
                dir,
                runner: RecordingRunner::new(),
                http: FakeHttp::default(),
                latency: FakeLatency(vec![]),
            }
        }
        fn init(&self) -> Init<'_> {
            Init {
                runner: &self.runner,
                http: &self.http,
                latency: &self.latency,
                paths: InitPaths {
                    config: self.dir.path().join("config.toml"),
                    setup: self.dir.path().join("setup.json"),
                    plugin_cache: self.dir.path().join("cache"),
                    work: self.dir.path().join("work"),
                    modules: self.dir.path().join("modules"),
                },
                retry_delay: Duration::ZERO,
            }
        }
    }

    const SSO: &str = r#"{"UserId":"AROAEXAMPLE:me","Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Operator_abc123/me"}"#;

    #[test]
    fn arns_are_classified() {
        assert_eq!(
            classify_arn("arn:aws:iam::123456789012:root").0,
            IdentityKind::Root
        );
        let (k, u) = classify_arn("arn:aws:iam::123456789012:user/team/ana");
        assert_eq!((k, u.as_deref()), (IdentityKind::IamUser, Some("ana")));
        assert_eq!(
            classify_arn("arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Op_1/me").0,
            IdentityKind::SsoRole
        );
        assert_eq!(
            classify_arn("arn:aws:sts::123456789012:assumed-role/Deployer/me").0,
            IdentityKind::AssumedRole
        );
        assert_eq!(
            classify_arn("arn:aws-us-gov:iam::123456789012:root").0,
            IdentityKind::Root
        );
        assert_eq!(classify_arn("garbage").0, IdentityKind::Other);
    }

    #[test]
    fn sso_sign_in_is_accepted_and_uses_the_profile() {
        let e = Env::new();
        e.runner.reply(out(0, SSO, ""));
        let id = e.init().sign_in(&target()).unwrap();
        assert_eq!(id.kind, IdentityKind::SsoRole);
        assert_eq!(id.account, "123456789012");
        let calls = e.runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(&calls[0].args[..2], ["sts", "get-caller-identity"]);
        assert!(calls[0].args.windows(2).any(|w| w == ["--profile", "work"]));
    }

    #[test]
    fn root_is_refused_without_asking_anything_else() {
        let e = Env::new();
        e.runner.reply(out(
            0,
            r#"{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:root"}"#,
            "",
        ));
        let err = e.init().sign_in(&target()).unwrap_err();
        assert_eq!(err.code, "root_refused");
        assert_eq!(e.runner.calls().len(), 1);
    }

    #[test]
    fn an_iam_user_with_keys_is_refused_and_one_we_cannot_check_too() {
        let user = r#"{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/ana"}"#;
        let e = Env::new();
        e.runner.reply(out(0, user, ""));
        e.runner
            .reply(out(0, r#"{"AccessKeyMetadata":[{"AccessKeyId":"x"}]}"#, ""));
        assert_eq!(
            e.init().sign_in(&target()).unwrap_err().code,
            "long_lived_keys_refused"
        );
        let e = Env::new();
        e.runner.reply(out(0, user, ""));
        e.runner.reply(out(254, "", "AccessDenied"));
        assert_eq!(
            e.init().sign_in(&target()).unwrap_err().code,
            "long_lived_keys_refused"
        );
        // No keys at all: a temporary session of a user. Accepted.
        let e = Env::new();
        e.runner.reply(out(0, user, ""));
        e.runner.reply(out(0, r#"{"AccessKeyMetadata":[]}"#, ""));
        assert_eq!(
            e.init().sign_in(&target()).unwrap().kind,
            IdentityKind::IamUser
        );
    }

    #[test]
    fn not_signed_in_says_how_to_sign_in() {
        let e = Env::new();
        e.runner.reply(out(255, "", "Unable to locate credentials"));
        let err = e.init().sign_in(&target()).unwrap_err();
        assert_eq!(err.code, "not_signed_in");
        assert!(err.fix.unwrap().contains("aws sso login --profile work"));
    }

    #[test]
    fn a_failed_sign_in_with_an_aws_cli_v1_says_v2_is_needed_not_that_you_are_signed_out() {
        let e = Env::new();
        e.runner
            .reply(out(2, "", "aws: error: argument operation: Invalid choice"));
        e.runner
            .reply(out(0, "", "aws-cli/1.18.69 Python/3.8.10 Linux/5.4"));
        let err = e.init().sign_in(&target()).unwrap_err();
        assert_eq!(err.code, "aws_cli_v1");
        assert!(
            err.message.contains("cannot run `aws sso login`") && err.message.contains("1.18.69")
        );
        assert_eq!(e.runner.calls()[1].args, ["--version"]);
    }

    #[test]
    fn a_missing_cli_is_its_own_finding() {
        struct Missing;
        impl CommandRunner for Missing {
            fn run(&self, _: &CommandSpec) -> ozbox_core::Result<Output> {
                Err(ozbox_core::Error::Io(std::io::ErrorKind::NotFound.into()))
            }
        }
        let e = Env::new();
        let mut init = e.init();
        init.runner = &Missing;
        assert_eq!(init.sign_in(&target()).unwrap_err().code, "tool_missing");
    }

    const ACCOUNT_REPLY: &str =
        r#"{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:role/ozbox-operator"}"#;

    #[test]
    fn probes_classify_and_only_ever_use_dry_runs_or_reads() {
        let e = Env::new();
        e.runner.reply(out(0, ACCOUNT_REPLY, ""));
        e.runner.reply(out(
            254,
            "",
            "An error occurred (DryRunOperation) when calling RunInstances",
        ));
        e.runner
            .reply(out(254, "", "An error occurred (UnauthorizedOperation)"));
        e.runner
            .reply(out(254, "", "An error occurred (InvalidVolume.NotFound)"));
        e.runner
            .reply(out(254, "", "An error occurred (DryRunOperation)"));
        e.runner.reply(out(0, "{}", ""));
        e.runner.reply(out(254, "", "Throttled"));
        let r = e.init().permissions(&target()).unwrap();
        let states: Vec<ProbeState> = r.probes.iter().map(|p| p.state).collect();
        assert_eq!(
            states,
            [
                ProbeState::Allowed,
                ProbeState::Denied,
                ProbeState::Allowed,
                ProbeState::Allowed,
                ProbeState::Allowed,
                ProbeState::Unknown
            ]
        );
        assert!(!r.ok);
        // a refusal names the policy statement that grants it
        let denied = r
            .probes
            .iter()
            .find(|p| p.state == ProbeState::Denied)
            .unwrap();
        let hint = denied.detail.as_deref().unwrap();
        assert!(
            hint.contains("CreateTaggedResources") && hint.contains("ozbox-managed=true"),
            "{hint}"
        );
        for c in e.runner.calls() {
            let a = &c.args;
            let verb = a.get(1).map(String::as_str).unwrap_or("");
            let dry = a.iter().any(|x| x == "--dry-run");
            assert!(
                dry || verb.starts_with("describe")
                    || verb == "head-bucket"
                    || verb == "get-caller-identity",
                "a probe must not mutate: {a:?}"
            );
            assert_ne!(verb, "list-buckets", "never list every bucket: {a:?}");
        }
    }

    #[test]
    fn the_state_bucket_probe_never_stops_setup_and_absent_is_not_denied() {
        // absent: allowed
        let e = Env::new();
        e.runner.reply(out(0, ACCOUNT_REPLY, ""));
        for _ in 0..5 {
            e.runner.reply(out(0, "{}", ""));
        }
        e.runner.reply(out(
            254,
            "",
            "An error occurred (404) when calling the HeadBucket operation: Not Found",
        ));
        let r = e.init().permissions(&target()).unwrap();
        assert!(r.ok);
        assert_eq!(r.probes.last().unwrap().state, ProbeState::Allowed);
        let last = e.runner.calls().last().unwrap().args.clone();
        assert!(
            last.contains(&"ozbox-state-123456789012-us-east-1".to_string()),
            "{last:?}"
        );
        // refused: reported (as unknown, with who grants it), never a stop
        let e = Env::new();
        e.runner.reply(out(0, ACCOUNT_REPLY, ""));
        for _ in 0..5 {
            e.runner.reply(out(0, "{}", ""));
        }
        e.runner.reply(out(
            254,
            "",
            "An error occurred (AccessDenied) when calling the HeadBucket operation",
        ));
        let r = e.init().permissions(&target()).unwrap();
        assert!(r.ok);
        let p = r.probes.last().unwrap();
        assert_eq!(p.state, ProbeState::Unknown);
        assert!(p.detail.as_deref().unwrap().contains("setup identity"));
    }

    /// The probes are held to the operator policy: each one asks for what `infra/aws/operator-policy.json` allows, in the
    /// shape it allows it. Before this, the create probes carried no tag and the bucket probe listed every bucket, so a
    /// correctly set-up operator role was refused by a check that tested permissions Oz Box never uses.
    #[test]
    fn every_probe_is_a_call_the_operator_policy_allows() {
        let policy: serde_json::Value =
            serde_json::from_str(include_str!("../../../infra/aws/operator-policy.json")).unwrap();
        let stmts = policy["Statement"].as_array().unwrap();
        let list = |v: &serde_json::Value| -> Vec<String> {
            match v {
                serde_json::Value::String(x) => vec![x.clone()],
                serde_json::Value::Array(a) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
                _ => vec![],
            }
        };
        let action_matches = |pat: &str, action: &str| {
            let (p, a) = (pat.to_ascii_lowercase(), action.to_ascii_lowercase());
            match p.split_once('*') {
                None => p == a,
                Some((h, t)) => a.starts_with(h) && a.ends_with(t) && a.len() >= h.len() + t.len(),
            }
        };
        // the tag a probe sends for its resource type, read back out of the argv like the CLI would
        let sent_tag = |args: &[String], resource: &str| -> Option<(String, String)> {
            let i = args.iter().position(|a| a == "--tag-specifications")?;
            let spec = args.get(i + 1)?;
            let rest = spec.strip_prefix(&format!("ResourceType={resource},Tags=[{{Key="))?;
            let (k, rest) = rest.split_once(",Value=")?;
            let v = rest.strip_suffix("}]")?;
            Some((k.to_string(), v.to_string()))
        };
        let region = "us-east-1";
        let defs = probe_defs(region, Some("123456789012"));
        assert!(defs.len() >= 6);
        for d in &defs {
            assert!(
                !d.args.iter().any(|a| a == "list-buckets"),
                "{}: the operator may not list every bucket",
                d.id
            );
            let allowing: Vec<&serde_json::Value> = stmts
                .iter()
                .filter(|s| {
                    s["Effect"] == "Allow"
                        && list(&s["Action"])
                            .iter()
                            .any(|p| action_matches(p, d.action))
                })
                .collect();
            match d.grant {
                Grant::Operator(sid) => {
                    let named = allowing
                        .iter()
                        .find(|s| s["Sid"] == sid)
                        .unwrap_or_else(|| {
                            panic!("{}: statement {sid} does not allow {}", d.id, d.action)
                        });
                    // the hint names a statement that really grants it, with the tag the statement demands
                    let cond = &named["Condition"]["StringEquals"];
                    if let Some(want) = cond.get("aws:RequestTag/ozbox-managed") {
                        let res = d.tag_resource.unwrap_or_else(|| {
                            panic!("{}: the statement needs a request tag", d.id)
                        });
                        let got = sent_tag(&d.args, res)
                            .unwrap_or_else(|| panic!("{}: sends no tag for {res}", d.id));
                        assert_eq!(got.0, MANAGED_TAG, "{}", d.id);
                        assert_eq!(&serde_json::Value::String(got.1), want, "{}", d.id);
                        let frag = format!(":{res}/");
                        let frag2 = format!("::{res}/");
                        assert!(
                            list(&named["Resource"])
                                .iter()
                                .any(|r| r.contains(&frag) || r.contains(&frag2)),
                            "{}: {sid} does not cover a {res}",
                            d.id
                        );
                    }
                    // and no tag a statement forbids is invented: an unconditioned allow needs none
                    let unconditioned = allowing.iter().any(|s| s.get("Condition").is_none());
                    if !unconditioned && d.tag_resource.is_none() {
                        assert!(
                            cond.get("aws:RequestTag/ozbox-managed").is_none(),
                            "{}: needs a tag the probe cannot send",
                            d.id
                        );
                    }
                }
                Grant::SetupIdentity => {
                    // never presented as an operator permission: the operator policy must not reach that bucket
                    let bucket = Init::bucket_name("123456789012", region);
                    let arn = format!("arn:aws:s3:::{bucket}");
                    for s in &allowing {
                        for r in list(&s["Resource"]) {
                            assert!(
                                !(r.ends_with('*') && arn.starts_with(r.trim_end_matches('*')))
                                    && r != arn,
                                "{} is the setup identity's, but {r} reaches it",
                                d.id
                            );
                        }
                    }
                    assert!(
                        d.args.iter().any(|a| a == &bucket),
                        "{}: names the bucket",
                        d.id
                    );
                }
            }
        }
        // negative control: the probes as they were (no tag) are exactly what this test refuses
        let untagged: Vec<String> = defs[1]
            .args
            .iter()
            .take_while(|a| *a != "--tag-specifications")
            .cloned()
            .collect();
        assert!(sent_tag(&untagged, "volume").is_none());
    }

    /// The probes are run by whoever runs `ozbox init`: the person signed in as the setup identity (`OzBoxSetup`,
    /// `infra/aws/setup-policy.json`). So every probe, the operator ones too, must be a call that permission set allows, in the
    /// shape it allows it: an Allow that names the action, reaches the resource the call acts on, and whose conditions the
    /// probe meets (it sends the `ozbox-managed=true` tag), with no Deny on it. Without this a person set up exactly as the
    /// guide says would be refused by init's own check.
    #[test]
    fn every_probe_is_a_call_the_setup_policy_allows() {
        let text = include_str!("../../../infra/aws/setup-policy.json");
        let policy: serde_json::Value = serde_json::from_str(text).unwrap();
        let stmts = policy["Statement"].as_array().unwrap();
        let list = |v: &serde_json::Value| -> Vec<String> {
            match v {
                serde_json::Value::String(x) => vec![x.clone()],
                serde_json::Value::Array(a) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
                _ => vec![],
            }
        };
        let action_matches = |pat: &str, action: &str| {
            let (p, a) = (pat.to_ascii_lowercase(), action.to_ascii_lowercase());
            match p.split_once('*') {
                None => p == a,
                Some((h, t)) => a.starts_with(h) && a.ends_with(t) && a.len() >= h.len() + t.len(),
            }
        };
        let glob = |pattern: &str, text: &str| -> bool {
            let parts: Vec<&str> = pattern.split('*').collect();
            let mut rest = text;
            for (i, part) in parts.iter().enumerate() {
                if i == 0 {
                    if !rest.starts_with(part) {
                        return false;
                    }
                    rest = &rest[part.len()..];
                } else if i == parts.len() - 1 {
                    return rest.ends_with(part);
                } else {
                    match rest.find(part) {
                        Some(at) => rest = &rest[at + part.len()..],
                        None => return false,
                    }
                }
            }
            rest.is_empty()
        };
        let account = "123456789012";
        let region = "us-east-1";
        // the resource each probe acts on
        let arn_of = |d: &ProbeDef| -> String {
            match (d.tag_resource, d.id) {
                (Some("snapshot"), _) => format!("arn:aws:ec2:{region}::snapshot/snap-0"),
                (Some(r), _) => format!("arn:aws:ec2:{region}:{account}:{r}/x-0"),
                (None, "s3_state_bucket") => {
                    format!("arn:aws:s3:::{}", Init::bucket_name(account, region))
                }
                (None, _) => "*".to_string(),
            }
        };
        // a request-tag condition is met only because the probe sends the tag: the one condition shape these statements use
        let condition_met = |s: &serde_json::Value, sends_tag: bool| -> bool {
            let Some(c) = s.get("Condition").and_then(|c| c.as_object()) else {
                return true;
            };
            c.iter().all(|(op, keys)| {
                op == "StringEquals"
                    && keys.as_object().is_some_and(|k| {
                        k.keys()
                            .all(|key| key == "aws:RequestTag/ozbox-managed" && sends_tag)
                    })
            })
        };
        let defs = probe_defs(region, Some(account));
        assert!(defs.len() >= 6);
        for d in &defs {
            let arn = arn_of(d);
            let reaches = |s: &serde_json::Value| {
                list(&s["Resource"])
                    .iter()
                    .any(|r| glob(&r.replace("${account_id}", account), &arn))
            };
            let on_action = |s: &serde_json::Value| {
                list(&s["Action"])
                    .iter()
                    .any(|p| action_matches(p, d.action))
            };
            assert!(
                stmts.iter().any(|s| s["Effect"] == "Allow"
                    && on_action(s)
                    && reaches(s)
                    && condition_met(s, d.tag_resource.is_some())),
                "{}: no statement of setup-policy.json allows {} on {arn} (with the tag the probe sends)",
                d.id,
                d.action
            );
            assert!(
                !stmts
                    .iter()
                    .any(|s| s["Effect"] == "Deny" && on_action(s) && reaches(s)),
                "{}: setup-policy.json denies {}",
                d.id,
                d.action
            );
        }
        // negative control: the bucket probe fails against a policy with the state-bucket statements removed, which is what
        // this test exists to catch (the setup identity could not even reach the bucket it must make)
        let bucket = defs.iter().find(|d| d.id == "s3_state_bucket").unwrap();
        let arn = arn_of(bucket);
        let without: Vec<&serde_json::Value> = stmts
            .iter()
            .filter(|s| !list(&s["Action"]).iter().any(|a| a.starts_with("s3:")))
            .collect();
        assert!(!without.iter().any(|s| s["Effect"] == "Allow"
            && list(&s["Action"])
                .iter()
                .any(|p| action_matches(p, bucket.action))
            && list(&s["Resource"])
                .iter()
                .any(|r| glob(&r.replace("${account_id}", account), &arn))));
    }

    #[test]
    fn expired_credentials_during_probes_read_as_not_signed_in() {
        let e = Env::new();
        e.runner
            .reply(out(254, "", "ExpiredToken: the security token is expired"));
        assert_eq!(
            e.init().permissions(&target()).unwrap_err().code,
            "not_signed_in"
        );
    }

    #[test]
    fn regions_are_ranked_and_the_suggestion_has_the_sizes() {
        let c = |r: &str, ms: Option<u64>, o: Option<bool>| RegionCandidate {
            region: r.into(),
            name: r.into(),
            ms,
            offers_sizes: o,
        };
        let r = rank_regions(vec![
            c("eu-west-1", Some(120), Some(true)),
            c("us-east-1", Some(40), Some(false)),
            c("sa-east-1", None, None),
            c("us-east-2", Some(60), None),
        ]);
        let order: Vec<&str> = r.candidates.iter().map(|c| c.region.as_str()).collect();
        assert_eq!(order, ["us-east-1", "us-east-2", "eu-west-1", "sa-east-1"]);
        assert_eq!(r.suggested.as_deref(), Some("us-east-2"));
        assert_eq!(rank_regions(vec![c("a-b-1", None, None)]).suggested, None);
    }

    #[test]
    fn measuring_regions_asks_the_fastest_three_about_sizes() {
        let mut e = Env::new();
        e.latency = FakeLatency(vec![
            ("eu-west-1", Some(30)),
            ("us-east-1", Some(80)),
            ("us-west-2", Some(90)),
            ("ap-south-1", Some(300)),
        ]);
        let offered = r#"{"InstanceTypeOfferings":[{"InstanceType":"m7i.xlarge"},{"InstanceType":"m7i.2xlarge"},{"InstanceType":"r7i.2xlarge"},{"InstanceType":"m7i.4xlarge"}]}"#;
        e.runner.reply(out(0, offered, ""));
        e.runner
            .reply(out(0, r#"{"InstanceTypeOfferings":[]}"#, ""));
        e.runner.reply(out(0, offered, ""));
        let r = e.init().regions(&target()).unwrap();
        assert_eq!(r.candidates[0].region, "eu-west-1");
        assert_eq!(r.candidates[0].offers_sizes, Some(true));
        assert_eq!(r.candidates[1].offers_sizes, Some(false));
        assert_eq!(r.suggested.as_deref(), Some("eu-west-1"));
        let calls = e.runner.calls();
        assert_eq!(calls.len(), 3);
        assert!(calls
            .iter()
            .all(|c| c.args[1] == "describe-instance-type-offerings"));
    }

    #[test]
    fn a_new_bucket_is_planned_with_every_protection() {
        let e = Env::new();
        e.runner.reply(out(
            254,
            "",
            "An error occurred (404) when calling the HeadBucket operation: Not Found",
        ));
        let p = e.init().plan_bucket(&target(), "123456789012").unwrap();
        let kinds: Vec<&str> = p.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "bucket.create",
                "bucket.versioning",
                "bucket.encryption",
                "bucket.public_access_block",
                "bucket.tls_only"
            ]
        );
        assert!(!p.noop);
        // Planning ran only the probe.
        assert_eq!(e.runner.calls().len(), 1);
        assert!(e.runner.calls()[0]
            .args
            .contains(&"head-bucket".to_string()));
        // us-east-1 takes no location constraint; another region does.
        assert!(!p.run[0]
            .args
            .iter()
            .any(|a| a.starts_with("LocationConstraint")));
        let e = Env::new();
        e.runner.reply(out(254, "", "404 Not Found"));
        let mut t2 = target();
        t2.region = Some("eu-west-1".into());
        let p = e.init().plan_bucket(&t2, "123456789012").unwrap();
        assert!(p.run[0]
            .args
            .contains(&"LocationConstraint=eu-west-1".to_string()));
        assert!(p.run[0]
            .args
            .contains(&"--create-bucket-configuration".to_string()));
    }

    #[test]
    fn a_complete_bucket_plans_to_nothing_and_a_partial_one_only_the_gap() {
        let versioned = r#"{"Status":"Enabled"}"#;
        let blocked = r#"{"PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}}"#;
        let e = Env::new();
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, versioned, ""));
        e.runner.reply(out(0, "{}", ""));
        e.runner.reply(out(0, blocked, ""));
        let p = e.init().plan_bucket(&target(), "123456789012").unwrap();
        assert!(p.noop && p.changes.is_empty());

        let e = Env::new();
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, "{}", ""));
        e.runner.reply(out(
            254,
            "",
            "ServerSideEncryptionConfigurationNotFoundError",
        ));
        e.runner.reply(out(0, blocked, ""));
        let p = e.init().plan_bucket(&target(), "123456789012").unwrap();
        let kinds: Vec<&str> = p.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["bucket.versioning", "bucket.encryption"]);
    }

    #[test]
    fn a_bucket_name_someone_else_owns_is_refused() {
        let e = Env::new();
        e.runner.reply(out(
            254,
            "",
            "An error occurred (403) when calling the HeadBucket operation: Forbidden",
        ));
        assert_eq!(
            e.init()
                .plan_bucket(&target(), "123456789012")
                .unwrap_err()
                .code,
            "bucket_not_ours"
        );
    }

    #[test]
    fn applying_a_bucket_plan_runs_its_commands_then_records_the_bucket() {
        let e = Env::new();
        e.runner.reply(out(254, "", "404"));
        let init = e.init();
        let p = init.plan_bucket(&target(), "123456789012").unwrap();
        let before = e.runner.calls().len();
        let a = init.apply(&target(), &p).unwrap();
        assert_eq!(e.runner.calls().len() - before, p.changes.len());
        assert_eq!(
            a.bucket.as_deref(),
            Some("ozbox-state-123456789012-us-east-1")
        );
        let rec = init.recorded("aws");
        assert_eq!(
            rec.get("state_bucket").map(String::as_str),
            Some("ozbox-state-123456789012-us-east-1")
        );
        assert_eq!(rec.get("region").map(String::as_str), Some("us-east-1"));
    }

    #[test]
    fn a_failed_command_stops_the_apply_and_records_nothing() {
        let e = Env::new();
        e.runner.reply(out(254, "", "404"));
        let init = e.init();
        let p = init.plan_bucket(&target(), "123456789012").unwrap();
        e.runner.reply(out(255, "", "BucketAlreadyExists: nope"));
        let err = init.apply(&target(), &p).unwrap_err();
        assert_eq!(err.code, "apply_failed");
        assert!(init.recorded("aws").is_empty());
    }

    #[test]
    fn the_network_needs_the_bucket_and_a_new_enough_tofu() {
        let e = Env::new();
        e.runner.reply(out(254, "", "404"));
        assert_eq!(
            e.init()
                .plan_network(&target(), "123456789012")
                .unwrap_err()
                .code,
            "bucket_missing"
        );
        let e = Env::new();
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.8.2"}"#, ""));
        assert_eq!(
            e.init()
                .plan_network(&target(), "123456789012")
                .unwrap_err()
                .code,
            "tofu_too_old"
        );
    }

    const PLAN: &str = "\n  # aws_vpc.this will be created\n  + resource \"aws_vpc\" \"this\" {}\n  # module.network.aws_nat_gateway.this will be created\n  # aws_subnet.private will be created\nPlan: 3 to add, 0 to change, 0 to destroy.\n";

    #[test]
    fn the_network_plan_lists_resources_seeds_plugins_and_uses_the_cache() {
        let e = Env::new();
        e.runner.reply(out(0, "", "")); // head-bucket
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", "")); // init aws-box (seed)
        e.runner.reply(out(0, "", "")); // init aws-network (seed)
        e.runner.reply(out(0, "", "")); // init with backend
        e.runner.reply(out(2, PLAN, "")); // plan
        let init = e.init();
        let p = init.plan_network(&target(), "123456789012").unwrap();
        assert_eq!(p.changes.len(), 3);
        assert!(p.changes[1].description.contains("nat gateway"));
        assert_eq!(p.estimate_usd_month, Some(NAT_USD_MONTH));
        let calls = e.runner.calls();
        let tofu: Vec<&CommandSpec> = calls.iter().filter(|c| c.program == "tofu").collect();
        assert!(tofu
            .iter()
            .skip(1)
            .all(|c| c.env.contains_key("TF_PLUGIN_CACHE_DIR")));
        assert!(tofu
            .iter()
            .any(|c| c.args.iter().any(|a| a == "-backend=false")));
        assert!(tofu.iter().any(|c| c
            .args
            .iter()
            .any(|a| a == "-backend-config=use_lockfile=true")));
        assert!(tofu
            .iter()
            .any(|c| c.args.iter().any(|a| a == "-detailed-exitcode")));
        // Nothing was applied while planning.
        assert!(!tofu.iter().any(|c| c.args.iter().any(|a| a == "apply")));
        // The generated root names the bucket only through backend flags; no credential is in a file.
        let main =
            std::fs::read_to_string(e.dir.path().join("work/network/us-east-1/main.tf")).unwrap();
        assert!(main.contains("backend \"s3\" {}") && main.contains("source = \""));
        assert_eq!(
            calls.last().map(|c| c.env.get("AWS_PROFILE").cloned()),
            Some(Some("work".into()))
        );
    }

    #[test]
    fn applying_the_network_reads_the_subnet_and_records_it() {
        let e = Env::new();
        // head-bucket, version, two seeds, backend init, plan
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(2, PLAN, ""));
        let init = e.init();
        let p = init.plan_network(&target(), "123456789012").unwrap();
        e.runner.reply(out(0, "", "")); // apply
        e.runner.reply(out(
            0,
            r#"{"private_subnet_id":{"value":"subnet-0abc"},"vpc_id":{"value":"vpc-0abc"}}"#,
            "",
        ));
        let a = init.apply(&target(), &p).unwrap();
        assert_eq!(a.subnet_id.as_deref(), Some("subnet-0abc"));
        assert_eq!(
            init.recorded("aws").get("subnet_id").map(String::as_str),
            Some("subnet-0abc")
        );
    }

    #[test]
    fn a_plugin_download_is_retried_and_then_reported() {
        let e = Env::new();
        let init = e.init();
        e.runner.reply(out(
            1,
            "",
            "Error: could not query provider registry: 504 Gateway Timeout",
        ));
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, "", ""));
        init.seed_plugins(&target()).unwrap();
        assert_eq!(e.runner.calls().len(), 3);

        let e = Env::new();
        let init = e.init();
        for _ in 0..3 {
            e.runner.reply(out(1, "", "Error: 502 Bad Gateway"));
        }
        let err = init.seed_plugins(&target()).unwrap_err();
        assert_eq!(err.code, "plugin_download_failed");
        assert!(err.message.contains("502"));
    }

    #[test]
    fn a_missing_module_directory_says_where_to_look() {
        let e = Env::new();
        let mut init = e.init();
        init.paths.modules = e.dir.path().join("nowhere");
        assert_eq!(
            init.seed_plugins(&target()).unwrap_err().code,
            "module_not_found"
        );
    }

    #[test]
    fn persisting_keeps_what_the_file_already_says() {
        let e = Env::new();
        std::fs::write(
            e.dir.path().join("config.toml"),
            "domain = \"boxes.example.org\"\n[hcloud]\nregion = \"fsn1\"\n",
        )
        .unwrap();
        let init = e.init();
        init.persist(&target(), &[("subnet_id", "subnet-0abc")])
            .unwrap();
        let c = crate::config::Config::load_from(&e.dir.path().join("config.toml")).unwrap();
        assert_eq!(c.provider.as_deref(), Some("aws"));
        assert_eq!(c.domain.as_deref(), Some("boxes.example.org"));
        assert_eq!(c.hcloud.unwrap().region.as_deref(), Some("fsn1"));
        let aws = c.aws.unwrap();
        assert_eq!(aws.subnet_id.as_deref(), Some("subnet-0abc"));
        // the profile init was run with is the setup identity: recorded apart, never as the daily profile
        assert_eq!(aws.setup_profile.as_deref(), Some("work"));
        assert_eq!(aws.profile, None);
        assert!(e.dir.path().join("config.toml.bak").exists());
    }

    const OLD_FLEET: &str = "# my fleet\nprovider = \"aws\"\ndomain = \"boxes.example.org\"\n\n[aws]\nregion = \"us-east-1\" # home region\nprofile = \"ozbox-operator\"\nsubnet_id = \"subnet-0abc\"\nimage = \"ami-0abc\"\nsecrets_key_arn = \"arn:aws:kms:us-east-1:123456789012:key/abc\"\nfleet = \"ozbox\"\n";

    #[test]
    fn persisting_into_an_existing_fleet_toml_keeps_every_key_and_the_daily_profile() {
        let e = Env::new();
        let fleet = e.dir.path().join("fleet.toml");
        std::fs::write(&fleet, OLD_FLEET).unwrap();
        // what the loader reads, and so what init must write to
        let cands = [e.dir.path().join("config.toml"), fleet.clone()];
        assert_eq!(
            crate::config::Config::active_in(&cands),
            Some(fleet.clone())
        );
        let mut init = e.init();
        init.paths.config = fleet.clone();
        let mut t = target();
        t.profile = Some("ozbox-setup".into());
        init.persist(
            &t,
            &[("state_bucket", "ozbox-state-123456789012-us-east-1")],
        )
        .unwrap();
        let text = std::fs::read_to_string(&fleet).unwrap();
        assert!(
            text.contains("# my fleet") && text.contains("# home region"),
            "{text}"
        );
        let c = crate::config::Config::load_from(&fleet).unwrap();
        let aws = c.aws.unwrap();
        assert_eq!(
            aws.profile.as_deref(),
            Some("ozbox-operator"),
            "daily profile untouched"
        );
        assert_eq!(aws.setup_profile.as_deref(), Some("ozbox-setup"));
        assert_eq!(aws.subnet_id.as_deref(), Some("subnet-0abc"));
        assert_eq!(aws.image.as_deref(), Some("ami-0abc"));
        assert_eq!(aws.fleet.as_deref(), Some("ozbox"));
        assert!(aws.secrets_key_arn.is_some());
        assert_eq!(
            aws.state_bucket.as_deref(),
            Some("ozbox-state-123456789012-us-east-1")
        );
        assert_eq!(c.domain.as_deref(), Some("boxes.example.org"));
        assert!(e.dir.path().join("fleet.toml.bak").exists());
        assert!(
            !e.dir.path().join("config.toml").exists(),
            "no second file that would shadow the first"
        );
    }

    #[test]
    fn a_subnet_in_the_config_is_found_missing_or_unknown() {
        let e = Env::new();
        std::fs::write(
            e.dir.path().join("config.toml"),
            "[aws]\nsubnet_id = \"subnet-0abc\"\n",
        )
        .unwrap();
        let init = e.init();
        assert_eq!(init.configured_subnet().as_deref(), Some("subnet-0abc"));
        e.runner.reply(Output {
            status: Some(0),
            stdout: r#"{"Subnets":[{"SubnetId":"subnet-0abc"}]}"#.into(),
            stderr: String::new(),
        });
        assert_eq!(
            init.check_subnet(&target(), "subnet-0abc").unwrap(),
            SubnetState::Found
        );
        e.runner.reply(Output {
            status: Some(254),
            stdout: String::new(),
            stderr: "An error occurred (InvalidSubnetID.NotFound)".into(),
        });
        assert_eq!(
            init.check_subnet(&target(), "subnet-0abc").unwrap(),
            SubnetState::Missing
        );
        e.runner.reply(Output {
            status: Some(254),
            stdout: String::new(),
            stderr: "An error occurred (UnauthorizedOperation)".into(),
        });
        assert!(matches!(
            init.check_subnet(&target(), "subnet-0abc").unwrap(),
            SubnetState::Unknown(_)
        ));
        std::fs::write(
            e.dir.path().join("config.toml"),
            "[aws]\nsubnet_id = \"oops\"\n",
        )
        .unwrap();
        assert_eq!(init.configured_subnet(), None);
    }

    #[test]
    fn a_broken_config_is_not_overwritten() {
        let e = Env::new();
        std::fs::write(e.dir.path().join("config.toml"), "provider = [").unwrap();
        assert_eq!(
            e.init().persist(&target(), &[]).unwrap_err().code,
            "bad_config"
        );
        assert_eq!(
            std::fs::read_to_string(e.dir.path().join("config.toml")).unwrap(),
            "provider = ["
        );
    }

    fn ready_settings() -> (Settings, MemorySecrets) {
        let mut s = Settings::default();
        s.budget.monthly_usd = Some(100.0);
        s.apps.email.enabled = true;
        s.apps.email.from = "a@example.com".into();
        s.apps.email.to = vec!["b@example.com".into()];
        let m = MemorySecrets::default();
        m.set("email-api-key", "re_example").unwrap();
        (s, m)
    }

    #[test]
    fn guardrails_need_a_budget_and_a_channel_that_can_deliver() {
        let (s, m) = ready_settings();
        let g = guardrails(&s, &m, 0);
        assert!(g.ok && g.channels == ["email"]);
        // Enabled but no key saved: not a channel.
        let g = guardrails(&s, &MemorySecrets::default(), 0);
        assert!(g.budget_set && !g.alert_ready && !g.ok);
        // No budget.
        let (mut s2, m2) = ready_settings();
        s2.budget.monthly_usd = None;
        assert!(!guardrails(&s2, &m2, 0).ok);
        s2.budget.monthly_usd = Some(0.0);
        assert!(!guardrails(&s2, &m2, 0).budget_set);
        // Telegram counts only once a chat is paired.
        let mut s3 = Settings::default();
        s3.budget.monthly_usd = Some(10.0);
        s3.apps.telegram.enabled = true;
        let m3 = MemorySecrets::default();
        m3.set("telegram-bot-token", "123:abc").unwrap();
        assert!(!guardrails(&s3, &m3, 0).ok);
        assert!(guardrails(&s3, &m3, 1).ok);
    }

    #[test]
    fn creating_is_held_back_only_when_setup_asked_and_the_cloud_is_real() {
        let op = ozbox_core::Operation::Create {
            spec: ozbox_core::BoxSpec::new(ozbox_core::BoxName::new("dev").unwrap(), Size::S),
        };
        let pause = ozbox_core::Operation::Pause {
            name: ozbox_core::BoxName::new("dev").unwrap(),
        };
        let none = guardrails(&Settings::default(), &MemorySecrets::default(), 0);
        let on = SetupFile {
            require_guardrails: true,
            ..SetupFile::default()
        };
        let e = require_guardrails(&on, &none, "aws", &op).unwrap_err();
        assert_eq!(e.code, "guardrails_missing");
        assert!(e.fix.is_some());
        assert!(require_guardrails(&on, &none, "fake", &op).is_ok());
        assert!(require_guardrails(&on, &none, "aws", &pause).is_ok());
        assert!(require_guardrails(&SetupFile::default(), &none, "aws", &op).is_ok());
        let (s, m) = ready_settings();
        assert!(require_guardrails(&on, &guardrails(&s, &m, 0), "aws", &op).is_ok());
    }

    #[test]
    fn security_refuses_root_and_asks_for_two_factor_acknowledgement() {
        let e = Env::new();
        let init = e.init();
        let sso = parse_identity(SSO).unwrap();
        let r = init.security(&target(), &sso).unwrap();
        assert!(!r.blocking && r.needs_ack);
        assert!(r
            .items
            .iter()
            .any(|i| i.id == "two_factor" && i.state == CheckState::Reminder));
        let root = Identity {
            account: "123456789012".into(),
            arn: "arn:aws:iam::123456789012:root".into(),
            kind: IdentityKind::Root,
            user: None,
        };
        assert!(init.security(&target(), &root).unwrap().blocking);
        // An IAM user with a device passes the two-factor check.
        let user = Identity {
            account: "123456789012".into(),
            arn: "arn:aws:iam::123456789012:user/ana".into(),
            kind: IdentityKind::IamUser,
            user: Some("ana".into()),
        };
        e.runner
            .reply(out(0, r#"{"MFADevices":[{"SerialNumber":"x"}]}"#, ""));
        let r = init.security(&target(), &user).unwrap();
        assert!(r
            .items
            .iter()
            .any(|i| i.id == "two_factor" && i.state == CheckState::Pass));
    }

    #[test]
    fn finishing_a_real_cloud_needs_the_acknowledgement_the_guard_rails_and_the_foundation() {
        let e = Env::new();
        let init = e.init();
        let (s, m) = ready_settings();
        let ok = guardrails(&s, &m, 0);
        let none = guardrails(&Settings::default(), &MemorySecrets::default(), 0);
        assert_eq!(
            init.finish(&target(), false, &ok, 1).unwrap_err().code,
            "ack_required"
        );
        assert_eq!(
            init.finish(&target(), true, &none, 1).unwrap_err().code,
            "guardrails_missing"
        );
        assert_eq!(
            init.finish(&target(), true, &ok, 1).unwrap_err().code,
            "foundation_missing"
        );
        init.persist(
            &target(),
            &[("state_bucket", "b"), ("subnet_id", "subnet-0abc")],
        )
        .unwrap();
        let f = init.finish(&target(), true, &ok, 42).unwrap();
        assert!(f.completed && f.require_guardrails && f.mfa_ack);
        assert_eq!(SetupFile::load(&e.dir.path().join("setup.json")), f);
    }

    #[test]
    fn the_free_sandbox_needs_nothing_and_requires_nothing() {
        let e = Env::new();
        let init = e.init();
        let t = Target {
            provider: "fake".into(),
            ..Target::default()
        };
        let none = guardrails(&Settings::default(), &MemorySecrets::default(), 0);
        let f = init.finish(&t, false, &none, 7).unwrap();
        assert!(f.completed && !f.require_guardrails);
        let c = crate::config::Config::load_from(&e.dir.path().join("config.toml")).unwrap();
        assert_eq!(c.provider.as_deref(), Some("fake"));
        assert!(e.runner.calls().is_empty());
    }

    #[test]
    fn hetzner_sign_in_reads_the_token_once_and_never_echoes_it() {
        let e = Env::new();
        let init = e.init();
        assert_eq!(init.hcloud_sign_in(None).unwrap_err().code, "not_signed_in");
        e.http.reply(401, "{}");
        let err = init.hcloud_sign_in(Some("sekrit-token")).unwrap_err();
        assert_eq!(err.code, "not_signed_in");
        assert!(!err.to_string().contains("sekrit-token"));
        e.http
            .reply(200, r#"{"locations":[{"name":"fsn1"},{"name":"hel1"}]}"#);
        assert!(init.hcloud_sign_in(Some("sekrit-token")).is_ok());
        e.http
            .reply(200, r#"{"locations":[{"name":"fsn1"},{"name":"hel1"}]}"#);
        assert_eq!(init.hcloud_locations("sekrit-token"), ["fsn1", "hel1"]);
    }

    #[test]
    fn targets_are_validated_before_anything_runs() {
        let mut t2 = target();
        t2.region = Some("us-east-1; rm".into());
        assert_eq!(t2.validate().unwrap_err().code, "bad_region");
        t2.region = Some("us-east-1".into());
        t2.profile = Some("a b".into());
        assert_eq!(t2.validate().unwrap_err().code, "bad_profile");
        t2.profile = None;
        t2.provider = "gcp".into();
        assert_eq!(t2.validate().unwrap_err().code, "bad_provider");
        for ok in [
            "us-east-1",
            "eu-central-1",
            "ap-southeast-2",
            "us-gov-west-1",
        ] {
            assert!(valid_region(ok), "{ok}");
        }
        for bad in ["", "useast1", "us-east", "US-EAST-1", "us-east-12"] {
            assert!(!valid_region(bad), "{bad}");
        }
    }

    const SEC_PLAN: &str = "\n  # module.security.aws_s3_bucket.session_logs[0] will be created\n  # module.security.aws_guardduty_detector_feature.runtime[0] will be created\nPlan: 2 to add, 0 to change, 0 to destroy.\n";

    fn security_env() -> Env {
        let e = Env::new();
        std::fs::create_dir_all(e.dir.path().join("modules/aws-security-baseline")).unwrap();
        e
    }

    #[test]
    fn the_security_plan_writes_the_options_into_the_root_and_applies_nothing_while_planning() {
        let e = security_env();
        e.runner.reply(out(0, "", "")); // head-bucket
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", "")); // seed init
        e.runner.reply(out(0, "", "")); // backend init
        e.runner.reply(out(0, "", "")); // state pull: no state yet
        e.runner.reply(out(0, r#"{"DetectorIds":[]}"#, "")); // list-detectors
        e.runner.reply(out(254, "", "not found")); // describe-document: absent
        e.runner.reply(out(2, SEC_PLAN, "")); // plan
        let init = e.init();
        let o = SecurityOpts {
            guardduty_runtime: true,
            session_logs: true,
            patching: true,
            retention_days: 730,
            lock_mode: "COMPLIANCE".into(),
        };
        let p = init.plan_security(&target(), "123456789012", &o).unwrap();
        assert_eq!(p.changes.len(), 2);
        assert_eq!(
            p.estimate_usd_month, None,
            "usage-billed: no invented figure"
        );
        let notes = p.notes.join("\n");
        assert!(
            notes.contains("per vCPU")
                && notes.contains("COMPLIANCE")
                && notes.contains("730")
                && notes.contains("never restarts")
        );
        let main =
            std::fs::read_to_string(e.dir.path().join("work/security/us-east-1/main.tf")).unwrap();
        for want in [
            "backend \"s3\" {}",
            "enable_guardduty_runtime = true",
            "enable_session_logs = true",
            "session_log_retention_days = 730",
            "session_log_retention_mode = \"COMPLIANCE\"",
            "manage_session_preferences = true",
            "enable_patching = true",
        ] {
            assert!(main.contains(want), "missing {want}");
        }
        let calls = e.runner.calls();
        assert!(calls.iter().any(|c| c
            .args
            .iter()
            .any(|a| a == "-backend-config=key=ozbox/security/us-east-1.tfstate")));
        assert!(!calls.iter().any(|c| c.args.iter().any(|a| a == "apply")));
        // every cloud call before the plan only lists or describes
        for c in calls.iter().filter(|c| c.program == "aws") {
            let verb = c.args.get(1).map(String::as_str).unwrap_or("");
            assert!(
                verb.starts_with("list-") || verb.starts_with("describe-") || verb == "head-bucket",
                "{:?}",
                c.args
            );
        }
    }

    #[test]
    fn an_existing_detector_is_used_and_existing_session_preferences_are_left_alone_and_said_so() {
        let e = security_env();
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, "", "")); // backend init
        e.runner.reply(out(0, "", "")); // state pull: this module manages nothing
        e.runner.reply(out(
            0,
            r#"{"DetectorIds":["12abc34d567e8fa901bc2d34e56789f0"]}"#,
            "",
        ));
        e.runner.reply(out(0, "{}", "")); // describe-document: exists
        e.runner.reply(out(0, "", "")); // plan: nothing to do
        let init = e.init();
        let o = SecurityOpts {
            guardduty_runtime: true,
            session_logs: true,
            ..SecurityOpts::default()
        };
        let p = init.plan_security(&target(), "123456789012", &o).unwrap();
        assert!(p.noop);
        let main =
            std::fs::read_to_string(e.dir.path().join("work/security/us-east-1/main.tf")).unwrap();
        assert!(
            main.contains("existing_guardduty_detector_id = \"12abc34d567e8fa901bc2d34e56789f0\"")
        );
        assert!(main.contains("manage_session_preferences = false"));
        let notes = p.notes.join("\n");
        assert!(
            notes.contains("already has a GuardDuty detector")
                && notes.contains("already has Session Manager preferences")
        );
        assert!(notes.contains("ozbox-sessionlogs-123456789012-us-east-1"));
    }

    /// What `tofu state pull` returns after a first run that made a detector and the session preferences.
    const OWN_STATE: &str = r#"{"version":4,"serial":7,"lineage":"l","resources":[
        {"module":"module.security","mode":"managed","type":"aws_guardduty_detector","name":"this","instances":[{"index_key":0,"attributes":{"id":"12abc34d567e8fa901bc2d34e56789f0"}}]},
        {"module":"module.security","mode":"managed","type":"aws_ssm_document","name":"session_preferences","instances":[{"index_key":0,"attributes":{"name":"SSM-SessionManagerRunShell"}}]},
        {"module":"module.security","mode":"data","type":"aws_iam_policy_document","name":"session_logs","instances":[{}]}
    ]}"#;

    #[test]
    fn a_second_harden_with_the_same_options_keeps_managing_what_the_first_made() {
        // The first run made the detector and the preferences. On the second, the live APIs report both as existing, and
        // that alone used to plan their destruction. The module's own state decides instead, and the APIs are not asked.
        let e = security_env();
        e.runner.reply(out(0, "", "")); // head-bucket
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", "")); // seed init
        e.runner.reply(out(0, "", "")); // backend init
        e.runner.reply(out(0, OWN_STATE, "")); // state pull
        e.runner.reply(out(0, "", "")); // plan: nothing to do
        let init = e.init();
        let o = SecurityOpts {
            guardduty_runtime: true,
            session_logs: true,
            ..SecurityOpts::default()
        };
        let p = init.plan_security(&target(), "123456789012", &o).unwrap();
        assert!(p.noop);
        let main =
            std::fs::read_to_string(e.dir.path().join("work/security/us-east-1/main.tf")).unwrap();
        assert!(!main.contains("existing_guardduty_detector_id"), "{main}");
        assert!(main.contains("manage_session_preferences = true"), "{main}");
        let calls = e.runner.calls();
        assert!(
            !calls.iter().any(|c| c
                .args
                .iter()
                .any(|a| a == "list-detectors" || a == "describe-document")),
            "the live APIs are not asked about what the module already manages"
        );
        // the state is read after the backend is opened and before the plan
        let pos = |w: &str| {
            calls
                .iter()
                .position(|c| c.args.iter().any(|a| a == w))
                .unwrap()
        };
        assert!(pos("pull") < pos("plan"));
        let notes = p.notes.join("\n");
        assert!(
            !notes.contains("already has a GuardDuty detector"),
            "{notes}"
        );
    }

    #[test]
    fn what_the_module_manages_is_read_from_its_state_only() {
        let m = SecurityManaged::of(OWN_STATE);
        assert!(m.detector && m.preferences);
        assert_eq!(SecurityManaged::of(""), SecurityManaged::default());
        assert_eq!(SecurityManaged::of("not json"), SecurityManaged::default());
        // a resource of the same type outside the module, or with no instance, is not the module's
        let other = r#"{"resources":[{"module":"module.other","mode":"managed","type":"aws_guardduty_detector","name":"this","instances":[{}]},{"module":"module.security","mode":"managed","type":"aws_ssm_document","name":"session_preferences","instances":[]}]}"#;
        assert_eq!(SecurityManaged::of(other), SecurityManaged::default());
    }

    #[test]
    fn a_bad_lock_mode_or_retention_is_refused_before_anything_is_written() {
        let e = security_env();
        for o in [
            SecurityOpts {
                lock_mode: "SOMETIMES".into(),
                session_logs: true,
                ..SecurityOpts::default()
            },
            SecurityOpts {
                retention_days: 0,
                session_logs: true,
                ..SecurityOpts::default()
            },
        ] {
            e.runner.reply(out(0, "", ""));
            e.runner
                .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
            let err = e
                .init()
                .plan_security(&target(), "123456789012", &o)
                .unwrap_err();
            assert_eq!(err.code, "bad_security_option");
        }
        assert!(!e.dir.path().join("work/security").exists());
    }

    #[test]
    fn applying_the_security_services_records_the_bucket_and_patch_group_and_clears_what_was_turned_off(
    ) {
        let e = security_env();
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", "")); // seed init
        e.runner.reply(out(0, "", "")); // backend init
        e.runner.reply(out(0, "", "")); // state pull
        e.runner.reply(out(254, "", ""));
        e.runner.reply(out(2, SEC_PLAN, ""));
        let init = e.init();
        let o = SecurityOpts {
            session_logs: true,
            patching: true,
            ..SecurityOpts::default()
        };
        let p = init.plan_security(&target(), "123456789012", &o).unwrap();
        e.runner.reply(out(0, "", "")); // apply
        e.runner.reply(out(0, r#"{"session_log_bucket":{"value":"ozbox-sessionlogs-123456789012-us-east-1"},"patch_group":{"value":"ozbox"}}"#, ""));
        let a = init.apply(&target(), &p).unwrap();
        assert_eq!(a.patch_group.as_deref(), Some("ozbox"));
        let rec = init.recorded("aws");
        assert_eq!(
            rec.get("session_log_bucket").map(String::as_str),
            Some("ozbox-sessionlogs-123456789012-us-east-1")
        );
        // the services are turned off: their keys are cleared from the configuration
        init.persist_keys(
            &target(),
            &[("session_log_bucket", None), ("patch_group", None)],
        )
        .unwrap();
        let rec = init.recorded("aws");
        assert!(!rec.contains_key("session_log_bucket") && !rec.contains_key("patch_group"));
    }

    // ---- the fleet's secrets key and the issuer ----

    #[test]
    fn a_simulation_says_allowed_denied_or_unknown_and_never_guesses() {
        let row = |a: &str, d: &str| format!(r#"{{"EvalActionName":"{a}","EvalDecision":"{d}"}}"#);
        let all = format!(
            r#"{{"EvaluationResults":[{},{}]}}"#,
            row("kms:CreateKey", "allowed"),
            row("kms:CreateAlias", "allowed")
        );
        assert_eq!(classify_simulation(&all), KeyPermission::Allowed);
        let some = format!(
            r#"{{"EvaluationResults":[{},{}]}}"#,
            row("kms:CreateKey", "implicitDeny"),
            row("kms:CreateAlias", "allowed")
        );
        assert_eq!(
            classify_simulation(&some),
            KeyPermission::Denied(vec!["kms:CreateKey".into()])
        );
        assert_eq!(classify_simulation("{}"), KeyPermission::Unknown);
        assert_eq!(
            classify_simulation(r#"{"EvaluationResults":[]}"#),
            KeyPermission::Unknown
        );
        assert_eq!(classify_simulation("not json"), KeyPermission::Unknown);
        assert_eq!(
            session_role_name("arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/me")
                .as_deref(),
            Some("AWSReservedSSO_Admin_abc")
        );
        assert!(session_role_name("arn:aws:iam::123456789012:user/me").is_none());
    }

    #[test]
    fn the_key_permission_is_asked_with_calls_that_cannot_change_anything() {
        let e = Env::new();
        e.runner.reply(out(0, "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc\n", ""));
        e.runner.reply(out(0, r#"{"EvaluationResults":[{"EvalActionName":"kms:CreateKey","EvalDecision":"implicitDeny"}]}"#, ""));
        e.runner.reply(out(0, r#"{"EvaluationResults":[{"EvalActionName":"kms:CreateAlias","EvalDecision":"allowed"}]}"#, ""));
        e.runner.reply(out(0, r#"{"EvaluationResults":[{"EvalActionName":"kms:DescribeKey","EvalDecision":"allowed"}]}"#, ""));
        let id = parse_identity(SSO).unwrap();
        let p = e.init().key_permission(&target(), &id);
        assert_eq!(p, KeyPermission::Denied(vec!["kms:CreateKey".into()]));
        let calls = e.runner.calls();
        // the role's own ARN, then one simulation per resource type
        assert_eq!(calls.len(), 4);
        for c in &calls {
            assert_eq!(c.program, "aws");
            // only reads: a role's own ARN, and a simulation (it evaluates policies and creates nothing)
            assert!(
                c.args[0] == "iam"
                    && (c.args[1] == "get-role" || c.args[1] == "simulate-principal-policy")
            );
        }
        assert!(calls[1].args.iter().any(|a| a == "kms:CreateKey"));
        assert!(calls[3].args.iter().any(|a| a == "kms:EnableKeyRotation"));
        // an identity that is not a role session, or a check that cannot run, is unknown, not allowed
        let user = parse_identity(
            r#"{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/me"}"#,
        )
        .unwrap();
        assert_eq!(
            e.init().key_permission(&target(), &user),
            KeyPermission::Unknown
        );
        let e2 = Env::new();
        e2.runner.reply(out(254, "", "AccessDenied"));
        assert_eq!(
            e2.init().key_permission(&target(), &id),
            KeyPermission::Unknown
        );
    }

    const KEY_PLAN: &str = "Plan: 2 to add, 0 to change, 0 to destroy.\n  # module.key.aws_kms_key.secrets will be created\n  # module.key.aws_kms_alias.secrets will be created\n";

    fn key_env() -> Env {
        let e = Env::new();
        std::fs::create_dir_all(e.dir.path().join("modules/aws-secrets-key")).unwrap();
        std::fs::create_dir_all(e.dir.path().join("modules/aws-issuer")).unwrap();
        e
    }

    #[test]
    fn the_key_is_planned_into_the_state_bucket_with_no_operator_rights_and_recorded_when_applied()
    {
        let e = key_env();
        e.runner.reply(out(0, "", "")); // head-bucket
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", "")); // init with backend
        e.runner.reply(out(0, "", "")); // state list: nothing yet
        e.runner.reply(out(0, r#"{"Aliases":[]}"#, "")); // no such alias in the account
        e.runner.reply(out(2, KEY_PLAN, "")); // plan
        let init = e.init();
        let p = init.plan_key(&target(), "123456789012").unwrap();
        assert_eq!(p.step, "secrets_key");
        assert!(!p.noop && p.summary.contains("alias/ozbox-ozbox-secrets"));
        let calls = e.runner.calls();
        // planning applies nothing, and the state goes to the encrypted bucket under its own key
        assert!(!calls.iter().any(|c| c.args.iter().any(|a| a == "apply")));
        assert!(calls.iter().any(|c| c
            .args
            .iter()
            .any(|a| a == "-backend-config=key=ozbox/secrets-key/us-east-1.tfstate")));
        assert!(calls
            .iter()
            .any(|c| c.args.iter().any(|a| a == "-backend-config=encrypt=true")));
        // the generated root names no operator role, so none is given a right to the key
        let main = std::fs::read_to_string(e.dir.path().join("work/secrets-key/us-east-1/main.tf"))
            .unwrap();
        assert!(
            main.contains("account_id = \"123456789012\"") && !main.contains("operator_role_arns")
        );
        // applying records the key and the fleet
        e.runner.reply(out(0, "", "")); // apply
        e.runner.reply(out(0, r#"{"key_arn":{"value":"arn:aws:kms:us-east-1:123456789012:key/abc"},"fleet":{"value":"ozbox"}}"#, ""));
        let a = init.apply(&target(), &p).unwrap();
        assert_eq!(a.fleet.as_deref(), Some("ozbox"));
        let rec = init.recorded("aws");
        assert_eq!(
            rec.get("secrets_key_arn").map(String::as_str),
            Some("arn:aws:kms:us-east-1:123456789012:key/abc")
        );
        assert_eq!(rec.get("fleet").map(String::as_str), Some("ozbox"));
        // a key that is already there plans to nothing and runs nothing
        let e = key_env();
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(
            0,
            "module.key.aws_kms_key.secrets\nmodule.key.aws_kms_alias.secrets\n",
            "",
        ));
        e.runner.reply(out(0, "", ""));
        let p = e.init().plan_key(&target(), "123456789012").unwrap();
        assert!(p.noop && p.run.is_empty());
    }

    const NO_DOCUMENT: &str = "An error occurred (InvalidDocument) when calling the DescribeDocument operation: The specified document does not exist.";
    const NO_POLICY: &str = "An error occurred (NoSuchEntity) when calling the GetPolicy operation: Policy was not found.";

    const ADOPT_PLAN: &str = "Plan: 1 to add, 0 to change, 0 to destroy.\n  # module.adopt.aws_ssm_document.adopt will be created\n";

    fn adopt_env() -> Env {
        let e = key_env();
        std::fs::create_dir_all(e.dir.path().join("modules/aws-adopt-command")).unwrap();
        e
    }

    #[test]
    fn the_adopt_document_is_its_own_step_with_its_own_state_and_never_part_of_the_key_module() {
        let e = adopt_env();
        e.runner.reply(out(0, "", "")); // head-bucket
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", "")); // init with backend
        e.runner.reply(out(0, "", "")); // state list: nothing yet
        e.runner.reply(out(254, "", NO_DOCUMENT)); // no such document
        e.runner.reply(out(2, ADOPT_PLAN, "")); // plan
        let init = e.init();
        let p = init.plan_adopt(&target(), "123456789012").unwrap();
        assert_eq!(p.step, "adopt_command");
        assert!(!p.noop && p.summary.contains("ozbox-adopt-ozbox"));
        let calls = e.runner.calls();
        assert!(calls.iter().any(|c| c
            .args
            .iter()
            .any(|a| a == "-backend-config=key=ozbox/adopt-command/us-east-1.tfstate")));
        // the key's state is untouched by this step
        assert!(!calls
            .iter()
            .any(|c| c.args.iter().any(|a| a.contains("secrets-key"))));
        let main =
            std::fs::read_to_string(e.dir.path().join("work/adopt-command/us-east-1/main.tf"))
                .unwrap();
        assert!(main.contains("aws-adopt-command") && !main.contains("aws-secrets-key"));
        assert!(main.contains("operator_adopt_policy_json"));
        // applying writes the operator policy where the person is told to find it
        e.runner.reply(out(0, "", "")); // apply
        e.runner.reply(out(
            0,
            r#"{"Version":"2012-10-17","Statement":[{"Sid":"SendOnlyTheAdoptDocument"}]}"#,
            "",
        ));
        let a = init.apply(&target(), &p).unwrap();
        let f = a.operator_adopt_policy_file.unwrap();
        assert!(std::fs::read_to_string(f)
            .unwrap()
            .contains("SendOnlyTheAdoptDocument"));
    }

    const NO_COMMAND: &str = "An error occurred (InvocationDoesNotExist) when calling the GetCommandInvocation operation:";
    const COMMAND_DENIED: &str = "An error occurred (AccessDeniedException) when calling the GetCommandInvocation operation: User is not authorized to perform: ssm:GetCommandInvocation";

    #[test]
    fn the_operator_policy_is_written_whole_on_every_run_and_names_the_adopt_statements() {
        let e = Env::new();
        let init = e.init();
        // no daily profile recorded: nothing is asked of AWS, and the file is still written
        let r = init.operator_policy(&target(), "123456789012").unwrap();
        assert_eq!(r.operator_check, OperatorCheck::NotChecked);
        assert!(e.runner.calls().is_empty());
        let text = std::fs::read_to_string(&r.file).unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        for sid in operator_policy::ADOPT_STATEMENTS {
            assert!(text.contains(sid), "{sid} is in the written policy");
        }
        // every older statement is still there, so applying the file drops nothing the operator had
        assert!(text.contains("TagOnCreateOnly") && text.contains("AttachTheFleetKeyPolicy"));
        assert!(text.contains("document/ozbox-adopt-ozbox"));
        for left in ["${account_id}", "${region}", "${fleet}"] {
            assert!(!text.contains(left), "{left} left unfilled");
        }
        assert_eq!(r.adopt_statements.len(), 3);
        // a second run writes the same file: nothing is appended or duplicated
        let again = init.operator_policy(&target(), "123456789012").unwrap();
        let doc2: Value =
            serde_json::from_str(&std::fs::read_to_string(&again.file).unwrap()).unwrap();
        assert_eq!(doc, doc2);
        let sids: Vec<&str> = doc["Statement"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["Sid"].as_str().unwrap())
            .collect();
        let unique: std::collections::BTreeSet<_> = sids.iter().collect();
        assert_eq!(sids.len(), unique.len());
        // a fleet in the config is the fleet in the policy
        std::fs::write(
            e.dir.path().join("config.toml"),
            "[aws]\nfleet = \"acme\"\n",
        )
        .unwrap();
        let r = init.operator_policy(&target(), "123456789012").unwrap();
        assert!(std::fs::read_to_string(&r.file)
            .unwrap()
            .contains("document/ozbox-adopt-acme"));
    }

    #[test]
    fn the_daily_sign_in_is_asked_with_a_read_of_a_command_that_does_not_exist() {
        for (reply, want) in [
            (out(254, "", NO_COMMAND), OperatorCheck::Allowed),
            (out(254, "", COMMAND_DENIED), OperatorCheck::Denied),
            (
                out(255, "", "Error loading SSO Token"),
                OperatorCheck::Unknown,
            ),
        ] {
            let e = Env::new();
            std::fs::write(
                e.dir.path().join("config.toml"),
                "[aws]\nprofile = \"ozbox-operator\"\n",
            )
            .unwrap();
            e.runner.reply(reply);
            let r = e.init().operator_policy(&target(), "123456789012").unwrap();
            assert_eq!(r.operator_check, want);
            let calls = e.runner.calls();
            assert_eq!(calls.len(), 1);
            let args = calls[0].args.join(" ");
            // the operator's own profile, a read, and nothing sent
            assert!(
                args.contains("ssm get-command-invocation")
                    && args.contains("--profile ozbox-operator"),
                "{args}"
            );
            assert!(!args.contains("send-command"));
        }
    }

    #[test]
    fn the_adopt_permission_is_asked_for_systems_manager_document_actions_and_not_kms() {
        let e = Env::new();
        e.runner.reply(out(0, "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc\n", ""));
        e.runner.reply(out(0, r#"{"EvaluationResults":[{"EvalActionName":"ssm:CreateDocument","EvalDecision":"implicitDeny"}]}"#, ""));
        let id = parse_identity(SSO).unwrap();
        let p = e.init().adopt_permission(&target(), &id);
        assert_eq!(p, KeyPermission::Denied(vec!["ssm:CreateDocument".into()]));
        let calls = e.runner.calls();
        assert!(calls[1].args.iter().any(|a| a == "ssm:CreateDocument"));
        assert!(!calls[1].args.iter().any(|a| a.starts_with("kms:")));
        assert!(ADOPT_ACTIONS.iter().all(|a| a.starts_with("ssm:")));
    }

    #[test]
    fn the_adopt_check_asks_for_exactly_what_the_apply_calls_and_against_the_documents_arn() {
        use ozbox_provider_aws::init_actions::resource_actions;
        // the pre-check list is the table's row for the document, no more and no less
        let mut row: Vec<&str> = resource_actions("aws_ssm_document").unwrap().to_vec();
        let mut asked: Vec<&str> = ADOPT_ACTIONS.to_vec();
        row.sort_unstable();
        asked.sort_unstable();
        assert_eq!(asked, row);
        // a simulation with no resource ARN runs against `*`, which a resource-scoped Allow does not match: they are passed
        let e = Env::new();
        e.runner.reply(out(0, "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc\n", ""));
        e.runner.reply(out(0, r#"{"EvaluationResults":[{"EvalActionName":"ssm:CreateDocument","EvalDecision":"allowed"}]}"#, ""));
        let id = parse_identity(SSO).unwrap();
        assert_eq!(
            e.init().adopt_permission(&target(), &id),
            KeyPermission::Allowed
        );
        let sim = &e.runner.calls()[1].args;
        let at = sim.iter().position(|a| a == "--resource-arns").unwrap();
        assert_eq!(
            sim[at + 1],
            "arn:aws:ssm:us-east-1:123456789012:document/ozbox-adopt-ozbox"
        );
        assert_eq!(sim[at + 2], "--output");
        // the action names come before the resources, and every action is there once
        let names = sim.iter().position(|a| a == "--action-names").unwrap();
        assert_eq!(&sim[names + 1..at], ADOPT_ACTIONS.map(String::from));
    }

    #[test]
    fn the_key_check_asks_for_exactly_what_the_key_module_creates_and_reads_back() {
        use ozbox_provider_aws::init_actions::resource_actions;
        // the exact set: the key's row without its update and destroy actions, plus the alias's create
        let mut want: Vec<&str> = resource_actions("aws_kms_key")
            .unwrap()
            .iter()
            .copied()
            .filter(|a| *a != "kms:UpdateKeyDescription" && *a != "kms:ScheduleKeyDeletion")
            .collect();
        want.push("kms:CreateAlias");
        want.sort_unstable();
        let mut asked: Vec<&str> = KEY_ACTIONS.to_vec();
        asked.sort_unstable();
        assert_eq!(asked, want);
        // the read-back calls the first version left out
        assert!(
            KEY_ACTIONS.contains(&"kms:GetKeyPolicy")
                && KEY_ACTIONS.contains(&"kms:ListResourceTags")
        );
    }

    #[test]
    fn each_key_action_is_simulated_against_its_own_resource_type_under_the_apply_context() {
        let reqs = key_sim_requests("us-east-1", "123456789012", "ozbox");
        let key = "arn:aws:kms:us-east-1:123456789012:key/*".to_string();
        let alias = "arn:aws:kms:us-east-1:123456789012:alias/ozbox-ozbox-secrets".to_string();
        let find = |a: &str| reqs.iter().find(|r| r.actions.contains(&a)).unwrap();
        assert_eq!(find("kms:CreateKey").resources, vec!["*".to_string()]);
        assert_eq!(
            find("kms:CreateAlias").resources,
            vec![alias.clone(), key.clone()]
        );
        for a in KEY_ACTIONS {
            if a != "kms:CreateKey" && a != "kms:CreateAlias" {
                // a key action is never asked against the alias, where it can only be an implicit deny
                assert_eq!(find(a).resources, vec![key.clone()], "{a}");
            }
        }
        // every action exactly once
        let mut all: Vec<&str> = reqs.iter().flat_map(|r| r.actions.clone()).collect();
        all.sort_unstable();
        let mut want = KEY_ACTIONS.to_vec();
        want.sort_unstable();
        assert_eq!(all, want);
        // the context the apply sends
        for r in &reqs {
            assert!(r
                .context
                .contains(&("aws:RequestTag/ozbox-managed", "string", "true")));
            assert!(r
                .context
                .contains(&("aws:ResourceTag/ozbox-managed", "string", "true")));
            assert!(r
                .context
                .contains(&("aws:TagKeys", "stringList", "ozbox-managed")));
        }
        // and it reaches the CLI call, once per request, ahead of `--output`
        let e = Env::new();
        e.runner.reply(out(0, "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc\n", ""));
        for a in ["kms:CreateKey", "kms:CreateAlias", "kms:DescribeKey"] {
            e.runner.reply(out(0, &format!(r#"{{"EvaluationResults":[{{"EvalActionName":"{a}","EvalDecision":"allowed"}}]}}"#), ""));
        }
        let id = parse_identity(SSO).unwrap();
        assert_eq!(
            e.init().key_permission(&target(), &id),
            KeyPermission::Allowed
        );
        let calls = e.runner.calls();
        assert_eq!(calls.len(), 4);
        let sim = &calls[2].args;
        let ra = sim.iter().position(|a| a == "--resource-arns").unwrap();
        let ce = sim.iter().position(|a| a == "--context-entries").unwrap();
        assert_eq!(&sim[ra + 1..ce], [alias, key]);
        assert_eq!(sim[ce + 1], "ContextKeyName=aws:RequestTag/ozbox-managed,ContextKeyValues=true,ContextKeyType=string");
        assert_eq!(
            sim[ce + 3],
            "ContextKeyName=aws:TagKeys,ContextKeyValues=ozbox-managed,ContextKeyType=stringList"
        );
        assert_eq!(sim[ce + 4], "--output");
        // a request that cannot be read is unknown, and a denied action wins over it
        let e = Env::new();
        e.runner.reply(out(0, "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc\n", ""));
        e.runner.reply(out(254, "", "Throttling"));
        e.runner.reply(out(0, r#"{"EvaluationResults":[{"EvalActionName":"kms:CreateAlias","EvalDecision":"implicitDeny"}]}"#, ""));
        e.runner.reply(out(0, r#"{"EvaluationResults":[{"EvalActionName":"kms:DescribeKey","EvalDecision":"allowed"}]}"#, ""));
        assert_eq!(
            e.init().key_permission(&target(), &id),
            KeyPermission::Denied(vec!["kms:CreateAlias".into()])
        );
    }

    /// A small stand-in for IAM, enough for `key-admin-policy.json`: an action is allowed when an Allow statement matches its
    /// action, resource and conditions, and no Deny statement does. `StringEquals` and `ForAllValues:StringLike`, with a missing
    /// context key making a condition false, as the simulation treats it.
    fn glob_match(pattern: &str, text: &str) -> bool {
        match pattern.split_once('*') {
            None => pattern == text,
            Some((head, rest)) => text.strip_prefix(head).is_some_and(|t| {
                (0..=t.len()).any(|i| t.is_char_boundary(i) && glob_match(rest, &t[i..]))
            }),
        }
    }

    fn strs(v: &Value) -> Vec<String> {
        match v {
            Value::String(s) => vec![s.clone()],
            Value::Array(a) => a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn condition_holds(cond: Option<&Value>, ctx: &[(&str, &str, &str)]) -> bool {
        let Some(Value::Object(ops)) = cond else {
            return true;
        };
        ops.iter().all(|(op, keys)| {
            let Value::Object(keys) = keys else {
                return false;
            };
            keys.iter().all(|(k, want)| {
                let Some((_, _, have)) = ctx.iter().find(|(n, _, _)| n == k) else {
                    return false;
                };
                let have: Vec<&str> = have.split(',').collect();
                let want = strs(want);
                match op.as_str() {
                    "StringEquals" => want.iter().any(|w| have.contains(&w.as_str())),
                    "ForAllValues:StringLike" => {
                        have.iter().all(|h| want.iter().any(|w| glob_match(w, h)))
                    }
                    // a condition kind this stand-in does not know is a failure, never a quiet pass
                    _ => false,
                }
            })
        })
    }

    fn policy_allows(policy: &Value, req: &SimRequest, action: &str) -> bool {
        let hits = |st: &Value, resource: &str| {
            strs(&st["Action"]).iter().any(|a| glob_match(a, action))
                && strs(&st["Resource"])
                    .iter()
                    .any(|r| glob_match(r, resource))
                && condition_holds(st.get("Condition"), &req.context)
        };
        let stmts = policy["Statement"].as_array().cloned().unwrap_or_default();
        req.resources.iter().all(|res| {
            let allow = stmts.iter().any(|s| s["Effect"] == "Allow" && hits(s, res));
            let deny = stmts.iter().any(|s| s["Effect"] == "Deny" && hits(s, res));
            allow && !deny
        })
    }

    #[test]
    fn an_identity_holding_only_the_key_admin_policy_is_simulated_as_allowed_under_the_apply_context(
    ) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../infra/aws/key-admin-policy.json");
        let text = std::fs::read_to_string(path)
            .unwrap()
            .replace("${account_id}", "123456789012");
        let policy: Value = serde_json::from_str(&text).unwrap();
        let reqs = key_sim_requests("us-east-1", "123456789012", "ozbox");
        for r in &reqs {
            for a in &r.actions {
                assert!(
                    policy_allows(&policy, r, a),
                    "{a} against {:?}",
                    r.resources
                );
            }
        }
        // the same requests with no context, as before, are denied: the context is what makes the difference
        for r in &reqs {
            let bare = SimRequest {
                context: Vec::new(),
                ..r.clone()
            };
            assert!(
                r.actions.iter().any(|a| !policy_allows(&policy, &bare, a)),
                "{:?} should need the context",
                r.actions
            );
        }
        // and a key action asked against the alias, as the first version did, is an implicit deny whatever the context
        let on_alias = SimRequest {
            actions: vec!["kms:DescribeKey"],
            resources: vec!["arn:aws:kms:us-east-1:123456789012:alias/ozbox-ozbox-secrets".into()],
            context: KEY_CONTEXT.to_vec(),
        };
        assert!(!policy_allows(&policy, &on_alias, "kms:DescribeKey"));
        // the production key stays out of reach: a Deny on its tag still wins
        let mut prod = reqs[2].clone();
        prod.context
            .push(("aws:ResourceTag/ozbox-production", "string", "true"));
        assert!(!policy_allows(&policy, &prod, "kms:PutKeyPolicy"));
    }

    #[test]
    fn the_messages_that_name_the_operator_policy_name_the_module_that_outputs_it() {
        let m = t(
            "upgrade.store_root_unreachable",
            &[("box", "b"), ("why", "w")],
        );
        assert!(m.contains("aws-adopt-command"), "{m}");
        assert!(!m.contains("aws-secrets-key"), "{m}");
    }

    #[test]
    fn an_answer_that_is_not_a_key_is_not_recorded() {
        let e = key_env();
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, "", "")); // state list
        e.runner.reply(out(0, r#"{"Aliases":[]}"#, "")); // no alias
        e.runner.reply(out(2, KEY_PLAN, ""));
        let init = e.init();
        let p = init.plan_key(&target(), "123456789012").unwrap();
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(
            0,
            r#"{"key_arn":{"value":"nope"},"fleet":{"value":"ozbox"}}"#,
            "",
        ));
        assert!(init.apply(&target(), &p).is_err());
        assert!(!init.recorded("aws").contains_key("secrets_key_arn"));
    }

    #[test]
    fn the_issuer_is_planned_from_the_named_package_with_its_hash_and_recorded_when_applied() {
        let e = key_env();
        let pkg = e.dir.path().join("issuer.zip");
        std::fs::write(&pkg, b"zip bytes").unwrap();
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(2, "Plan: 12 to add, 0 to change, 0 to destroy.\n  # module.issuer.aws_lambda_function.issuer will be created\n", ""));
        let init = e.init();
        let hex: String = ring::digest::digest(&ring::digest::SHA256, b"zip bytes")
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        // the hash must be given, and must be the file's: a wrong one, a missing one and a made-up one are refused before any call
        for bad in ["", "abc", &"0".repeat(64)] {
            assert!(
                init.plan_issuer(&target(), "123456789012", &pkg, bad)
                    .is_err(),
                "{bad}"
            );
        }
        assert!(e.runner.calls().is_empty());
        let p = init
            .plan_issuer(&target(), "123456789012", &pkg, &hex)
            .unwrap();
        assert_eq!(p.step, "issuer");
        let main =
            std::fs::read_to_string(e.dir.path().join("work/issuer/us-east-1/main.tf")).unwrap();
        let sha = crate::serve::auth::b64::encode_std(
            ring::digest::digest(&ring::digest::SHA256, b"zip bytes").as_ref(),
        );
        assert!(
            main.contains(&format!("package_sha256 = \"{sha}\""))
                && main.contains("region         = \"us-east-1\"")
        );
        assert!(!e
            .runner
            .calls()
            .iter()
            .any(|c| c.args.iter().any(|a| a == "apply")));
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, r#"{"function_url":{"value":"https://abc.lambda-url.us-east-1.on.aws/"},"function_arn":{"value":"arn:aws:lambda:us-east-1:123456789012:function:ozbox-ozbox-issuer"}}"#, ""));
        let a = init.apply(&target(), &p).unwrap();
        assert!(a.issuer_url.is_some());
        assert!(init.recorded("aws").contains_key("issuer_url"));
        // a package that is not there is said plainly, and nothing ran
        let e = key_env();
        assert!(e
            .init()
            .plan_issuer(
                &target(),
                "123456789012",
                &e.dir.path().join("missing.zip"),
                &"0".repeat(64)
            )
            .is_err());
        assert!(e.runner.calls().is_empty());
    }

    /// the issuer's OpenTofu state (and every setup-identity state) is in `Init::bucket_name`, a bucket the daily
    /// operator cannot write. The operator's S3 rights are `ozbox-tfstate-*` (box state); the two names must never overlap, or
    /// the operator could tamper with a plan the person is about to approve.
    #[test]
    fn the_issuer_state_bucket_is_outside_every_s3_resource_the_operator_may_write() {
        let policy: serde_json::Value =
            serde_json::from_str(include_str!("../../../infra/aws/operator-policy.json")).unwrap();
        let bucket = Init::bucket_name("123456789012", "us-east-1");
        let arn = format!("arn:aws:s3:::{bucket}/ozbox/issuer/us-east-1.tfstate");
        for s in policy["Statement"].as_array().unwrap() {
            if s["Effect"] != "Allow" {
                continue;
            }
            let s3 = s["Action"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .any(|x| x.as_str().is_some_and(|x| x.starts_with("s3:")))
                })
                .unwrap_or_else(|| s["Action"].as_str().is_some_and(|x| x.starts_with("s3:")));
            if !s3 {
                continue;
            }
            let res: Vec<&str> = match &s["Resource"] {
                serde_json::Value::String(r) => vec![r.as_str()],
                serde_json::Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect(),
                _ => vec![],
            };
            for r in res {
                let prefix = r.trim_end_matches('*');
                assert!(
                    r.ends_with('*') && !arn.starts_with(prefix),
                    "{r} reaches the issuer state"
                );
            }
        }
    }

    #[test]
    fn the_box_policy_is_planned_once_for_the_account_and_attaches_nothing() {
        let e = key_env();
        std::fs::create_dir_all(e.dir.path().join("modules/aws-box-policy")).unwrap();
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, "", "")); // state list
        e.runner.reply(out(254, "", NO_POLICY)); // no session policy yet
        e.runner.reply(out(254, "", NO_POLICY)); // no parameters policy yet
        e.runner.reply(out(2, "Plan: 1 to add, 0 to change, 0 to destroy.\n  # module.policy.aws_iam_policy.session will be created\n", ""));
        let init = e.init();
        let p = init.plan_box_policy(&target(), "123456789012").unwrap();
        assert_eq!(p.step, "box_policy");
        assert!(!p.noop && p.summary.contains("ozbox-box-session-manager"));
        let calls = e.runner.calls();
        // one state for the whole account, whatever the region; nothing applied while planning
        assert!(calls.iter().any(|c| c
            .args
            .iter()
            .any(|a| a == "-backend-config=key=ozbox/box-policy/account.tfstate")));
        assert!(!calls.iter().any(|c| c.args.iter().any(|a| a == "apply")));
        let main = std::fs::read_to_string(e.dir.path().join("work/box-policy/us-east-1/main.tf"))
            .unwrap();
        assert!(main.contains("aws-box-policy") || main.contains("module \"policy\""));
        assert!(!main.contains("AmazonSSM"));
    }

    // ----- adopting what is already there (ADR 0053) -----

    const KEY_ID: &str = "1234abcd-12ab-34cd-56ef-1234567890ab";
    const KEY_ARN: &str =
        "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    const OTHER_KEY_ARN: &str =
        "arn:aws:kms:us-east-1:123456789012:key/ffffffff-12ab-34cd-56ef-1234567890ab";

    fn aliases_with(alias: &str) -> String {
        format!(
            r#"{{"Aliases":[{{"AliasName":"alias/aws/ebs","TargetKeyId":"aaaa"}},{{"AliasName":"{alias}","TargetKeyId":"{KEY_ID}"}}]}}"#
        )
    }

    const TAGGED_KEY: &str = r#"{"Tags":[{"TagKey":"ozbox-managed","TagValue":"true"},{"TagKey":"ozbox-fleet","TagValue":"ozbox"}]}"#;
    const OTHER_KEY: &str = r#"{"Tags":[{"TagKey":"team","TagValue":"data"}]}"#;
    const TAGGED_DOCUMENT: &str = r#"{"Document":{"Name":"ozbox-adopt-ozbox","Tags":[{"Key":"ozbox-managed","Value":"true"}]}}"#;
    const TAGGED_POLICY: &str =
        r#"{"Policy":{"PolicyName":"x","Tags":[{"Key":"ozbox-managed","Value":"true"}]}}"#;
    const DENIED: &str = "An error occurred (AccessDeniedException) when calling the ListResourceTags operation: not authorized";

    /// Queue what every state-module plan reads first: the bucket, the OpenTofu version and the backend init.
    fn queue_prologue(e: &Env) {
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        e.runner.reply(out(0, "", ""));
    }

    fn policy_env() -> Env {
        let e = key_env();
        std::fs::create_dir_all(e.dir.path().join("modules/aws-box-policy")).unwrap();
        std::fs::create_dir_all(e.dir.path().join("modules/aws-adopt-command")).unwrap();
        e
    }

    fn adopt_tf(e: &Env, dir: &str) -> String {
        std::fs::read_to_string(
            e.dir
                .path()
                .join("work")
                .join(dir)
                .join("us-east-1/adopt.tf"),
        )
        .unwrap_or_default()
    }

    #[test]
    fn an_existing_key_and_alias_are_adopted_not_created_a_second_time() {
        let e = key_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", "")); // state list: this step has no state yet
        e.runner
            .reply(out(0, &aliases_with("alias/ozbox-ozbox-secrets"), ""));
        e.runner.reply(out(0, TAGGED_KEY, "")); // the key carries the tag
                                                // the key's policy differs from the module's: shown as an in-place change, never a replacement
        e.runner.reply(out(2, "Plan: 2 to import, 0 to add, 1 to change, 0 to destroy.\n  # module.key.aws_kms_key.secrets will be updated in-place\n  # (imported from \"1234abcd\")\n", ""));
        let p = e.init().plan_key(&target(), "123456789012").unwrap();
        let said: Vec<&str> = p.changes.iter().map(|c| c.description.as_str()).collect();
        assert!(
            said.iter().any(|d| d.starts_with("Adopt existing KMS key")
                && d.contains(KEY_ID)
                && d.contains("module.key.aws_kms_key.secrets")),
            "{said:?}"
        );
        assert!(said
            .iter()
            .any(|d| d.starts_with("Adopt existing KMS alias")
                && d.contains("alias/ozbox-ozbox-secrets")));
        // no create for either, and the remaining difference is listed honestly
        assert!(
            !p.changes.iter().any(|c| c.kind == "network.create"),
            "{said:?}"
        );
        assert!(p.changes.iter().any(|c| c.kind == "network.update"));
        assert!(!p.noop && !p.run.is_empty());
        // the import blocks sit beside the generated root, one for each, by the ids found
        let tf = adopt_tf(&e, "secrets-key");
        assert!(
            tf.contains("to = module.key.aws_kms_key.secrets")
                && tf.contains(&format!("id = \"{KEY_ID}\""))
        );
        assert!(
            tf.contains("to = module.key.aws_kms_alias.secrets")
                && tf.contains("id = \"alias/ozbox-ozbox-secrets\"")
        );
        // lookups only read, and the plan is written before anything is applied
        let calls = e.runner.calls();
        assert!(calls
            .iter()
            .any(|c| c.args.iter().any(|a| a == "list-aliases")));
        assert!(!calls.iter().any(|c| c.args.iter().any(|a| a == "apply")));
        assert!(p.notes.iter().any(|n| n.contains("Adopt existing")));
    }

    #[test]
    fn a_key_the_config_already_records_is_adopted_when_the_alias_is_gone_and_a_disagreement_is_refused(
    ) {
        // recorded, no alias: the recorded key is adopted and only the alias is made
        let e = key_env();
        e.init()
            .persist(
                &target(),
                &[("secrets_key_arn", KEY_ARN), ("fleet", "ozbox")],
            )
            .unwrap();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, r#"{"Aliases":[]}"#, ""));
        e.runner.reply(out(0, TAGGED_KEY, ""));
        e.runner.reply(out(2, "Plan: 1 to import, 1 to add, 0 to change, 0 to destroy.\n  # module.key.aws_kms_alias.secrets will be created\n", ""));
        let p = e.init().plan_key(&target(), "123456789012").unwrap();
        assert!(p
            .changes
            .iter()
            .any(|c| c.kind == "adopt.import" && c.description.contains(KEY_ID)));
        assert!(!p
            .changes
            .iter()
            .any(|c| c.description.starts_with("Create kms key")));
        assert!(adopt_tf(&e, "secrets-key").contains("aws_kms_key.secrets"));
        assert!(!adopt_tf(&e, "secrets-key").contains("aws_kms_alias"));
        // recorded one key, the alias points at another: neither is picked
        let e = key_env();
        e.init()
            .persist(
                &target(),
                &[("secrets_key_arn", OTHER_KEY_ARN), ("fleet", "ozbox")],
            )
            .unwrap();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, &aliases_with("alias/ozbox-ozbox-secrets"), ""));
        let err = e.init().plan_key(&target(), "123456789012").unwrap_err();
        assert_eq!(err.code, "adopt_mismatch");
    }

    #[test]
    fn an_existing_adopt_document_is_imported() {
        let e = adopt_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, TAGGED_DOCUMENT, ""));
        e.runner.reply(out(0, "", "")); // plan: nothing else differs
        let p = e.init().plan_adopt(&target(), "123456789012").unwrap();
        assert!(
            !p.noop && !p.run.is_empty(),
            "an import must still be applied to record it"
        );
        assert!(
            p.changes.len() == 1
                && p.changes[0]
                    .description
                    .contains("Adopt existing Systems Manager document ozbox-adopt-ozbox")
        );
        let tf = adopt_tf(&e, "adopt-command");
        assert!(
            tf.contains("to = module.adopt.aws_ssm_document.adopt")
                && tf.contains("id = \"ozbox-adopt-ozbox\"")
        );
    }

    #[test]
    fn existing_box_policies_are_imported_and_the_next_plan_shows_no_change() {
        let e = policy_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, TAGGED_POLICY, ""));
        e.runner.reply(out(0, TAGGED_POLICY, ""));
        e.runner.reply(out(0, "", ""));
        let p = e.init().plan_box_policy(&target(), "123456789012").unwrap();
        assert_eq!(
            p.changes
                .iter()
                .filter(|c| c.kind == "adopt.import")
                .count(),
            2
        );
        let tf = adopt_tf(&e, "box-policy");
        assert!(tf.contains("to = module.policy.aws_iam_policy.session\n"));
        assert!(tf.contains("id = \"arn:aws:iam::123456789012:policy/ozbox-box-session-manager\""));
        assert!(tf.contains("id = \"arn:aws:iam::123456789012:policy/ozbox-box-parameters\""));
        // once applied they are in the state: no lookup, no import file, nothing to do
        let e2 = policy_env();
        std::fs::create_dir_all(e2.dir.path().join("work/box-policy/us-east-1")).unwrap();
        std::fs::write(
            e2.dir.path().join("work/box-policy/us-east-1/adopt.tf"),
            "stale",
        )
        .unwrap();
        queue_prologue(&e2);
        e2.runner.reply(out(
            0,
            "module.policy.aws_iam_policy.session\nmodule.policy.aws_iam_policy.parameters\n",
            "",
        ));
        e2.runner.reply(out(0, "", ""));
        let p = e2
            .init()
            .plan_box_policy(&target(), "123456789012")
            .unwrap();
        assert!(p.noop && p.run.is_empty());
        assert!(!e2
            .runner
            .calls()
            .iter()
            .any(|c| c.args.iter().any(|a| a == "get-policy")));
        assert!(!e2
            .dir
            .path()
            .join("work/box-policy/us-east-1/adopt.tf")
            .exists());
    }

    #[test]
    fn the_counted_policies_are_looked_for_only_when_the_module_makes_them() {
        let e = policy_env();
        e.init()
            .persist(
                &target(),
                &[
                    ("secrets_key_arn", KEY_ARN),
                    ("fleet", "ozbox"),
                    ("session_log_bucket", "logs-bucket"),
                ],
            )
            .unwrap();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        for _ in 0..4 {
            e.runner.reply(out(0, TAGGED_POLICY, ""));
        }
        e.runner.reply(out(0, "", ""));
        let p = e.init().plan_box_policy(&target(), "123456789012").unwrap();
        assert_eq!(p.changes.len(), 4);
        let tf = adopt_tf(&e, "box-policy");
        assert!(tf.contains("to = module.policy.aws_iam_policy.fleet_key[0]"));
        assert!(tf.contains("to = module.policy.aws_iam_policy.session_logs[0]"));
        assert!(tf.contains("policy/ozbox-box-fleet-key-ozbox"));
    }

    #[test]
    fn a_look_alike_without_the_ozbox_tag_is_refused_and_says_why() {
        // a document
        let e = adopt_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(
            0,
            r#"{"Document":{"Name":"ozbox-adopt-ozbox","Tags":[{"Key":"team","Value":"x"}]}}"#,
            "",
        ));
        let err = e.init().plan_adopt(&target(), "123456789012").unwrap_err();
        assert_eq!(err.code, "adopt_untagged");
        assert!(
            err.message.contains("ozbox-adopt-ozbox")
                && err.message.contains("not tagged ozbox-managed=true"),
            "{err}"
        );
        assert!(err.fix.is_some());
        assert!(!adopt_tf(&e, "adopt-command").contains("import"));
        // a key whose tags are there but not ours
        let e = key_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, &aliases_with("alias/ozbox-ozbox-secrets"), ""));
        e.runner.reply(out(0, OTHER_KEY, ""));
        assert_eq!(
            e.init()
                .plan_key(&target(), "123456789012")
                .unwrap_err()
                .code,
            "adopt_untagged"
        );
        // a key whose tags the setup rights cannot read is the same refusal, with its own reason
        let e = key_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner
            .reply(out(0, &aliases_with("alias/ozbox-ozbox-secrets"), ""));
        e.runner.reply(out(254, "", DENIED));
        let err = e.init().plan_key(&target(), "123456789012").unwrap_err();
        assert_eq!(err.code, "adopt_untagged");
        assert!(
            err.message.contains("could not read it as one of its own"),
            "{err}"
        );
        // a policy
        let e = policy_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, r#"{"Policy":{"Tags":[]}}"#, ""));
        let err = e
            .init()
            .plan_box_policy(&target(), "123456789012")
            .unwrap_err();
        assert_eq!(err.code, "adopt_untagged");
        assert!(err.message.contains("ozbox-box-session-manager"));
    }

    #[test]
    fn a_lookup_that_cannot_answer_stops_the_step_instead_of_planning_a_create() {
        let e = adopt_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(254, "", "An error occurred (AccessDeniedException) when calling the DescribeDocument operation: nope"));
        let err = e.init().plan_adopt(&target(), "123456789012").unwrap_err();
        assert_eq!(err.code, "adopt_lookup_failed");
        // an answer that is not readable is not "absent" either
        let e = adopt_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(0, "not json", ""));
        assert_eq!(
            e.init()
                .plan_adopt(&target(), "123456789012")
                .unwrap_err()
                .code,
            "adopt_lookup_failed"
        );
        // and the plan is never reached
        assert!(!e
            .runner
            .calls()
            .iter()
            .any(|c| c.args.iter().any(|a| a == "plan")));
    }

    #[test]
    fn a_plan_that_would_replace_or_remove_what_was_adopted_is_refused() {
        for verb in ["must be replaced", "will be destroyed"] {
            let e = policy_env();
            queue_prologue(&e);
            e.runner.reply(out(0, "", ""));
            e.runner.reply(out(0, TAGGED_POLICY, ""));
            e.runner.reply(out(254, "", NO_POLICY));
            e.runner.reply(out(
                2,
                &format!("Plan: 1 to import, 1 to add, 0 to change, 1 to destroy.\n  # module.policy.aws_iam_policy.session {verb}\n  # module.policy.aws_iam_policy.parameters will be created\n"),
                "",
            ));
            let err = e
                .init()
                .plan_box_policy(&target(), "123456789012")
                .unwrap_err();
            assert_eq!(err.code, "adopt_replace", "{verb}");
            assert!(err.message.contains("module.policy.aws_iam_policy.session"));
        }
        // a replacement of something that was NOT adopted is not this refusal's business
        let e = policy_env();
        queue_prologue(&e);
        e.runner.reply(out(0, "", ""));
        e.runner.reply(out(254, "", NO_POLICY));
        e.runner.reply(out(254, "", NO_POLICY));
        e.runner.reply(out(2, "Plan: 1 to add, 1 to destroy.\n  # module.policy.aws_iam_policy.session must be replaced\n", ""));
        assert!(e.init().plan_box_policy(&target(), "123456789012").is_ok());
    }

    #[test]
    fn the_import_file_is_written_for_what_was_found_and_removed_when_nothing_is() {
        let d = tempfile::tempdir().unwrap();
        let one = adopt::Adopted {
            address: "module.x.aws_thing.y[0]".into(),
            what: "thing",
            id: "abc-123".into(),
        };
        adopt::write_imports(d.path(), &[one]).unwrap();
        let text = std::fs::read_to_string(d.path().join(adopt::ADOPT_FILE)).unwrap();
        assert!(text.contains("import {\n  to = module.x.aws_thing.y[0]\n  id = \"abc-123\"\n}"));
        adopt::write_imports(d.path(), &[]).unwrap();
        assert!(!d.path().join(adopt::ADOPT_FILE).exists());
        // removing what is not there is not an error
        adopt::write_imports(d.path(), &[]).unwrap();
    }
}
