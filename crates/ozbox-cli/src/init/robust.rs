//! What keeps `ozbox init` from leaving an account half set up, and from telling a person the wrong thing:
//!
//! * **Sign-in failures are told apart.** An AWS outage (a 5xx answer), throttling and a network that cannot reach AWS are
//!   never reported as "you are not signed in"; an expired login, a missing profile and refused keys each name their own next
//!   step ([`classify_sign_in_failure`]).
//! * **Quotas are read before the network is planned to be made.** The network needs one Elastic IP address and one NAT
//!   gateway; an account with none free is refused in the plan with the numbers, not half-way through an apply
//!   ([`Init::network_quota_preflight`]).
//! * **A half-applied step is rolled back.** A step that only creates is planned with the command that removes exactly what it
//!   was creating, run if its apply fails part way ([`destroy_created`]).
//! * **One pinned AWS plugin and one lock file** for every step ([`AWS_PROVIDER_VERSION`], [`Init::ensure_provider_lock`]).
//! * **A dry run previews every step**, even before the state bucket exists: each step is planned against an empty local state
//!   in a scratch folder ([`Init::preview_root`]); such a plan carries no command and cannot be applied.
//!
//! Everything here reads, or writes this program's own scratch files; nothing changes the account.

use std::path::{Path, PathBuf};

use ozbox_core::CommandSpec;
use serde_json::Value;

use super::{Finding, Init, Res, Target};
use crate::messages::t;

// ---------- sign-in ----------

/// Why `aws sts get-caller-identity` failed, read from what the AWS CLI printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInFailure {
    /// AWS answered with a service error (500, 503, `ServiceUnavailable`, `InternalFailure`): not the person's login.
    Unavailable,
    /// AWS is limiting requests (`Throttling`, `RequestLimitExceeded`, "Rate exceeded").
    Throttled,
    /// No answer at all: no network, a proxy, a name that does not resolve.
    Unreachable,
    /// The login was there and has expired (an SSO session or a session token).
    Expired,
    /// The named profile is not configured on this computer.
    NoProfile,
    /// Keys were sent and AWS refused them (wrong or revoked).
    BadKeys,
    /// No credentials at all.
    NotSignedIn,
}

/// The kind of a sign-in failure, or `None` when the text names none of them. Outages are checked before logins: a 503 is
/// never a reason to sign in again.
pub fn classify_sign_in_failure(stderr: &str) -> Option<SignInFailure> {
    let has = |needles: &[&str]| needles.iter().any(|n| stderr.contains(n));
    if has(&[
        "ServiceUnavailable",
        "Service Unavailable",
        "InternalFailure",
        "InternalError",
        "InternalServerError",
        "status code: 500",
        "status code: 502",
        "status code: 503",
        "status code: 504",
        "(503)",
        "(500)",
        "503 Service",
        "502 Bad Gateway",
        "504 Gateway",
    ]) {
        return Some(SignInFailure::Unavailable);
    }
    if has(&[
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "Rate exceeded",
        "TooManyRequests",
        "SlowDown",
    ]) {
        return Some(SignInFailure::Throttled);
    }
    if has(&[
        "Could not connect to the endpoint URL",
        "Connect timeout on endpoint",
        "Read timeout on endpoint",
        "EndpointConnectionError",
        "Name or service not known",
        "nodename nor servname",
        "Temporary failure in name resolution",
        "Connection was closed before we received a valid response",
    ]) {
        return Some(SignInFailure::Unreachable);
    }
    if has(&[
        "ExpiredToken",
        "Token has expired",
        "token has expired",
        "has expired",
        "UnauthorizedSSOTokenError",
        "Error loading SSO Token",
        "refresh failed",
    ]) {
        return Some(SignInFailure::Expired);
    }
    if stderr.contains("The config profile") && stderr.contains("could not be found") {
        return Some(SignInFailure::NoProfile);
    }
    if has(&[
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "UnrecognizedClientException",
        "AuthFailure",
    ]) {
        return Some(SignInFailure::BadKeys);
    }
    if has(&["Unable to locate credentials", "NoCredentialProviders"]) {
        return Some(SignInFailure::NotSignedIn);
    }
    None
}

/// The error line of what a command printed, short and on one line: enough to recognise it, never a whole dump.
pub(super) fn short_why(stderr: &str) -> String {
    let line = stderr
        .lines()
        .find(|l| l.contains("rror") || l.contains("(") || l.contains("xpired"))
        .or_else(|| stderr.lines().find(|l| !l.trim().is_empty()))
        .unwrap_or("")
        .trim();
    let s: String = line.chars().take(160).collect();
    if s.is_empty() {
        "no reason given".into()
    } else {
        s
    }
}

/// The finding for a failed sign-in check. The outage kinds have codes of their own (`aws_unavailable`, `aws_throttled`,
/// `aws_unreachable`); every kind of missing or expired login keeps the code `not_signed_in` and says which it is.
pub fn sign_in_finding(kind: SignInFailure, stderr: &str, profile: &str, region: &str) -> Finding {
    let why = short_why(stderr);
    let p = [("profile", profile)];
    match kind {
        SignInFailure::Unavailable => Finding::new(
            "aws_unavailable",
            t("init.signin_unavailable", &[("why", &why)]),
        )
        .with_fix(t("init.signin_unavailable_fix", &[("region", region)])),
        SignInFailure::Throttled => Finding::new(
            "aws_throttled",
            t("init.signin_throttled", &[("why", &why)]),
        )
        .with_fix(t("init.signin_throttled_fix", &[])),
        SignInFailure::Unreachable => Finding::new(
            "aws_unreachable",
            t("init.signin_unreachable", &[("why", &why)]),
        )
        .with_fix(t("init.signin_unreachable_fix", &[])),
        SignInFailure::Expired => Finding::new("not_signed_in", t("init.signin_expired", &p))
            .with_fix(t("init.signin_expired_fix", &p)),
        SignInFailure::NoProfile => Finding::new("not_signed_in", t("init.signin_no_profile", &p))
            .with_fix(t("init.signin_no_profile_fix", &p)),
        SignInFailure::BadKeys => Finding::new("not_signed_in", t("init.signin_bad_keys", &p))
            .with_fix(t("init.sign_in_fix", &p)),
        SignInFailure::NotSignedIn => Finding::new("not_signed_in", t("init.not_signed_in", &[]))
            .with_fix(t("init.sign_in_fix", &p)),
    }
}

// ---------- quotas ----------

/// The Service Quotas code of "EC2-VPC Elastic IPs" (per region).
pub const EIP_QUOTA: (&str, &str) = ("ec2", "L-0263D0A3");
/// The Service Quotas code of "NAT gateways per Availability Zone".
pub const NAT_QUOTA: (&str, &str) = ("vpc", "L-FE5A380F");

/// What a quota allows against what a plan needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaVerdict {
    Enough {
        free: u32,
    },
    /// Not enough: `want` is the quota value that would be.
    Short {
        free: u32,
        want: u32,
    },
}

/// Pure: `needed` more against a quota and what is in use. A quota that is not a whole number is rounded down.
pub fn quota_verdict(needed: u32, quota: f64, used: u32) -> QuotaVerdict {
    let q = if quota.is_finite() && quota > 0.0 {
        // quotas are small whole numbers; anything past u32 is as good as unlimited
        quota.min(f64::from(u32::MAX)).floor() as u32
    } else {
        0
    };
    let free = q.saturating_sub(used);
    if free >= needed {
        QuotaVerdict::Enough { free }
    } else {
        QuotaVerdict::Short {
            free,
            want: used.saturating_add(needed),
        }
    }
}

/// How many Elastic IP addresses and NAT gateways a plan creates, from its entries.
pub fn network_needs(entries: &[(String, &str)]) -> (u32, u32) {
    let count = |kind: &str| {
        let n = entries
            .iter()
            .filter(|(a, v)| *v == "create" && a.rsplit('.').nth(1) == Some(kind))
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    };
    (count("aws_eip"), count("aws_nat_gateway"))
}

fn json_of(out: &ozbox_core::Output) -> Result<Value, String> {
    if out.status != Some(0) {
        return Err(short_why(&out.stderr));
    }
    serde_json::from_str(&out.stdout).map_err(|_| "unreadable answer".to_string())
}

fn array_len(v: &Value, key: &str) -> Result<u32, String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| u32::try_from(a.len()).unwrap_or(u32::MAX))
        .ok_or_else(|| "unreadable answer".to_string())
}

impl Init<'_> {
    fn read_json(&self, target: &Target, args: &[&str]) -> Result<Value, String> {
        let out = self
            .exec(&self.aws(target, args))
            .map_err(|f| f.message.chars().take(160).collect::<String>())?;
        json_of(&out)
    }

    fn quota_value(&self, target: &Target, (service, code): (&str, &str)) -> Result<f64, String> {
        let v = self.read_json(
            target,
            &[
                "service-quotas",
                "get-service-quota",
                "--service-code",
                service,
                "--quota-code",
                code,
            ],
        )?;
        v.pointer("/Quota/Value")
            .and_then(Value::as_f64)
            .ok_or_else(|| "unreadable answer".to_string())
    }

    /// The zone the network module places its NAT gateway in: the first available Availability Zone by name, as the module's
    /// `aws_availability_zones` data source sorts them.
    fn first_zone(&self, target: &Target) -> Result<String, String> {
        let v = self.read_json(
            target,
            &[
                "ec2",
                "describe-availability-zones",
                "--filters",
                "Name=state,Values=available",
            ],
        )?;
        let mut names: Vec<String> = v
            .get("AvailabilityZones")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter(|z| {
                        z.get("ZoneType")
                            .and_then(Value::as_str)
                            .is_none_or(|t| t == "availability-zone")
                    })
                    .filter_map(|z| z.get("ZoneName").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
            .into_iter()
            .next()
            .ok_or_else(|| "no available zone listed".to_string())
    }

    fn nat_in_zone(&self, target: &Target, zone: &str) -> Result<u32, String> {
        let v = self.read_json(
            target,
            &[
                "ec2",
                "describe-nat-gateways",
                "--filter",
                "Name=state,Values=pending,available",
            ],
        )?;
        let subnets: Vec<String> = v
            .get("NatGateways")
            .and_then(Value::as_array)
            .ok_or_else(|| "unreadable answer".to_string())?
            .iter()
            .filter_map(|g| g.get("SubnetId").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        if subnets.is_empty() {
            return Ok(0);
        }
        let mut args = vec!["ec2", "describe-subnets", "--subnet-ids"];
        args.extend(subnets.iter().map(String::as_str));
        let s = self.read_json(target, &args)?;
        let in_zone: Vec<&str> = s
            .get("Subnets")
            .and_then(Value::as_array)
            .ok_or_else(|| "unreadable answer".to_string())?
            .iter()
            .filter(|x| x.get("AvailabilityZone").and_then(Value::as_str) == Some(zone))
            .filter_map(|x| x.get("SubnetId").and_then(Value::as_str))
            .collect();
        // one entry per gateway: several gateways may share a subnet
        let n = subnets
            .iter()
            .filter(|id| in_zone.contains(&id.as_str()))
            .count();
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Read the Elastic IP and NAT gateway quotas the network needs, before anything is made. Not enough of either refuses the
    /// plan with the numbers and the request that raises it; a quota that cannot be read (no `servicequotas:GetServiceQuota`, a
    /// network error) is said in the plan's notes and never taken as enough or as short.
    pub(super) fn network_quota_preflight(
        &self,
        target: &Target,
        eip_needed: u32,
        nat_needed: u32,
    ) -> Res<Vec<String>> {
        let region = target.region_or_err()?.to_string();
        let mut notes = Vec::new();
        let mut check = |what: String,
                         (service, code): (&str, &str),
                         needed: u32,
                         read: &dyn Fn() -> Result<(f64, u32), String>|
         -> Res<()> {
            match read() {
                Ok((quota, used)) => match quota_verdict(needed, quota, used) {
                    QuotaVerdict::Enough { free } => {
                        notes.push(t(
                            "init.quota_ok",
                            &[
                                ("what", &what),
                                ("region", &region),
                                ("needed", &needed.to_string()),
                                ("free", &free.to_string()),
                                ("quota", &format!("{quota}")),
                            ],
                        ));
                        Ok(())
                    }
                    QuotaVerdict::Short { free, want } => Err(Finding::new(
                        "quota_short",
                        t(
                            "init.quota_short",
                            &[
                                ("what", &what),
                                ("region", &region),
                                ("needed", &needed.to_string()),
                                ("quota", &format!("{quota}")),
                                ("used", &used.to_string()),
                                ("free", &free.to_string()),
                            ],
                        ),
                    )
                    .with_fix(t(
                        "init.quota_short_fix",
                        &[
                            ("service", service),
                            ("code", code),
                            ("want", &want.to_string()),
                            ("region", &region),
                        ],
                    ))),
                },
                Err(why) => {
                    notes.push(t(
                        "init.quota_unknown",
                        &[("what", &what), ("region", &region), ("why", &why)],
                    ));
                    Ok(())
                }
            }
        };
        if eip_needed > 0 {
            let read = || -> Result<(f64, u32), String> {
                let quota = self.quota_value(target, EIP_QUOTA)?;
                let used = array_len(
                    &self.read_json(target, &["ec2", "describe-addresses"])?,
                    "Addresses",
                )?;
                Ok((quota, used))
            };
            check(t("init.quota_eip", &[]), EIP_QUOTA, eip_needed, &read)?;
        }
        if nat_needed > 0 {
            let zone = self.first_zone(target);
            let what = t(
                "init.quota_nat",
                &[("zone", zone.as_deref().unwrap_or("the first zone"))],
            );
            let read = || -> Result<(f64, u32), String> {
                let zone = zone.clone()?;
                let quota = self.quota_value(target, NAT_QUOTA)?;
                let used = self.nat_in_zone(target, &zone)?;
                Ok((quota, used))
            };
            check(what, NAT_QUOTA, nat_needed, &read)?;
        }
        Ok(notes)
    }
}

// ---------- rollback ----------

/// The command that removes exactly what a plan was creating, for a step whose plan ONLY creates (nothing changed, replaced,
/// destroyed or adopted): then everything in those addresses was made by this apply, and nothing older is touched. Any other
/// plan gets no rollback (an empty list), because undoing it could remove something that was there before.
pub fn destroy_created(
    tofu_env: impl Fn(CommandSpec) -> CommandSpec,
    chdir: &str,
    entries: &[(String, &str)],
) -> Vec<CommandSpec> {
    if entries.is_empty() || entries.iter().any(|(_, v)| *v != "create") {
        return Vec::new();
    }
    let mut args = vec![
        chdir.to_string(),
        "destroy".into(),
        "-auto-approve".into(),
        "-input=false".into(),
        "-no-color".into(),
    ];
    args.extend(entries.iter().map(|(a, _)| format!("-target={a}")));
    vec![tofu_env(CommandSpec::new("tofu").args(args))]
}

// ---------- one pinned provider, one lock ----------

/// The AWS plugin version every step of setup uses. One version, pinned, so the steps (and a box created afterwards) run the
/// same plugin; the modules themselves accept a range (`>= 5.60.0, < 7.0.0`) for anyone using them on their own.
pub const AWS_PROVIDER_VERSION: &str = "6.73.0";

/// The `required_providers` block every generated root carries.
pub fn pinned_providers_block() -> String {
    format!(
        "  required_providers {{\n    aws = {{\n      source  = \"hashicorp/aws\"\n      version = \"= {AWS_PROVIDER_VERSION}\"\n    }}\n  }}\n"
    )
}

/// The lock file's file name, as OpenTofu writes it.
pub const LOCK_FILE: &str = ".terraform.lock.hcl";

/// Whether a lock file's AWS entry is the pinned version.
pub fn lock_pins(text: &str) -> bool {
    let mut in_aws = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("provider ") {
            in_aws = l.contains("/hashicorp/aws\"");
        } else if in_aws && l.starts_with("version") {
            return l.split('=').nth(1).map(str::trim)
                == Some(&format!("\"{AWS_PROVIDER_VERSION}\""));
        }
    }
    false
}

impl Init<'_> {
    fn provider_dir(&self) -> PathBuf {
        self.paths.work.join("provider")
    }

    /// The one lock file every step's root and module copies.
    pub(super) fn shared_lock(&self) -> PathBuf {
        self.provider_dir().join(LOCK_FILE)
    }

    /// Make the shared lock file once: a root with only the pinned provider, initialised with the plugin cache. A lock that
    /// already pins the version is kept (no command runs); one for another version is replaced.
    pub(super) fn ensure_provider_lock(&self, target: &Target) -> Res<()> {
        let lock = self.shared_lock();
        if std::fs::read_to_string(&lock).is_ok_and(|s| lock_pins(&s)) {
            return Ok(());
        }
        let dir = self.provider_dir();
        let io = |e: std::io::Error| {
            Finding::new(
                "provider_lock_failed",
                t(
                    "init.provider_lock_failed",
                    &[("version", AWS_PROVIDER_VERSION), ("why", &e.to_string())],
                ),
            )
        };
        std::fs::create_dir_all(&dir).map_err(io)?;
        let _ = std::fs::remove_file(&lock);
        std::fs::write(
            dir.join("main.tf"),
            format!(
                "terraform {{\n  required_version = \">= 1.10.0\"\n{}}}\n",
                pinned_providers_block()
            ),
        )
        .map_err(io)?;
        let cmd = CommandSpec::new("tofu").args([
            format!("-chdir={}", dir.display()),
            "init".into(),
            "-backend=false".into(),
            "-input=false".into(),
            "-no-color".into(),
        ]);
        self.init_with_retry(target, &cmd)
    }

    /// Copy the shared lock into a root or module folder before it is initialised, so OpenTofu takes the pinned version from it.
    pub(super) fn use_shared_lock(&self, dir: &Path) -> Res<()> {
        let lock = self.shared_lock();
        if !lock.is_file() {
            return Ok(());
        }
        std::fs::create_dir_all(dir)
            .and_then(|()| std::fs::copy(&lock, dir.join(LOCK_FILE)))
            .map(|_| ())
            .map_err(|e| Finding::new("command_failed", e.to_string()))
    }

    // ---------- previews ----------

    /// A copy of a step's generated root, with no backend (an empty local state), in a scratch folder of its own: what a dry run
    /// plans when the state bucket does not exist yet. The real root is not touched.
    pub(super) fn preview_root(&self, dir: &Path) -> Res<PathBuf> {
        let rel = dir.strip_prefix(&self.paths.work).unwrap_or(dir);
        let rel = rel.strip_prefix("/").unwrap_or(rel);
        let preview = self.paths.work.join("preview").join(rel);
        let io = |e: std::io::Error| Finding::new("command_failed", e.to_string());
        std::fs::create_dir_all(&preview).map_err(io)?;
        let text = std::fs::read_to_string(dir.join("main.tf")).map_err(io)?;
        std::fs::write(
            preview.join("main.tf"),
            text.replace("  backend \"s3\" {}\n", ""),
        )
        .map_err(io)?;
        self.use_shared_lock(&preview)?;
        Ok(preview)
    }
}

/// A lock file that pins [`AWS_PROVIDER_VERSION`], for tests: with it in place, no step runs the lock's own `init`.
#[cfg(test)]
pub(crate) fn write_test_lock(work: &Path) {
    let dir = work.join("provider");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(
        dir.join(LOCK_FILE),
        format!(
            "provider \"registry.opentofu.org/hashicorp/aws\" {{\n  version     = \"{AWS_PROVIDER_VERSION}\"\n  constraints = \"= {AWS_PROVIDER_VERSION}\"\n}}\n"
        ),
    );
}
