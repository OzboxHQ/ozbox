//! The fleet roles' IAM documents (ADR 0040 §3), from their one source (`infra/aws/fleet-*.json`), filled in for an account.
//!
//! Two roles, both in the reserved namespace the daily operator cannot touch (`role/obx/`, names starting `obx-`):
//!
//! - `obx-fleet-read`: what a box's dashboard may READ about the fleet (instances, volumes, snapshots, prices, and the bill when
//!   the account is Oz Box's own). Only `main`'s own role (`obx-main`) may assume it.
//! - `obx-fleet-change`: create, resize, pause, resume, clone and destroy `ozbox-managed` resources, and nothing that changes
//!   who may do what. Only the owner's own sign-in on their computer (an Identity Center permission set) may assume it, and it
//!   does so per plan with a session policy (a "change window"); `main`'s role is NOT in its trust.
//!
//! The documents are templates. [`render`] is the only code that fills them in; the setup module
//! (`infra/tofu/modules/aws-fleet-manager`) does the same replacements, and a test holds the two to the same tokens. A list
//! placeholder is written as a quoted string (`"${regions}"`) and replaced, quotes included, by a JSON array, so the file
//! stays valid JSON. IAM's own policy variables (`${aws:userid}`) are left as they are.

use serde_json::Value;

/// The documents, each carried from the same file the setup module and the tests read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Doc {
    /// `obx-fleet-read`'s permissions.
    Read,
    /// `obx-fleet-read`'s cost permissions, attached only in an account of Oz Box's own (ADR 0040 decision 4).
    Cost,
    /// `obx-fleet-change`'s allows.
    Change,
    /// `obx-fleet-change`'s explicit denies (a second managed policy: one document would pass the managed-policy size).
    ChangeGuard,
    /// Who may assume `obx-fleet-read`: `main`'s own role, nothing else.
    ReadTrust,
    /// Who may assume `obx-fleet-change`: the owner's window sign-in, never `main`.
    ChangeTrust,
    /// The one permission `main`'s role gets: assume the read role.
    MainAssume,
}

impl Doc {
    pub const ALL: [Doc; 7] = [
        Doc::Read,
        Doc::Cost,
        Doc::Change,
        Doc::ChangeGuard,
        Doc::ReadTrust,
        Doc::ChangeTrust,
        Doc::MainAssume,
    ];

    /// The file under `infra/aws/`.
    pub fn file(self) -> &'static str {
        match self {
            Doc::Read => "fleet-read-policy.json",
            Doc::Cost => "fleet-cost-policy.json",
            Doc::Change => "fleet-change-policy.json",
            Doc::ChangeGuard => "fleet-change-guard-policy.json",
            Doc::ReadTrust => "fleet-read-trust-policy.json",
            Doc::ChangeTrust => "fleet-change-trust-policy.json",
            Doc::MainAssume => "fleet-main-assume-policy.json",
        }
    }

    pub fn template(self) -> &'static str {
        match self {
            Doc::Read => include_str!("../../../infra/aws/fleet-read-policy.json"),
            Doc::Cost => include_str!("../../../infra/aws/fleet-cost-policy.json"),
            Doc::Change => include_str!("../../../infra/aws/fleet-change-policy.json"),
            Doc::ChangeGuard => include_str!("../../../infra/aws/fleet-change-guard-policy.json"),
            Doc::ReadTrust => include_str!("../../../infra/aws/fleet-read-trust-policy.json"),
            Doc::ChangeTrust => include_str!("../../../infra/aws/fleet-change-trust-policy.json"),
            Doc::MainAssume => include_str!("../../../infra/aws/fleet-main-assume-policy.json"),
        }
    }
}

/// The reserved path every protected role lives under (ADR 0040 §3.1).
pub const RESERVED_PATH: &str = "/obx/";
/// The fleet roles' names.
pub const READ_ROLE: &str = "obx-fleet-read";
pub const CHANGE_ROLE: &str = "obx-fleet-change";
/// `main`'s own role, made by the setup identity, outside the pool and never passable.
pub const MAIN_ROLE: &str = "obx-main";
/// The tag that marks `main`'s machine, its `/work` volume and its snapshots: nothing a fleet role does may touch them.
pub const FLEET_MANAGER_TAG: &str = "ozbox-fleet-manager";

/// The values a rendered document is made of. Every one is checked, so a value can never carry a `"` or a `${`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetVars {
    pub account_id: String,
    pub regions: Vec<String>,
    /// Machine types a fleet change may launch or resize to (the catalog's mapping of the sizes it offers).
    pub sizes: Vec<String>,
    /// Oz Box's own images, the only ones a fleet change may launch.
    pub image_ids: Vec<String>,
    pub max_volume_gb: u32,
    pub max_iops: u32,
    pub max_throughput: u32,
    /// The owner's Identity Center role for fleet windows (`arn:aws:iam::<acct>:role/aws-reserved/sso.amazonaws.com/...`).
    /// A trailing `*` is allowed after the permission set's name (the suffix changes when the role is recreated).
    pub window_principal_arn: String,
}

fn is_plain(s: &str, ok: impl Fn(char) -> bool) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(ok)
}

fn list(values: &[String], what: &str, ok: impl Fn(&str) -> bool) -> Result<String, String> {
    if values.is_empty() {
        return Err(format!("{what}: at least one is needed"));
    }
    if values.iter().any(|v| !ok(v)) {
        return Err(format!("{what}: a value is not a plain name"));
    }
    serde_json::to_string(values).map_err(|_| format!("{what}: cannot be written"))
}

/// `main`'s role ARN in an account.
pub fn main_role_arn(account_id: &str) -> String {
    format!("arn:aws:iam::{account_id}:role/obx/{MAIN_ROLE}")
}

/// A document, filled in. Refused when any value is not a plain identifier, or anything but IAM's own variables is left.
pub fn render(doc: Doc, v: &FleetVars) -> Result<Value, String> {
    let acct = &v.account_id;
    if acct.len() != 12 || !acct.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the account id is not 12 digits".into());
    }
    let regions = list(&v.regions, "regions", |r| {
        is_plain(r, |c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
        })
    })?;
    let sizes = list(&v.sizes, "machine types", |s| {
        is_plain(s, |c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'
        }) && s.contains('.')
    })?;
    let images = list(&v.image_ids, "images", |i| {
        i.strip_prefix("ami-").is_some_and(|h| {
            (8..=17).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit())
        })
    })?;
    if v.max_volume_gb == 0 || v.max_volume_gb > 16_384 {
        return Err("the largest volume must be between 1 and 16384 GB".into());
    }
    if v.max_iops < 3000 || v.max_throughput < 125 {
        return Err("gp3's baseline (3000 IOPS, 125 MB/s) must fit under the limits".into());
    }
    let sso = format!("arn:aws:iam::{acct}:role/aws-reserved/sso.amazonaws.com/");
    let principal_ok = v
        .window_principal_arn
        .strip_prefix(&sso)
        .and_then(|rest| rest.strip_prefix("AWSReservedSSO_"))
        .is_some_and(|rest| {
            let name = rest.strip_suffix('*').unwrap_or(rest);
            is_plain(name, |c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        });
    if !principal_ok {
        return Err(
            "the window sign-in must be an Identity Center role of this account (aws-reserved/sso.amazonaws.com/AWSReservedSSO_...)"
                .into(),
        );
    }
    let text = doc
        .template()
        .replace("\"${regions}\"", &regions)
        .replace("\"${sizes}\"", &sizes)
        .replace("\"${image_ids}\"", &images)
        .replace("${account_id}", acct)
        .replace("${max_volume_gb}", &v.max_volume_gb.to_string())
        .replace("${max_iops}", &v.max_iops.to_string())
        .replace("${max_throughput}", &v.max_throughput.to_string())
        .replace("${main_role_arn}", &main_role_arn(acct))
        .replace("${window_principal_arn}", &v.window_principal_arn);
    if text.replace("${aws:", "").contains("${") {
        return Err(format!("{} has a placeholder nothing fills", doc.file()));
    }
    serde_json::from_str(&text).map_err(|_| format!("{} is not valid JSON", doc.file()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn vars() -> FleetVars {
        FleetVars {
            account_id: "123456789012".into(),
            regions: vec!["us-east-1".into()],
            sizes: vec!["m7i.xlarge".into(), "c7i.xlarge".into()],
            image_ids: vec!["ami-0123456789abcdef0".into()],
            max_volume_gb: 500,
            max_iops: 6000,
            max_throughput: 500,
            window_principal_arn:
                "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_OzboxFleetWindow_*"
                    .into(),
        }
    }

    #[test]
    fn every_document_renders_and_leaves_only_iams_own_variables() {
        for d in Doc::ALL {
            let v = render(d, &vars()).unwrap();
            let t = v.to_string();
            assert!(!t.replace("${aws:", "").contains("${"), "{d:?}");
            assert_eq!(v["Version"], "2012-10-17");
        }
    }

    #[test]
    fn a_value_that_could_hide_json_or_a_placeholder_is_refused() {
        let mut bad = Vec::new();
        let mut v = vars();
        v.account_id = "12345".into();
        bad.push(v);
        let mut v = vars();
        v.regions = vec!["us-east-1\"]".into()];
        bad.push(v);
        let mut v = vars();
        v.regions = Vec::new();
        bad.push(v);
        let mut v = vars();
        v.sizes = vec!["${x}".into()];
        bad.push(v);
        let mut v = vars();
        v.image_ids = vec!["ami-zz".into()];
        bad.push(v);
        let mut v = vars();
        v.window_principal_arn = "arn:aws:iam::123456789012:role/obx/obx-main".into();
        bad.push(v);
        let mut v = vars();
        v.window_principal_arn = "*".into();
        bad.push(v);
        let mut v = vars();
        v.window_principal_arn =
            "arn:aws:iam::210987654321:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_X_*"
                .into();
        bad.push(v);
        let mut v = vars();
        v.max_volume_gb = 0;
        bad.push(v);
        for v in bad {
            assert!(render(Doc::Change, &v).is_err(), "{v:?}");
        }
    }
}
