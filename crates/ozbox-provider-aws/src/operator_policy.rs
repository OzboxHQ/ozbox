//! The daily operator's IAM policy, from its one source (`infra/aws/operator-policy.json`), filled in for an account, a
//! region and a fleet.
//!
//! The file is a template with three placeholders, `${account_id}`, `${region}` and `${fleet}`; [`render`] is the only code
//! that fills them in, and what it returns is what `ozbox init` writes for an administrator to apply. The fleet and region are
//! part of the policy so that `ssm:SendCommand` reaches the fleet's own adopt document and boxes in its own region, never any
//! other document or region. `ozbox init` cannot apply the policy itself: the setup identity has no right over the operator's
//! permissions, on purpose (a setup identity that could rewrite the operator's policy could widen it).

use serde_json::Value;

/// The template, carried in the program from the same file the documentation and the tests read.
pub const TEMPLATE: &str = include_str!("../../../infra/aws/operator-policy.json");

/// The statements that let the operator run `ozbox adopt-fleet-key` (and the root read `ozbox upgrade` uses): send the fleet's
/// adopt document to boxes Oz Box manages, and read a command's result. Releases before 0.2.0 did not carry them, so a
/// permission set made from such a release needs them added, and a test holds this list to the template.
pub const ADOPT_STATEMENTS: [&str; 3] = [
    "SendOnlyTheAdoptDocument",
    "ToBoxesOzBoxManages",
    "ReadACommandThatWasSent",
];

fn plain(value: &str, what: &str, ok: impl Fn(char) -> bool) -> Result<(), String> {
    if value.is_empty() || value.len() > 63 || !value.chars().all(ok) {
        return Err(format!("{what} is not a plain name"));
    }
    Ok(())
}

/// The policy for an account, region and fleet. Each value must be a plain identifier (never a place to hide a `"` or a `${`),
/// so what is written is exactly the template with three names filled in.
pub fn render(account: &str, region: &str, fleet: &str) -> Result<Value, String> {
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the account id is not 12 digits".into());
    }
    plain(region, "the region", |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
    })?;
    plain(fleet, "the fleet name", |c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
    })?;
    let text = TEMPLATE
        .replace("${account_id}", account)
        .replace("${region}", region)
        .replace("${fleet}", fleet);
    serde_json::from_str(&text).map_err(|_| "the operator policy template is not valid JSON".into())
}

/// The statements of a rendered policy that are in `sids`, in policy order.
pub fn statements_named(policy: &Value, sids: &[&str]) -> Vec<Value> {
    policy["Statement"]
        .as_array()
        .map(|all| {
            all.iter()
                .filter(|s| s["Sid"].as_str().is_some_and(|id| sids.contains(&id)))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}
