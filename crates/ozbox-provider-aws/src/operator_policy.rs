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

/// What [`merge_statements`] did with each statement it was given, by `Sid` (a statement with no `Sid` is named by its position,
/// `#1` for the first one given).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct MergeReport {
    /// Statements the policy did not have, appended in the order given.
    pub added: Vec<String>,
    /// Statements whose `Sid` the policy had with different content: the given version took its place, where it was.
    pub replaced: Vec<String>,
    /// Statements the policy already held exactly (`"ssm:SendCommand"` and `["ssm:SendCommand"]` are the same).
    pub unchanged: Vec<String>,
}

/// A statement with its one-value lists written as plain values, so the two ways IAM accepts the same statement compare equal.
fn normal(v: &Value) -> Value {
    match v {
        Value::Array(a) if a.len() == 1 => normal(&a[0]),
        Value::Array(a) => Value::Array(a.iter().map(normal).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), normal(v))).collect()),
        other => other.clone(),
    }
}

/// A statement's content without its `Sid`: how a statement given without one is matched.
fn content(v: &Value) -> Value {
    let mut n = normal(v);
    if let Some(o) = n.as_object_mut() {
        o.remove("Sid");
    }
    n
}

/// Merge `extra` statements (another step's output, such as the adopt step's operator statements) into `policy`, so the person
/// gets ONE complete policy and never merges JSON by hand. Pure: nothing is read or written.
///
/// * **Order-stable.** The policy's own statements keep their order; a statement it already has (same `Sid`) is replaced
///   where it stands; new ones are appended in the order given.
/// * **De-duplicated.** A `Sid` given twice is taken once (the first); a statement without a `Sid` that the policy already
///   holds with the same content (whatever its `Sid`) is not added again.
/// * **Idempotent.** Merging the result with the same statements again changes nothing.
///
/// Everything outside `Statement` (the `Version`) is kept as it is.
pub fn merge_statements(policy: &Value, extra: &[Value]) -> (Value, MergeReport) {
    let mut out = policy.clone();
    let mut list: Vec<Value> = policy["Statement"].as_array().cloned().unwrap_or_default();
    let mut report = MergeReport::default();
    let mut seen: Vec<String> = Vec::new();
    for (i, s) in extra.iter().enumerate() {
        let sid = s["Sid"].as_str().filter(|x| !x.is_empty());
        let name = sid.map_or_else(|| format!("#{}", i + 1), str::to_string);
        if let Some(sid) = sid {
            if seen.iter().any(|x| x == sid) {
                continue;
            }
            seen.push(sid.to_string());
            match list.iter().position(|x| x["Sid"].as_str() == Some(sid)) {
                Some(at) if normal(&list[at]) == normal(s) => report.unchanged.push(name),
                Some(at) => {
                    list[at] = s.clone();
                    report.replaced.push(name);
                }
                None => {
                    list.push(s.clone());
                    report.added.push(name);
                }
            }
        } else if list.iter().any(|x| content(x) == content(s)) {
            report.unchanged.push(name);
        } else {
            list.push(s.clone());
            report.added.push(name);
        }
    }
    if let Some(o) = out.as_object_mut() {
        o.insert("Statement".into(), Value::Array(list));
    }
    (out, report)
}
