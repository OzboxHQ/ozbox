//! Rebuilding a box's OpenTofu state from the cloud resources it already has (`ozbox adopt`), the part every provider
//! shares: import the resources the provider found, correct what an import leaves behind, plan, and keep the result only
//! if that plan is a no-op or changes tags or labels only. A provider finds the resources (read-only calls by their
//! `ozbox-*` tags or labels) and says how to correct its own import artefacts; this does the rest and never touches the
//! cloud. The state is backed up before and after, whichever backend holds it.

use crate::tofu::{check_adopt_plan, TofuModule};
use crate::{BoxName, Error, ModuleVars, Result};

/// One resource to import: where it goes in the module and what it is in the cloud.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AdoptItem {
    pub address: String,
    pub id: String,
    pub what: String,
}

/// What adopting a box would import. Read-only to make; carries the module variables the final plan needs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdoptPlan {
    pub box_name: String,
    pub items: Vec<AdoptItem>,
    #[serde(skip)]
    vars: Option<ModuleVars>,
}

impl AdoptPlan {
    pub fn new(box_name: &BoxName, items: Vec<AdoptItem>, vars: ModuleVars) -> Self {
        Self {
            box_name: box_name.to_string(),
            items,
            vars: Some(vars),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AdoptReport {
    pub imported: Vec<String>,
    pub corrected: Vec<String>,
    pub tag_only: Vec<String>,
    pub backup_before: Option<String>,
    pub backup_after: Option<String>,
}

/// Corrects a freshly imported state document: `(new document, a sentence per correction)`. Pure.
pub type ImportFixer = fn(&str) -> Result<(String, Vec<String>)>;

/// Import, correct, verify. Any refusal takes the imported resources back out of the state again (state only).
pub fn adopt_apply(tofu: &TofuModule, plan: &AdoptPlan, fix: ImportFixer) -> Result<AdoptReport> {
    let name = BoxName::new(&plan.box_name)?;
    let vars = plan
        .vars
        .as_ref()
        .ok_or_else(|| Error::Provider("an adoption plan carries its module variables".into()))?;
    tofu.workspace_create(&name)?;
    let backup_before = tofu
        .backup(&name, "adopt-before")?
        .map(|p| p.display().to_string());
    let present = tofu.state_list(&name)?;
    let mut done: Vec<String> = Vec::new();
    for it in &plan.items {
        if present.contains(&it.address) {
            done.push(it.address.clone());
            continue;
        }
        if let Err(e) = tofu.state_import(vars, &it.address, &it.id) {
            take_back(tofu, &name, &done);
            return Err(Error::Provider(format!(
                "importing {} ({}) failed: {e}. What was imported before it was taken back out; nothing in the cloud changed.",
                it.address, it.id
            )));
        }
        done.push(it.address.clone());
    }
    let pulled = tofu.state_pull(&name)?;
    let (fixed, corrected) = fix(&pulled)?;
    if !corrected.is_empty() {
        tofu.state_push(&name, &fixed)?;
    }
    let tag_only = match tofu.plan_show(vars).and_then(|j| check_adopt_plan(&j)) {
        Ok(t) => t,
        Err(e) => {
            take_back(tofu, &name, &done);
            return Err(e);
        }
    };
    let backup_after = tofu
        .backup(&name, "adopt-after")?
        .map(|p| p.display().to_string());
    Ok(AdoptReport {
        imported: done,
        corrected,
        tag_only,
        backup_before,
        backup_after,
    })
}

/// Forget what an adoption imported (state only; the cloud is not touched).
fn take_back(tofu: &TofuModule, name: &BoxName, addresses: &[String]) {
    let refs: Vec<&str> = addresses.iter().map(String::as_str).collect();
    if !refs.is_empty() {
        let _ = tofu.state_rm(name, &refs);
    }
}
