//! Who made an approval code, and whether that signer may approve what the code is spent on (ADR 0041 §3, Amendment of
//! 2026-11-17).
//!
//! A scope-only approval code (the legacy path, `secrets_approval`) is made in one of two ways: by the dashboard after the
//! person's passkey or authenticator code, or by a key kept in a computer's keychain (`approval_key`, an Ed25519 software key:
//! any process of that computer's user can use it without a prompt). **A software key never approves Production**, with no
//! opt-in. So the box records which signer made every code, and the gate refuses a software key's code for anything in the
//! Production tier, whatever its scope, project and environment match. The request path (ADR 0041 requests) applies the same
//! rule in `ozbox_core::approval` (`software_cell`).
//!
//! Every scope a code can be for has a row in [`PRODUCTION_TIER`] saying how the box tells whether an act in it is Production.
//! A test keeps that table equal to `secrets_approval::SCOPES`, and a scope with no row is Production (the fail-safe reading),
//! so a new scope cannot silently miss the check.

use ozbox_core::approval_subject::is_production_environment;

/// Who made an approval code. Recorded with the code when it is minted and read when it is spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    /// The dashboard, after the person's passkey or authenticator code (the supervisor's step-up).
    Dashboard,
    /// A laptop key kept in a computer's keychain, by its id: a software key, with no proved user presence.
    SoftwareKey(String),
}

impl Signer {
    /// How the change was allowed, in words for the audit line (the words the box has always written).
    pub fn via(&self) -> String {
        match self {
            Signer::Dashboard => "dashboard-stepup".to_string(),
            Signer::SoftwareKey(id) => format!("laptop-key:{id}"),
        }
    }

    /// Whether this signer may approve an act in the Production tier.
    pub fn may_approve_production(&self) -> bool {
        match self {
            Signer::Dashboard => true,
            Signer::SoftwareKey(_) => false,
        }
    }
}

/// How the box tells whether an act in a scope is Production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// The code's environment names it: Production unless it is a listed non-Production environment (`import`).
    ByEnvironment,
    /// The thing being approved names it: the code carries no environment, so the spender says (a declaration whose commands
    /// take secrets from a Production environment, or that changes the project's Production identifiers: `policy`). A code
    /// that does name an environment is judged by it as well.
    ByDeclaration,
    /// The code names one change by digest (`guard-override`): anything else in its place is refused for a software key.
    ChangeDigest,
    /// The box's own settings and keys, not a project's environment, so not in the Production tier: the tunnel token, the
    /// approvers, the first-time code, the store key's escrow, the box's own vault, its guards.
    BoxOwn,
}

/// Every scope a code can be for, and how its Production tier is told. In the order of `secrets_approval::SCOPES` (a test).
pub const PRODUCTION_TIER: &[(&str, Tier)] = &[
    ("import", Tier::ByEnvironment),
    ("policy", Tier::ByDeclaration),
    ("tunnel-token", Tier::BoxOwn),
    ("guard-override", Tier::ChangeDigest),
    ("signer-enroll", Tier::BoxOwn),
    ("setup-code", Tier::BoxOwn),
    ("kek-export", Tier::BoxOwn),
    ("box-secrets", Tier::BoxOwn),
    ("host-guard", Tier::BoxOwn),
];

/// The row for `scope`, or `None` for a scope this version does not know.
pub fn tier(scope: &str) -> Option<Tier> {
    PRODUCTION_TIER
        .iter()
        .find(|(s, _)| *s == scope)
        .map(|(_, t)| *t)
}

/// Whether an act in `scope` for `env` is in the Production tier. `declared` is what the spender knows of the thing itself (a
/// declaration that touches Production); it can only make the answer stricter. A scope with no row is Production.
pub fn is_production(scope: &str, env: &str, declared: bool) -> bool {
    if declared {
        return true;
    }
    match tier(scope) {
        None => true,
        Some(Tier::ByEnvironment) => is_production_environment(env),
        Some(Tier::ByDeclaration) => !env.is_empty() && is_production_environment(env),
        Some(Tier::ChangeDigest) => !(env.len() == 16 && env.bytes().all(|b| b.is_ascii_hexdigit())),
        Some(Tier::BoxOwn) => false,
    }
}

/// Whether `signer` may approve this act. The one check every path that mints or spends a code calls.
pub fn allowed(signer: &Signer, scope: &str, env: &str, declared: bool) -> bool {
    signer.may_approve_production() || !is_production(scope, env, declared)
}

/// What a person is told when a software key's code is refused for Production: the rule, and what does approve it.
pub fn refusal(scope: &str) -> String {
    crate::messages::t("approval.software_key_production", &[("scope", scope)])
}

/// Whether a project declaration touches Production for the rule above: a command takes secrets from a Production environment
/// (in the declaration being written or in the one it replaces, so a software key can neither add nor remove such a command), or
/// the project's Production identifiers change.
pub fn declaration_touches_production(
    new: &crate::workload_policy::Policy,
    current: Option<&crate::workload_policy::Policy>,
) -> bool {
    let prod_envs = |p: &crate::workload_policy::Policy| {
        p.commands
            .values()
            .any(|c| c.envs.iter().any(|e| is_production_environment(e)))
    };
    prod_envs(new)
        || current.is_some_and(prod_envs)
        || current.map_or(!new.production_ids.is_empty(), |c| {
            c.production_ids != new.production_ids
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_scope_a_code_can_be_for_has_a_production_tier_in_the_same_order() {
        let have: Vec<&str> = PRODUCTION_TIER.iter().map(|(s, _)| *s).collect();
        assert_eq!(have, crate::secrets_approval::SCOPES);
        // and a scope with no row is Production for every signer but the dashboard
        assert!(is_production("a-scope-from-later", "staging", false));
        assert!(!allowed(
            &Signer::SoftwareKey("laptop".into()),
            "a-scope-from-later",
            "staging",
            false
        ));
    }

    /// The whole table, scope by scope: what a software key may approve and what it may not, and that the dashboard's
    /// approvals are untouched. A new scope added to `SCOPES` fails the row count until it is listed here.
    #[test]
    fn a_software_key_never_approves_production_in_any_scope_and_the_dashboard_still_does() {
        let soft = Signer::SoftwareKey("laptop".into());
        let dash = Signer::Dashboard;
        let digest = "0123456789abcdef";
        // (scope, env, declared, software allowed)
        let rows: &[(&str, &str, bool, bool)] = &[
            ("import", "staging", false, true),
            ("import", "dev", false, true),
            ("import", "production", false, false),
            ("import", "prod", false, false),
            ("import", "live", false, false),
            ("import", "qa", false, false),
            ("import", "", false, false),
            ("import", "staging", true, false),
            ("policy", "", false, true),
            ("policy", "", true, false),
            ("policy", "production", false, false),
            ("tunnel-token", "0123456789abcdef0123456789abcdef", false, true),
            ("guard-override", digest, false, true),
            ("guard-override", "production", false, false),
            ("guard-override", digest, true, false),
            ("signer-enroll", "", false, true),
            ("setup-code", "", false, true),
            ("kek-export", "", false, true),
            ("box-secrets", "", false, true),
            ("host-guard", "", false, true),
        ];
        for (scope, env, declared, want) in rows {
            assert_eq!(
                allowed(&soft, scope, env, *declared),
                *want,
                "software key: {scope} {env} declared={declared}"
            );
            assert!(
                allowed(&dash, scope, env, *declared),
                "dashboard: {scope} {env}"
            );
        }
        let listed: std::collections::BTreeSet<&str> = rows.iter().map(|r| r.0).collect();
        let scopes: std::collections::BTreeSet<&str> =
            crate::secrets_approval::SCOPES.iter().copied().collect();
        assert_eq!(listed, scopes, "every scope has a row in this test");
    }

    #[test]
    fn the_refusal_names_the_rule_and_what_approves_it() {
        let e = refusal("import");
        assert!(e.contains("import") && e.contains("Production"), "{e}");
        assert!(
            e.contains("dashboard") && e.contains("passkey") && e.contains("authenticator"),
            "{e}"
        );
        assert!(!e.starts_with("approval."), "the key is in the catalogue");
    }

    #[test]
    fn a_declaration_touches_production_by_its_environments_or_its_production_ids() {
        let p = |envs: &[&str], ids: &[&str]| {
            let text = serde_json::json!({"dir":"/work/projects/app","production_ids":ids,
                "commands":{"t":{"allow":["K"],"env":["K"],"argv":["node","t.mjs"],"envs":envs,
                "pin":[{"file":"t.mjs","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}})
            .to_string();
            crate::workload_policy::Policy::parse(&text).unwrap()
        };
        let staging = p(&["staging"], &[]);
        let prod = p(&["production"], &[]);
        assert!(!declaration_touches_production(&staging, None));
        assert!(!declaration_touches_production(&staging, Some(&staging)));
        assert!(declaration_touches_production(&prod, None));
        // removing a Production command is a Production change too
        assert!(declaration_touches_production(&staging, Some(&prod)));
        // so is adding, changing or removing the project's Production identifiers
        let ids = p(&["staging"], &["abcdefghijklmnop"]);
        assert!(declaration_touches_production(&ids, None));
        assert!(declaration_touches_production(&staging, Some(&ids)));
        assert!(!declaration_touches_production(&ids, Some(&ids)));
    }
}
