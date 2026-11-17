// Generated from crates/ozbox-core/src/approval.rs (RULES). Do not edit by hand: a Rust test compares this file
// with the table and fails when they differ. Regenerate with `OZBOX_WRITE_APPROVAL_RULES=1 cargo test -p ozbox-cli the_dashboards_copy_of_the_rule_table`.

export interface ApprovalRule {
  scope: string;
  journal: boolean;
  filers: readonly string[];
  dashboard: string;
  laptopPresence: boolean;
  software: string;
  telegram: string;
  spendBy: string;
  bootstrap: string;
}

export const APPROVAL_RULES: readonly ApprovalRule[] = [
  { scope: 'import', journal: true, filers: ['laptop-key', 'root-helper'], dashboard: 'import-rule', laptopPresence: true, software: 'new-non-production-names', telegram: 'notify-only', spendBy: 'inside', bootstrap: 'allowed' },
  { scope: 'policy', journal: true, filers: ['supervisor', 'laptop-key', 'root-helper'], dashboard: 'policy-rule', laptopPresence: true, software: 'never', telegram: 'notify-only', spendBy: 'inside', bootstrap: 'first-setting-only' },
  { scope: 'tunnel-token', journal: true, filers: ['root-helper', 'laptop-key'], dashboard: 'owner-until-presence-key', laptopPresence: true, software: 'never', telegram: 'notify-only', spendBy: 'admin-socket', bootstrap: 'allowed' },
  { scope: 'guard-override', journal: true, filers: ['box-user'], dashboard: 'owner-or-member', laptopPresence: true, software: 'member-level', telegram: 'notify-only', spendBy: 'box-socket', bootstrap: 'refused' },
  { scope: 'signer-enroll', journal: true, filers: ['supervisor', 'laptop-key', 'root-helper'], dashboard: 'enrol-rule', laptopPresence: true, software: 'never', telegram: 'notify-only', spendBy: 'inside', bootstrap: 'refused' },
  { scope: 'box-secrets', journal: true, filers: ['root-helper', 'laptop-key'], dashboard: 'owner', laptopPresence: true, software: 'never', telegram: 'notify-only', spendBy: 'admin-socket', bootstrap: 'first-setting-only' },
  { scope: 'host-guard', journal: true, filers: ['root-helper'], dashboard: 'owner-until-presence-key', laptopPresence: true, software: 'never', telegram: 'notify-only', spendBy: 'admin-socket', bootstrap: 'refused' },
  { scope: 'setup-code', journal: true, filers: ['laptop-key'], dashboard: 'not-decidable', laptopPresence: true, software: 'never', telegram: 'notify-only', spendBy: 'inside', bootstrap: 'allowed' },
  { scope: 'kek-export', journal: true, filers: ['laptop-key'], dashboard: 'not-decidable', laptopPresence: true, software: 'never', telegram: 'notify-only', spendBy: 'inside', bootstrap: 'refused' },
  { scope: 'worker-keys', journal: true, filers: ['hub-agent'], dashboard: 'owner', laptopPresence: true, software: 'never', telegram: 'notify-only', spendBy: 'inside', bootstrap: 'refused' },
  { scope: 'secret-use', journal: false, filers: [], dashboard: 'issuer', laptopPresence: true, software: 'never', telegram: 'notify-only', spendBy: 'not-applicable', bootstrap: 'refused' },
  { scope: 'dashboard-auth', journal: false, filers: [], dashboard: 'own-store', laptopPresence: true, software: 'not-applicable', telegram: 'notify-only', spendBy: 'admin-socket', bootstrap: 'refused' },
  { scope: 'agent-action', journal: false, filers: [], dashboard: 'own-store', laptopPresence: false, software: 'not-applicable', telegram: 'notify-only', spendBy: 'not-applicable', bootstrap: 'refused' },
  { scope: 'agent-action-protected', journal: false, filers: [], dashboard: 'own-store', laptopPresence: false, software: 'not-applicable', telegram: 'notify-only', spendBy: 'not-applicable', bootstrap: 'refused' },
  { scope: 'agent-action-production', journal: false, filers: [], dashboard: 'own-store', laptopPresence: false, software: 'not-applicable', telegram: 'notify-only', spendBy: 'not-applicable', bootstrap: 'refused' },
] as const;

export const APPROVAL_REQUEST_SCOPES = ['import', 'policy', 'tunnel-token', 'guard-override', 'signer-enroll', 'box-secrets', 'host-guard', 'setup-code', 'kek-export', 'worker-keys'] as const;
