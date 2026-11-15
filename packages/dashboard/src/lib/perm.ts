import type { AuditEntry, Grant, Mode, NewGrantBody, PermSettings, Rule, Scope, VerifyReport } from '../api/perm';

/** Minutes a grant has left, rounded up; 0 once it is over. */
export function minutesLeft(g: Pick<Grant, 'expires_ms'>, now: number): number {
  return Math.max(0, Math.ceil((g.expires_ms - now) / 60_000));
}

export function splitGrants(grants: Grant[]): { active: Grant[]; past: Grant[] } {
  return { active: grants.filter((g) => g.state === 'active'), past: grants.filter((g) => g.state !== 'active') };
}

export interface GrantForm {
  scope: Scope;
  scopeId: string;
  reason: string;
  minutes: string;
  actions: string;
  allowUnattended: boolean;
  confirm: string;
}

export const EMPTY_GRANT: GrantForm = { scope: 'box', scopeId: '', reason: '', minutes: '30', actions: '*', allowUnattended: false, confirm: '' };

export type GrantProblem = 'scope_id' | 'reason' | 'minutes' | 'actions' | 'confirm';

/** What is wrong with a grant form, before the server is asked. The server checks the same limits. */
export function grantProblem(f: GrantForm, maxMinutes: number, signedIn: boolean): GrantProblem | null {
  if (!/^[A-Za-z0-9._:@-]{1,64}$/.test(f.scopeId.trim())) return 'scope_id';
  if (f.reason.trim().length < 8 || f.reason.length > 300) return 'reason';
  const m = Number(f.minutes);
  if (!Number.isInteger(m) || m < 1 || m > maxMinutes) return 'minutes';
  if (actionList(f.actions).length === 0) return 'actions';
  if (!signedIn && f.confirm.trim() !== f.scopeId.trim()) return 'confirm';
  return null;
}

export function actionList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((a) => a.trim())
    .filter((a) => /^[A-Za-z0-9._*-]{1,40}$/.test(a));
}

export function grantBody(f: GrantForm, signedIn: boolean): NewGrantBody {
  return {
    scope: f.scope,
    scope_id: f.scopeId.trim(),
    actions: actionList(f.actions),
    reason: f.reason.trim(),
    minutes: Number(f.minutes),
    allow_unattended: f.allowUnattended,
    ...(signedIn ? {} : { confirm: f.confirm.trim() }),
  };
}

export function newRule(): Rule {
  return { id: '', effect: 'deny', action: '', scope: 'person', scope_id: null, path: null, command: null, env: null, tool: null, server: null, note: '' };
}

/** A rule as it is sent: empty optional fields become null, and a person-wide rule has no id. */
export function cleanRule(r: Rule): Rule {
  const nz = (v: string | null) => (v && v.trim() ? v.trim() : null);
  return { ...r, action: r.action.trim(), scope_id: r.scope === 'person' ? nz(r.scope_id) : nz(r.scope_id), path: nz(r.path), command: nz(r.command), tool: nz(r.tool), server: nz(r.server), note: r.note.trim() };
}

export function ruleProblem(r: Rule): 'action' | 'scope_id' | null {
  const c = cleanRule(r);
  if (!/^[A-Za-z0-9._*-]{1,40}$/.test(c.action)) return 'action';
  if (c.scope !== 'person' && !c.scope_id) return 'scope_id';
  return null;
}

export function withRule(s: PermSettings, r: Rule): PermSettings {
  return { ...s, rules: [...s.rules, cleanRule(r)] };
}

export function withoutRule(s: PermSettings, id: string): PermSettings {
  return { ...s, rules: s.rules.filter((r) => r.id !== id) };
}

export function withMode(s: PermSettings, mode: Mode): PermSettings {
  return { ...s, default_mode: mode };
}

export const AUDIT_FILTERS = ['', 'permission.', 'tool.', 'grant.', 'approval.', 'run.', 'box.'] as const;

/** What a person typed into the browser hosts box: names or `*.` patterns, separated by spaces, commas or new lines. */
export function hostList(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((h) => h.trim().toLowerCase()).filter(Boolean))];
}

export function hostProblem(hosts: string[]): boolean {
  return hosts.length > 50 || hosts.some((h) => !/^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(h));
}

export function withHosts(s: PermSettings, hosts: string[]): PermSettings {
  return { ...s, browser_hosts: hosts };
}

/** A person-readable list of what a failed check found, as [kind, detail] pairs the page turns into sentences. */
export function problems(r: VerifyReport): [string, string][] {
  const out: [string, string][] = [];
  if (r.altered.length) out.push(['altered', r.altered.join(', ')]);
  for (const g of r.deleted) out.push(['deleted', `${g.after_seq}-${g.before_seq}`]);
  if (r.out_of_order.length) out.push(['order', r.out_of_order.join(', ')]);
  if (r.bad_seals.length) out.push(['seals', r.bad_seals.join(', ')]);
  if (r.truncated) out.push(['truncated', `${r.truncated.sealed_seq}/${r.truncated.last_seq}`]);
  if (r.unreadable_lines.length) out.push(['unreadable', r.unreadable_lines.join(', ')]);
  return out;
}

/** The first twelve characters of a hash: enough to compare by eye, copy the rest from the list. */
export function shortHash(h: string): string {
  return h ? h.slice(0, 12) : '';
}

export function entryText(e: AuditEntry): string {
  return `${e.action} ${e.actor} ${e.subject ?? ''} ${e.detail}`.toLowerCase();
}
