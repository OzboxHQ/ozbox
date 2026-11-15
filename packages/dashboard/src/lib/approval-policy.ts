// The approval policy and the spend limits as a person edits them: form text in, validated settings out, and a plain list
// of what changed for the review step that comes before saving.

import type { ActionKind, ApprovalPolicy, SpendCaps } from '../api/tasks';
import { ACTION_KINDS } from '../api/tasks';
import { parseDollars, splitList } from './tasks';

export const EXPIRY_CHOICES: { seconds: number; label: string }[] = [
  { seconds: 900, label: 'policy.expiry_15m' },
  { seconds: 3600, label: 'policy.expiry_1h' },
  { seconds: 4 * 3600, label: 'policy.expiry_4h' },
  { seconds: 8 * 3600, label: 'policy.expiry_8h' },
  { seconds: 24 * 3600, label: 'policy.expiry_24h' },
  { seconds: 72 * 3600, label: 'policy.expiry_72h' },
];

export interface PolicyForm {
  ask: ActionKind[];
  step_up: ActionKind[];
  protected_branches: string;
  ask_commands: string;
  spend_threshold: string;
  expiry_s: number;
  approvers: string;
  allow_requester: boolean;
}

export function policyToForm(p: ApprovalPolicy): PolicyForm {
  return {
    ask: [...p.ask],
    step_up: [...p.step_up],
    protected_branches: p.protected_branches.join('\n'),
    ask_commands: p.ask_commands.join('\n'),
    spend_threshold: p.spend_threshold_cents === null ? '' : (p.spend_threshold_cents / 100).toFixed(2),
    expiry_s: p.expiry_s,
    approvers: p.approvers.join('\n'),
    allow_requester: p.allow_requester,
  };
}

export type FormResult<T> = { ok: true; value: T } | { ok: false; error: string };

const WORD = /^[\x21-\x7e]{1,100}$/;

/** Turn the form back into a policy. The error is a catalogue key. */
export function formToPolicy(f: PolicyForm): FormResult<ApprovalPolicy> {
  const branches = splitList(f.protected_branches);
  if (!branches.every((b) => WORD.test(b))) return { ok: false, error: 'policy.err_branches' };
  const commands = splitList(f.ask_commands);
  if (!commands.every((c) => /^[\x20-\x7e]{1,100}$/.test(c))) return { ok: false, error: 'policy.err_commands' };
  const approvers = splitList(f.approvers);
  if (!approvers.every((a) => WORD.test(a))) return { ok: false, error: 'policy.err_approvers' };
  let threshold: number | null = null;
  if (f.spend_threshold.trim() !== '') {
    threshold = parseDollars(f.spend_threshold);
    if (threshold === null) return { ok: false, error: 'policy.err_threshold' };
  }
  return {
    ok: true,
    value: {
      ask: ACTION_KINDS.filter((k) => f.ask.includes(k)),
      step_up: ACTION_KINDS.filter((k) => f.step_up.includes(k)),
      protected_branches: branches,
      ask_commands: commands,
      spend_threshold_cents: threshold,
      expiry_s: f.expiry_s,
      approvers,
      allow_requester: f.allow_requester,
    },
  };
}

export interface Change {
  /** Catalogue key of the setting. */
  key: string;
  from: string;
  to: string;
}

const list = (v: string[]) => (v.length === 0 ? '' : v.join(', '));

/** What differs between two policies, setting by setting, for the review step. */
export function policyChanges(a: ApprovalPolicy, b: ApprovalPolicy, kindName: (k: ActionKind) => string): Change[] {
  const out: Change[] = [];
  const add = (key: string, from: string, to: string) => {
    if (from !== to) out.push({ key, from, to });
  };
  add('policy.f_ask', list(a.ask.map(kindName)), list(b.ask.map(kindName)));
  add('policy.f_step_up', list(a.step_up.map(kindName)), list(b.step_up.map(kindName)));
  add('policy.f_branches', list(a.protected_branches), list(b.protected_branches));
  add('policy.f_commands', list(a.ask_commands), list(b.ask_commands));
  add('policy.f_threshold', a.spend_threshold_cents === null ? '' : String(a.spend_threshold_cents), b.spend_threshold_cents === null ? '' : String(b.spend_threshold_cents));
  add('policy.f_expiry', String(a.expiry_s), String(b.expiry_s));
  add('policy.f_approvers', list(a.approvers), list(b.approvers));
  add('policy.f_requester', String(a.allow_requester), String(b.allow_requester));
  return out;
}

/** An expiry raised past this many seconds (the 8-hour default) is a loosening; mirrors `LOOSENING_EXPIRY_S` (owner decision D16). */
export const LOOSENING_EXPIRY_S = 8 * 3600;

/**
 * Whether replacing `a` by `b` asks for LESS than before. The server decides (and asks for a passkey); this tells a person in
 * the review that it will. It mirrors `ApprovalPolicy::loosens` in the server.
 */
export function policyLoosens(a: ApprovalPolicy, b: ApprovalPolicy): boolean {
  const dropped = (was: string[], now: string[]) => was.some((x) => !now.includes(x));
  const threshold = a.spend_threshold_cents !== null && (b.spend_threshold_cents === null || b.spend_threshold_cents > a.spend_threshold_cents);
  const approvers = a.approvers.length > 0 && (b.approvers.length === 0 || b.approvers.some((p) => !a.approvers.includes(p)));
  return dropped(a.ask, b.ask) || dropped(a.protected_branches, b.protected_branches) || dropped(a.ask_commands, b.ask_commands) || threshold || approvers || (!a.allow_requester && b.allow_requester) || dropped(a.step_up, b.step_up) || (b.expiry_s > LOOSENING_EXPIRY_S && b.expiry_s > a.expiry_s);
}

/**
 * Whether replacing the limits `a` by `b` allows more spend: a limit raised or removed (the fleet's, the default one, or a
 * named person's, where a dropped own limit falls back to the default and a new own limit above it is a raise). Mirrors
 * `SpendCaps::loosens` in the server.
 */
export function capsLoosen(a: SpendCaps, b: SpendCaps): boolean {
  const wider = (was: number | null, now: number | null) => was !== null && (now === null || now > was);
  const limit = (c: SpendCaps, who: string): number | null => c.per_person[who] ?? c.person_monthly_cents;
  const people = new Set([...Object.keys(a.per_person), ...Object.keys(b.per_person)]);
  return wider(a.fleet_monthly_cents, b.fleet_monthly_cents) || wider(a.person_monthly_cents, b.person_monthly_cents) || [...people].some((who) => wider(limit(a, who), limit(b, who)));
}

export interface CapsForm {
  fleet: string;
  person: string;
  /** One `person = dollars` per line. */
  overrides: string;
}

export function capsToForm(c: SpendCaps): CapsForm {
  const d = (v: number | null) => (v === null ? '' : (v / 100).toFixed(2));
  return {
    fleet: d(c.fleet_monthly_cents),
    person: d(c.person_monthly_cents),
    overrides: Object.entries(c.per_person)
      .map(([k, v]) => `${k} = ${(v / 100).toFixed(2)}`)
      .join('\n'),
  };
}

export function formToCaps(f: CapsForm): FormResult<SpendCaps> {
  const money = (raw: string): number | null | undefined => (raw.trim() === '' ? null : (parseDollars(raw) ?? undefined));
  const fleet = money(f.fleet);
  const person = money(f.person);
  if (fleet === undefined) return { ok: false, error: 'caps.err_fleet' };
  if (person === undefined) return { ok: false, error: 'caps.err_person' };
  const per: Record<string, number> = {};
  for (const line of f.overrides.split('\n').map((l) => l.trim()).filter(Boolean)) {
    const m = /^([^=\s]{1,64})\s*=\s*(.+)$/.exec(line);
    const cents = m ? parseDollars(m[2] ?? '') : null;
    if (!m || cents === null) return { ok: false, error: 'caps.err_override' };
    per[m[1] ?? ''] = cents;
  }
  return { ok: true, value: { fleet_monthly_cents: fleet, person_monthly_cents: person, per_person: per } };
}

/** The share of a monthly limit already used, 0 to 100, or null when there is no limit. */
export function usedPct(spent: number, limit: number | null): number | null {
  if (limit === null || limit <= 0) return null;
  return Math.min(100, Math.round((spent / limit) * 100));
}
