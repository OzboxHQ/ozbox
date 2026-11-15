// Pure helpers for the task board and the approvals inbox. No React here, so every rule is tested without a browser.

import type { MessageKey } from './i18n';
import type { ActionKind, ApprovalRequest, BulkAction, Needs, Task, TaskState } from '../api/tasks';

export type Column = 'queued' | 'running' | 'needs_you' | 'review' | 'done';

export const COLUMNS: Column[] = ['queued', 'running', 'needs_you', 'review', 'done'];

/** The board has five columns: a failed or cancelled run sits in Done, marked as what it is. */
export function columnOf(state: TaskState): Column {
  return state === 'failed' || state === 'cancelled' ? 'done' : state;
}

export function groupByColumn(tasks: Task[]): Record<Column, Task[]> {
  const out: Record<Column, Task[]> = { queued: [], running: [], needs_you: [], review: [], done: [] };
  for (const t of tasks) out[columnOf(t.state)].push(t);
  return out;
}

/** Whole US cents as a dollar amount: 1234 becomes $12.34. */
export function fmtCents(cents: number): string {
  const d = Math.floor(cents / 100);
  return `$${d.toLocaleString('en-US')}.${String(cents % 100).padStart(2, '0')}`;
}

/** 3725 seconds as 1h 02m; under a minute as 45s. */
export function fmtElapsed(s: number): string {
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m`;
}

/** Dollars typed by a person ("5", "5.5", "$5.50") as cents; null when it is not an amount. */
export function parseDollars(raw: string): number | null {
  const m = /^\$?\s*(\d{1,7})(?:\.(\d{1,2}))?$/.exec(raw.trim());
  if (!m) return null;
  return Number(m[1]) * 100 + Number((m[2] ?? '').padEnd(2, '0') || '0');
}

/** A whole number of at most `max` digits, or null. */
export function parseCount(raw: string, max = 9): number | null {
  const s = raw.trim();
  return new RegExp(`^\\d{1,${max}}$`).test(s) ? Number(s) : null;
}

const BULK_FROM: Record<BulkAction, TaskState[]> = {
  cancel: ['queued', 'running', 'needs_you'],
  retry: ['failed', 'cancelled'],
  review: ['done', 'failed', 'cancelled'],
};

export function canBulk(action: BulkAction, t: Task): boolean {
  return BULK_FROM[action].includes(t.state) && !(action === 'cancel' && t.cancelling);
}

/** How many of the chosen runs the action applies to. */
export function bulkCount(action: BulkAction, tasks: Task[], chosen: Set<string>): number {
  return tasks.filter((t) => chosen.has(t.id) && canBulk(action, t)).length;
}

/** The catalogue key that says why a run needs a person. */
export function needsKey(n: Needs): MessageKey {
  switch (n.kind) {
    case 'spend_cap':
      return 'tasks.needs_spend';
    case 'time_cap':
      return 'tasks.needs_time';
    case 'token_cap':
      return 'tasks.needs_tokens';
    case 'monthly_cap':
      return 'tasks.needs_monthly';
    case 'paused':
      return 'tasks.needs_paused';
    case 'approval':
      return 'tasks.needs_approval';
  }
}

/** A run paused at a limit can be given more; one waiting for an approval is answered in the inbox. */
export function isCapPause(t: Task): boolean {
  return t.state === 'needs_you' && t.needs !== null && t.needs.kind !== 'approval';
}

export function stateTone(s: TaskState): 'default' | 'secondary' | 'destructive' | 'outline' {
  switch (s) {
    case 'failed':
      return 'destructive';
    case 'needs_you':
      return 'default';
    case 'queued':
    case 'cancelled':
      return 'outline';
    default:
      return 'secondary';
  }
}

export interface Filters {
  box: string;
  engine: string;
  person: string;
  state: TaskState | '';
  /** `any`, `today`, `7d` or `30d`. */
  date: 'any' | 'today' | '7d' | '30d';
}

export const NO_FILTERS: Filters = { box: '', engine: '', person: '', state: '', date: 'any' };

/** The filters a link can set: `/tasks?box=name` (from a box's page). Anything else in the address is ignored. */
export function filtersFromSearch(search: string): Filters {
  const box = new URLSearchParams(search).get('box') ?? '';
  return { ...NO_FILTERS, box: box.length > 0 && box.length <= 64 ? box : '' };
}

export function sinceFor(date: Filters['date'], nowMs: number): number | undefined {
  const day = 86_400_000;
  switch (date) {
    case 'today':
      return nowMs - (nowMs % day);
    case '7d':
      return nowMs - 7 * day;
    case '30d':
      return nowMs - 30 * day;
    default:
      return undefined;
  }
}

export function anyFilter(f: Filters): boolean {
  return f.box !== '' || f.engine !== '' || f.person !== '' || f.state !== '' || f.date !== 'any';
}

/** Minutes left before a request expires, never below one while it is open. */
export function minutesLeft(a: ApprovalRequest): number {
  return Math.max(1, Math.round(a.expires_in_s / 60));
}

export const KIND_KEY: Record<ActionKind, MessageKey> = {
  push_protected_branch: 'approvals.kind_push_protected_branch',
  open_pr_to_main: 'approvals.kind_open_pr_to_main',
  ask_command: 'approvals.kind_ask_command',
  outbound_message: 'approvals.kind_outbound_message',
  spend_above_threshold: 'approvals.kind_spend_above_threshold',
  production_resource: 'approvals.kind_production_resource',
  tool_call: 'approvals.kind_tool_call',
};

/** Split a typed list (commas or new lines) into trimmed, non-empty, distinct entries. */
export function splitList(raw: string): string[] {
  return [...new Set(raw.split(/[\n,]/).map((x) => x.trim()).filter(Boolean))];
}

/** A link an agent produced, only if it is a web address: anything else (a script, a file) is never made clickable. */
export function safeHref(raw: string): string | null {
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch {
    return null;
  }
}

export type TaskAction = 'cancel' | 'retry' | 'review' | 'accept' | 'resume';

/**
 * What a person may be offered on one task. The server refuses every one of these to a role that cannot start runs, so a
 * page that offers them to a viewer only produces a refusal; offering none says the truth in the first place.
 */
export function offeredActions(task: Pick<Task, 'state' | 'cancelling' | 'needs'>, mayStart: boolean): TaskAction[] {
  if (!mayStart) return [];
  const out: TaskAction[] = [];
  if (['queued', 'running', 'needs_you'].includes(task.state) && !task.cancelling) out.push('cancel');
  if (['failed', 'cancelled'].includes(task.state)) out.push('retry');
  if (['done', 'failed', 'cancelled'].includes(task.state)) out.push('review');
  if (task.state === 'review') out.push('accept');
  if (isCapPause(task as Task)) out.push('resume');
  return out;
}
