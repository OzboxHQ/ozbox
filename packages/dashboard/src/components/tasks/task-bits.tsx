import { Badge } from '@/components/ui/badge';
import type { Task, TaskState } from '../../api/tasks';
import { t, type MessageKey } from '../../lib/i18n';
import { fmtCents, fmtElapsed, needsKey, safeHref, stateTone } from '../../lib/tasks';

const STATE_LABEL: Record<TaskState, MessageKey> = {
  queued: 'tasks.state_queued',
  running: 'tasks.state_running',
  needs_you: 'tasks.state_needs_you',
  review: 'tasks.state_review',
  done: 'tasks.state_done',
  failed: 'tasks.state_failed',
  cancelled: 'tasks.state_cancelled',
};

export function stateLabel(s: TaskState): string {
  return t(STATE_LABEL[s]);
}

export function StateBadge({ state }: { state: TaskState }) {
  return <Badge variant={stateTone(state)}>{stateLabel(state)}</Badge>;
}

/** Why a run is not simply running: a pause, a request, or the reason it still waits. */
export function whyLine(task: Task): string | null {
  if (task.needs?.kind === 'monthly_cap') return t('tasks.needs_monthly_scope', { scope: task.needs.scope });
  if (task.needs) return t(needsKey(task.needs));
  if (task.state === 'queued' && task.queue_reason) return t('tasks.waiting', { why: task.queue_reason });
  return null;
}

export function pullRequest(task: Task): string | null {
  const url = task.links.find((l) => l.kind === 'pull_request')?.url;
  return url ? safeHref(url) : null;
}

/** Cost and time with their limits, in the words the card and the list share. */
export function costText(task: Task): string {
  const cap = task.caps.max_spend_cents;
  return cap !== null ? `${fmtCents(task.spend_cents)} ${t('tasks.of_cap', { cap: fmtCents(cap) })}` : fmtCents(task.spend_cents);
}

export function timeText(task: Task): string {
  const cap = task.caps.max_runtime_s;
  return cap !== null ? `${fmtElapsed(task.elapsed_s)} ${t('tasks.of_cap', { cap: fmtElapsed(cap) })}` : fmtElapsed(task.elapsed_s);
}

export function originText(task: Task): string | null {
  if (task.origin.kind === 'schedule') return t('tasks.origin_schedule', { id: task.origin.id });
  if (task.origin.kind === 'trigger') return t('tasks.origin_trigger', { id: task.origin.id });
  return null;
}

/** Whether the cost figure is the engine's own or an estimate; nothing is said before anything is counted. */
export function costSourceText(task: Task): string | null {
  if (task.cost_source === 'reported') return t('tasks.cost_reported');
  if (task.cost_source === 'estimated') return t('tasks.cost_estimated');
  return null;
}

/** The provider and model a run uses ("openai / gpt-4o"), or null when it uses the engine's own login. */
export function modelText(task: Task): string | null {
  const m = task.model;
  return m ? t('tasks.model_value', { provider: m.provider_id, model: m.model }) : null;
}

/** When the provider refused the run: where it switched from and why. */
export function fallbackText(task: Task): string | null {
  const m = task.model;
  if (!m?.fell_back_from) return null;
  return t('tasks.model_fell_back', { from: m.fell_back_from.model, reason: m.fallback_reason ?? '' });
}
