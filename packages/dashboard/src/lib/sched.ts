import { z } from 'zod';

import type { Delivery, ScheduleInput, ScheduleItem, SchedRun, TriggerInput } from '../api/sched';
import { t, type MessageKey } from './i18n';

const NAME = /^[a-z0-9._-]+$/;

const PROFILE = 'profile:';

/** A "box" choice in the form is a box name, or `profile:<name>` for "any box with this profile". */
export function targetFromChoice(choice: string): { box_name: string | null; profile: string | null } {
  return choice.startsWith(PROFILE) ? { box_name: null, profile: choice.slice(PROFILE.length) } : { box_name: choice, profile: null };
}

export function choiceFromTarget(target: { box_name: string | null; profile: string | null }): string {
  return target.profile ? `${PROFILE}${target.profile}` : (target.box_name ?? '');
}

/** The choices a box picker offers: every box, then every profile the boxes carry. */
export function boxChoices(boxes: { spec: { name: string; labels?: Record<string, string> } }[]): string[] {
  const profiles = [...new Set(boxes.map((b) => b.spec.labels?.profile).filter((p): p is string => !!p))].sort();
  return [...boxes.map((b) => b.spec.name), ...profiles.map((p) => `${PROFILE}${p}`)];
}

export function boxChoiceLabel(choice: string): string {
  return choice.startsWith(PROFILE) ? t('schedules.f_profile_any', { profile: choice.slice(PROFILE.length) }) : choice;
}

/** The schedule form, as a person fills it in. Money is in dollars here and in cents on the wire. */
export const scheduleSchema = z
  .object({
    name: z.string().trim().min(1, 'err_name').max(80),
    kind: z.enum(['task', 'heartbeat']),
    whenText: z.string().trim().max(200),
    cron: z.string().trim().max(120),
    everyMinutes: z.string().trim(),
    timeZone: z.string().trim(),
    engine: z.string().trim().regex(NAME, 'err_engine'),
    prompt: z.string().max(8000),
    skill: z.string().trim().max(60),
    box: z.string().trim().min(1, 'err_box'),
    maxSpend: z.string().trim(),
    maxMinutes: z.string().trim(),
    catchUp: z.string().trim(),
    alertOnFinish: z.boolean(),
  })
  .superRefine((v, ctx) => {
    if (v.kind === 'heartbeat') {
      const n = Number(v.everyMinutes);
      if (!Number.isInteger(n) || n < 5 || n > 1440) ctx.addIssue({ code: 'custom', path: ['everyMinutes'], message: 'err_every' });
    } else {
      if (!v.whenText && !v.cron) ctx.addIssue({ code: 'custom', path: ['whenText'], message: 'err_when' });
      if (!v.prompt.trim() && !v.skill) ctx.addIssue({ code: 'custom', path: ['prompt'], message: 'err_prompt' });
    }
    for (const f of ['maxSpend', 'maxMinutes', 'catchUp'] as const) {
      const raw = v[f];
      if (raw !== '' && !(Number(raw) > 0)) ctx.addIssue({ code: 'custom', path: [f], message: 'err_number' });
    }
  });

export type ScheduleForm = z.infer<typeof scheduleSchema>;

/** The engine a supervisor registers, and so the one a new schedule or trigger runs on. (`claude` was never one: a run on it failed to start.) */
export const DEFAULT_ENGINE = 'claude-code';
/** A demo server runs only its own `fake` engine, so that is what a new item defaults to there. */
export const DEMO_ENGINE = 'fake';

export function defaultEngine(source: 'simulated' | 'live' | null | undefined): string {
  return source === 'simulated' ? DEMO_ENGINE : DEFAULT_ENGINE;
}

/** The engines to offer, always including the one the item already has (so an unusual stored value is shown, not lost). */
export function engineChoices(source: 'simulated' | 'live' | null | undefined, current: string): string[] {
  const base = source === 'simulated' ? [DEMO_ENGINE, DEFAULT_ENGINE] : [DEFAULT_ENGINE];
  return current && !base.includes(current) ? [...base, current] : base;
}

export function emptyScheduleForm(zone: string, engine: string = DEFAULT_ENGINE): ScheduleForm {
  return { name: '', kind: 'task', whenText: '', cron: '', everyMinutes: '30', timeZone: zone, engine, prompt: '', skill: '', box: '', maxSpend: '', maxMinutes: '', catchUp: '', alertOnFinish: true };
}

export function scheduleToForm(s: ScheduleItem): ScheduleForm {
  return {
    name: s.name,
    kind: s.heartbeat ? 'heartbeat' : 'task',
    whenText: s.plain ?? '',
    cron: s.plain ? '' : s.when.kind === 'cron' ? s.when.expr : '',
    everyMinutes: s.when.kind === 'every' ? String(s.when.minutes) : '30',
    timeZone: s.time_zone,
    engine: s.engine,
    prompt: s.prompt ?? '',
    skill: s.skill ?? '',
    box: choiceFromTarget(s.target),
    maxSpend: s.caps.max_spend_cents ? String(s.caps.max_spend_cents / 100) : '',
    maxMinutes: s.caps.max_minutes ? String(s.caps.max_minutes) : '',
    catchUp: String(s.catch_up_minutes),
    alertOnFinish: s.results_to.includes('alert'),
  };
}

const num = (s: string): number | null => (s === '' ? null : Number(s));
const cents = (s: string): number | null => (s === '' ? null : Math.round(Number(s) * 100));

export function formToInput(f: ScheduleForm): ScheduleInput {
  const base: ScheduleInput = {
    name: f.name.trim(),
    time_zone: f.timeZone,
    engine: f.engine,
    target: targetFromChoice(f.box),
    caps: { max_spend_cents: cents(f.maxSpend), max_minutes: num(f.maxMinutes) },
    results_to: f.alertOnFinish ? ['alert'] : [],
    heartbeat: f.kind === 'heartbeat',
  };
  if (f.prompt.trim()) base.prompt = f.prompt.trim();
  if (f.skill) base.skill = f.skill;
  const catchUp = num(f.catchUp);
  if (catchUp !== null) base.catch_up_minutes = catchUp;
  if (f.kind === 'heartbeat') base.every_minutes = Number(f.everyMinutes);
  else if (f.whenText) base.when_text = f.whenText;
  else base.cron = f.cron;
  return base;
}

/** What the preview was made for: any change to this invalidates it. */
export function previewKey(f: ScheduleForm): string {
  return JSON.stringify([f.kind, f.whenText.trim(), f.cron.trim(), f.timeZone]);
}

export function whenText(s: ScheduleItem): string {
  if (s.when.kind === 'every') return t('schedules.every_minutes', { minutes: s.when.minutes });
  return s.plain ?? t('schedules.cron_in_zone', { cron: s.when.expr, zone: s.time_zone });
}

const STATUS: Record<SchedRun['status'], MessageKey> = {
  starting: 'schedules.status_starting',
  running: 'schedules.status_running',
  succeeded: 'schedules.status_succeeded',
  failed: 'schedules.status_failed',
  skipped: 'schedules.status_skipped',
  missed: 'schedules.status_missed',
};

export const statusLabel = (s: SchedRun['status']): string => t(STATUS[s]);

export function sourceLabel(source: string): string {
  if (source === 'manual') return t('schedules.source_manual');
  if (source === 'trigger') return t('schedules.source_trigger');
  return t('schedules.source_schedule');
}

/** A run's reason in the dashboard's own words; the server's sentence only when the reason is not one we word. */
export function runNote(r: SchedRun, catchUpWindow: number): string {
  const parts: string[] = [];
  switch (r.reason) {
    case 'overlap':
      parts.push(t('schedules.reason_overlap'));
      break;
    case 'missed':
      parts.push(t('schedules.reason_missed', { window: catchUpWindow }));
      break;
    case 'caught_up':
      parts.push(t('schedules.reason_caught_up', { minutes: r.args.late_minutes ?? '' }));
      break;
    case 'lost':
      parts.push(t('schedules.reason_lost'));
      break;
    default:
      if (r.detail) parts.push(r.detail);
  }
  if (r.args.skipped_earlier) parts.push(t('schedules.reason_skipped_earlier', { count: r.args.skipped_earlier }));
  return parts.join(' ');
}

const WHY: Record<string, MessageKey> = {
  bad_signature: 'triggers.why_bad_signature',
  missing_signature: 'triggers.why_missing_signature',
  expired: 'triggers.why_expired',
  bad_timestamp: 'triggers.why_bad_timestamp',
  replayed: 'triggers.why_replayed',
  too_large: 'triggers.why_too_large',
  rate_limited: 'triggers.why_rate_limited',
  missing_delivery: 'triggers.why_missing_delivery',
  busy: 'triggers.why_busy',
  no_secret: 'triggers.why_no_secret',
  ping: 'triggers.why_ping',
  event_not_listed: 'triggers.why_event_not_listed',
};

export function deliveryWhy(d: Delivery): string {
  if (d.outcome === 'test') return t('triggers.why_test');
  if (d.outcome === 'accepted') return t('triggers.why_none');
  const key = WHY[d.reason];
  return key ? t(key) : d.reason;
}

export function deliveryOutcome(d: Delivery): string {
  const map: Record<string, MessageKey> = {
    accepted: 'triggers.outcome_accepted',
    refused: 'triggers.outcome_refused',
    ignored: 'triggers.outcome_ignored',
    test: 'triggers.outcome_test',
  };
  const key = map[d.outcome];
  return key ? t(key) : d.outcome;
}

export const triggerSchema = z.object({
  name: z.string().trim().min(1, 'err_name').max(80),
  scheme: z.enum(['github', 'generic', 'stripe']),
  engine: z.string().trim().regex(NAME, 'err_engine'),
  template: z.string().trim().min(1, 'err_template').max(8000),
  events: z.string().trim(),
  box: z.string().trim().min(1, 'err_box'),
  maxSpend: z.string().trim().refine((v) => v === '' || Number(v) > 0, 'err_number'),
  maxMinutes: z.string().trim().refine((v) => v === '' || Number(v) > 0, 'err_number'),
});

export type TriggerForm = z.infer<typeof triggerSchema>;

export function emptyTriggerForm(engine: string = DEFAULT_ENGINE): TriggerForm {
  return { name: '', scheme: 'github', engine, template: '', events: '', box: '', maxSpend: '', maxMinutes: '' };
}

export function triggerFormToInput(f: TriggerForm): TriggerInput {
  const events = f.scheme === 'github' ? f.events.split(',').map((e) => e.trim()).filter(Boolean) : [];
  const out: TriggerInput = {
    name: f.name.trim(),
    scheme: f.scheme,
    engine: f.engine,
    template: f.template.trim(),
    target: targetFromChoice(f.box),
    caps: { max_spend_cents: cents(f.maxSpend), max_minutes: num(f.maxMinutes) },
    results_to: ['alert'],
    events,
  };
  return out;
}
