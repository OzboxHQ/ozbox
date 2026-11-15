import { z } from 'zod';

import type { BackupItem, BackupsSettings, ResticKind, Schedule, ScheduleKind } from '../api/backups';
import { ABSENT, fmtBytes, fmtCost } from './format';
import { t, type MessageKey } from './i18n';

const WEEKDAYS: MessageKey[] = ['backups.weekday_0', 'backups.weekday_1', 'backups.weekday_2', 'backups.weekday_3', 'backups.weekday_4', 'backups.weekday_5', 'backups.weekday_6'];

export function weekdayName(n: number): string {
  const key = WEEKDAYS[n];
  return key ? t(key) : ABSENT;
}

/** "Every day at 02:00", "Every Sunday at 02:00" or "Off", on the person's own clock. */
export function scheduleText(s: Schedule): string {
  if (s.kind === 'off') return t('backups.schedule_off');
  if (s.kind === 'daily') return t('backups.schedule_daily', { time: s.time });
  return t('backups.schedule_weekly', { day: weekdayName(s.weekday), time: s.time });
}

export function retentionText(r: BackupsSettings['retention']): string {
  return t('backups.retention_value', { d: r.keep_daily, w: r.keep_weekly, m: r.keep_monthly });
}

export function destinationsText(b: BackupsSettings): string[] {
  const out: string[] = [];
  if (b.provider_snapshots) out.push(t('backups.dest_snapshots'));
  if (b.restic) out.push(t('backups.dest_repository', { where: repositoryLabel(b.restic.kind, b.restic.location) }));
  return out.length > 0 ? out : [t('backups.dest_none')];
}

/** Where a repository is, without credentials: the location is not a secret, the keys never reach the browser. */
export function repositoryLabel(kind: ResticKind, location: string): string {
  return `${t(KIND_LABEL[kind])} · ${location}`;
}

export const KIND_LABEL: Record<ResticKind, MessageKey> = {
  s3: 'backups.kind_s3',
  b2: 'backups.kind_b2',
  sftp: 'backups.kind_sftp',
  local: 'backups.kind_local',
};

export const LOCATION_HINT: Record<ResticKind, MessageKey> = {
  s3: 'backups.loc_hint_s3',
  b2: 'backups.loc_hint_b2',
  sftp: 'backups.loc_hint_sftp',
  local: 'backups.loc_hint_local',
};

/** A moment on the person's own clock (their time zone, daylight saving included), with the zone named. */
export function fmtWhen(ms: number | null | undefined, zone: string): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return ABSENT;
  try {
    return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short', timeZone: zone }).format(new Date(ms));
  } catch {
    return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(ms)) + ' UTC';
  }
}

export function fmtIso(iso: string | null | undefined, zone: string): string {
  if (!iso) return ABSENT;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? ABSENT : fmtWhen(ms, zone);
}

export function itemKindText(i: BackupItem): string {
  return t(i.kind === 'snapshot' ? 'backups.kind_snapshot' : 'backups.kind_restic');
}

export function itemStatusText(status: string): string {
  if (status === 'completed') return t('backups.status_completed');
  if (status === 'pending') return t('backups.status_pending');
  return t('backups.status_error');
}

/** The labels a person reads: who made it, and anything that limits it. */
export function itemLabels(i: BackupItem): string[] {
  const out: string[] = [];
  if (i.kind === 'snapshot') out.push(i.scheduled ? t('backups.label_scheduled') : t('backups.label_manual'));
  if (!i.includes_work) out.push(t('backups.label_no_work'));
  return out;
}

export const itemSize = (i: BackupItem): string => fmtBytes(i.size_bytes);

/** Only a finished backup can be restored from; a snapshot that is still being made or failed can only be waited on or deleted. */
export function canRestore(i: BackupItem): boolean {
  return i.status === 'completed';
}

/** What a snapshot can be restored as: a provider snapshot that holds /work can be cloned or replace /work; a repository backup goes into a new box, a folder or over /work. */
export type RestoreTarget = 'new_box' | 'in_place' | 'folder';
export function restoreTargets(i: BackupItem): RestoreTarget[] {
  if (!canRestore(i)) return [];
  if (i.kind === 'snapshot') return i.includes_work ? ['new_box', 'in_place'] : [];
  // The folder stays the default: it changes nothing that exists. A new box is one click away.
  return ['folder', 'new_box', 'in_place'];
}

export function estimateText(e: { monthly: number | null; currency: string | null }): string {
  if (e.monthly === null) return t('backups.estimate_none');
  return t('backups.estimate_value', { amount: fmtCost(e.monthly, e.currency ?? 'USD') });
}

// ---------- the policy form ----------

const hhmm = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, t('backups.err_time'));
const count = z.string().regex(/^\d{1,4}$/, t('backups.err_number')).refine((v) => Number(v) <= 3650, t('backups.err_number'));

export const backupsSchema = z
  .object({
    every: z.enum(['off', 'daily', 'weekly']),
    time: hhmm,
    weekday: z.string().regex(/^[0-6]$/),
    keepDaily: count,
    keepWeekly: count,
    keepMonthly: count,
    catchUp: z.string().regex(/^\d{1,3}$/, t('backups.err_hours')).refine((v) => Number(v) >= 1 && Number(v) <= 168, t('backups.err_hours')),
    providerSnapshots: z.boolean(),
    useRepo: z.boolean(),
    repoKind: z.enum(['s3', 'b2', 'sftp', 'local']),
    repoLocation: z.string(),
    /** Write-only: empty keeps what is saved. */
    password: z.string(),
    accessKey: z.string(),
    secretKey: z.string(),
  })
  .superRefine((v, ctx) => {
    if (Number(v.keepDaily) + Number(v.keepWeekly) + Number(v.keepMonthly) === 0) ctx.addIssue({ code: 'custom', path: ['keepDaily'], message: t('backups.err_keep_any') });
    if (v.useRepo && v.repoLocation.trim() === '') ctx.addIssue({ code: 'custom', path: ['repoLocation'], message: t('backups.err_location') });
  });
export type BackupsForm = z.infer<typeof backupsSchema>;

export function settingsToForm(b: BackupsSettings): BackupsForm {
  return {
    every: b.schedule.kind,
    time: b.schedule.time,
    weekday: String(b.schedule.weekday),
    keepDaily: String(b.retention.keep_daily),
    keepWeekly: String(b.retention.keep_weekly),
    keepMonthly: String(b.retention.keep_monthly),
    catchUp: String(b.catch_up_hours),
    providerSnapshots: b.provider_snapshots,
    useRepo: b.restic !== null,
    repoKind: b.restic?.kind ?? 's3',
    repoLocation: b.restic?.location ?? '',
    password: '',
    accessKey: '',
    secretKey: '',
  };
}

/** The settings the form describes, keeping each box's own choices. The credentials are not part of them. */
export function formToSettings(f: BackupsForm, current: BackupsSettings): BackupsSettings {
  const schedule: Schedule = { kind: f.every as ScheduleKind, time: f.time, weekday: Number(f.weekday) };
  return {
    schedule,
    retention: { keep_daily: Number(f.keepDaily), keep_weekly: Number(f.keepWeekly), keep_monthly: Number(f.keepMonthly) },
    provider_snapshots: f.providerSnapshots,
    restic: f.useRepo ? { kind: f.repoKind, location: f.repoLocation.trim() } : null,
    catch_up_hours: Number(f.catchUp),
    overrides: current.overrides,
  };
}

/** A repository kind that needs an access key and a secret key besides the password. */
export const needsKeys = (k: ResticKind): boolean => k === 's3' || k === 'b2';

/** The credential a repository still lacks, in words: the form refuses to turn it on without it. */
export function missingSecret(f: BackupsForm, flags: { password: boolean; access_key: boolean; secret_key: boolean }): string | null {
  if (!f.useRepo) return null;
  if (!flags.password && f.password === '') return t('backups.what_password');
  if (needsKeys(f.repoKind)) {
    if (!flags.access_key && f.accessKey === '') return t('backups.what_access_key');
    if (!flags.secret_key && f.secretKey === '') return t('backups.what_secret_key');
  }
  return null;
}
