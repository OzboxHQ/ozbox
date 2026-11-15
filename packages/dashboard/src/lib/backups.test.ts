import { describe, expect, it } from 'vitest';

import type { BackupItem, BackupsSettings } from '../api/backups';
import { backupsSchema, canRestore, destinationsText, estimateText, fmtWhen, formToSettings, itemLabels, missingSecret, restoreTargets, scheduleText, settingsToForm } from './backups';

const settings: BackupsSettings = {
  schedule: { kind: 'daily', time: '02:30', weekday: 6 },
  retention: { keep_daily: 7, keep_weekly: 4, keep_monthly: 6 },
  provider_snapshots: true,
  restic: { kind: 's3', location: 'https://objects.example.com/bucket' },
  catch_up_hours: 12,
  overrides: { quiet: { enabled: false, schedule: null } },
};

const snap = (o: Partial<BackupItem> = {}): BackupItem => ({ id: 'snap-1', kind: 'snapshot', created_at: '2026-11-09T01:00:00Z', size_bytes: 1073741824, status: 'completed', includes_work: true, labels: {}, scheduled: true, ...o });

describe('schedule and policy text', () => {
  it('says the schedule in words on the persons clock', () => {
    expect(scheduleText({ kind: 'off', time: '02:00', weekday: 0 })).toBe('Off');
    expect(scheduleText(settings.schedule)).toBe('Every day at 02:30');
    expect(scheduleText({ kind: 'weekly', time: '03:00', weekday: 6 })).toBe('Every Sunday at 03:00');
  });

  it('lists the destinations, and says plainly when there are none', () => {
    expect(destinationsText(settings)).toEqual(['Provider snapshots of /work', 'Your repository: S3-compatible object storage · https://objects.example.com/bucket']);
    expect(destinationsText({ ...settings, provider_snapshots: false, restic: null })[0]).toContain('Nowhere yet');
  });

  it('shows a moment in the persons zone, daylight saving included', () => {
    // 07:30 UTC is 02:30 in New York in winter and 03:30 in summer
    expect(fmtWhen(Date.parse('2026-01-15T07:30:00Z'), 'America/New_York')).toContain('2:30');
    expect(fmtWhen(Date.parse('2026-07-15T07:30:00Z'), 'America/New_York')).toContain('3:30');
    expect(fmtWhen(null, 'UTC')).toBe('—');
    expect(fmtWhen(0, 'Not/AZone')).toContain('UTC');
  });

  it('never invents a cost: no figure without a price, and it is called an estimate', () => {
    expect(estimateText({ monthly: null, currency: null })).toContain('Not estimated');
    expect(estimateText({ monthly: 8.5, currency: 'USD' })).toBe('About $8.50 a month at most (estimate)');
  });
});

describe('what a backup can be restored as', () => {
  it('a provider snapshot with /work is cloned or replaces /work; one without /work offers nothing', () => {
    expect(restoreTargets(snap())).toEqual(['new_box', 'in_place']);
    expect(restoreTargets(snap({ includes_work: false }))).toEqual([]);
    expect(itemLabels(snap({ includes_work: false }))).toContain('Root disk only, not /work');
  });

  it('a repository backup goes into a folder (the default), a new box or over /work', () => {
    expect(restoreTargets(snap({ kind: 'restic', scheduled: false }))).toEqual(['folder', 'new_box', 'in_place']);
  });

  it('a snapshot that is not finished cannot be restored from', () => {
    expect(canRestore(snap({ status: 'pending' }))).toBe(false);
    expect(restoreTargets(snap({ status: 'pending' }))).toEqual([]);
    expect(restoreTargets(snap({ status: 'error' }))).toEqual([]);
  });

  it('says who made a snapshot, so a person knows retention will remove it', () => {
    expect(itemLabels(snap())).toContain('Scheduled');
    expect(itemLabels(snap({ scheduled: false }))).toContain('Taken by hand');
  });
});

describe('the policy form', () => {
  it('round-trips and keeps each boxs own choice', () => {
    const f = settingsToForm(settings);
    expect(backupsSchema.safeParse(f).success).toBe(true);
    expect(formToSettings(f, settings)).toEqual(settings);
  });

  it('refuses a bad time, a retention that keeps nothing and a repository with no location', () => {
    const f = settingsToForm(settings);
    expect(backupsSchema.safeParse({ ...f, time: '25:00' }).success).toBe(false);
    expect(backupsSchema.safeParse({ ...f, keepDaily: '0', keepWeekly: '0', keepMonthly: '0' }).success).toBe(false);
    expect(backupsSchema.safeParse({ ...f, repoLocation: '  ' }).success).toBe(false);
    expect(backupsSchema.safeParse({ ...f, catchUp: '0' }).success).toBe(false);
    expect(backupsSchema.safeParse({ ...f, keepDaily: '4000' }).success).toBe(false);
  });

  it('a repository without a saved or typed credential is not turned on', () => {
    const f = settingsToForm(settings);
    const none = { password: false, access_key: false, secret_key: false };
    expect(missingSecret(f, none)).toBe('repository password');
    expect(missingSecret({ ...f, password: 'x' }, { ...none, password: true })).toBe('access key id');
    expect(missingSecret(f, { password: true, access_key: true, secret_key: true })).toBeNull();
    // a local folder needs only the password
    expect(missingSecret({ ...f, repoKind: 'local' }, { ...none, password: true })).toBeNull();
    expect(missingSecret({ ...f, useRepo: false }, none)).toBeNull();
  });

  it('the credentials are never part of the settings sent to the server', () => {
    const f = { ...settingsToForm(settings), password: 'correct-horse-battery', accessKey: 'AKIAEXAMPLE', secretKey: 'sekrit' };
    const sent = JSON.stringify(formToSettings(f, settings));
    for (const s of ['correct-horse-battery', 'AKIAEXAMPLE', 'sekrit']) expect(sent).not.toContain(s);
  });
});
