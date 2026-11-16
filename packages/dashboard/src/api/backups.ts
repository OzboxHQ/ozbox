// Backups: the fleet-wide policy, each box's snapshots and repository backups, and the credentials hand-off. The server
// keeps the repository password and keys in its secret store; nothing here reads one back.

import type { MetricsSource } from './types';

export type ScheduleKind = 'off' | 'daily' | 'weekly';

export interface Schedule {
  kind: ScheduleKind;
  /** `HH:MM` on the person's own clock. */
  time: string;
  /** Weekly only: 0 = Monday … 6 = Sunday. */
  weekday: number;
}

export interface Retention {
  keep_daily: number;
  keep_weekly: number;
  keep_monthly: number;
}

export type ResticKind = 's3' | 'b2' | 'sftp' | 'local';

export interface ResticTarget {
  kind: ResticKind;
  location: string;
}

export interface BoxOverride {
  enabled: boolean | null;
  schedule: Schedule | null;
}

export interface BackupsSettings {
  schedule: Schedule;
  retention: Retention;
  provider_snapshots: boolean;
  restic: ResticTarget | null;
  catch_up_hours: number;
  overrides: Record<string, BoxOverride>;
}

export interface RunRecord {
  ts_ms: number;
  ok: boolean;
  /** `snapshot`, `restic` or `schedule`. */
  kind: string;
  detail: string;
  scheduled: boolean;
}

export interface FleetBox {
  name: string;
  state: string;
  schedule: Schedule;
  next_run_ms: number | null;
  last: RunRecord | null;
  running: boolean;
}

export interface FleetBackups {
  /** `simulated` when the schedule, snapshots and repository below belong to the demo provider. Absent from an older server. */
  source?: MetricsSource;
  zone: string;
  now_ms: number;
  settings: BackupsSettings;
  /** Whether each credential is set. Never its value. */
  secrets: { password: boolean; access_key: boolean; secret_key: boolean };
  boxes: FleetBox[];
  estimate: { basis: 'estimate'; monthly: number | null; currency: string | null; snapshot_gb_month: number | null; note: string };
}

export interface BackupItem {
  id: string;
  kind: 'snapshot' | 'restic';
  created_at: string | null;
  size_bytes: number | null;
  status: string;
  includes_work: boolean;
  labels: Record<string, unknown>;
  /** Made by the schedule (and so removed by its retention); a snapshot taken by hand is never pruned. */
  scheduled: boolean;
}

export interface BoxBackups {
  /** `simulated` for the demo provider: its snapshots and repository backups are made up. Absent from an older server. */
  source?: MetricsSource;
  box: string;
  state: string;
  items: BackupItem[];
  provider: { supported: boolean; includes_work: boolean | null; error: string | null };
  restic: { target_set: boolean; configured_on_box: boolean | null; error: string | null; running: unknown; /** A prune holds the repository: its list was not read, which is not "no backups" and not an error. Absent from an older server. */ busy?: boolean; /** `false`: the box's secrets service is not up yet, so "no credentials" is "not known". Absent from an older server (ready). */ secrets_ready?: boolean };
  /** Backups were switched off for this box (Settings, or "Turn off backups on this box"). Absent from an older server. */
  turned_off?: boolean;
  /** The /work disks a restore replaced and kept; they keep costing storage until deleted. `pending` while a restore is unfinished. */
  old_disks?: { id: string; size_gb: number | null; restored_from: string | null; state: 'kept' | 'pending' }[];
  /** A restore into this (new) box that is still being carried out. */
  new_box_restore?: { from: string; snapshot: string; started_ms: number; detail: string } | null;
  schedule: Schedule;
  zone: string;
  next_run_ms: number | null;
  last: RunRecord | null;
  running: boolean;
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export interface BackupsApi {
  fleet(signal?: AbortSignal): Promise<FleetBackups>;
  saveSettings(settings: BackupsSettings, signal?: AbortSignal): Promise<FleetBackups>;
  box(name: string, signal?: AbortSignal): Promise<BoxBackups>;
  /** Put the repository credentials on the box now (from the server's secret store). */
  pushCredentials(name: string, signal?: AbortSignal): Promise<void>;
  removeCredentials(name: string, signal?: AbortSignal): Promise<void>;
  /** Retire this box's backups: remove its repository credentials from the box and switch its schedule off. Existing backups stay. */
  turnOff(name: string, signal?: AbortSignal): Promise<void>;
}

export function createBackupsApi(request: Request): BackupsApi {
  const box = (n: string) => `/v1/boxes/${encodeURIComponent(n)}/backups`;
  return {
    fleet: (s) => request('GET', '/v1/backups', undefined, s),
    saveSettings: (b, s) => request('PUT', '/v1/backups/settings', b, s),
    box: (n, s) => request('GET', box(n), undefined, s),
    pushCredentials: async (n, s) => {
      await request('POST', `${box(n)}/credentials`, undefined, s);
    },
    removeCredentials: async (n, s) => {
      await request('DELETE', `${box(n)}/credentials`, undefined, s);
    },
    turnOff: async (n, s) => {
      await request('POST', `${box(n)}/off`, undefined, s);
    },
  };
}
