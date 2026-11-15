/** What became of an alert, per person, and the shapes of a background test send and of a day's summary. */

export type OutcomeStatus = 'delivered' | 'held_quiet' | 'held_limit' | 'not_sent' | 'retrying' | 'failed' | 'partial';

/** What finally became of one channel of a person's route. */
export type ChannelState = 'sent' | 'retrying' | 'failed' | 'refused';

export interface ChannelResult {
  channel: string;
  state: ChannelState;
  /** How many tries were made. */
  attempts: number;
  /** Why it failed or was refused. */
  detail?: string;
}

export interface AlertOutcome {
  /** Whose rules decided it; absent when no one has routing rules, or the alert was refused for everyone. */
  person?: string;
  status: OutcomeStatus;
  /** Where it went, or would have gone. */
  channels?: string[];
  /** What finally became of each channel. Absent on alerts recorded before this was kept, and on a hold. */
  results?: ChannelResult[];
}

export type TestItemStatus = 'pending' | 'sent' | 'failed';

export interface TestItem {
  channel: string;
  person?: string;
  status: TestItemStatus;
  /** What happened, in words. Absent while pending. */
  detail?: string;
}

/** A test send: `running` until every channel has answered or been given up on. */
export interface TestRun {
  id: string;
  state: 'running' | 'done';
  items: TestItem[];
}

export interface SummaryItem {
  ts_ms: number;
  key: string;
  kind: string;
  title: string;
  severity: 'normal' | 'urgent';
  box_name: string | null;
  person: string | null;
  /** Null for an alert recorded before outcomes were kept. */
  status: OutcomeStatus | null;
  channels: string[];
}

export interface AlertSummary {
  date: string;
  /** The person whose day this is; null for the fleet's day. */
  person?: string | null;
  time_zone: string | null;
  utc_offset_minutes: number;
  counts: { delivered: number; held_quiet: number; held_limit: number; not_sent: number; unknown: number; retrying?: number; failed?: number; partial?: number };
  items: SummaryItem[];
}
