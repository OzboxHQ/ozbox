import type { ChannelResult, OutcomeStatus, TestItem } from '../api/alert-types';
import type { RecentAlert } from '../api/types';
import { en } from '../i18n/en';
import { t, type MessageKey } from './i18n';

const STATUSES: readonly OutcomeStatus[] = ['delivered', 'held_quiet', 'held_limit', 'not_sent', 'retrying', 'failed', 'partial'];

export const isOutcome = (s: unknown): s is OutcomeStatus => typeof s === 'string' && (STATUSES as readonly string[]).includes(s);

export const outcomeLabel = (s: OutcomeStatus): string => t(`outcome.${s}` as MessageKey);

/** Delivered reads calmly, a hold or a pending retry is a note, and an alert nobody got (or not everybody) is a warning. */
export const outcomeVariant = (s: OutcomeStatus): 'secondary' | 'outline' | 'destructive' =>
  s === 'delivered' ? 'secondary' : s === 'not_sent' || s === 'failed' || s === 'partial' ? 'destructive' : 'outline';

/** The query string of a summary request: the day and the person, each only when given. */
export function summaryQuery(date?: string, person?: string): string {
  const q = new URLSearchParams();
  if (date) q.set('date', date);
  if (person) q.set('person', person);
  const s = q.toString();
  return s ? `?${s}` : '';
}

/** One channel's result in words: `SMS`, `SMS retrying`, `SMS failed after 4 tries: …`, `SMS refused: …`. */
export function resultText(r: ChannelResult): string {
  const channel = channelName(r.channel);
  const detail = r.detail ? `: ${r.detail}` : '';
  switch (r.state) {
    case 'sent':
      return channel;
    case 'retrying':
      return t('outcome.result_retrying', { channel, detail });
    case 'failed':
      return t('outcome.result_failed', { channel, tries: r.attempts, detail });
    default:
      return t('outcome.result_refused', { channel, detail });
  }
}

/** A channel's name for a person: `sms` is SMS, `webhook:ops` is a Webhook, an unknown one is shown as it is. */
export function channelName(id: string): string {
  if (id.startsWith('webhook:')) return t('ch.webhook');
  const key = `ch.${id}`;
  return key in en ? t(key as MessageKey) : id;
}

/** One line per person: `ada: Held: quiet hours (SMS, Push)`. */
export function outcomeLine(o: NonNullable<RecentAlert['outcomes']>[number], everyone: string): string {
  const person = o.person ?? everyone;
  const status = outcomeLabel(o.status);
  const channels = o.results && o.results.length > 0 ? o.results.map(resultText).join(', ') : (o.channels ?? []).map(channelName).join(', ');
  return channels ? t('outcome.line', { person, status, channels }) : t('outcome.line_bare', { person, status });
}

export function testItemLabel(i: TestItem): string {
  const channel = channelName(i.channel);
  return i.person ? t('test.for_person', { channel, person: i.person }) : channel;
}

/** `2026-11-09` moved by whole days, on the calendar and not the clock, so a change of clocks cannot skip a day. */
export function shiftDate(date: string, days: number): string {
  const [y, m, d] = date.split('-').map(Number);
  const at = new Date(Date.UTC(y ?? 1970, (m ?? 1) - 1, (d ?? 1) + days));
  return at.toISOString().slice(0, 10);
}

/** The day itself and the six before it, newest first. */
export function lastDays(today: string, count = 7): string[] {
  return Array.from({ length: count }, (_, i) => shiftDate(today, -i));
}

export function fmtOffset(minutes: number): string {
  const sign = minutes >= 0 ? '+' : '-';
  const abs = Math.abs(minutes);
  return `${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`;
}
