import type { PersonRouting, Route } from '../api/channel-types';
import { t } from './i18n';

export const CHANNEL_IDS = ['sms', 'telegram', 'push', 'slack', 'email', 'whatsapp', 'discord', 'teams'] as const;
export type ChannelId = (typeof CHANNEL_IDS)[number];

/** What a new person starts with: urgent to SMS, Telegram and push (even in quiet hours), normal to Telegram and Slack, and
 * a daily summary by email at 08:00. The same defaults the server uses. */
export function defaultPerson(): PersonRouting {
  return {
    time_zone: null,
    quiet_from: null,
    quiet_to: null,
    phone: null,
    whatsapp: null,
    emails: [],
    push: [],
    urgent: { channels: ['sms', 'telegram', 'push'], bypass_quiet: true },
    normal: { channels: ['telegram', 'slack'], bypass_quiet: false },
    digest: { enabled: true, time: '08:00', channels: ['email'] },
  };
}

export function toMinutes(hhmm: string): number | null {
  const m = /^(\d{2}):(\d{2})$/.exec(hhmm);
  if (!m) return null;
  const h = Number(m[1]);
  const min = Number(m[2]);
  return h < 24 && min < 60 ? h * 60 + min : null;
}

/** Whether a clock time falls in quiet hours; the window may cross midnight. */
export function inQuiet(minuteOfDay: number, from: string, to: string): boolean {
  const f = toMinutes(from);
  const e = toMinutes(to);
  if (f === null || e === null || f === e) return false;
  return f < e ? minuteOfDay >= f && minuteOfDay < e : minuteOfDay >= f || minuteOfDay < e;
}

/** `Africa/Lagos` reads as "Lagos". */
export function zoneCity(zone: string): string {
  const last = zone.split('/').pop() ?? zone;
  return last.replace(/_/g, ' ');
}

function list(items: string[]): string {
  try {
    return new Intl.ListFormat('en', { style: 'long', type: 'conjunction' }).format(items);
  } catch {
    return items.join(', ');
  }
}

export interface PreviewContext {
  /** The zone the person's clock follows (their own, else the fleet's). */
  zone: string;
  /** The fleet's quiet hours, used when the person has none of their own. */
  fleetQuiet: { from: string; to: string };
  /** Display name of a channel id (`webhook:ci` needs the webhook's label). */
  channelLabel: (id: string) => string;
}

function channelsOf(r: Route, ctx: PreviewContext): string {
  return list(r.channels.map(ctx.channelLabel));
}

/** Plain-language lines that say what the rules do at a given hour, so a person can check them before saving. */
export function preview(p: PersonRouting, ctx: PreviewContext): string[] {
  const from = p.quiet_from ?? ctx.fleetQuiet.from;
  const to = p.quiet_to ?? ctx.fleetQuiet.to;
  const city = zoneCity(ctx.zone);
  const lines: string[] = [];
  const cases: { kind: 'urgent' | 'normal'; hour: number; label: string }[] = [
    { kind: 'urgent', hour: 2, label: '2am' },
    { kind: 'normal', hour: 2, label: '2am' },
    { kind: 'normal', hour: 14, label: '2pm' },
  ];
  for (const c of cases) {
    const route = c.kind === 'urgent' ? p.urgent : p.normal;
    const severity = t(c.kind === 'urgent' ? 'routing.sev_word_urgent' : 'routing.sev_word_normal');
    const params = { severity, time: c.label, zone: city };
    const quiet = inQuiet(c.hour * 60, from, to);
    if (quiet && !(c.kind === 'urgent' && route.bypass_quiet)) {
      lines.push(t(p.digest.enabled ? 'routing.preview_held' : 'routing.preview_held_nosummary', params));
    } else if (route.channels.length === 0) {
      lines.push(t('routing.preview_none', params));
    } else {
      lines.push(t('routing.preview_goes', { ...params, channels: channelsOf(route, ctx) }));
    }
  }
  if (p.digest.enabled && p.digest.channels.length > 0) {
    lines.push(t('routing.preview_summary', { channels: list(p.digest.channels.map(ctx.channelLabel)), time: p.digest.time, zone: city }));
  } else {
    lines.push(t('routing.preview_no_summary'));
  }
  return lines;
}
