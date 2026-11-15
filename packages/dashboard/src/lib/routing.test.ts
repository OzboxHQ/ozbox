import { describe, expect, it } from 'vitest';

import { defaultPerson, inQuiet, preview, toMinutes, zoneCity } from './routing';

const labels: Record<string, string> = { sms: 'SMS', telegram: 'Telegram', push: 'Push', slack: 'Slack', email: 'Email' };
const ctx = { zone: 'Africa/Lagos', fleetQuiet: { from: '22:00', to: '07:00' }, channelLabel: (id: string) => labels[id] ?? id };

describe('quiet hours', () => {
  it('cross midnight and ignore an empty window', () => {
    expect(inQuiet(toMinutes('23:30') ?? 0, '22:00', '07:00')).toBe(true);
    expect(inQuiet(toMinutes('02:00') ?? 0, '22:00', '07:00')).toBe(true);
    expect(inQuiet(toMinutes('07:00') ?? 0, '22:00', '07:00')).toBe(false);
    expect(inQuiet(toMinutes('13:00') ?? 0, '12:00', '14:00')).toBe(true);
    expect(inQuiet(60, '07:00', '07:00')).toBe(false);
    expect(inQuiet(60, 'nope', '07:00')).toBe(false);
    expect(toMinutes('24:00')).toBeNull();
  });
});

describe('routing preview', () => {
  it('says an urgent alert at 2am Lagos time goes to SMS, Telegram and Push, with the defaults', () => {
    const lines = preview(defaultPerson(), ctx);
    expect(lines[0]).toBe('Urgent alerts at 2am Lagos time go to SMS, Telegram, and Push.');
  });

  it('holds a normal alert at 2am for the daily summary but delivers it at 2pm', () => {
    const lines = preview(defaultPerson(), ctx);
    expect(lines[1]).toBe('Normal alerts at 2am Lagos time are held for the daily summary, because it is quiet hours.');
    expect(lines[2]).toContain('at 2pm Lagos time go to Telegram and Slack');
    expect(lines[3]).toBe('The daily summary is sent to Email at 08:00 Lagos time.');
  });

  it('follows the person\'s own quiet hours and the urgent bypass', () => {
    const p = defaultPerson();
    p.urgent.bypass_quiet = false;
    p.quiet_from = '13:00';
    p.quiet_to = '15:00';
    const lines = preview(p, ctx);
    expect(lines[0]).toContain('go to'); // 2am is not quiet for this person
    expect(lines[2]).toContain('held'); // 2pm is
  });

  it('says so when nothing is chosen or there is no summary', () => {
    const p = defaultPerson();
    p.urgent.channels = [];
    p.digest.enabled = false;
    p.quiet_from = '01:00';
    p.quiet_to = '03:00';
    const lines = preview(p, ctx);
    expect(lines[0]).toContain('go nowhere');
    expect(lines[1]).toContain('are not sent');
    expect(lines.at(-1)).toBe('There is no daily summary.');
  });

  it('names a zone by its city', () => {
    expect(zoneCity('America/Argentina/Buenos_Aires')).toBe('Buenos Aires');
    expect(zoneCity('UTC')).toBe('UTC');
  });
});
