import { describe, expect, it } from 'vitest';

import { en } from '../i18n/en';
import { channelName, isOutcome, lastDays, outcomeLabel, outcomeLine, outcomeVariant, resultText, shiftDate, summaryQuery, testItemLabel } from './alert-outcome';

describe('outcome words', () => {
  it('names each outcome the way the daily summary tags it', () => {
    expect(outcomeLabel('delivered')).toBe('Delivered');
    expect(outcomeLabel('held_quiet')).toBe('Held: quiet hours');
    expect(outcomeLabel('held_limit')).toBe('Held: text limit');
    expect(outcomeLabel('not_sent')).toBe('Not sent');
  });

  it('warns only about an alert nobody received', () => {
    expect(outcomeVariant('not_sent')).toBe('destructive');
    expect(outcomeVariant('held_quiet')).toBe('outline');
    expect(outcomeVariant('delivered')).toBe('secondary');
  });

  it('says the person and the channels where they are known', () => {
    expect(outcomeLine({ person: 'ada', status: 'held_quiet', channels: ['sms', 'push'] }, 'everyone')).toBe('ada: Held: quiet hours (SMS, Push)');
    expect(outcomeLine({ status: 'not_sent' }, 'everyone')).toBe('everyone: Not sent');
  });

  it('names channels, webhooks and anything unknown', () => {
    expect(channelName('telegram')).toBe(en['ch.telegram']);
    expect(channelName('webhook:ops')).toBe(en['ch.webhook']);
    expect(channelName('carrier-pigeon')).toBe('carrier-pigeon');
    expect(testItemLabel({ channel: 'sms', person: 'ada', status: 'pending' })).toBe('SMS for ada');
    expect(testItemLabel({ channel: 'slack', status: 'sent' })).toBe('Slack');
  });
});

describe('delivery results', () => {
  it('names the new outcomes and warns when nobody, or not everybody, was reached', () => {
    expect(outcomeLabel('retrying')).toBe('Retrying');
    expect(outcomeLabel('failed')).toBe('Delivery failed');
    expect(outcomeLabel('partial')).toBe('Partly delivered');
    expect(['retrying', 'failed', 'partial'].every(isOutcome)).toBe(true);
    expect(isOutcome('exploded')).toBe(false);
    expect(outcomeVariant('failed')).toBe('destructive');
    expect(outcomeVariant('partial')).toBe('destructive');
    expect(outcomeVariant('retrying')).toBe('outline');
  });

  it('says in words how each channel ended, and why', () => {
    expect(resultText({ channel: 'sms', state: 'sent', attempts: 1 })).toBe('SMS');
    expect(resultText({ channel: 'sms', state: 'retrying', attempts: 1, detail: 'the service answered HTTP 503' })).toBe('SMS retrying: the service answered HTTP 503');
    expect(resultText({ channel: 'sms', state: 'failed', attempts: 4, detail: 'the service answered HTTP 503' })).toBe('SMS failed after 4 tries: the service answered HTTP 503');
    expect(resultText({ channel: 'sms', state: 'refused', attempts: 1 })).toBe('SMS refused');
  });

  it('puts each channel result on the person line, and falls back to the channel list for older alerts', () => {
    expect(
      outcomeLine({ person: 'ada', status: 'failed', channels: ['sms'], results: [{ channel: 'sms', state: 'failed', attempts: 4, detail: 'HTTP 503' }] }, 'everyone'),
    ).toBe('ada: Delivery failed (SMS failed after 4 tries: HTTP 503)');
    expect(outcomeLine({ person: 'ada', status: 'delivered', channels: ['sms', 'push'] }, 'everyone')).toBe('ada: Delivered (SMS, Push)');
  });
});

describe('summary request', () => {
  it('asks for a day, a person, both or neither, and encodes them', () => {
    expect(summaryQuery()).toBe('');
    expect(summaryQuery('2026-11-09')).toBe('?date=2026-11-09');
    expect(summaryQuery(undefined, 'ada')).toBe('?person=ada');
    expect(summaryQuery('2026-11-09', 'a b&c')).toBe('?date=2026-11-09&person=a+b%26c');
  });
});

describe('days', () => {
  it('moves by calendar days across months, years and leap days', () => {
    expect(shiftDate('2026-11-09', -1)).toBe('2026-11-08');
    expect(shiftDate('2026-11-01', -1)).toBe('2026-10-31');
    expect(shiftDate('2026-01-01', -1)).toBe('2025-12-31');
    expect(shiftDate('2028-03-01', -1)).toBe('2028-02-29');
    expect(shiftDate('2026-12-31', 1)).toBe('2027-01-01');
  });

  it('lists the day and the six before it, newest first', () => {
    expect(lastDays('2026-11-09')).toEqual(['2026-11-09', '2026-11-08', '2026-11-07', '2026-11-06', '2026-11-05', '2026-11-04', '2026-11-03']);
  });
});
