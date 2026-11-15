/** What became of each alert, the test send that reports channel by channel, and the daily summary view. English first. */
export const enAlerts = {
  // A test send, one line per channel.
  'test.title': 'Test send',
  'test.pending': 'Sending',
  'test.sent': 'Sent',
  'test.failed': 'Failed',
  'test.for_person': '{channel} for {person}',
  'test.waiting': 'Waiting for each channel to answer.',
  'test.timeout': 'No answer yet. The test may still arrive; Recent alerts will show how it went.',

  // The outcome of an alert.
  'outcome.label': 'Outcome',
  'outcome.unknown': 'Not recorded',
  'outcome.delivered': 'Delivered',
  'outcome.held_quiet': 'Held: quiet hours',
  'outcome.held_limit': 'Held: text limit',
  'outcome.not_sent': 'Not sent',
  'outcome.retrying': 'Retrying',
  'outcome.failed': 'Delivery failed',
  'outcome.partial': 'Partly delivered',
  'outcome.result_retrying': '{channel} retrying{detail}',
  'outcome.result_failed': '{channel} failed after {tries} tries{detail}',
  'outcome.result_refused': '{channel} refused{detail}',
  'outcome.line': '{person}: {status} ({channels})',
  'outcome.line_bare': '{person}: {status}',

  // The daily summary.
  'summary.open': 'Daily summary',
  'summary.title': 'Daily summary',
  'summary.help': 'Every alert of one day and what became of it: delivered, held for quiet hours or the text limit, or not sent.',
  'summary.day': 'Day',
  'summary.zone': 'Days follow {zone}.',
  'summary.zone_offset': 'Days follow UTC{offset}.',
  'summary.counts': '{delivered} delivered, {held} held, {not_sent} not sent, {failed} failed, {retrying} retrying, {unknown} unknown',
  'summary.person': 'Person',
  'summary.person_all': 'Everyone (fleet time zone)',
  'summary.none': 'No alert on this day.',
  'summary.everyone': 'everyone',
  'summary.load_failed': 'The summary could not be read.',
} as const;
