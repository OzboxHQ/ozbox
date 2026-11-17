import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ListNote } from '../components/list-note';

const NOW = 1_800_000_000_000;
const render = (list: Parameters<typeof ListNote>[0]['list']) => renderToStaticMarkup(createElement(ListNote, { list, now: NOW }));

describe('ListNote', () => {
  it('shows nothing for a fresh list', () => {
    expect(render({ asOf: NOW - 1000, refreshing: false, refreshFailed: false })).toBe('');
  });

  it('shows the age and that the list is being read again', () => {
    const html = render({ asOf: NOW - 40_000, refreshing: true, refreshFailed: false });
    expect(html).toContain('data-kind="refreshing"');
    expect(html).toContain('40 s ago');
    expect(html).toContain('Reading them again now');
  });

  it('shows the age of a stale list that is not being read again', () => {
    const html = render({ asOf: NOW - 300_000, refreshing: false, refreshFailed: false });
    expect(html).toContain('data-kind="stale"');
    expect(html).toContain('5 min ago');
  });

  it('says that the last read failed', () => {
    const html = render({ asOf: NOW - 20_000, refreshing: false, refreshFailed: true });
    expect(html).toContain('data-kind="failed"');
    expect(html).toContain('failed');
  });
});
