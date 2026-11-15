import { describe, expect, it } from 'vitest';

import type { Catalog, CatalogTool, ToolState } from '../api/tools';
import { bundleSelectable, bundleTicked, groupRows, jobProgress, selectable, sizeLabel, statusOf, toggle, validBoxName, validProfileName } from './tools';

const tool = (id: string, over: Partial<CatalogTool> = {}): CatalogTool => ({
  id,
  name: id.toUpperCase(),
  group: 'g1',
  description: `${id} does things`,
  homepage: 'https://example.com',
  source: 'https://example.com',
  verified: true,
  verification: 'apt_archive',
  size_mb: 10,
  updates: { how: 'apt', detail: 'x' },
  requires: [],
  ...over,
});

const catalog: Catalog = {
  schema: 1,
  version: 't',
  groups: [
    { id: 'g1', name: 'One' },
    { id: 'g2', name: 'Two' },
  ],
  bundles: [{ id: 'web', name: 'Web', description: '', tools: ['a', 'b'] }],
  tools: [tool('a'), tool('b'), tool('c', { group: 'g2', verified: false, verification: 'unverified' }), tool('z', { group: 'g2', verification: 'client_managed' })],
};
const states: ToolState[] = [{ id: 'a', installed: true, version: '1.2.3', managed_by_client: false }];

describe('tool rows', () => {
  it('says what each tool is on this box', () => {
    expect(statusOf(catalog.tools[0]!, states[0])).toBe('installed');
    expect(statusOf(catalog.tools[1]!, undefined)).toBe('available');
    expect(statusOf(catalog.tools[2]!, undefined)).toBe('unavailable');
    expect(statusOf(catalog.tools[3]!, undefined)).toBe('client');
  });

  it('groups, searches and filters by bundle, leaving out empty groups', () => {
    expect(groupRows(catalog, states, '', null).map((g) => g.id)).toEqual(['g1', 'g2']);
    expect(groupRows(catalog, states, 'B DOES', null).flatMap((g) => g.rows.map((r) => r.tool.id))).toEqual(['b']);
    expect(groupRows(catalog, states, '', 'web').map((g) => g.id)).toEqual(['g1']);
    expect(groupRows(catalog, states, 'nothing like this', null)).toEqual([]);
  });

  it('only a verified tool that is not on the box can be ticked', () => {
    const rows = groupRows(catalog, states, '', null).flatMap((g) => g.rows);
    expect(rows.filter(selectable).map((r) => r.tool.id)).toEqual(['b']);
  });
});

describe('selection', () => {
  it('toggles without changing the old set', () => {
    const a = new Set<string>();
    const b = toggle(a, 'x');
    expect([...a]).toEqual([]);
    expect([...b]).toEqual(['x']);
    expect([...toggle(b, 'x')]).toEqual([]);
  });

  it('a bundle offers only what is not installed and is ticked when all of that is', () => {
    expect(bundleSelectable(catalog, states, 'web')).toEqual(['b']);
    expect(bundleTicked(catalog, states, new Set(), 'web')).toBe(false);
    expect(bundleTicked(catalog, states, new Set(['b']), 'web')).toBe(true);
  });
});

describe('formatting and validation', () => {
  it('sizes, progress and names', () => {
    expect(sizeLabel(0)).toBe('0 MB');
    expect(sizeLabel(250)).toBe('250 MB');
    expect(sizeLabel(1500)).toBe('1.5 GB');
    expect(jobProgress([{ index: 0, title: 'a', state: 'ok' }, { index: 1, title: 'b', state: 'failed' }])).toEqual({ done: 1, total: 2, failed: true });
    expect(validProfileName('web-2')).toBe(true);
    expect(validProfileName('Web')).toBe(false);
    expect(validProfileName('-x')).toBe(false);
    expect(validBoxName('dev')).toBe(true);
    expect(validBoxName('a--b')).toBe(false);
    expect(validBoxName('1a')).toBe(false);
  });
});
