import { describe, expect, it } from 'vitest';

import { buildItems } from '../components/command-palette';
import { hrefs, SETTINGS_SECTIONS } from './router';

describe('the command palette', () => {
  it('lists every Settings section, so none can only be reached from the sub-navigation', () => {
    const run = buildItems([]).map((i) => i.run);
    for (const section of SETTINGS_SECTIONS) {
      expect(run, section).toContainEqual({ kind: 'go', href: hrefs.settings(section) });
    }
  });

  it('gives each Settings section its own label', () => {
    const labels = buildItems([])
      .filter((i) => i.run.kind === 'go' && i.run.href.startsWith('/settings'))
      .map((i) => i.item.label);
    expect(new Set(labels).size).toBe(labels.length);
    expect(labels.length).toBe(SETTINGS_SECTIONS.length);
  });
});
