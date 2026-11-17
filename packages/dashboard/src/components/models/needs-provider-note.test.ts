import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ADD_PROVIDER_ID, NeedsProviderNote } from './needs-provider-note';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');

describe('NeedsProviderNote', () => {
  const html = renderToStaticMarkup(createElement(NeedsProviderNote, { id: 'engines-needs-provider' }));

  it('says why Edit is unavailable, in plain words from the message catalogue', () => {
    expect(html).toContain('id="engines-needs-provider"');
    expect(html).toContain('Add a provider first');
    expect(html).not.toContain('models.needs_provider');
  });

  it('links to the Add provider button with a 44px target below 1024px', () => {
    expect(html).toContain(`href="#${ADD_PROVIDER_ID}"`);
    expect(html).toContain('Go to Add provider');
    expect(html).toMatch(/class="[^"]*\bmin-h-11\b[^"]*\blg:min-h-0\b/);
  });
});

describe('the Models cards whose Edit needs a provider', () => {
  for (const [file, id] of [
    ['./engines-card.tsx', 'engines-needs-provider'],
    ['./prices-card.tsx', 'prices-needs-provider'],
    ['../../pages/settings-models.tsx', 'defaults-needs-provider'],
  ] as const) {
    it(`${file} explains a disabled Edit and points the button at the note`, () => {
      const src = read(file);
      expect(src).toContain(`providers.length === 0 ? <NeedsProviderNote id="${id}" /> : null`);
      expect(src).toContain(`aria-describedby={providers.length === 0 ? '${id}' : undefined}`);
    });
  }

  it('the link has somewhere to go: the Add provider button carries its id', () => {
    expect(read('../../pages/settings-models.tsx')).toContain('<Button id={ADD_PROVIDER_ID}');
  });
});
