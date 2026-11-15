import { describe, expect, it } from 'vitest';

import { parseBrowserApproval } from './browser';

describe('a browser approval as a person reads it', () => {
  it('shows where a form goes, the check of what was shown, and the fields', () => {
    const b = parseBrowserApproval(
      'browser.browser_click: this would submit a form on app.example: click -> app.example/save (check 0123abcd) [name=Ada, password=[masked]]',
    );
    expect(b).toMatchObject({ tool: 'browser_click', host: 'app.example', action: 'click', dest: 'app.example/save', check: '0123abcd' });
    expect(b?.fields).toEqual([
      { name: 'name', value: 'Ada', masked: false },
      { name: 'password', value: '[masked]', masked: true },
    ]);
  });

  it('reads an older approval without a destination, and one with no host (a held-back file)', () => {
    expect(parseBrowserApproval('browser.browser_click: this would submit a form on a.example: click [q=x]')?.dest).toBe('');
    const f = parseBrowserApproval('browser.browser_downloads: this file is held back: a script on : open_download (check 99aa) [file=tool.sh]');
    expect(f).toMatchObject({ host: '', action: 'open_download', check: '99aa' });
  });

  it('is not fooled into another structure by a field name the page chose', () => {
    // the worker turns `=` and `, ` inside a name into `_`, so there is one field, not two
    const b = parseBrowserApproval('browser.browser_click: this would submit a form on a.example: click [a_b_ c_d=x]');
    expect(b?.fields).toEqual([{ name: 'a_b_ c_d', value: 'x', masked: false }]);
  });
});
