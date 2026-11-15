import { describe, expect, it } from 'vitest';

import { decidePaste, MAX_PASTE_CHARS, readClipboardText } from './terminal-paste';

describe('reading the clipboard', () => {
  it('returns the text when the browser hands it over', async () => {
    expect(await readClipboardText({ readText: async () => 'ls -la' })).toEqual({ kind: 'text', text: 'ls -la' });
  });

  it('reports an empty clipboard instead of doing nothing', async () => {
    expect(await readClipboardText({ readText: async () => '' })).toEqual({ kind: 'empty' });
  });

  it('falls back to the manual box when there is no readText (Firefox before 125, a locked-down profile)', async () => {
    expect(await readClipboardText({})).toEqual({ kind: 'manual' });
    expect(await readClipboardText(undefined)).toEqual({ kind: 'manual' });
    expect(await readClipboardText(null)).toEqual({ kind: 'manual' });
  });

  it('falls back to the manual box when the browser refuses (permission denied, the Paste bubble dismissed)', async () => {
    const denied = () => Promise.reject(new DOMException('denied', 'NotAllowedError'));
    expect(await readClipboardText({ readText: denied })).toEqual({ kind: 'manual' });
    expect(await readClipboardText({ readText: () => Promise.reject(new Error('anything')) })).toEqual({ kind: 'manual' });
  });

  it('falls back when readText throws before returning a promise', async () => {
    expect(
      await readClipboardText({
        readText: () => {
          throw new TypeError('not allowed');
        },
      }),
    ).toEqual({ kind: 'manual' });
  });
});

describe('what is sent to the shell', () => {
  it('sends text as it is, multi-line included', () => {
    expect(decidePaste('a\nb')).toEqual({ kind: 'send', text: 'a\nb' });
  });

  it('says so when there is nothing to send', () => {
    expect(decidePaste('')).toEqual({ kind: 'empty' });
  });

  it('refuses a paste larger than the limit and says how large it was', () => {
    expect(decidePaste('x'.repeat(MAX_PASTE_CHARS))).toMatchObject({ kind: 'send' });
    expect(decidePaste('x'.repeat(MAX_PASTE_CHARS + 1))).toEqual({ kind: 'too_large', chars: MAX_PASTE_CHARS + 1 });
  });
});
