import { describe, expect, it } from 'vitest';

import { ACTIVATION_MS, clipboardKeyAction, decideOsc52, hasRecentActivation, isMacPlatform, MAX_OSC52_CHARS, parseOsc52, screenText, type KeyLike } from './terminal-clipboard';

const key = (k: string, mods: Partial<KeyLike> = {}): KeyLike => ({ type: 'keydown', key: k, ctrlKey: false, shiftKey: false, altKey: false, metaKey: false, ...mods });
const b64 = (s: string) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));

describe('one keymap per computer', () => {
  const other = { mac: false, hasSelection: false };
  const otherSel = { mac: false, hasSelection: true };
  const mac = { mac: true, hasSelection: false };
  const macSel = { mac: true, hasSelection: true };

  it('Ctrl+C is the interrupt with nothing selected and a copy with a selection, on Windows and Linux', () => {
    expect(clipboardKeyAction(key('c', { ctrlKey: true }), other)).toBe('terminal');
    expect(clipboardKeyAction(key('c', { ctrlKey: true }), otherSel)).toBe('browser-copy');
    // Caps Lock on: the key arrives upper case
    expect(clipboardKeyAction(key('C', { ctrlKey: true }), otherSel)).toBe('browser-copy');
  });

  it('on a Mac Ctrl+C is always the interrupt and Cmd+C copies', () => {
    expect(clipboardKeyAction(key('c', { ctrlKey: true }), macSel)).toBe('terminal');
    expect(clipboardKeyAction(key('c', { metaKey: true }), macSel)).toBe('browser-copy');
    expect(clipboardKeyAction(key('c', { metaKey: true }), mac)).toBe('terminal');
  });

  it('paste is the browser\'s own paste, so Ctrl+V never reaches the shell as ^V', () => {
    expect(clipboardKeyAction(key('v', { ctrlKey: true }), other)).toBe('browser-paste');
    expect(clipboardKeyAction(key('V', { ctrlKey: true, shiftKey: true }), other)).toBe('browser-paste');
    expect(clipboardKeyAction(key('Insert', { shiftKey: true }), other)).toBe('browser-paste');
    expect(clipboardKeyAction(key('v', { metaKey: true }), mac)).toBe('browser-paste');
    // on a Mac Ctrl+V is the shell's literal-next key, as in every Mac terminal
    expect(clipboardKeyAction(key('v', { ctrlKey: true }), mac)).toBe('terminal');
  });

  it('Ctrl+Shift+C copies through the page (its browser default opens developer tools), and only with a selection', () => {
    expect(clipboardKeyAction(key('C', { ctrlKey: true, shiftKey: true }), otherSel)).toBe('page-copy');
    expect(clipboardKeyAction(key('C', { ctrlKey: true, shiftKey: true }), other)).toBe('terminal');
    expect(clipboardKeyAction(key('Insert', { ctrlKey: true }), otherSel)).toBe('browser-copy');
  });

  it('everything else, and every event but keydown, belongs to the terminal', () => {
    expect(clipboardKeyAction(key('d', { ctrlKey: true }), otherSel)).toBe('terminal');
    expect(clipboardKeyAction(key('c'), otherSel)).toBe('terminal');
    expect(clipboardKeyAction(key('c', { ctrlKey: true, altKey: true }), otherSel)).toBe('terminal');
    expect(clipboardKeyAction({ ...key('v', { ctrlKey: true }), type: 'keyup' }, other)).toBe('terminal');
  });

  it('knows a Mac keyboard, an iPad included', () => {
    expect(isMacPlatform({ platform: 'MacIntel' })).toBe(true);
    expect(isMacPlatform({ userAgentData: { platform: 'macOS' } })).toBe(true);
    expect(isMacPlatform({ platform: 'iPad' })).toBe(true);
    expect(isMacPlatform({ platform: 'Win32' })).toBe(false);
    expect(isMacPlatform({ platform: 'Linux x86_64' })).toBe(false);
    expect(isMacPlatform(undefined)).toBe(false);
  });
});

describe('OSC 52 from the box', () => {
  it('a copy is decoded, UTF-8 included', () => {
    expect(parseOsc52(`c;${b64('héllo ✓\nline 2')}`)).toEqual({ kind: 'write', text: 'héllo ✓\nline 2' });
    expect(parseOsc52(`;${b64('x')}`)).toEqual({ kind: 'write', text: 'x' });
  });

  it('a request to read the clipboard is recognised and never answered', () => {
    expect(parseOsc52('c;?')).toEqual({ kind: 'query' });
    expect(decideOsc52(parseOsc52('c;?'), true)).toEqual({ kind: 'nothing' });
  });

  it('empty, damaged and missing payloads do nothing', () => {
    for (const d of ['c;', 'c', 'c;not base64!', 'c;a']) expect(decideOsc52(parseOsc52(d), true)).toEqual({ kind: 'nothing' });
  });

  it('is capped: too much is refused with its size, never cut short', () => {
    const big = 'a'.repeat(MAX_OSC52_CHARS + 1);
    expect(parseOsc52(`c;${btoa(big)}`)).toEqual({ kind: 'too_large', chars: MAX_OSC52_CHARS + 1 });
    expect(parseOsc52(`c;${btoa('a'.repeat(MAX_OSC52_CHARS))}`).kind).toBe('write');
    // a huge payload is refused before it is decoded
    expect(parseOsc52(`c;${'QUFB'.repeat(MAX_OSC52_CHARS * 2)}`).kind).toBe('too_large');
  });

  it('is written only right after the person pressed a key or clicked; otherwise it is offered', () => {
    const w = parseOsc52(`c;${b64('copied')}`);
    expect(decideOsc52(w, true)).toEqual({ kind: 'write', text: 'copied' });
    expect(decideOsc52(w, false)).toEqual({ kind: 'ask', text: 'copied' });
  });

  it('activation: the browser decides when it can say; otherwise the last gesture within five seconds', () => {
    expect(hasRecentActivation({ isActive: true }, 0, 10)).toBe(true);
    expect(hasRecentActivation({ isActive: false }, 9, 10)).toBe(false);
    expect(hasRecentActivation(undefined, 1_000, 1_000 + ACTIVATION_MS)).toBe(true);
    expect(hasRecentActivation(undefined, 1_000, 1_001 + ACTIVATION_MS)).toBe(false);
    expect(hasRecentActivation(null, 0, 5)).toBe(false);
  });
});

describe('the Copy box', () => {
  it('keeps the screen\'s text and drops blank edges and trailing spaces', () => {
    expect(screenText(['', 'user@box:~$ ls   ', 'a  b', '', ''])).toBe('user@box:~$ ls\na  b');
    expect(screenText(['', ''])).toBe('');
  });
});
