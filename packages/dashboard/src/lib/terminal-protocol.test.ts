import { describe, expect, it } from 'vitest';

import { applyCtrl, backoffMs, dataFrame, encodeFrame, F, FrameReader, KEYS, MAX_RECONNECTS, nextState, resizeFrame, safeLink, stepFont } from './terminal-protocol';

describe('terminal frames', () => {
  it('encodes and decodes across arbitrary chunk boundaries', () => {
    const bytes = [dataFrame('héllo'), resizeFrame(120, 40), encodeFrame(F.EXIT, new Uint8Array([0, 0, 0, 3]))];
    const all = new Uint8Array(bytes.reduce((n, b) => n + b.length, 0));
    let at = 0;
    for (const b of bytes) {
      all.set(b, at);
      at += b.length;
    }
    for (const step of [1, 3, 7, all.length]) {
      const r = new FrameReader();
      const got = [];
      for (let i = 0; i < all.length; i += step) got.push(...r.push(all.slice(i, i + step)));
      expect(got.map((f) => f.type)).toEqual([F.DATA, F.RESIZE, F.EXIT]);
      expect(new TextDecoder().decode(got[0]?.payload)).toBe('héllo');
      expect(Array.from(got[1]?.payload ?? [])).toEqual([0, 120, 0, 40]);
    }
  });

  it('refuses an oversize frame on either side', () => {
    expect(() => encodeFrame(F.DATA, new Uint8Array(64 * 1024 + 1))).toThrow();
    const bad = new Uint8Array([1, 0, 1, 0, 1]);
    expect(() => new FrameReader().push(bad)).toThrow();
  });
});

describe('reconnecting', () => {
  it('backs off to a ceiling', () => {
    expect([1, 2, 3, 4, 5, 6].map(backoffMs)).toEqual([1000, 2000, 4000, 8000, 15000, 15000]);
  });

  it('a live terminal that loses its connection tries again, and gives up after the limit', () => {
    expect(nextState('connecting', { type: 'ready' }, 0)).toBe('live');
    expect(nextState('live', { type: 'lost' }, 0)).toBe('reconnecting');
    expect(nextState('reconnecting', { type: 'retry' }, 1)).toBe('connecting');
    expect(nextState('connecting', { type: 'lost' }, MAX_RECONNECTS)).toBe('failed');
    expect(nextState('live', { type: 'exit' }, 0)).toBe('ended');
    expect(nextState('ended', { type: 'lost' }, 0)).toBe('ended');
    expect(nextState('connecting', { type: 'error', fatal: true }, 0)).toBe('failed');
    expect(nextState('live', { type: 'error', fatal: false }, 0)).toBe('reconnecting');
    expect(nextState('connecting', { type: 'error', fatal: false }, 1)).toBe('reconnecting');
    expect(nextState('connecting', { type: 'error', fatal: false }, MAX_RECONNECTS)).toBe('failed');
  });
});

describe('the key bar', () => {
  it('sends the escape sequences terminals expect', () => {
    expect(KEYS.esc).toBe('\u001b');
    expect(KEYS.up).toBe('\u001b[A');
    expect(KEYS.left).toBe('\u001b[D');
  });

  it('turns the next character into its control code', () => {
    expect(applyCtrl('c')).toBe('\x03');
    expect(applyCtrl('C')).toBe('\x03');
    expect(applyCtrl('d')).toBe('\x04');
    expect(applyCtrl('[')).toBe('\x1b');
    expect(applyCtrl('abc')).toBe('abc');
    expect(applyCtrl('1')).toBe('1');
  });

  it('steps the font within its range', () => {
    expect(stepFont(13, 1)).toBe(14);
    expect(stepFont(11, -1)).toBe(11);
    expect(stepFont(20, 1)).toBe(20);
  });
});

describe('links', () => {
  it('opens web addresses only', () => {
    expect(safeLink('https://example.com/a')).toBe('https://example.com/a');
    expect(safeLink('http://example.com')).toBe('http://example.com/');
    for (const bad of ['javascript:alert(1)', 'file:///etc/passwd', 'data:text/html,x', 'smb://host/x', 'not a url']) expect(safeLink(bad), bad).toBeNull();
  });
});
