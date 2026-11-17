import { describe, expect, it } from 'vitest';

import { ageWords, listNote, STALE_AFTER_MS } from './list-freshness';

const NOW = 1_800_000_000_000;

describe('listNote', () => {
  it('says nothing about a list the server read a moment ago', () => {
    expect(listNote({ asOf: NOW - 2000, refreshing: false, refreshFailed: false }, NOW)).toEqual({ kind: 'none' });
    expect(listNote({ asOf: NOW - 2000, refreshing: true, refreshFailed: false }, NOW)).toEqual({ kind: 'none' });
  });

  it('says nothing when the server gave no age', () => {
    expect(listNote({ asOf: null, refreshing: false, refreshFailed: false }, NOW)).toEqual({ kind: 'none' });
    expect(listNote(null, NOW)).toEqual({ kind: 'none' });
  });

  it('says the list is old and is being read again', () => {
    expect(listNote({ asOf: NOW - STALE_AFTER_MS - 1, refreshing: true, refreshFailed: false }, NOW)).toEqual({ kind: 'refreshing', ageMs: STALE_AFTER_MS + 1 });
  });

  it('says the list is old when no new read is running', () => {
    expect(listNote({ asOf: NOW - 60_000, refreshing: false, refreshFailed: false }, NOW)).toEqual({ kind: 'stale', ageMs: 60_000 });
  });

  it('says a failed read at any age, because a failure must never look like a fresh list', () => {
    expect(listNote({ asOf: NOW - 1000, refreshing: false, refreshFailed: true }, NOW)).toEqual({ kind: 'failed', ageMs: 1000 });
  });

  it('never shows a negative age when the two clocks disagree', () => {
    expect(listNote({ asOf: NOW + 5000, refreshing: false, refreshFailed: true }, NOW)).toEqual({ kind: 'failed', ageMs: 0 });
  });
});

describe('ageWords', () => {
  it('counts seconds up to a minute and a half, then minutes', () => {
    expect(ageWords(400)).toEqual({ key: 'listnote.age_seconds', n: 1 });
    expect(ageWords(45_000)).toEqual({ key: 'listnote.age_seconds', n: 45 });
    expect(ageWords(180_000)).toEqual({ key: 'listnote.age_minutes', n: 3 });
  });
});
