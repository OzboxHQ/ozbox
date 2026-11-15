import { test } from 'node:test';
import assert from 'node:assert/strict';
import { stampText, writtenOut } from '../scripts/stamp-release-date.mjs';

test('stamps only placeholder labels', () => {
  const src = '<Update label="[Release date]" tags={["CLI"]}>\n<Update label="May 1, 2026" tags={[]}>\nbody [Release date]';
  const { text, count } = stampText(src, 'June 2, 2026');
  assert.equal(count, 1);
  assert.match(text, /label="June 2, 2026"/);
  assert.match(text, /label="May 1, 2026"/);
  assert.match(text, /body \[Release date\]/);
});

test('writes dates out in full', () => {
  assert.equal(writtenOut(new Date(2026, 10, 10)), 'November 10, 2026');
});
