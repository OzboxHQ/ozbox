import { test } from 'node:test';
import assert from 'node:assert/strict';
import { site, run, page } from './helpers.mjs';

test('check-links: a missing image fails', () => {
  const r = run('check-links.mjs', [site({ 'other.mdx': page('Other', '![logo](/img/none.svg)') })]);
  assert.equal(r.code, 1);
  assert.match(r.out, /none\.svg/);
});

test('check-links: an existing image passes', () => {
  const r = run('check-links.mjs', [site({ 'other.mdx': page('Other', '![logo](/img/a.svg)'), 'img/a.svg': '<svg/>' })]);
  assert.equal(r.code, 0, r.out);
});

test('check-links: a folder index resolves as /folder', () => {
  const r = run('check-links.mjs', [site({ 'guides/index.mdx': page('Guides'), 'other.mdx': page('Other', '[g](/guides)') })]);
  assert.equal(r.code, 0, r.out);
});

test('check-links: links inside code are ignored', () => {
  const r = run('check-links.mjs', [site({ 'other.mdx': page('Other', 'Use `[x](/nope)` like that.') })]);
  assert.equal(r.code, 0, r.out);
});

test('compile-check: an unescaped {x} in prose fails', () => {
  const r = run('compile-check.mjs', [site({ 'other.mdx': page('Other', 'Replace {x} with a name.') })]);
  assert.equal(r.code, 1);
  assert.match(r.out, /other\.mdx/);
});

test('compile-check: an escaped brace and a brace in code pass', () => {
  const r = run('compile-check.mjs', [site({ 'other.mdx': page('Other', 'Replace \\{x\\} with `{y}`.\n\n```json\n{ "a": 1 }\n```') })]);
  assert.equal(r.code, 0, r.out);
});

test('compile-check: a planted HTML comment fails to compile', () => {
  const r = run('compile-check.mjs', [site({ 'other.mdx': page('Other', ['<!', '-- c --', '>'].join('')) })]);
  assert.equal(r.code, 1);
});
