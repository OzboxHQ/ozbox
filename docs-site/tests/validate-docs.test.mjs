import { test } from 'node:test';
import assert from 'node:assert/strict';
import { site, run, page } from './helpers.mjs';

const hazard = ['<!', '-- hidden --', '>'].join('');

test('a valid site passes', () => {
  const r = run('validate-docs.mjs', [site()]);
  assert.equal(r.code, 0, r.out);
});

test('a planted HTML comment fails', () => {
  const r = run('validate-docs.mjs', [site({ 'other.mdx': page('Other', `Before\n\n${hazard}\n`) })]);
  assert.equal(r.code, 1);
  assert.match(r.out, /HTML comment/);
});

test('an HTML comment inside a code block is allowed', () => {
  const r = run('validate-docs.mjs', [site({ 'other.mdx': page('Other', `\`\`\`html\n${hazard}\n\`\`\``) })]);
  assert.equal(r.code, 0, r.out);
});

test('a broken internal link fails', () => {
  const r = run('validate-docs.mjs', [site({ 'other.mdx': page('Other', 'Go to [nowhere](/missing-page).') })]);
  assert.equal(r.code, 1);
  assert.match(r.out, /missing-page/);
});

test('an orphan page fails', () => {
  const r = run('validate-docs.mjs', [site({ 'orphan.mdx': page('Orphan') })]);
  assert.equal(r.code, 1);
  assert.match(r.out, /orphan\.mdx: not in the navigation/);
});

test('a navigation entry with no file fails', () => {
  const r = run('validate-docs.mjs', [site({}, ['index', 'other', 'ghost'])]);
  assert.equal(r.code, 1);
  assert.match(r.out, /ghost/);
});

test('a missing description fails', () => {
  const r = run('validate-docs.mjs', [site({ 'other.mdx': '---\ntitle: "Other"\n---\n\nText.\n' })]);
  assert.equal(r.code, 1);
  assert.match(r.out, /description/);
});

test('a private name fails, built from parts so this file stays clean', () => {
  const word = ['Cli', 'nik', 'EHR'].join('');
  const r = run('validate-docs.mjs', [site({ 'other.mdx': page('Other', `Made by ${word}.`) })]);
  assert.equal(r.code, 1);
  assert.match(r.out, /private product or company name/);
});

test('an account id in prose fails but in a code sample passes', () => {
  assert.equal(run('validate-docs.mjs', [site({ 'other.mdx': page('Other', 'Account 123456789012 here.') })]).code, 1);
  assert.equal(run('validate-docs.mjs', [site({ 'other.mdx': page('Other', '`123456789012`') })]).code, 0);
});

test('a link to a missing anchor fails, to a real one passes', () => {
  assert.equal(run('validate-docs.mjs', [site({ 'index.mdx': page('Home', '[x](/other#nope)') })]).code, 1);
  assert.equal(run('validate-docs.mjs', [site({ 'index.mdx': page('Home', '[x](/other#a-heading)') })]).code, 0);
});

test('--strict-dates refuses a placeholder changelog date, and passes once stamped', () => {
  const files = { 'changelog/index.mdx': page('Changelog', '<Update label="[Release date]" tags={["CLI"]}>\n  ## Something\n</Update>') };
  const dir = site(files, ['index', 'other', 'changelog/index']);
  assert.equal(run('validate-docs.mjs', [dir]).code, 0);
  const strict = run('validate-docs.mjs', [dir, '--strict-dates']);
  assert.equal(strict.code, 1);
  assert.match(strict.out, /placeholder/);
  assert.equal(run('stamp-release-date.mjs', [dir, '--date', 'November 10, 2026']).code, 0);
  assert.equal(run('validate-docs.mjs', [dir, '--strict-dates']).code, 0);
});

test('a compliance or certification claim fails, built from parts so this file stays clean', () => {
  const claim = ['HIP', 'AA compl', 'iant'].join('');
  const r = run('validate-docs.mjs', [site({ 'other.mdx': page('Other', `Oz Box is ${claim}.`) })]);
  assert.equal(r.code, 1);
  assert.match(r.out, /compliance or certification claim/);
  const ok = run('validate-docs.mjs', [site({ 'other.mdx': page('Other', 'Oz Box describes its controls and holds no certification.') })]);
  assert.equal(ok.code, 0, ok.out);
});
