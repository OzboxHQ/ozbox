// Self-test of the gate's logic on invented FIXTURES (not results): `node --test scripts/benchmark/gate.test.mjs`.
// Cheap and offline, but not wired into CI; the gate itself is a release step.
import test from 'node:test';
import assert from 'node:assert/strict';
import { merge, compare } from './gate.mjs';

const m = (id, value, dir = 'lower', status = 'ok', unit = 's') => ({ id, label: id, unit, direction: dir, status, value, n_ok: status === 'ok' ? 1 : 0, n_total: 1, reason: status === 'ok' ? '' : 'why' });
const doc = (metrics, over = {}) => ({ schema: 1, suite: 's', variant: 'cold', guard: 'on', comparable: true, comparable_reasons: '', shape: { vcpus: 4 }, metrics, ...over });

test('a metric within the limit passes, beyond it regresses, in both directions', () => {
  const base = doc([m('spawn', 100), m('stream_triad', 1000, 'higher', 'ok', 'MB/s')]);
  assert.equal(compare(doc([m('spawn', 109), m('stream_triad', 910, 'higher', 'ok', 'MB/s')]), base).code, 0);
  assert.equal(compare(doc([m('spawn', 111), m('stream_triad', 1000, 'higher', 'ok', 'MB/s')]), base).code, 1);
  assert.equal(compare(doc([m('spawn', 100), m('stream_triad', 890, 'higher', 'ok', 'MB/s')]), base).code, 1);
});

test('a baseline number that is now failed, unsupported or absent is a regression, never a pass', () => {
  const base = doc([m('spawn', 100)]);
  assert.equal(compare(doc([m('spawn', null, 'lower', 'failed')]), base).code, 1);
  assert.equal(compare(doc([m('spawn', null, 'lower', 'unsupported')]), base).code, 1);
  assert.equal(compare(doc([]), base).code, 1);
});

test('a gap in the baseline is disclosed and not gated, and zero is never invented', () => {
  const base = doc([m('spawn', null, 'lower', 'unsupported')]);
  const r = compare(doc([m('spawn', 5)]), base);
  assert.equal(r.code, 0);
  assert.match(r.lines.join('\n'), /gap\s+spawn/);
});

test('it refuses to judge: wrong shape, no baseline, another variant or guard setting', () => {
  const base = doc([m('spawn', 100)]);
  assert.equal(compare(doc([m('spawn', 1)], { comparable: false, comparable_reasons: 'memory is 16 GiB' }), base).code, 2);
  assert.equal(compare(doc([m('spawn', 1)]), null).code, 2);
  assert.equal(compare(doc([m('spawn', 1)], { variant: 'warm' }), base).code, 2);
  assert.equal(compare(doc([m('spawn', 1)], { guard: 'off' }), base).code, 2);
});

test('merge takes medians, keeps gaps as gaps, and refuses to mix variants', () => {
  const a = doc([m('spawn', 10), m('git_common_ops', null, 'lower', 'unsupported')]);
  const b = doc([m('spawn', 30), m('git_common_ops', 4)]);
  const c = doc([m('spawn', 20)]);
  const out = merge([a, b, c]);
  assert.equal(out.metrics.find((x) => x.id === 'spawn').value, 20);
  assert.equal(out.metrics.find((x) => x.id === 'git_common_ops').value, 4);
  assert.throws(() => merge([a, doc([m('spawn', 1)], { variant: 'warm' })]), /separate variant/);
  const gap = merge([doc([m('spawn', null, 'lower', 'failed')])]);
  assert.equal(gap.metrics[0].value, null);
  assert.equal(gap.metrics[0].status, 'failed');
});

test('a shapeless lifecycle file does not make the merge incomparable, but no shape at all does', () => {
  assert.equal(merge([doc([m('spawn', 1)]), { schema: 1, metrics: [m('resume', 2)] }]).comparable, true);
  assert.equal(merge([{ schema: 1, metrics: [m('resume', 2)] }]).comparable, false);
});
