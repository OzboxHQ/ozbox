#!/usr/bin/env node
// Lifecycle timings for the benchmark gate, taken from the computer that drives the box (the part suite.sh cannot see).
// Not part of CI: it creates, pauses and resumes a real box and costs money. A release step (docs/releasing.md).
//
//   node scripts/benchmark/lifecycle.mjs create NAME --out spawn.json [--provider aws] [--region R] [--usd-per-hour N --usd-source "..."]
//   node scripts/benchmark/lifecycle.mjs pause  NAME --out pause.json
//   node scripts/benchmark/lifecycle.mjs resume NAME --out resume.json     # the warm variant starts here
//   node scripts/benchmark/lifecycle.mjs destroy NAME --out destroy.json
//
// `create` always asks for size XS and a 40 GB /work disk: the benchmark shape. The time is the wall time until the ozbox
// command returns, which is when the provider call finishes; it is NOT "until a shell works on the box", and the report
// says so. A command that fails is recorded as failed with its exit code, never as a time.
// `--usd-per-hour` is a number the person copies from the provider's price list for the machine type the plan printed;
// without it USD per hour is reported as missing, never guessed.
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';

const argv = process.argv.slice(2);
const [verb, name] = argv;
const opt = (k) => { const i = argv.indexOf(k); return i > 0 ? argv[i + 1] : undefined; };
const fail = (m) => { console.error(`lifecycle.mjs: ${m}`); process.exit(2); };
if (!['create', 'pause', 'resume', 'destroy'].includes(verb)) fail('the verb is create, pause, resume or destroy');
if (!name || name.startsWith('--')) fail('a box name is required');
const out = opt('--out') ?? fail('--out is required');
const bin = opt('--ozbox') ?? 'ozbox';
const provider = opt('--provider');

const ids = { create: ['spawn', 'Spawn (create to ready)'], pause: ['pause', 'Pause'], resume: ['resume', 'Resume (resume to ready)'], destroy: ['destroy', 'Destroy'] };
const args = [...(provider ? ['--provider', provider] : []), '--yes', verb, name];
if (verb === 'create') args.push('--size', 'XS', '--disk', '40', ...(opt('--region') ? ['--region', opt('--region')] : []));

const t0 = performance.now();
const r = spawnSync(bin, args, { encoding: 'utf8' });
const secs = Number(((performance.now() - t0) / 1000).toFixed(3));
const [id, label] = ids[verb];
const metrics = [];
if (r.error || r.status !== 0) {
  const why = r.error ? String(r.error.message) : `exit ${r.status}: ${(r.stderr || '').trim().slice(-200)}`;
  metrics.push({ id, label, unit: 's', direction: 'lower', status: 'failed', value: null, n_ok: 0, n_total: 1, reason: why });
} else {
  metrics.push({ id, label, unit: 's', direction: 'lower', status: 'ok', value: secs, n_ok: 1, n_total: 1,
    reason: 'wall time until the ozbox command returned; not "a shell works on the box"' });
}
if (verb === 'create') {
  const usd = opt('--usd-per-hour');
  const src = opt('--usd-source');
  if (usd !== undefined && src && Number.isFinite(Number(usd)) && Number(usd) > 0) {
    metrics.push({ id: 'usd_per_hour', label: 'USD per hour', unit: 'USD', direction: 'lower', status: 'ok', value: Number(usd), n_ok: 1, n_total: 1, reason: `price given by the operator: ${src}` });
  } else {
    metrics.push({ id: 'usd_per_hour', label: 'USD per hour', unit: 'USD', direction: 'lower', status: 'unsupported', value: null, n_ok: 0, n_total: 0, reason: 'no --usd-per-hour with --usd-source given' });
  }
}
writeFileSync(out, JSON.stringify({ schema: 1, suite: 'ozbox-subset-v1', metrics }, null, 2) + '\n');
console.log(`lifecycle.mjs: ${verb} ${name}: ${metrics[0].status}${metrics[0].value !== null ? ` in ${secs}s` : ''}; wrote ${out}`);
process.exit(metrics[0].status === 'ok' ? 0 : 1);
