#!/usr/bin/env node
// The benchmark gate, first version. Merges result files and compares them with a stored baseline.
// Not part of CI: it judges a real box's numbers, which cost money to get. A release step (docs/releasing.md).
//
//   node scripts/benchmark/gate.mjs merge   --out merged.json  suite.json lifecycle.json [more boxes' files ...]
//   node scripts/benchmark/gate.mjs compare --results merged.json [--baseline FILE] [--threshold 10]
//   node scripts/benchmark/gate.mjs record  --results merged.json                  # store it as the baseline for its variant
//
// Exit codes: 0 pass, 1 a headline metric regressed (or is now failed / missing where the baseline had a number),
// 2 the gate could not judge (wrong shape, no baseline, variants differ, unreadable file). It never passes by default.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const HEADLINE = [
  'mastra_cold_install', 'better_auth_build', 'git_common_ops',
  'fio_randwrite_4k_direct', 'stream_triad', 'spawn', 'resume', 'usd_per_hour',
];
export const DEFAULT_THRESHOLD_PCT = 10;
const HERE = dirname(fileURLToPath(import.meta.url));

const median = (xs) => {
  const a = [...xs].sort((x, y) => x - y);
  const n = a.length;
  return n % 2 ? a[(n - 1) / 2] : (a[n / 2 - 1] + a[n / 2]) / 2;
};

/** Merge result files (one per box, plus the lifecycle files). Medians of the ok values; a gap stays a gap. */
export function merge(docs) {
  if (!docs.length) throw new Error('nothing to merge');
  const first = docs.find((d) => d.variant) ?? docs[0];
  for (const d of docs) {
    for (const k of ['variant', 'guard']) {
      if (d[k] !== undefined && first[k] !== undefined && d[k] !== first[k]) throw new Error(`files disagree on ${k}: ${first[k]} vs ${d[k]}; a warm or guard-off result is a separate variant, never merged with another`);
    }
  }
  const byId = new Map();
  for (const d of docs) for (const m of d.metrics ?? []) {
    if (!byId.has(m.id)) byId.set(m.id, []);
    byId.get(m.id).push(m);
  }
  const metrics = [];
  for (const [id, entries0] of byId) {
    const real = entries0.filter((e) => e.status !== 'unsupported');
    const entries = real.length ? real : entries0;
    const oks = entries.filter((e) => (e.status === 'ok' || e.status === 'partial') && typeof e.value === 'number');
    const base = entries[0];
    const nTotal = entries.reduce((s, e) => s + (e.n_total ?? 0), 0);
    const nOk = entries.reduce((s, e) => s + (e.n_ok ?? 0), 0);
    const reasons = [...new Set(entries.map((e) => e.reason).filter(Boolean))].join('; ');
    let status; let value = null;
    if (oks.length) {
      value = Number(median(oks.map((e) => e.value)).toFixed(3));
      status = entries.every((e) => e.status === 'ok') ? 'ok' : 'partial';
    } else status = entries.some((e) => e.status === 'failed') ? 'failed' : 'unsupported';
    metrics.push({ id, label: base.label, unit: base.unit, direction: base.direction, status, value, n_ok: nOk, n_total: nTotal, reason: reasons });
  }
  const shapes = docs.filter((d) => d.shape);
  return {
    schema: 1, suite: first.suite, variant: first.variant ?? 'cold', guard: first.guard ?? 'unknown', boxes: shapes.length,
    created_at: new Date().toISOString(),
    comparable: shapes.length > 0 && docs.filter((d) => d.shape).every((d) => d.comparable === true),
    comparable_reasons: [...new Set(shapes.map((d) => d.comparable_reasons).filter(Boolean))].join('; '),
    shape: first.shape ?? null, metrics,
  };
}

/** Judge `results` against `baseline`. Returns { code, lines }. */
export function compare(results, baseline, thresholdPct = DEFAULT_THRESHOLD_PCT) {
  const lines = [];
  const stop = (m) => ({ code: 2, lines: [...lines, `CANNOT JUDGE: ${m}`] });
  if (!results.comparable) return stop(`these results are not from the benchmark shape (4 vCPU, about 8 GiB, about 40 GB /work): ${results.comparable_reasons || 'no box shape recorded'}`);
  if (!baseline) return stop('no baseline for this variant; run the suite, review it, then `gate.mjs record`. A first run is not a pass.');
  for (const k of ['suite', 'variant', 'guard']) {
    if (results[k] !== baseline[k]) return stop(`${k} differs (results ${results[k]}, baseline ${baseline[k]}); a warm box, a guard-off run or another suite is a separate variant and is never compared across`);
  }
  let regressed = 0;
  for (const id of HEADLINE) {
    const r = results.metrics.find((m) => m.id === id);
    const b = baseline.metrics.find((m) => m.id === id);
    const hasB = b && b.status === 'ok' && typeof b.value === 'number';
    const hasR = r && r.status === 'ok' && typeof r.value === 'number';
    if (!hasB) { lines.push(`gap      ${id}: no baseline number (${b ? b.status : 'absent'}${b?.reason ? `: ${b.reason}` : ''}); not gated`); continue; }
    if (!hasR) { regressed++; lines.push(`REGRESS  ${id}: baseline ${b.value} ${b.unit}, now ${r ? r.status : 'missing'}${r?.reason ? ` (${r.reason})` : ''}; a metric that stopped being measured is not a pass`); continue; }
    const worse = b.direction === 'lower' ? (r.value - b.value) / b.value * 100 : (b.value - r.value) / b.value * 100;
    const tag = worse > thresholdPct ? 'REGRESS ' : 'ok      ';
    if (worse > thresholdPct) regressed++;
    lines.push(`${tag} ${id}: baseline ${b.value} ${b.unit}, now ${r.value} ${r.unit} (${worse >= 0 ? '+' : ''}${worse.toFixed(1)}% worse than baseline; limit ${thresholdPct}%)`);
  }
  lines.push(regressed ? `FAIL: ${regressed} headline metric(s) regressed or went missing` : 'PASS: no headline metric regressed beyond the limit (gaps above are disclosed, not passed)');
  return { code: regressed ? 1 : 0, lines };
}

const baselinePath = (d) => join(HERE, 'baseline', `${d.variant}-guard-${d.guard}.json`);
const read = (p) => JSON.parse(readFileSync(p, 'utf8'));

function main(argv) {
  const [cmd, ...rest] = argv;
  const opt = (k) => { const i = rest.indexOf(k); return i >= 0 ? rest[i + 1] : undefined; };
  try {
    if (cmd === 'merge') {
      const out = opt('--out');
      const files = rest.filter((a, i) => !a.startsWith('--') && rest[i - 1] !== '--out');
      if (!out || !files.length) throw new Error('usage: merge --out merged.json FILE...');
      writeFileSync(out, JSON.stringify(merge(files.map(read)), null, 2) + '\n');
      console.log(`gate: merged ${files.length} file(s) into ${out}`);
      return 0;
    }
    if (cmd === 'compare') {
      const results = read(opt('--results') ?? (() => { throw new Error('--results is required'); })());
      const bp = opt('--baseline') ?? baselinePath(results);
      const th = opt('--threshold') !== undefined ? Number(opt('--threshold')) : DEFAULT_THRESHOLD_PCT;
      if (!Number.isFinite(th) || th < 0) throw new Error('--threshold is a percentage, 0 or more');
      const { code, lines } = compare(results, existsSync(bp) ? read(bp) : null, th);
      console.log(`gate: ${results.variant} variant, guard ${results.guard}, baseline ${bp}\n${lines.join('\n')}`);
      return code;
    }
    if (cmd === 'record') {
      const results = read(opt('--results') ?? (() => { throw new Error('--results is required'); })());
      if (!results.comparable) throw new Error('refusing to record a baseline from a box that is not the benchmark shape');
      const bp = baselinePath(results);
      mkdirSync(dirname(bp), { recursive: true });
      writeFileSync(bp, JSON.stringify(results, null, 2) + '\n');
      console.log(`gate: baseline written to ${bp}; review and commit it`);
      return 0;
    }
    throw new Error('usage: gate.mjs merge|compare|record');
  } catch (e) {
    console.error(`gate: ${e.message}`);
    return 2;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) process.exit(main(process.argv.slice(2)));
