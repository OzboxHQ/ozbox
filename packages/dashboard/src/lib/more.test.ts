import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import type { BoxRecord } from '../api/types';
import { connectInfo, openInReason } from './connect';
import { csvCell, toCsv } from './csv';
import { parseSse } from './events';
import { filterItems } from './palette';
import { buildItems } from '../components/command-palette';
import { movedTo, parseRoute } from './router';

function box(name: string, state: BoxRecord['state'] = 'running'): BoxRecord {
  return { spec: { name, size: 'M', work_disk_gb: 100, image: null, region: null, from_snapshot: null, labels: {} }, state, provider: 'fake', provider_id: null, machine_type: null, snapshots: [], created_at: null, last_activity_at: null };
}

describe('csv', () => {
  it('neutralises formulas and quotes', () => {
    for (const bad of ['=HYPERLINK("x")', '+1', '-2', '@SUM(A1)', '\tx', '\rx']) expect(csvCell(bad).replace(/^"/, '')).toMatch(/^'/);
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell(null)).toBe('');
    expect(csvCell(5)).toBe('5');
    expect(toCsv(['a'], [['=x']])).toBe("a\r\n'=x\r\n");
  });
});

describe('sse parser', () => {
  it('reads events, skips keepalives and keeps the unfinished tail', () => {
    const r = parseSse('retry: 3000\n\nevent: hello\ndata: {}\n\n: keepalive\n\nevent: changed\ndata: {"version":1}\n\nevent: cha');
    expect(r.events.map((e) => e.event)).toEqual(['message', 'hello', 'changed']);
    expect(r.rest).toBe('event: cha');
  });
});

describe('connect', () => {
  it('explains why the IDE is off and never builds an unsafe address', () => {
    expect(connectInfo(box('a'), null).reason).toMatch(/No domain/);
    expect(connectInfo(box('a', 'paused'), 'example.com').reason).toMatch(/paused/);
    expect(connectInfo(box('a'), 'example.com/evil').ideUrl).toBeNull();
    const ok = connectInfo(box('a'), 'example.com');
    expect(ok.ideUrl).toBe('https://a.example.com');
    expect(ok.command).toBe('ozbox connect a --shell');
  });
});

describe('open in', () => {
  it('needs no domain for an AWS box, and says why otherwise', () => {
    const aws = { ...box('a'), provider: 'aws', provider_id: 'i-1' };
    expect(openInReason(aws, null)).toBeNull();
    expect(openInReason({ ...aws, state: 'paused' }, null)).toMatch(/paused/);
    expect(openInReason(box('a'), null)).toMatch(/domain and tunnel/);
    expect(openInReason(box('a'), 'example.com')).toBeNull();
  });
});

describe('palette', () => {
  it('filters by every word and offers actions that still need a plan', () => {
    const items = buildItems([box('alpha'), box('delta', 'paused')]);
    const labels = items.map((i) => i.item.label);
    expect(labels).toContain('Pause alpha');
    expect(labels).toContain('Resume delta');
    expect(labels).not.toContain('Pause delta');
    expect(filterItems(items.map((i) => i.item), 'pause alp').map((i) => i.label)).toEqual(['Pause alpha']);
    expect(items.filter((i) => i.run.kind === 'action').every((i) => i.item.hint.includes('plan'))).toBe(true);
  });
});

describe('routes', () => {
  it('knows every page', () => {
    expect(parseRoute('/tasks')).toEqual({ page: 'tasks' });
    expect(parseRoute('/approvals')).toEqual({ page: 'approvals' });
    expect(parseRoute('/chat')).toEqual({ page: 'chat' });
    expect(parseRoute('/activity')).toEqual({ page: 'activity' });
    expect(parseRoute('/settings/budgets')).toEqual({ page: 'settings', section: 'budgets' });
    expect(parseRoute('/settings/members')).toEqual({ page: 'settings', section: 'members' });
    expect(parseRoute('/settings/nope')).toEqual({ page: 'missing' });
    expect(parseRoute('/boxes/a%20b')).toEqual({ page: 'box', name: 'a b' });
  });
  it('sends the old Runs address to Tasks, with or without a trailing slash', () => {
    expect(movedTo('/runs')).toBe('/tasks');
    expect(movedTo('/runs/')).toBe('/tasks');
    expect(movedTo('/tasks')).toBeNull();
    expect(parseRoute('/runs')).toEqual({ page: 'tasks' });
    expect(parseRoute('/runs/')).toEqual({ page: 'tasks' });
  });
});

describe('service worker', () => {
  const sw = readFileSync(join(__dirname, '../../public/sw.js'), 'utf8');
  it('never touches API data and never takes over by itself', () => {
    expect(sw).toContain("startsWith('/v1/')");
    // the guard returns before any respondWith
    expect(sw.indexOf("startsWith('/v1/')")).toBeLessThan(sw.indexOf('respondWith'));
    // skipWaiting only on a message from the page (the Refresh button), never in the install handler
    const install = sw.slice(sw.indexOf("'install'"), sw.indexOf("'activate'"));
    expect(install).not.toContain('skipWaiting');
    expect(sw).toContain('SKIP_WAITING');
  });
});

import { OPEN_IN_APPS, fillSteps } from './open-in-apps';

describe('open-in apps', () => {
  it('lists the five apps, never guesses a link scheme and fills the alias', () => {
    expect(OPEN_IN_APPS.map((a) => a.id)).toEqual(['vscode', 'cursor', 'antigravity', 'windsurf', 'zed', 'jetbrains', 'claude-code', 'codex']);
    // No app's official documentation describes a remote-folder link, so none may carry one.
    // a link only where the editor documents one, or marked unverified where it is a fork's guess
    for (const a of OPEN_IN_APPS) {
      if (a.uri === null) continue;
      expect(['vscode', 'zed'].includes(a.id) || a.unverified === true, a.id).toBe(true);
    }
    expect(OPEN_IN_APPS.find((a) => a.id === 'vscode')!.uri!('ozbox-dev', '/work/repos')).toBe('vscode://vscode-remote/ssh-remote+ozbox-dev/work/repos');
    expect(OPEN_IN_APPS.find((a) => a.id === 'zed')!.uri!('ozbox-dev', '/work/repos')).toBe('zed://ssh/ozbox-dev/work/repos');
    expect(OPEN_IN_APPS.find((a) => a.id === 'jetbrains')!.uri).toBeNull();
    const steps = fillSteps(OPEN_IN_APPS[0]!, 'ozbox-dev');
    expect(steps.join('\n')).toContain('choose ozbox-dev');
    expect(steps.join('\n')).not.toContain('{');
    expect(fillSteps(OPEN_IN_APPS[6]!, 'ozbox-dev').join('\n')).toContain('ssh ozbox-dev');
  });
});
