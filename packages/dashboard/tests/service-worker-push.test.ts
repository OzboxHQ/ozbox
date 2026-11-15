import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import vm from 'node:vm';

import { describe, expect, it } from 'vitest';

const SOURCE = readFileSync(resolve(__dirname, '../public/sw.js'), 'utf8');

type Handler = (event: Record<string, unknown>) => void;

function load() {
  const handlers: Record<string, Handler> = {};
  const shown: { title: string; options: Record<string, unknown> }[] = [];
  const opened: string[] = [];
  let focused = 0;
  let windows: { focus: () => void }[] = [];
  const self = {
    location: { origin: 'https://box.example.com' },
    addEventListener: (name: string, h: Handler) => {
      handlers[name] = h;
    },
    registration: {
      showNotification: (title: string, options: Record<string, unknown>) => {
        shown.push({ title, options });
        return Promise.resolve();
      },
    },
    clients: {
      matchAll: () => Promise.resolve(windows),
      openWindow: (u: string) => {
        opened.push(u);
        return Promise.resolve();
      },
    },
    skipWaiting: () => undefined,
  };
  const caches = { open: () => Promise.resolve({ addAll: () => Promise.resolve(), put: () => undefined }), keys: () => Promise.resolve([]), match: () => Promise.resolve(undefined), delete: () => Promise.resolve(true) };
  vm.runInNewContext(SOURCE, { self, caches, URL, fetch: () => Promise.reject(new Error('no network in this test')) });
  return {
    handlers,
    shown,
    opened,
    focusCount: () => focused,
    setWindows: (n: number) => {
      windows = Array.from({ length: n }, () => ({ focus: () => void (focused += 1) }));
    },
  };
}

async function push(sw: ReturnType<typeof load>, data: unknown) {
  const waits: Promise<unknown>[] = [];
  const event = {
    data: data === undefined ? null : { json: () => (typeof data === 'string' ? JSON.parse(data) : data) },
    waitUntil: (p: Promise<unknown>) => waits.push(p),
  };
  sw.handlers['push']?.(event);
  await Promise.all(waits);
}

describe('service worker push', () => {
  it('shows the notification the server sent, with the alert as its tag', async () => {
    const sw = load();
    await push(sw, { title: 'Disk full', body: 'Box dev is at 96%', tag: 'disk:dev', urgent: true });
    expect(sw.shown).toHaveLength(1);
    expect(sw.shown[0]?.title).toBe('Disk full');
    expect(sw.shown[0]?.options).toMatchObject({ body: 'Box dev is at 96%', tag: 'disk:dev', requireInteraction: true });
  });

  it('still shows something when the payload is empty or broken, and bounds what it shows', async () => {
    const sw = load();
    await push(sw, undefined);
    await push(sw, '{ not json');
    await push(sw, { title: 'x'.repeat(500), body: 'y'.repeat(2000), urgent: 'yes' });
    expect(sw.shown.map((s) => s.title.length)).toEqual([6, 6, 120]);
    expect(String(sw.shown[2]?.options['body']).length).toBe(400);
    expect(sw.shown[2]?.options['requireInteraction']).toBeUndefined();
  });

  it('opens or focuses the dashboard when a notification is clicked', async () => {
    const sw = load();
    const click = async () => {
      const waits: Promise<unknown>[] = [];
      sw.handlers['notificationclick']?.({ notification: { close: () => undefined }, waitUntil: (p: Promise<unknown>) => waits.push(p) });
      await Promise.all(waits);
    };
    await click();
    expect(sw.opened).toEqual(['/']);
    sw.setWindows(1);
    await click();
    expect(sw.focusCount()).toBe(1);
  });

  it('never answers or stores a request for live data', () => {
    expect(SOURCE).toContain("url.pathname.startsWith('/v1/')");
    const sw = load();
    let responded = false;
    sw.handlers['fetch']?.({
      request: { method: 'GET', url: 'https://box.example.com/v1/boxes' },
      respondWith: () => void (responded = true),
    });
    expect(responded).toBe(false);
  });
});
