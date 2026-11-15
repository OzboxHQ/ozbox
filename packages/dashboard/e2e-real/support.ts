import { expect, type APIRequestContext, type Page } from '@playwright/test';

import { expectHonestPage } from '../e2e/honesty';
import { ROUTE_SAMPLES } from '../src/lib/route-samples';
import type { RealStack } from './real-stack';

export const WIDTHS = [390, 820, 1024, 1440] as const;

/** Where a server's mode is stated, so a spec follows what the server says it is rather than assuming. */
export interface InfoLite {
  provider: string;
  metrics: string;
  fleet: { mode: string; demo: boolean; connected: boolean };
}

export const bearer = (s: RealStack): Record<string, string> => ({ Authorization: `Bearer ${s.token}` });

export async function info(request: APIRequestContext, s: RealStack): Promise<InfoLite> {
  const r = await request.get(`${s.origin}/v1/info`, { headers: bearer(s) });
  expect(r.status()).toBe(200);
  return (await r.json()) as InfoLite;
}

/** Pages that, on a box, show a fleet and so must say it is not connected. */
export const FLEET_PAGES = new Set(['fleet', 'boxes', 'usage', 'bill']);

/**
 * The every-route sweep of a REAL server: every page is honest (not blank, not loading forever, no `undefined`), shows no demo
 * banner, and says "Fleet not connected" where it shows a fleet. `fleetNotConnected` follows the server's own `/v1/info`.
 */
export async function sweepEveryRoute(page: Page, origin: string, box: string, width: number, i: InfoLite): Promise<void> {
  await page.setViewportSize({ width, height: 900 });
  for (const s of ROUTE_SAMPLES) {
    const path = s.path(box);
    await page.goto(origin + path);
    await expectHonestPage(page, `${path} at ${width}px`, { demo: i.fleet.demo });
    if (i.fleet.mode === 'this_box' && FLEET_PAGES.has(s.page)) {
      await expect(page.getByTestId('fleet-not-connected'), `${path}: a box's fleet page must say the fleet is not connected`).toBeVisible({ timeout: 20_000 });
    }
  }
}
