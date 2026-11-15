import AxeBuilder from '@axe-core/playwright';
import { expect, type Locator, type Page } from '@playwright/test';

export const url = (): string => {
  const u = process.env['OZBOX_E2E_URL'];
  if (!u) throw new Error('OZBOX_E2E_URL is not set: global setup did not run');
  return u;
};

export const WIDTHS = [390, 820, 1024, 1440] as const;

export async function open(page: Page, path = ''): Promise<void> {
  const u = new URL(url());
  await page.goto(`${u.origin}${path}${u.hash}`);
}

/** The page itself never scrolls sideways (a table may scroll inside its own box). */
export async function expectNoSidewaysScroll(page: Page): Promise<void> {
  const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(over, 'page scrolls sideways').toBeLessThanOrEqual(1);
}

/** On touch widths, every visible control is at least 44 x 44 px. */
export async function expectTouchTargets(_page: Page, scope: Locator): Promise<void> {
  const controls = scope.locator('button:visible, a[href]:visible, [role="tab"]:visible, input:visible, [role="combobox"]:visible');
  const n = await controls.count();
  const bad: string[] = [];
  for (let i = 0; i < n; i++) {
    const el = controls.nth(i);
    const box = await el.boundingBox();
    if (!box) continue;
    // a skip link and anything off screen is not a thumb target
    if (box.y + box.height < 0 || box.x + box.width < 0) continue;
    const text = ((await el.innerText().catch(() => '')) || (await el.getAttribute('aria-label')) || '').trim().slice(0, 30);
    // inline text links inside a sentence are exempt (WCAG 2.5.8); controls are not
    const inline = await el.evaluate((e) => e.tagName === 'A' && getComputedStyle(e).display === 'inline');
    if (inline) continue;
    // a skip link is visually hidden until it takes focus
    if (await el.evaluate((e) => getComputedStyle(e).clip !== 'auto' && getComputedStyle(e).position === 'absolute')) continue;
    if (box.height < 43.5 || box.width < 43.5) bad.push(`${text || (await el.evaluate((e) => e.outerHTML.slice(0, 60)))}: ${Math.round(box.width)}x${Math.round(box.height)}`);
  }
  expect(bad, `controls under 44px: ${bad.join('; ')}`).toEqual([]);
}

/**
 * Resolves when no CSS transition or animation is running on the page. A contrast check that samples a colour part-way through
 * a transition (a badge fading to its resting colour) reads a colour nobody ever sees at rest, so it waits for the colours to settle first.
 */
export async function settled(page: Page): Promise<void> {
  await page.evaluate(async () => {
    await Promise.all(document.getAnimations().map((a) => a.finished.catch(() => undefined)));
  });
}

/**
 * The one accessibility scan every spec uses (WCAG 2.0, 2.1 and 2.2 A and AA), over the whole page or inside `scope`. It waits for
 * running transitions to finish first, so a colour is read at rest and never part-way through a fade.
 */
export async function axeScan(page: Page, scope?: string) {
  await settled(page);
  const builder = new AxeBuilder({ page });
  if (scope !== undefined) builder.include(scope);
  return builder.withTags(['wcag2a', 'wcag2aa', 'wcag22aa']).analyze();
}
