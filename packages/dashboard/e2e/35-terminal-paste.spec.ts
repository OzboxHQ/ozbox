import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { expectNoSidewaysScroll, expectTouchTargets, WIDTHS } from './fixtures';

// The terminal's Paste button in the three situations browsers put it in: the clipboard is readable (Chrome once allowed),
// there is no readText at all (Firefox before 125, a locked-down profile), and the browser refuses (a denied permission, a
// dismissed bubble). In the last two the paste is never dropped: a box opens that takes Ctrl+V. The browser's own clipboard
// behaviour differs per engine; what is asserted here is the page's behaviour for each outcome.
test.describe.configure({ mode: 'serial' });

let server: AuthServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startAuthServer(4197, ['dev'], 5);
  const context = await browser.newContext();
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: server.origin });
  page = await context.newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, server);
});

test.afterAll(() => server.stop());

/** A new tab in the signed-in browser with the terminal live; `script` runs before the page does (it shapes the clipboard). */
async function terminalWith(w: number, script?: () => void): Promise<Page> {
  const tab = await page.context().newPage();
  if (script) await tab.addInitScript(script);
  await tab.setViewportSize({ width: w, height: 900 });
  await tab.goto(server.origin + '/boxes/dev/terminal');
  await expect(tab.getByTestId('terminal-status')).toHaveAttribute('data-state', 'live', { timeout: 20_000 });
  // "live" is the connection; the shell is ready when it has printed its prompt. A shell clears what was typed before that when it
  // sets up its line editing, so text sent earlier is lost. The screen starts with a measuring strip of one repeated character: skip it.
  await expect
    .poll(async () => ((await tab.getByTestId('terminal-screen').textContent()) ?? '').replace(/^(.)\1{15,}/, '').trim().length, { timeout: 20_000 })
    .toBeGreaterThan(0);
  return tab;
}

// what Firefox before 125 looks like to a page: the Clipboard API has no readText
const noReadText = () => Object.defineProperty(Clipboard.prototype, 'readText', { value: undefined, configurable: true });
const refusedRead = () =>
  Object.defineProperty(Clipboard.prototype, 'readText', { value: () => Promise.reject(new DOMException('denied', 'NotAllowedError')), configurable: true });
const emptyRead = () => Object.defineProperty(Clipboard.prototype, 'readText', { value: () => Promise.resolve(''), configurable: true });

for (const w of WIDTHS) {
  test(`a readable clipboard is pasted straight into the shell at ${w}px`, async () => {
    const tab = await terminalWith(w);
    await tab.evaluate((text) => navigator.clipboard.writeText(text), `echo ozbox-paste-$((40+2))-${w}\n`);
    await tab.getByRole('button', { name: 'Paste', exact: true }).click();
    await expect(tab.getByTestId('terminal-screen')).toContainText(`ozbox-paste-42-${w}`, { timeout: 10_000 });
    await expect(tab.getByTestId('paste-sheet')).toHaveCount(0);
    await expectNoSidewaysScroll(tab);
    await tab.close();
  });

  test(`with no readText the paste box opens and the text still reaches the shell at ${w}px`, async () => {
    const tab = await terminalWith(w, noReadText);
    await tab.getByRole('button', { name: 'Paste', exact: true }).click();
    const sheet = tab.getByTestId('paste-sheet');
    await expect(sheet).toBeVisible();
    await expect(tab.getByTestId('paste-box')).toBeFocused();
    await expect(tab.getByTestId('paste-send')).toBeDisabled();
    if (w < 1024) await expectTouchTargets(tab, sheet);
    await expectNoSidewaysScroll(tab);
    await tab.getByTestId('paste-box').fill(`echo ozbox-manual-$((40+2))-${w}`);
    // Where the keyboard is at the instant the box leaves the page (a mutation observer runs before any timer): a key typed
    // right after the box closes must reach the shell, not the page behind it.
    await tab.evaluate(() => {
      const w = window as unknown as { __focusAtClose?: boolean };
      const obs = new MutationObserver(() => {
        if (document.querySelector('[data-testid="paste-sheet"]')) return;
        w.__focusAtClose = !!document.activeElement?.closest('[data-testid="terminal-screen"]');
        obs.disconnect();
      });
      obs.observe(document.body, { childList: true, subtree: true });
    });
    await tab.getByTestId('paste-send').click();
    await expect(sheet).toHaveCount(0);
    expect(await tab.evaluate(() => (window as unknown as { __focusAtClose?: boolean }).__focusAtClose)).toBe(true);
    await tab.keyboard.press('Enter');
    await expect(tab.getByTestId('terminal-screen')).toContainText(`ozbox-manual-42-${w}`, { timeout: 10_000 });
    await tab.close();
  });
}

test('a refused clipboard read opens the paste box, and Cancel sends nothing', async () => {
  const tab = await terminalWith(1440, refusedRead);
  await tab.getByRole('button', { name: 'Paste', exact: true }).click();
  await tab.getByTestId('paste-box').fill('echo ozbox-never-sent');
  await tab.getByRole('button', { name: 'Cancel' }).click();
  await expect(tab.getByTestId('paste-sheet')).toHaveCount(0);
  await expect(tab.getByTestId('terminal-screen')).not.toContainText('ozbox-never-sent');
  await tab.close();
});

test('an empty clipboard says so instead of doing nothing', async () => {
  const tab = await terminalWith(1440, emptyRead);
  await tab.getByRole('button', { name: 'Paste', exact: true }).click();
  await expect(tab.getByText('The clipboard is empty, so nothing was pasted.')).toBeVisible();
  await expect(tab.getByTestId('paste-sheet')).toHaveCount(0);
  await tab.close();
});
