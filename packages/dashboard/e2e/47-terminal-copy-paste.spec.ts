import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { expectNoSidewaysScroll, expectTouchTargets } from './fixtures';

// Copy and paste in the dashboard's terminal with the keyboard, in a real browser and a real shell (the demo shell is bash,
// which turns on bracketed paste). This runs on Linux, so the keymap is the Windows and Linux one: Ctrl+C copies a selection
// and is the interrupt otherwise, Ctrl+V pastes. Chromium with clipboard permission granted; the other browsers' own rules
// (Firefox's and Safari's Paste button, their activation window) are checked by hand on a real box.
test.describe.configure({ mode: 'serial' });

let server: AuthServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  server = await startAuthServer(4252, ['dev'], 5);
  const context = await browser.newContext();
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: server.origin });
  page = await context.newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, server);
});

test.afterAll(() => server.stop());

async function terminal(w = 1440): Promise<Page> {
  const tab = await page.context().newPage();
  await tab.setViewportSize({ width: w, height: 900 });
  await tab.goto(server.origin + '/boxes/dev/terminal');
  await expect(tab.getByTestId('terminal-status')).toHaveAttribute('data-state', 'live', { timeout: 20_000 });
  await expect
    .poll(async () => ((await tab.getByTestId('terminal-screen').textContent()) ?? '').replace(/^(.)\1{15,}/, '').trim().length, { timeout: 20_000 })
    .toBeGreaterThan(0);
  await tab.getByTestId('terminal-screen').click();
  return tab;
}

const screen = (tab: Page) => tab.getByTestId('terminal-screen');
const setClipboard = (tab: Page, text: string) => tab.evaluate((x) => navigator.clipboard.writeText(x), text);
const clipboard = (tab: Page) => tab.evaluate(() => navigator.clipboard.readText());

async function run(tab: Page, line: string) {
  await tab.keyboard.type(line);
  await tab.keyboard.press('Enter');
}

/** Double-click a word printed on its own line, which selects it in the terminal. */
async function selectWord(tab: Page, word: string) {
  const row = tab.locator('.xterm-rows > div', { hasText: new RegExp(`^${word}\\s*$`) }).last();
  await expect(row).toBeVisible();
  await row.dblclick({ position: { x: 8, y: 6 } });
}

test('Ctrl+V pastes (it is not the shell\'s ^V), and a multi-line paste waits for Enter', async () => {
  const tab = await terminal();
  await setClipboard(tab, 'echo one-$((1+0))\necho two-$((1+1))');
  await tab.keyboard.press('Control+V');
  await expect(screen(tab)).toContainText('echo two-$((1+1))');
  // bracketed paste: the shell holds both lines until Enter, so a pasted line never runs by itself
  await tab.waitForTimeout(800);
  await expect(screen(tab)).not.toContainText('one-1');
  await tab.keyboard.press('Enter');
  await expect(screen(tab)).toContainText('one-1');
  await expect(screen(tab)).toContainText('two-2');
  await tab.close();
});

test('Ctrl+Shift+V and Shift+Insert paste too', async () => {
  const tab = await terminal();
  await setClipboard(tab, 'echo shiftv-$((40+2))');
  await tab.keyboard.press('Control+Shift+V');
  await tab.keyboard.press('Enter');
  await expect(screen(tab)).toContainText('shiftv-42');
  await setClipboard(tab, 'echo insert-$((40+3))');
  await tab.keyboard.press('Shift+Insert');
  await tab.keyboard.press('Enter');
  await expect(screen(tab)).toContainText('insert-43');
  await tab.close();
});

test('Ctrl+C copies a selection, then stops the running command once nothing is selected', async () => {
  const tab = await terminal();
  await setClipboard(tab, 'before');
  await run(tab, 'echo copyme-$((5+6))');
  await selectWord(tab, 'copyme-11');
  await tab.keyboard.press('Control+C');
  await expect.poll(() => clipboard(tab)).toBe('copyme-11');
  // the copy cleared the selection: the next Ctrl+C is the interrupt again
  await run(tab, 'sleep 30');
  await tab.waitForTimeout(300);
  await tab.keyboard.press('Control+C');
  await run(tab, 'echo after-$((3+4))');
  await expect(screen(tab)).toContainText('after-7', { timeout: 5_000 });
  await tab.close();
});

test('Ctrl+Shift+C copies a selection', async () => {
  const tab = await terminal();
  await run(tab, 'echo shiftc-$((6+6))');
  await selectWord(tab, 'shiftc-12');
  await tab.keyboard.press('Control+Shift+C');
  await expect.poll(() => clipboard(tab)).toBe('shiftc-12');
  await tab.close();
});

test('a copy a program on the box makes (OSC 52, as tmux sends) reaches the clipboard right after a key press', async () => {
  const tab = await terminal();
  await setClipboard(tab, 'before');
  await run(tab, `printf '\\033]52;c;%s\\a' "$(printf 'osc-copied-%s' 42 | base64)"`);
  await expect.poll(() => clipboard(tab)).toBe('osc-copied-42');
  await expect(tab.getByText('Copied from the terminal')).toBeVisible();
  await tab.close();
});

test('a copy with no key press behind it is offered, never written by itself', async () => {
  const tab = await terminal();
  await setClipboard(tab, 'before');
  // the browser's activation lasts about five seconds; this copy comes later
  await run(tab, `sleep 6; printf '\\033]52;c;%s\\a' "$(printf 'late-%s' 77 | base64)"`);
  const offer = tab.getByText('A program in the terminal copied 7 characters. Put them on your clipboard?');
  await expect(offer).toBeVisible({ timeout: 15_000 });
  expect(await clipboard(tab)).toBe('before');
  await tab.getByRole('button', { name: 'Copy', exact: true }).last().click();
  await expect.poll(() => clipboard(tab)).toBe('late-77');
  await tab.close();
});

test('a program on the box asking to read the clipboard gets no answer', async () => {
  const tab = await terminal();
  await setClipboard(tab, 'never-leaves-this-computer');
  // ask, then wait a moment for any answer; an answer would arrive as typed input
  await run(tab, `printf '\\033]52;c;?\\a'; read -t 2 -r answer; echo "answer=[\${answer}]"`);
  await expect(screen(tab)).toContainText('answer=[]', { timeout: 10_000 });
  await expect(screen(tab)).not.toContainText('never-leaves-this-computer');
  await tab.close();
});

for (const w of [390, 1440]) {
  test(`Copy with nothing selected opens the screen's text to select from at ${w}px`, async () => {
    const tab = await terminal(w);
    await run(tab, 'echo screen-$((8+8))');
    await expect(screen(tab)).toContainText('screen-16');
    await tab.getByRole('button', { name: 'Copy', exact: true }).click();
    const sheet = tab.getByTestId('copy-sheet');
    await expect(sheet).toBeVisible();
    await expect(tab.getByTestId('copy-box')).toHaveValue(/screen-16/);
    if (w < 1024) await expectTouchTargets(tab, sheet);
    await expectNoSidewaysScroll(tab);
    await tab.getByTestId('copy-all').click();
    await expect(sheet).toHaveCount(0);
    await expect.poll(() => clipboard(tab)).toContain('screen-16');
    await expect(tab.getByTestId('terminal-keys-help')).toContainText('Ctrl+C copies what you selected');
    await tab.close();
  });
}
