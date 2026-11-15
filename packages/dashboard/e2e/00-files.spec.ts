import { createHash } from 'node:crypto';

import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, url, axeScan } from './fixtures';

// Runs first (with 00-usage-*), while alpha is still running: later specs pause and destroy boxes.
// The demo box `alpha` answers file requests from the same code a real box runs, over a private folder of sample files.
const BOX = 'alpha';
const auth = () => ({ Authorization: `Bearer ${new URL(url()).hash.replace('#token=', '')}` });
const origin = () => new URL(url()).origin;
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

async function root(request: APIRequestContext): Promise<string> {
  const r = await request.get(`${origin()}/v1/boxes/${BOX}/files/roots`, { headers: auth() });
  return ((await r.json()) as { roots: { path: string }[] }).roots[0]?.path ?? '';
}

async function rowAction(page: Page, file: string, action: string): Promise<void> {
  await page.getByRole('button', { name: `Actions for ${file}` }).click();
  const phone = (page.viewportSize()?.width ?? 1440) < 768;
  const item = phone ? page.getByRole('dialog').getByRole('button', { name: action, exact: true }) : page.getByRole('menuitem', { name: action, exact: true });
  await item.click();
}

for (const width of WIDTHS) {
  test.describe(`files at ${width}px`, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
    });

    test('browse, upload, preview, quick edit with a diff, trash, restore, share', async ({ page, request }) => {
      const name = `w${width}-${Date.now()}.txt`;
      await open(page, `/boxes/${BOX}/files`);
      await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible();

      // browse into a folder
      await expect(page.getByRole('button', { name: 'exchange', exact: true })).toBeVisible();
      await expectNoSidewaysScroll(page);
      await page.getByRole('button', { name: 'exchange', exact: true }).click();
      await expect(page.getByRole('button', { name: 'welcome.txt', exact: true })).toBeVisible();
      await expect(page.getByRole('navigation', { name: 'Folder path' })).toContainText('exchange');
      if (width < 1024) await expectTouchTargets(page, page.locator('main, body').first());
      await expectNoSidewaysScroll(page);

      // upload
      await page.locator('input[type="file"]').setInputFiles({ name, mimeType: 'text/plain', buffer: Buffer.from('first line\nsecond line\n') });
      await expect(page.getByRole('button', { name, exact: true })).toBeVisible();
      await expect(page.getByRole('progressbar', { name: `Uploading ${name}` })).toHaveAttribute('aria-valuenow', '100');

      // preview
      await page.getByRole('button', { name, exact: true }).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog.getByText('second line')).toBeVisible();

      // quick edit, with the diff shown before anything is saved
      await dialog.getByRole('button', { name: 'Edit', exact: true }).click();
      await page.getByLabel('File contents').fill('first line\nchanged line\nthird line\n');
      await page.getByRole('button', { name: 'Review changes' }).click();
      await expect(page.getByText('changed line')).toBeVisible();
      await expect(page.getByText('2 added, 1 removed')).toBeVisible();
      const before = await request.get(`${origin()}/v1/boxes/${BOX}/files/preview?path=${encodeURIComponent(`${await root(request)}/exchange/${name}`)}`, { headers: auth() });
      expect(((await before.json()) as { text: string }).text).toBe('first line\nsecond line\n');
      await page.getByRole('button', { name: 'Save changes' }).click();
      await expect(dialog).toBeHidden();
      await page.getByRole('button', { name, exact: true }).click();
      await expect(page.getByRole('dialog').getByText('changed line')).toBeVisible();
      await page.getByRole('dialog').getByRole('button', { name: 'Close' }).first().click();

      // share: a link that works, then does not
      await rowAction(page, name, 'Share');
      await page.getByRole('button', { name: 'Create link' }).click();
      const link = await page.getByLabel('Download link').inputValue();
      expect(link).toContain(`/dl/${BOX}/`);
      const ok = await request.get(link);
      expect(ok.status()).toBe(200);
      expect(await ok.text()).toContain('changed line');
      await page.getByRole('button', { name: `Revoke the link for ${name}` }).click();
      await expect.poll(async () => (await request.get(link)).status()).toBe(404);
      await page.getByRole('dialog').getByRole('button', { name: 'Close' }).first().click();

      // delete to the Trash, then restore
      await rowAction(page, name, 'Delete');
      await expect(page.getByRole('alertdialog')).toContainText('30 days');
      await page.getByRole('button', { name: 'Move to Trash' }).click();
      await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
      await page.getByRole('button', { name: 'Trash', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'Trash' })).toBeVisible();
      await expectNoSidewaysScroll(page);
      await page.getByRole('button', { name: `Restore ${name}` }).click();
      await page.getByRole('button', { name: 'Back to files' }).click();
      await expect(page.getByRole('button', { name, exact: true })).toBeVisible();
    });

    test('a secret file is shown greyed with its reason and cannot be opened or sent', async ({ page, request }) => {
      const dir = `${await root(request)}/projects/demo`;
      await open(page, `/boxes/${BOX}/files?path=${encodeURIComponent(dir)}`);
      await expect(page.getByRole('button', { name: 'README.md', exact: true })).toBeVisible();
      await page.getByLabel('Show hidden files').click();
      await expect(page.getByText('.env', { exact: true })).toBeVisible();
      await expect(page.getByText('Can hold secrets').first()).toBeVisible();
      await expect(page.getByRole('button', { name: '.env', exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: '.env.example', exact: true })).toBeVisible();
      await expectNoSidewaysScroll(page);
      // the box refuses it at every door, with the same words
      for (const op of ['preview', 'read']) {
        const r = await request.get(`${origin()}/v1/boxes/${BOX}/files/${op}?path=${encodeURIComponent(`${dir}/.env`)}`, { headers: auth() });
        expect(r.status()).toBe(403);
        expect(((await r.json()) as { code: string }).code).toBe('secret_blocked');
      }
      const tok = await request.post(`${origin()}/v1/boxes/${BOX}/files/tokens`, { headers: auth(), data: { paths: [`${dir}/.env`] } });
      expect(tok.status()).toBe(403);
    });

    test('a stale edit is refused and explained, with a reload', async ({ page, request }) => {
      const leaf = `stale-${width}-${Date.now()}.txt`;
      const file = `${await root(request)}/exchange/${leaf}`;
      const put = (text: string, ifMatch: string) =>
        request.put(`${origin()}/v1/boxes/${BOX}/files/write?path=${encodeURIComponent(file)}&if_match=${ifMatch}`, { headers: { ...auth(), 'Content-Type': 'text/plain' }, data: text });
      expect((await put('v1\n', 'none')).status()).toBe(200);
      await open(page, `/boxes/${BOX}/files?path=${encodeURIComponent(`${await root(request)}/exchange`)}`);
      await page.getByRole('button', { name: leaf, exact: true }).click();
      await page.getByRole('dialog').getByRole('button', { name: 'Edit', exact: true }).click();
      await page.getByLabel('File contents').fill('mine\n');
      // someone else saves first
      expect((await put('theirs\n', sha('v1\n'))).status()).toBe(200);
      await page.getByRole('button', { name: 'Review changes' }).click();
      await page.getByRole('button', { name: 'Save changes' }).click();
      await expect(page.getByRole('alert').getByText('This file changed while you were editing')).toBeVisible();
      await page.getByRole('button', { name: 'Reload the latest' }).click();
      await expect(page.getByLabel('File contents')).toHaveValue('theirs\n');
    });

    test('no serious accessibility violations on the files page', async ({ page }) => {
      await open(page, `/boxes/${BOX}/files`);
      await expect(page.getByRole('button', { name: 'exchange', exact: true })).toBeVisible();
      const r = await axeScan(page);
      expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
    });

    test('layout holds: no sideways scroll, reachable controls', async ({ page }) => {
      await open(page, `/boxes/${BOX}/files`);
      const toolbar = page.getByRole('toolbar', { name: 'File actions' });
      await expect(toolbar.getByRole('button', { name: 'Upload' })).toBeVisible();
      await expect(toolbar.getByRole('button', { name: 'New folder' })).toBeVisible();
      await expect(toolbar.getByRole('button', { name: 'Search' })).toBeVisible();
      await expectNoSidewaysScroll(page);
      await page.getByRole('button', { name: 'Grid' }).click();
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, page.locator('main, body').first());
      await toolbar.getByRole('button', { name: 'Search' }).click();
      const dialog = page.getByRole('dialog');
      await dialog.getByRole('searchbox', { name: 'Search' }).fill('welcome');
      await dialog.getByRole('button', { name: 'Search', exact: true }).click();
      await expect(dialog.getByText('welcome.txt', { exact: true })).toBeVisible();
      // accessibility with a panel open, then a result opens its preview
      const open2 = await axeScan(page);
      expect(open2.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
      await dialog.getByRole('button', { name: /welcome\.txt/ }).click();
      await expect(page.getByRole('dialog').getByText('Hello from a demo box.')).toBeVisible();
    });
  });
}
