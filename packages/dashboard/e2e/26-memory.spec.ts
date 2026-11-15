
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

import { WIDTHS, expectNoSidewaysScroll, expectTouchTargets, open, axeScan } from './fixtures';

// Memory: add a note, find it by search, change it, refuse a secret, forget it. The notes belong to this spec alone (the
// titles carry the width), and it removes its own, so it depends on no box and no other spec.

const token = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').hash.replace('#token=', '');
const origin = () => new URL(process.env['OZBOX_E2E_URL'] ?? '').origin;
const headers = () => ({ Authorization: `Bearer ${token()}` });

async function axeClean(page: Page, testId: string) {
  const r = await axeScan(page, `[data-testid="${testId}"]`);
  expect(r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')).toEqual([]);
}

async function removeNotes(request: APIRequestContext, prefix: string) {
  const r = await request.get(`${origin()}/v1/memory`, { headers: headers() });
  const body = (await r.json()) as { notes: { id: string; title: string }[] };
  for (const n of body.notes.filter((x) => x.title.startsWith(prefix))) await request.delete(`${origin()}/v1/memory/${n.id}`, { headers: headers() });
}

for (const width of WIDTHS) {
  test(`memory at ${width}px: add, search, edit, refuse a secret, forget`, async ({ page, request }) => {
    const title = `e2e-note-${width}`;
    await removeNotes(request, 'e2e-note-');
    try {
      await page.setViewportSize({ width, height: 900 });
      await open(page, '/memory');
      await expect(page.getByRole('heading', { name: 'Memory', level: 1 })).toBeVisible();
      await expectNoSidewaysScroll(page);

      await page.getByRole('button', { name: 'Add a note' }).first().click();
      const sheet = page.getByTestId('mem-sheet');
      await sheet.getByLabel('Whose memory').fill('project:e2e');
      await sheet.getByLabel('Title').fill(title);
      await sheet.getByLabel('Note', { exact: true }).fill('The e2e project releases the database first, then the app.');
      await sheet.getByLabel('Tags').fill('release, order');
      if (width < 1024) await expectTouchTargets(page, sheet);
      await axeClean(page, 'mem-sheet');
      await sheet.getByRole('button', { name: 'Save note' }).click();
      await expect(sheet).toHaveCount(0);

      const card = page.getByTestId('mem-note').filter({ hasText: title });
      await expect(card).toBeVisible();
      await expect(card).toContainText('project:e2e');
      await expectNoSidewaysScroll(page);
      if (width < 1024) await expectTouchTargets(page, card);

      // search finds it by a word prefix, and a word that is not in it finds nothing
      await page.getByLabel('Search notes').fill('databas');
      await expect(page.getByTestId('mem-note').filter({ hasText: title })).toBeVisible();
      await page.getByLabel('Search notes').fill('zzzunrelated');
      await expect(page.getByTestId('mem-note').filter({ hasText: title })).toHaveCount(0);
      await page.getByLabel('Search notes').fill('');

      // edit
      await card.getByRole('button', { name: 'Edit' }).click();
      const edit = page.getByTestId('mem-sheet');
      await edit.getByLabel('Note', { exact: true }).fill('Changed: the app first is wrong; the database goes first.');
      await edit.getByRole('button', { name: 'Save note' }).click();
      await expect(edit).toHaveCount(0);
      await expect(page.getByTestId('mem-note').filter({ hasText: title })).toContainText('Revision 2');

      // reload: the note is a record, not page state
      await page.reload();
      await expect(page.getByTestId('mem-note').filter({ hasText: title })).toContainText('Changed:');

      // a secret is refused, in words that do not repeat it
      await page.getByRole('button', { name: 'Add a note' }).first().click();
      const bad = page.getByTestId('mem-sheet');
      await bad.getByLabel('Whose memory').fill('project:e2e');
      await bad.getByLabel('Title').fill(`${title}-secret`);
      await bad.getByLabel('Note', { exact: true }).fill(`use s${'k'}-abcdefghijklmnopqrstuvwxyz0123456789 for it`);
      await bad.getByRole('button', { name: 'Save note' }).click();
      await expect(bad.getByRole('alert')).toContainText('looks like');
      await expect(bad.getByRole('alert')).not.toContainText(`s${'k'}-abcdef`);
      await bad.getByRole('button', { name: 'Cancel' }).click();

      // forget, behind a confirmation
      await page.getByTestId('mem-note').filter({ hasText: title }).getByRole('button', { name: 'Forget' }).click();
      await page.getByRole('button', { name: 'Forget note' }).click();
      await expect(page.getByTestId('mem-note').filter({ hasText: title })).toHaveCount(0);
    } finally {
      await removeNotes(request, 'e2e-note-');
    }
  });
}
