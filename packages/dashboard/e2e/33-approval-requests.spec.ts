import { expect, test, type Page } from '@playwright/test';

import { addVirtualAuthenticator, firstSignIn, startAuthServer, type AuthServer } from './auth-fixtures';
import { expectNoSidewaysScroll, expectTouchTargets, WIDTHS } from './fixtures';
import { callSocket, fileGuardRequest, startSecretsService } from './secrets-service-fixture';

// Change requests (ADR 0041, phase 2): a request filed on the box socket shows on Approvals, and a person decides it with a
// passkey (approve) or a confirmation (deny). A real secrets service on temporary sockets, a dashboard behind a sign-in with
// a virtual authenticator, a second dashboard for a viewer. It owns every socket and port, so it depends on no other spec.
// The requests are fictional: a hook that scanned a README with nothing secret in it.
// That a chat route can change nothing is proved by the Rust tests, not here.

test.describe.configure({ mode: 'serial' });

const THREE = WIDTHS.filter((w) => w !== 1024);
// A viewer alone is refused at start (a dashboard needs at least one owner), so the owner is listed beside the watcher.
const VIEWER = '[[users]]\nid = "owner"\nlabel = "Owner"\n\n[[users]]\nid = "watcher"\nlabel = "Watcher"\nrole = "viewer"\n';
const card = (page: Page, id: string) => page.locator(`[data-testid="request-card"][data-request-id="${id}"]`);

let service: Awaited<ReturnType<typeof startSecretsService>>;
let server: AuthServer;
let viewerServer: AuthServer;
let page: Page;
let approvedId = '';
let deniedId = '';

test.beforeAll(async ({ browser }) => {
  service = await startSecretsService();
  // Without OZBOX_SUPERVISOR_SOCKET the server prints its first-time setup code instead of handing it to the service (which a
  // real box does for the owner's computer); the broker variable still points at the supervisor socket, so the dashboard
  // reaches the request operations there.
  const env = { ...service.env };
  delete env.OZBOX_SUPERVISOR_SOCKET;
  server = await startAuthServer(4195, ['alpha'], 5, undefined, env);
  viewerServer = await startAuthServer(4196, ['alpha'], 5, undefined, env, VIEWER);
  page = await (await browser.newContext()).newPage();
  await addVirtualAuthenticator(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(page, server);
  // A box with no second factor decides a change as it is filed (bootstrap). The dashboard tells its service a second factor
  // exists once a passkey is made, and from then on a request waits for a person; this says so on the supervisor's socket, the
  // way the dashboard does, so the requests below are filed waiting.
  const enrolled = await callSocket(service.supervisor, { op: 'enroll' });
  if (!enrolled.ok) throw new Error(`the service did not take the enrolment: ${enrolled.error ?? 'no reason given'}`);
});

test.afterAll(async () => {
  await server?.stop();
  await viewerServer?.stop();
  service?.stop();
});

for (const w of THREE) {
  test(`at ${w}px a request shows every row with its source, the requester as sent and the reason quoted`, async () => {
    const id = await fileGuardRequest(service.box, 'a');
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${server.origin}/approvals`);
    const c = card(page, id);
    await expect(c).toBeVisible({ timeout: 30_000 });
    await expect(c.getByTestId('request-scope')).toHaveText('A commit or push that holds a key');
    await expect(c.getByTestId('request-state')).toHaveText('Waiting');
    // every display row names where it came from
    const rows = c.getByTestId('request-row');
    const n = await rows.count();
    expect(n).toBeGreaterThan(0);
    await expect(c.getByTestId('request-row-source')).toHaveCount(n);
    for (let i = 0; i < n; i++) await expect(rows.nth(i).getByTestId('request-row-source')).toHaveText(/^source: (service|root helper|from the box)$/);
    // the requester, each fact on its own line
    await expect(c.getByTestId('request-requester-kind')).toContainText('box user');
    await expect(c.getByTestId('request-requester-uid')).toBeVisible();
    // the reason is quoted and labelled as the box's
    await expect(c.getByTestId('request-reason')).toContainText('From the box');
    await expect(c.getByTestId('request-reason')).toContainText('“a public url”');
    await expect(c.getByTestId('request-digest')).toContainText(/Digest [0-9a-f]{16}\b/);
    await expect(c.getByTestId('request-rule')).toHaveText('Needs your passkey');
    await expect(c.getByTestId('request-time')).toContainText('left');
    await expectNoSidewaysScroll(page);
    await expect(c.getByTestId('request-approve')).toBeVisible();
    if (w < 1024) await expectTouchTargets(page, c);
  });
}

test('Approve names what it approves, asks for the passkey, and the card becomes approved by you with a passkey', async () => {
  approvedId = await fileGuardRequest(service.box, 'b');
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${server.origin}/approvals`);
  const c = card(page, approvedId);
  await expect(c).toBeVisible({ timeout: 30_000 });
  const digest16 = ((await c.getByTestId('request-digest').textContent()) ?? '').match(/Digest ([0-9a-f]{16})/)?.[1] ?? '';
  expect(digest16).toHaveLength(16);
  await c.getByTestId('request-approve').click();
  const sheet = page.getByTestId('approve-sheet');
  await expect(sheet).toBeVisible();
  await expect(sheet.getByTestId('approve-sheet-scope')).toHaveText('A commit or push that holds a key');
  await expect(sheet.getByTestId('approve-sheet-digest')).toHaveText(digest16);
  await sheet.getByTestId('approve-sheet-confirm').click();
  await expect(sheet.getByTestId('approve-sheet-done')).toBeVisible({ timeout: 30_000 });
  await sheet.getByTestId('approve-sheet-close').click();
  await expect(sheet).toBeHidden();
  await expect(c.getByTestId('request-state')).toHaveText('Approved', { timeout: 15_000 });
  await expect(c.getByTestId('request-decision')).toHaveText(/^Approved by owner, passkey, .+$/i);
  // the decision is on the record: it survives a reload
  await page.reload();
  await expect(card(page, approvedId).getByTestId('request-state')).toHaveText('Approved');
  // an approved request can still be withdrawn until the change uses it
  await expect(card(page, approvedId).getByTestId('request-deny')).toHaveText('Revoke approval');
});

test('Deny asks first, says what stops, and the card becomes denied', async () => {
  deniedId = await fileGuardRequest(service.box, 'c');
  await page.goto(`${server.origin}/approvals`);
  const c = card(page, deniedId);
  await expect(c).toBeVisible({ timeout: 30_000 });
  await c.getByTestId('request-deny').click();
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toContainText('the change does not happen');
  await dialog.getByRole('button', { name: 'Deny' }).click();
  await expect(c.getByTestId('request-state')).toHaveText('Denied', { timeout: 15_000 });
  await expect(c.getByTestId('request-decision')).toHaveText(/^Denied by owner, .+$/i);
  await expect(c.getByTestId('request-approve')).toHaveCount(0);
  await expect(c.getByTestId('request-deny')).toHaveCount(0);
});

test('a second tab that denied it first makes the passkey step say so in the server\'s words, and nothing is approved', async () => {
  const id = await fileGuardRequest(service.box, 'd');
  await page.goto(`${server.origin}/approvals`);
  const c = card(page, id);
  await expect(c).toBeVisible({ timeout: 30_000 });
  await c.getByTestId('request-approve').click();
  const sheet = page.getByTestId('approve-sheet');
  await expect(sheet).toBeVisible();
  // the other tab, same person, denies it while the first one is still looking at it
  const other = await page.context().newPage();
  await other.goto(`${server.origin}/approvals`);
  const theirs = card(other, id);
  await expect(theirs).toBeVisible({ timeout: 30_000 });
  await theirs.getByTestId('request-deny').click();
  await other.getByRole('alertdialog').getByRole('button', { name: 'Deny' }).click();
  await expect(theirs.getByTestId('request-state')).toHaveText('Denied', { timeout: 15_000 });
  await other.close();
  await sheet.getByTestId('approve-sheet-confirm').click();
  const note = sheet.getByTestId('approve-sheet-note');
  await expect(note).toBeVisible({ timeout: 30_000 });
  expect(((await note.textContent()) ?? '').trim().length).toBeGreaterThan(0);
  await sheet.getByTestId('approve-sheet-close').click();
  await expect(c.getByTestId('request-state')).toHaveText('Denied', { timeout: 15_000 });
  await expect(c.getByTestId('request-decision')).toContainText('Denied');
});

test('a link from a chat message opens the page on that request, marks it and brings it into view', async () => {
  const id = await fileGuardRequest(service.box, 'e');
  await page.setViewportSize({ width: 390, height: 700 });
  await page.goto(`${server.origin}/approvals?request=${id}`);
  const c = card(page, id);
  await expect(c).toBeVisible({ timeout: 30_000 });
  await expect(c).toHaveClass(/ring-2/);
  await expect(c).toBeInViewport({ ratio: 0.1 });
  // opening it decided nothing
  await expect(c.getByTestId('request-state')).toHaveText('Waiting');
});

test('a viewer reads the requests and is offered nothing to press', async ({ browser }) => {
  const id = await fileGuardRequest(service.box, 'f');
  const ctx = await browser.newContext();
  const v = await ctx.newPage();
  await addVirtualAuthenticator(v);
  await v.setViewportSize({ width: 1440, height: 900 });
  await firstSignIn(v, viewerServer, 'watcher');
  for (const w of THREE) {
    await v.setViewportSize({ width: w, height: 900 });
    await v.goto(`${viewerServer.origin}/approvals`);
    const c = card(v, id);
    await expect(c).toBeVisible({ timeout: 30_000 });
    await expect(v.getByTestId('requests-viewer-note')).toBeVisible();
    await expect(c.getByTestId('request-read-only')).toBeVisible();
    await expect(c.getByTestId('request-approve')).toHaveCount(0);
    await expect(c.getByTestId('request-deny')).toHaveCount(0);
    // every row is still readable, with its source
    await expect(c.getByTestId('request-row').first()).toBeVisible();
    await expectNoSidewaysScroll(v);
  }
  // and the server refuses the same thing when asked directly
  const denied = await v.evaluate(async (rid) => {
    const csrf = ((await (await fetch('/auth/session')).json()) as { csrf?: string }).csrf ?? '';
    const res = await fetch(`/v1/approvals/requests/${encodeURIComponent(rid)}/deny`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-ozbox-csrf': csrf }, body: '{}' });
    return res.status;
  }, id);
  expect(denied).toBe(403);
  await ctx.close();
});

for (const w of THREE) {
  test(`at ${w}px the passkey sheet fits, its actions are inside the window and every control is a touch target`, async () => {
    const id = await fileGuardRequest(service.box, w === 390 ? '1' : w === 820 ? '2' : '3');
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${server.origin}/approvals`);
    const c = card(page, id);
    await expect(c).toBeVisible({ timeout: 30_000 });
    await c.getByTestId('request-approve').click();
    const sheet = page.getByTestId('approve-sheet');
    await expect(sheet).toBeVisible();
    await expect(sheet.getByTestId('approve-sheet-confirm')).toBeInViewport();
    await expect(sheet.getByTestId('approve-sheet-close')).toBeInViewport();
    await expectNoSidewaysScroll(page);
    if (w < 1024) await expectTouchTargets(page, sheet);
    await sheet.getByTestId('approve-sheet-close').click();
    await expect(sheet).toBeHidden();
    // closing decided nothing
    await expect(c.getByTestId('request-state')).toHaveText('Waiting');
  });
}

test('Settings, Approvers explains that chat apps never approve and lists the signed-in person\'s passkeys at every width', async () => {
  for (const w of THREE) {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${server.origin}/settings/approvers`);
    await expect(page.getByTestId('approvers-section')).toBeVisible();
    await expect(page.getByTestId('approvers-chat-note')).toContainText('never approve');
    await expect(page.getByTestId('approvers-passkey').first()).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId('approvers-add-passkey')).toHaveAttribute('href', '/account');
    // no laptop key is enrolled on a fresh box
    await expect(page.getByTestId('approvers-keys-none').or(page.getByTestId('approvers-keys-unavailable'))).toBeVisible({ timeout: 30_000 });
    await expectNoSidewaysScroll(page);
    if (w < 1024) await expectTouchTargets(page, page.getByRole('main'));
  }
});
