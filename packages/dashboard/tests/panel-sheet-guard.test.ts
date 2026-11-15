import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p: string) => readFileSync(join(root, p), 'utf8');

// Overlays that hold a form, a review or a step flow open in a PanelSheet. The forbidden needles are built by
// concatenation so this file never contains the text it forbids.
const DIALOG_CONTENT = '<Dialog' + 'Content';
const ALERT_CONTENT = '<AlertDialog' + 'Content';
const SHEET_CONTENT = '<Sheet' + 'Content';

const OVERLAYS = [
  'src/components/box-action-sheets.tsx',
  'src/components/upgrade-sheet.tsx',
  'src/components/shell.tsx',
  'src/components/command-palette.tsx',
  'src/components/open-in.tsx',
  'src/pages/boxes-page.tsx',
  'src/pages/schedules-page.tsx',
  'src/pages/triggers-page.tsx',
  'src/pages/activity-page.tsx',
  'src/pages/settings-page.tsx',
  'src/pages/settings-access.tsx',
  'src/pages/settings-approvals.tsx',
  'src/components/tasks/new-task-sheet.tsx',
  'src/components/tasks/task-detail-sheet.tsx',
  'src/pages/settings-backups.tsx',
  'src/pages/settings-models.tsx',
  'src/components/models/engines-card.tsx',
  'src/components/models/local-ai-card.tsx',
  'src/components/backups-tab.tsx',
  'src/components/bill/orphans-card.tsx',
  'src/components/auth/step-up-host.tsx',
  'src/pages/account-page.tsx',
  'src/components/approvals/approve-sheet.tsx',
  'src/components/terminal/paste-sheet.tsx',
];

describe('overlays are PanelSheets', () => {
  for (const file of OVERLAYS) {
    it(`${file} renders <PanelSheetContent>, never a dialog or an edge drawer`, () => {
      const src = read(file);
      expect(src).toContain('<PanelSheetContent');
      expect(src).not.toContain(DIALOG_CONTENT);
      expect(src).not.toContain(ALERT_CONTENT);
      expect(src).not.toContain(SHEET_CONTENT);
    });
  }

  it('the plan review keeps Apply in the footer', () => {
    const src = read('src/components/box-action-sheets.tsx');
    const footer = src.slice(src.indexOf('<PanelSheetFooter>'), src.indexOf('</PanelSheetFooter>'));
    expect(footer).toContain("t('plan.apply");
    expect(footer).toContain('confirm-name');
  });

  it('no native browser dialogs anywhere in the app', () => {
    for (const file of [...OVERLAYS, 'src/App.tsx', 'src/pages/box-page.tsx', 'src/pages/approvals-page.tsx']) {
      const src = read(file);
      for (const fn of ['confirm', 'alert', 'prompt']) expect(src).not.toMatch(new RegExp(`window\\.${fn}\\(`));
    }
  });
});
