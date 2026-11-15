import { defineConfig } from '@playwright/test';

// The real-server specs (G7, tiers B and C). Each spec starts what it needs itself (`e2e-real/real-stack.ts`): a real `ozboxd`
// and a real `ozbox serve`, with no stand-ins. Tier C (`c-*.spec.ts`) points at a server somebody else runs, through
// OZBOX_E2E_URL, and runs only with OZBOX_E2E_REAL=1. Build the programs first:
//   npm run build && cargo build -p ozbox-cli -p ozboxd      (a DEBUG build: the daemon-socket switch is debug-only)
// then: OZBOX_BIN=<target>/debug/ozbox npm run e2e:real
export default defineConfig({
  testDir: './e2e-real',
  timeout: 90_000,
  fullyParallel: false,
  workers: 1,
  retries: process.env['CI'] ? 1 : 0,
  reporter: process.env['CI'] ? [['list'], ['html', { open: 'never', outputFolder: 'playwright-report-real' }]] : 'list',
  outputDir: 'test-results-real',
  use: { trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
