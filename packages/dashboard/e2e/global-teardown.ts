import { readFileSync } from 'node:fs';

export default function globalTeardown(): void {
  const file = process.env['OZBOX_E2E_PIDFILE'];
  if (!file) return;
  try {
    process.kill(Number(readFileSync(file, 'utf8')));
  } catch {
    // already gone
  }
}
