import { describe, expect, it } from 'vitest';

import { capabilitiesOf, EVERYTHING } from './roles';
import { mayWrite, PAGE_CAPABILITY, PAGE_CANNOT } from './role-gates';
import { en } from '../i18n/en';

const asCan = (caps: Record<string, boolean>) => {
  const c = capabilitiesOf(caps);
  return (cap: keyof typeof c) => c[cap];
};

// what `capabilities(role)` answers in crates/ozbox-core/src/roles.rs
const VIEWER = {};
const MEMBER = { watch_browser: true, control_browser: true, approve: true, start_runs: true, use_boxes: true };
const OWNER = { ...MEMBER, change_settings: true, manage_costs: true, manage_people: true };

describe('mayWrite', () => {
  it('offers a viewer no write on memory, skills or orchestrations', () => {
    for (const p of ['memory', 'skills', 'orchestrations'] as const) expect(mayWrite(p, asCan(VIEWER)), p).toBe(false);
  });
  it('offers a member memory and orchestrations but not skills', () => {
    expect(mayWrite('memory', asCan(MEMBER))).toBe(true);
    expect(mayWrite('orchestrations', asCan(MEMBER))).toBe(true);
    expect(mayWrite('skills', asCan(MEMBER))).toBe(false);
  });
  it('offers an owner everything, and so does a dashboard with no sign-in', () => {
    for (const p of ['memory', 'skills', 'orchestrations'] as const) {
      expect(mayWrite(p, asCan(OWNER)), p).toBe(true);
      expect(mayWrite(p, (c) => EVERYTHING[c]), p).toBe(true);
    }
  });
  it('offers a viewer neither a suggestion to apply nor the bill to read, and a member both', () => {
    for (const p of ['usage', 'bill'] as const) {
      expect(mayWrite(p, asCan(VIEWER)), p).toBe(false);
      expect(mayWrite(p, asCan(MEMBER)), p).toBe(true);
    }
  });
  it('treats a capability an older server did not send as not allowed', () => {
    expect(mayWrite('skills', asCan({ use_boxes: true }))).toBe(false);
  });
  it('every page names a capability and has its words in the catalogue', () => {
    for (const p of ['memory', 'skills', 'orchestrations', 'usage', 'bill'] as const) {
      expect(PAGE_CAPABILITY[p]).toBeTruthy();
      expect(en[PAGE_CANNOT[p]], p).toMatch(/\w/);
    }
  });
});
