import { describe, expect, it } from 'vitest';

import { CAPABILITIES, capabilitiesOf, EVERYTHING, isRole } from './roles';

describe('what the dashboard offers a person', () => {
  it('reads the server list, and a name it did not send is off', () => {
    const c = capabilitiesOf({ approve: true, start_runs: true, change_settings: false });
    expect(c.approve && c.start_runs).toBe(true);
    expect(c.change_settings).toBe(false);
    expect(c.watch_browser).toBe(false);
    expect(Object.keys(c).sort()).toEqual([...CAPABILITIES].sort());
  });

  it('turns everything off when the server said nothing, never on', () => {
    expect(Object.values(capabilitiesOf(undefined)).some(Boolean)).toBe(false);
    expect(Object.values(capabilitiesOf(null)).some(Boolean)).toBe(false);
    // only an exact true counts
    expect(capabilitiesOf({ approve: 'yes' as unknown as boolean }).approve).toBe(false);
  });

  it('gives a dashboard with no sign-in everything', () => {
    expect(Object.values(EVERYTHING).every(Boolean)).toBe(true);
  });

  it('knows the three roles and nothing else', () => {
    expect(['owner', 'member', 'viewer'].every(isRole)).toBe(true);
    expect(isRole('admin')).toBe(false);
    expect(isRole(undefined)).toBe(false);
  });
});
