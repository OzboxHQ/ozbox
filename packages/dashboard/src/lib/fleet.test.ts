import { describe, expect, it } from 'vitest';

import type { Info } from '../api/types';
import { en } from '../i18n/en';
import { fleetMode, fleetNotConnected, isDemo, showsFleetNotice } from './fleet';

const base = { version: '0', provider: 'aws', metrics: 'live', domain: null, capabilities: { resize: 'x', online_disk_grow: false, disk_shrink: false, snapshots: false }, sizes: [] } as Info;
const withFleet = (mode: 'connected' | 'this_box' | 'demo'): Info => ({ ...base, fleet: { mode, connected: mode !== 'this_box', demo: mode === 'demo' } });

describe('fleet mode', () => {
  it('claims nothing until the server has answered', () => {
    expect(fleetMode(null)).toBeNull();
    expect(isDemo(null)).toBe(false);
    expect(fleetNotConnected(null)).toBe(false);
  });

  it('treats a server that sends no fleet field as a real fleet, as before', () => {
    expect(fleetMode(base)).toBe('connected');
    expect(isDemo(base)).toBe(false);
    expect(fleetNotConnected(base)).toBe(false);
  });

  it('marks demo data and a fleet that is not connected apart', () => {
    expect(isDemo(withFleet('demo'))).toBe(true);
    expect(fleetNotConnected(withFleet('demo'))).toBe(false);
    expect(isDemo(withFleet('this_box'))).toBe(false);
    expect(fleetNotConnected(withFleet('this_box'))).toBe(true);
  });

  it('shows the not-connected notice on the pages that show a fleet, and not on the others', () => {
    expect(showsFleetNotice({ page: 'fleet' })).toBe(true);
    expect(showsFleetNotice({ page: 'boxes' })).toBe(true);
    expect(showsFleetNotice({ page: 'usage' })).toBe(true);
    expect(showsFleetNotice({ page: 'bill' })).toBe(true);
    expect(showsFleetNotice({ page: 'settings' } as never)).toBe(false);
  });

  it('has words for both states', () => {
    expect(en['fleetnote.nc_title']).toBe('Fleet not connected');
    expect(en['fleetnote.nc_body']).toContain('only this box');
    expect(en['fleetnote.demo_title']).toBe('Demo data');
  });
});
