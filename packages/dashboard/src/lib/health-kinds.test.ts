import { describe, expect, it } from 'vitest';
import { incidentText } from './health';

describe('incident labels', () => {
  it('labels the disk growth incidents through the catalogue', () => {
    expect(incidentText({ ts_ms: 0, kind: 'disk_grown', detail: '' })).toBe('Work disk grown');
    expect(incidentText({ ts_ms: 0, kind: 'disk_grow_failed', detail: '' })).toBe('Work disk could not be grown');
  });
});
