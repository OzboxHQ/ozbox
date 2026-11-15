import type { BoxRecord, MetricsNow, SelfTest } from '../api/types';
import { failingSteps } from './health';
import { diskUsedPct, memUsedPct } from './format';

export type Severity = 'warning' | 'critical';

export interface Alert {
  id: string;
  box: string;
  severity: Severity;
  text: string;
}

export const MEMORY_ALERT_PCT = 90;
export const DISK_ALERT_PCT = 85;

/**
 * What needs a person, from the data the server has today: boxes in a state Oz Box does not understand, memory
 * pressure, a full work disk and a failing self-test. `selftests` holds the newest self-test of each running box that
 * answered; a box missing from it is said nothing about here (an unreachable box is shown by the page that asked).
 */
export function deriveAlerts(
  boxes: BoxRecord[],
  metrics: Record<string, MetricsNow | undefined>,
  selftests: Record<string, SelfTest | undefined> = {},
): Alert[] {
  const out: Alert[] = [];
  for (const b of boxes) {
    const name = b.spec.name;
    if (b.state === 'unknown') {
      out.push({
        id: `${name}:state`,
        box: name,
        severity: 'critical',
        text: `${name}: the provider reported a state Oz Box does not recognise. Nothing will be changed automatically.`,
      });
    }
    const failing = selftests[name] ? failingSteps(selftests[name] as SelfTest) : [];
    if (failing.length > 0) {
      const first = failing[0];
      out.push({
        id: `${name}:selftest`,
        box: name,
        severity: 'critical',
        text: `${name}: the self-test failed at "${first?.step ?? 'a check'}"${failing.length > 1 ? ` and ${failing.length - 1} more` : ''}.`,
      });
    }
    const sample = metrics[name]?.sample;
    const mem = memUsedPct(sample);
    if (mem !== null && mem >= MEMORY_ALERT_PCT) {
      out.push({
        id: `${name}:memory`,
        box: name,
        severity: 'critical',
        text: `${name}: memory is ${Math.round(mem)}% used.`,
      });
    }
    const disk = diskUsedPct(sample);
    if (disk !== null && disk >= DISK_ALERT_PCT) {
      out.push({
        id: `${name}:disk`,
        box: name,
        severity: 'warning',
        text: `${name}: the work disk is ${Math.round(disk)}% full.`,
      });
    }
  }
  return out.sort((a, b) => (a.severity === b.severity ? a.id.localeCompare(b.id) : a.severity === 'critical' ? -1 : 1));
}
