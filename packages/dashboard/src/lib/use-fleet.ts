import type { ApiClient } from '../api/client';
import type { BoxRecord, Info, MetricsNow } from '../api/types';
import { useAsync } from './use-async';

/** A running box whose usage could not be read, and why. */
export interface Unreachable {
  name: string;
  reason: string;
}

export interface Fleet {
  boxes: BoxRecord[];
  metrics: Record<string, MetricsNow | undefined>;
  /** Running boxes that did not answer. Never hidden: a box with no bars says so. */
  unreachable: Unreachable[];
}

/** The boxes plus each running box's current usage, refreshed every 5 s. */
export function useFleet(client: ApiClient, info: Info | null) {
  const wantMetrics = info !== null;
  return useAsync<Fleet>(
    async (signal) => {
      const boxes = await client.listBoxes(signal);
      const metrics: Record<string, MetricsNow | undefined> = {};
      const unreachable: Unreachable[] = [];
      if (wantMetrics) {
        await Promise.all(
          boxes
            .filter((b) => b.state === 'running')
            .map(async (b) => {
              try {
                metrics[b.spec.name] = await client.metricsNow(b.spec.name, signal);
              } catch (e) {
                if (signal.aborted) throw e;
                unreachable.push({ name: b.spec.name, reason: e instanceof Error ? e.message : String(e) });
              }
            }),
        );
      }
      unreachable.sort((a, b) => a.name.localeCompare(b.name));
      return { boxes, metrics, unreachable };
    },
    [client, wantMetrics],
    5000,
  );
}
