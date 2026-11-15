import { useMemo } from 'react';

import type { Capabilities, Capability, Role } from '../api/people';
import { capabilitiesOf, EVERYTHING } from './roles';
import { useSession } from './session-context';

export interface Can {
  /** The signed-in person's role; `owner` on a dashboard with no sign-in (its one operator). */
  role: Role;
  caps: Capabilities;
  can: (c: Capability) => boolean;
}

/**
 * What the signed-in person may do, to decide what the page offers. The server refuses what a role may not do on every
 * request; this only keeps the page from offering it.
 */
export function useCan(): Can {
  const session = useSession();
  const status = session?.status;
  return useMemo(() => {
    if (!session) return { role: 'owner', caps: EVERYTHING, can: () => true };
    const caps = capabilitiesOf(status?.can);
    return { role: status?.role ?? 'viewer', caps, can: (c: Capability) => caps[c] };
  }, [session, status?.can, status?.role]);
}
