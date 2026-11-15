import { createContext, useContext } from 'react';

import type { SessionApi, SessionStatus } from '../api/session';

export interface SessionValue {
  api: SessionApi;
  status: SessionStatus;
  /** Re-read who is signed in (after a passkey was added, say). */
  refresh: () => Promise<void>;
  signOut: (everywhere: boolean) => Promise<void>;
}

export const SessionCtx = createContext<SessionValue | null>(null);

/** `null` when the dashboard is opened with the local access token (there is no sign-in then). */
export function useSession(): SessionValue | null {
  return useContext(SessionCtx);
}
