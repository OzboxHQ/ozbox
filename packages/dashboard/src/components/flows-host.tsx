import { useEffect, useState } from 'react';

import { useApp } from '../App';
import { fleetNotConnected } from '../lib/fleet';
import { FleetNotConnectedSheet } from './fleet-notice';
import type { SetupProvider } from '../api/setup';
import { FLOW_EVENT, type FlowKind } from '../lib/flows';
import { CreateBoxSheet } from './create-box/create-box-sheet';
import { SetupSheet } from './setup/setup-sheet';

/** Mounted once. Opens "Create a box" and "Set up your fleet" when anything asks (see lib/flows). */
export function FlowsHost() {
  const { info } = useApp();
  const [create, setCreate] = useState(false);
  const [setup, setSetup] = useState<{ open: boolean; provider: SetupProvider | null }>({ open: false, provider: null });
  useEffect(() => {
    const on = (e: Event) => {
      const kind = (e as CustomEvent<FlowKind>).detail;
      if (kind === 'create') setCreate(true);
      else if (kind === 'setup') setSetup({ open: true, provider: null });
      else if (kind === 'sandbox') setSetup({ open: true, provider: 'fake' });
    };
    window.addEventListener(FLOW_EVENT, on);
    return () => window.removeEventListener(FLOW_EVENT, on);
  }, []);
  return (
    <>
      {fleetNotConnected(info) ? <FleetNotConnectedSheet open={create} onClose={() => setCreate(false)} info={info} /> : <CreateBoxSheet open={create} onClose={() => setCreate(false)} />}
      <SetupSheet
        open={setup.open}
        initialProvider={setup.provider}
        onClose={() => {
          setSetup((s) => ({ ...s, open: false }));
          window.dispatchEvent(new Event('ozbox:changed'));
        }}
      />
    </>
  );
}
