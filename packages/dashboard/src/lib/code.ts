// The Code panel's decisions, with no React in them so they can be tested on their own.

import type { CodeService, CodeStatus, ServiceState, ServiceStatus } from '../api/code';

export const SERVICE_IDS: CodeService[] = ['ide', 'desktop'];

const STATE_KEYS = {
  running: 'code.state_running',
  stopped: 'code.state_stopped',
  not_set_up: 'code.state_not_set_up',
  unavailable: 'code.state_unavailable',
  unknown: 'code.state_unknown',
} as const;

/** The catalogue key of a service's state. */
export function stateKey(s: ServiceState): (typeof STATE_KEYS)[ServiceState] {
  return STATE_KEYS[s];
}

export type Primary = 'set_up' | 'open' | 'none';

/** What the main button of a service does. */
export function primaryAction(s: ServiceStatus): Primary {
  switch (s.state) {
    case 'running':
      return 'open';
    case 'stopped':
    case 'not_set_up':
      return 'set_up';
    default:
      return 'none';
  }
}

/** Can the service be stopped and removed? Only when there is something to remove. */
export function canRemove(s: ServiceStatus): boolean {
  return s.state === 'running' || s.state === 'stopped';
}

/** How Open works: on this computer (the server opens a local address), through the service's own address, or not at all. */
export type OpenWay = { kind: 'local' } | { kind: 'address'; path: string } | { kind: 'none'; reason: 'shared' | 'not_running' };

export function openWay(status: CodeStatus, s: ServiceStatus): OpenWay {
  if (s.state !== 'running') return { kind: 'none', reason: 'not_running' };
  if (status.mode === 'local') return { kind: 'local' };
  if (s.enter) return { kind: 'address', path: s.enter };
  return { kind: 'none', reason: 'shared' };
}

/** The address switch is on when the service has its own host name. It can be turned on only for a service that runs, in sign-in mode, with a tunnel that carries a second name. */
export function addressSwitch(status: CodeStatus, s: ServiceStatus): { on: boolean; enabled: boolean; why: 'ready' | 'needs_sign_in' | 'tunnel' | 'not_running' } {
  const on = s.public_host !== null;
  if (on) return { on, enabled: true, why: 'ready' };
  if (!status.can_serve_public) return { on, enabled: false, why: 'needs_sign_in' };
  if (status.tunnel && !status.tunnel.supports_hosts) return { on, enabled: false, why: 'tunnel' };
  if (s.state !== 'running') return { on, enabled: false, why: 'not_running' };
  return { on, enabled: true, why: 'ready' };
}

/** Is an address one the server will accept the shape of (https, a host name)? The server checks again. */
export function addressProblem(raw: string): 'empty' | 'https' | 'shape' | null {
  const v = raw.trim();
  if (!v) return 'empty';
  if (!v.toLowerCase().startsWith('https://')) return 'https';
  const rest = v.slice('https://'.length).replace(/\/$/, '');
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}(:\d+)?$/i.test(rest)) return 'shape';
  return null;
}

/** Where each tunnel provider is told about the extra host name. */
export function guideKey(kind: string | undefined): 'cloudflare' | 'caddy' | 'other' {
  if (kind === 'cloudflare') return 'cloudflare';
  if (kind === 'caddy') return 'caddy';
  return 'other';
}

/** Still waiting for the box to answer? */
export function waiting(s: CodeStatus | null): boolean {
  return !s || (!s.probed && s.box_state === 'running') || s.refreshing && !s.probed;
}
