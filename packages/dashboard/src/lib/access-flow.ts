// The logic of the Dashboard access screen, apart from React: what a form sends, what a status means, what to run.

import type { AccessStatus, CaddySettings, SaveTunnelRequest, SavedTunnel, TunnelProvider } from '../api/access';
import type { MessageKey } from './i18n';

export const PROVIDERS: TunnelProvider[] = ['cloudflare', 'tailscale-funnel', 'tailscale-serve', 'caddy', 'ngrok'];

export interface AccessForm {
  publicUrl: string;
  token: string;
  sshHost: string;
  sshUser: string;
  sshPort: string;
  keyFile: string;
  remotePort: string;
}

export const emptyForm = (): AccessForm => ({ publicUrl: '', token: '', sshHost: '', sshUser: '', sshPort: '22', keyFile: '', remotePort: '7878' });

export function formFromSaved(t: SavedTunnel | null): AccessForm {
  const f = emptyForm();
  if (!t) return f;
  f.publicUrl = t.public_url;
  if (t.caddy) {
    f.sshHost = t.caddy.host;
    f.sshUser = t.caddy.user;
    f.sshPort = String(t.caddy.ssh_port);
    f.keyFile = t.caddy.key_file;
    f.remotePort = String(t.caddy.remote_port);
  }
  return f;
}

/** The host of an `https://host` address, or `null` when it is not one the server would accept. */
export function httpsHost(raw: string): string | null {
  const m = /^https:\/\/([A-Za-z0-9.-]+)(?::\d{1,5})?\/?$/.exec(raw.trim());
  const host = m?.[1]?.toLowerCase();
  if (!host || !host.includes('.') || /^\d+(\.\d+){3}$/.test(host) || host.startsWith('-') || host.startsWith('.') || host.endsWith('.') || host.endsWith('-')) return null;
  return host;
}

const HOST = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/;
const USER = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;
const PATH = /^[A-Za-z0-9/._~][A-Za-z0-9/._~-]*$/;

/** Errors by field, as catalogue keys. Empty when the form can be sent. */
export function validate(provider: TunnelProvider, f: AccessForm): Partial<Record<keyof AccessForm, MessageKey>> {
  const e: Partial<Record<keyof AccessForm, MessageKey>> = {};
  const host = httpsHost(f.publicUrl);
  if (!host) e.publicUrl = 'access.err_url';
  else if ((provider === 'tailscale-funnel' || provider === 'tailscale-serve') && !host.endsWith('.ts.net')) e.publicUrl = 'access.err_tsnet';
  if (provider === 'caddy') {
    if (!HOST.test(f.sshHost) || f.sshHost.length > 253) e.sshHost = 'access.err_host';
    if (!USER.test(f.sshUser) || f.sshUser.length > 32) e.sshUser = 'access.err_user';
    if (!PATH.test(f.keyFile) || f.keyFile.length > 256) e.keyFile = 'access.err_key';
    const sp = Number(f.sshPort);
    if (!Number.isInteger(sp) || sp < 1 || sp > 65535) e.sshPort = 'access.err_port';
    const rp = Number(f.remotePort);
    if (!Number.isInteger(rp) || rp < 1024 || rp > 65535) e.remotePort = 'access.err_remote_port';
  }
  return e;
}

export function toRequest(provider: TunnelProvider, f: AccessForm): SaveTunnelRequest {
  const body: SaveTunnelRequest = { provider, public_url: f.publicUrl.trim().replace(/\/+$/, '') };
  if (provider === 'caddy') {
    const caddy: CaddySettings = { host: f.sshHost.trim(), user: f.sshUser.trim(), ssh_port: Number(f.sshPort), key_file: f.keyFile.trim(), remote_port: Number(f.remotePort) };
    body.caddy = caddy;
  }
  return body;
}

export function tokenSecretName(provider: TunnelProvider): string | null {
  if (provider === 'cloudflare') return 'tunnel-token-cloudflare';
  if (provider === 'ngrok') return 'tunnel-token-ngrok';
  return null;
}

/** The command that starts the dashboard with this tunnel. */
export function serveCommand(provider: TunnelProvider, publicUrl: string): string {
  return `ozbox serve --public-url ${publicUrl.trim().replace(/\/+$/, '') || 'https://…'} --tunnel ${provider}`;
}

/** The Caddyfile a person puts on their own server. */
export function caddyfile(publicUrl: string, remotePort: string): string {
  return `${httpsHost(publicUrl) ?? 'ozbox.example.com'} {\n\treverse_proxy 127.0.0.1:${remotePort || '7878'}\n}`;
}

export type TunnelView = 'running' | 'stopped' | 'failed' | 'unmanaged';

/** What the card says about a saved tunnel. `unmanaged`: this server did not start it, so it reports nothing. */
export function tunnelView(t: SavedTunnel): TunnelView {
  if (!t.managed || !t.live) return 'unmanaged';
  return t.live.state;
}

export interface TunnelControls {
  start: boolean;
  stop: boolean;
  restart: boolean;
}

/** Which of Start, Stop and Restart the card offers. A tunnel this server did not start cannot be stopped from here,
 * but it can be started (which brings it under this server's care). Everything is off when the server cannot do it. */
export function tunnelControls(t: SavedTunnel, canControl: boolean): TunnelControls {
  if (!canControl) return { start: false, stop: false, restart: false };
  const v = tunnelView(t);
  const up = v === 'running' || v === 'failed';
  return { start: !up, stop: up, restart: up };
}

export function codeKey(code: string | null | undefined): MessageKey | null {
  const known: Record<string, MessageKey> = {
    no_token: 'access.code_no_token',
    tool_missing: 'access.code_tool_missing',
    spawn_failed: 'access.code_spawn_failed',
    exited: 'access.code_exited',
    signed_out: 'access.code_signed_out',
    name_mismatch: 'access.code_name_mismatch',
    funnel_is_on: 'access.code_funnel_is_on',
    funnel_off: 'access.code_funnel_off',
    tailscale_failed: 'access.code_tailscale_failed',
    bad_answer: 'access.code_bad_answer',
    bad_address: 'access.code_bad_address',
    ok: 'access.code_ok',
    unreachable: 'access.code_unreachable',
    refused: 'access.code_refused',
    bad_status: 'access.code_bad_status',
    not_running: 'access.code_not_running',
    not_applicable: 'access.code_not_applicable',
  };
  return code ? (known[code] ?? null) : null;
}

export const GUIDE_STEPS: Record<TunnelProvider, MessageKey[]> = {
  cloudflare: ['access.cf_1', 'access.cf_2', 'access.cf_3', 'access.cf_4', 'access.cf_5'],
  'tailscale-funnel': ['access.tf_1', 'access.tf_2', 'access.tf_3', 'access.tf_4'],
  'tailscale-serve': ['access.ts_1', 'access.ts_2', 'access.ts_3'],
  caddy: ['access.cd_1', 'access.cd_2', 'access.cd_3', 'access.cd_4', 'access.cd_5'],
  ngrok: ['access.ng_1', 'access.ng_2', 'access.ng_3', 'access.ng_4'],
};

export const PROVIDER_NAME: Record<TunnelProvider, MessageKey> = {
  cloudflare: 'access.p_cloudflare',
  'tailscale-funnel': 'access.p_tailscale_funnel',
  'tailscale-serve': 'access.p_tailscale_serve',
  caddy: 'access.p_caddy',
  ngrok: 'access.p_ngrok',
};

export const PROVIDER_NOTE: Record<TunnelProvider, MessageKey> = {
  cloudflare: 'access.n_cloudflare',
  'tailscale-funnel': 'access.n_tailscale_funnel',
  'tailscale-serve': 'access.n_tailscale_serve',
  caddy: 'access.n_caddy',
  ngrok: 'access.n_ngrok',
};

/** Public mode with nothing strong behind it can only be a half-set-up server; the screen says so. */
export function isProtected(a: AccessStatus): boolean {
  return a.mode === 'token' || a.strong_methods.length > 0;
}
