// How the dashboard is reached from outside, and the tunnel that carries it. A token is saved through the secrets route
// (write-only); nothing here ever returns one.

export type TunnelProvider = 'cloudflare' | 'tailscale-funnel' | 'tailscale-serve' | 'caddy' | 'ngrok';

export interface ProviderInfo {
  id: TunnelProvider;
  public: boolean;
  program: string;
  token_secret: string | null;
}

export interface CaddySettings {
  host: string;
  user: string;
  ssh_port: number;
  key_file: string;
  remote_port: number;
}

export interface TunnelSnapshot {
  provider: TunnelProvider;
  public_url: string;
  port: number;
  state: 'running' | 'stopped' | 'failed';
  code: string | null;
  restarts: number;
  health: { ok: boolean; code: string; http_status: number | null; checked_ms: number } | null;
  updated_ms: number;
}

export interface SavedTunnel {
  provider: TunnelProvider;
  public_url: string;
  public: boolean;
  token_secret: string | null;
  /** Whether a token is saved: `null` for a provider with none. */
  token_set: boolean | null;
  caddy: CaddySettings | null;
  /** This server started the tunnel and reports its state. */
  managed: boolean;
  live: TunnelSnapshot | null;
}

export interface AccessStatus {
  mode: 'token' | 'public';
  public_url: string | null;
  strong_methods: string[];
  can_save: boolean;
  /** This server can start, stop and restart the tunnel from here. */
  can_control?: boolean;
  tunnel: SavedTunnel | null;
  providers: ProviderInfo[];
}

export interface SaveTunnelRequest {
  provider: TunnelProvider;
  public_url: string;
  caddy?: CaddySettings;
}

export interface CheckResult {
  health: { ok: boolean; code: string; http_status: number | null; checked_ms: number };
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export interface AccessApi {
  status(signal?: AbortSignal): Promise<AccessStatus>;
  saveTunnel(body: SaveTunnelRequest, signal?: AbortSignal): Promise<AccessStatus>;
  removeTunnel(signal?: AbortSignal): Promise<AccessStatus>;
  /** Asks the saved public address whether the dashboard answers there. */
  check(signal?: AbortSignal): Promise<CheckResult>;
  /** Start the saved tunnel now (it applies the saved settings). */
  startTunnel(signal?: AbortSignal): Promise<AccessStatus>;
  /** Take the tunnel down. A tunnel being used to read this page cuts the page off. */
  stopTunnel(signal?: AbortSignal): Promise<AccessStatus>;
  restartTunnel(signal?: AbortSignal): Promise<AccessStatus>;
}

export function createAccessApi(request: Request): AccessApi {
  return {
    status: (s) => request('GET', '/v1/dashboard-access', undefined, s),
    saveTunnel: (body, s) => request('PUT', '/v1/dashboard-access/tunnel', body, s),
    removeTunnel: (s) => request('DELETE', '/v1/dashboard-access/tunnel', undefined, s),
    check: (s) => request('POST', '/v1/dashboard-access/check', undefined, s),
    startTunnel: (s) => request('POST', '/v1/dashboard-access/tunnel/start', undefined, s),
    stopTunnel: (s) => request('POST', '/v1/dashboard-access/tunnel/stop', undefined, s),
    restartTunnel: (s) => request('POST', '/v1/dashboard-access/tunnel/restart', undefined, s),
  };
}
