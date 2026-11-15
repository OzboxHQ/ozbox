import { describe, expect, it } from 'vitest';

import type { SavedTunnel } from '../api/access';
import { createAccessApi } from '../api/access';
import { en } from '../i18n/en';
import { GUIDE_STEPS, PROVIDERS, PROVIDER_NAME, PROVIDER_NOTE, caddyfile, codeKey, emptyForm, formFromSaved, httpsHost, serveCommand, toRequest, tokenSecretName, tunnelControls, tunnelView, validate } from './access-flow';

const saved = (over: Partial<SavedTunnel> = {}): SavedTunnel => ({
  provider: 'cloudflare',
  public_url: 'https://ozbox.example.com',
  public: true,
  token_secret: 'tunnel-token-cloudflare',
  token_set: true,
  caddy: null,
  managed: false,
  live: null,
  ...over,
});

describe('the address', () => {
  it('accepts an https host name and nothing else', () => {
    expect(httpsHost('https://ozbox.example.com')).toBe('ozbox.example.com');
    expect(httpsHost('https://Ozbox.Example.com:8443/')).toBe('ozbox.example.com');
    for (const bad of ['http://ozbox.example.com', 'https://1.2.3.4', 'https://localhost', 'https://x.example.com/path', 'https://user@x.example.com', 'ozbox.example.com', 'https://.example.com', 'javascript:alert(1)']) {
      expect(httpsHost(bad), bad).toBeNull();
    }
  });
  it('a Tailscale provider needs a .ts.net name', () => {
    expect(validate('tailscale-funnel', { ...emptyForm(), publicUrl: 'https://ozbox.example.com' }).publicUrl).toBe('access.err_tsnet');
    expect(validate('tailscale-serve', { ...emptyForm(), publicUrl: 'https://box.tail1234.ts.net' })).toEqual({});
  });
});

describe('the form', () => {
  const caddy = { ...emptyForm(), publicUrl: 'https://ozbox.example.com', sshHost: 'vps.example.com', sshUser: 'ozbox-tunnel', keyFile: '/work/key' };
  it('needs only an address for a provider with a token', () => {
    expect(validate('cloudflare', { ...emptyForm(), publicUrl: 'https://ozbox.example.com' })).toEqual({});
    expect(validate('cloudflare', emptyForm()).publicUrl).toBe('access.err_url');
  });
  it('checks the fields of a server of your own, including ones that could inject an ssh option', () => {
    expect(validate('caddy', caddy)).toEqual({});
    expect(validate('caddy', { ...caddy, sshHost: '-oProxyCommand=x' }).sshHost).toBe('access.err_host');
    expect(validate('caddy', { ...caddy, sshUser: 'a b' }).sshUser).toBe('access.err_user');
    expect(validate('caddy', { ...caddy, keyFile: '-i/etc/passwd' }).keyFile).toBe('access.err_key');
    expect(validate('caddy', { ...caddy, remotePort: '80' }).remotePort).toBe('access.err_remote_port');
    expect(validate('caddy', { ...caddy, sshPort: '0' }).sshPort).toBe('access.err_port');
  });
  it('sends the address without a trailing slash, the server settings only for Caddy, and never the token', () => {
    const body = toRequest('cloudflare', { ...emptyForm(), publicUrl: ' https://ozbox.example.com/ ', token: 'SENTINEL' });
    expect(body).toEqual({ provider: 'cloudflare', public_url: 'https://ozbox.example.com' });
    expect(JSON.stringify(body)).not.toContain('SENTINEL');
    expect(toRequest('caddy', caddy).caddy).toEqual({ host: 'vps.example.com', user: 'ozbox-tunnel', ssh_port: 22, key_file: '/work/key', remote_port: 7878 });
  });
  it('is filled from what is saved, and a token is never part of it', () => {
    expect(formFromSaved(saved()).publicUrl).toBe('https://ozbox.example.com');
    expect(formFromSaved(saved()).token).toBe('');
    expect(formFromSaved(null)).toEqual(emptyForm());
  });
  it('names the secret only for the providers that have a token', () => {
    expect(PROVIDERS.map((p) => tokenSecretName(p))).toEqual(['tunnel-token-cloudflare', null, null, null, 'tunnel-token-ngrok']);
  });
});

describe('what the screen says', () => {
  it('a tunnel this server did not start reports nothing', () => {
    expect(tunnelView(saved())).toBe('unmanaged');
    const live = { provider: 'cloudflare', public_url: 'x', port: 7878, state: 'failed', code: 'exited', restarts: 2, health: null, updated_ms: 1 } as const;
    expect(tunnelView(saved({ managed: true, live: { ...live } }))).toBe('failed');
  });
  it('every code the server can report has words', () => {
    for (const c of ['no_token', 'tool_missing', 'spawn_failed', 'exited', 'signed_out', 'name_mismatch', 'funnel_is_on', 'funnel_off', 'tailscale_failed', 'bad_answer', 'bad_address', 'ok', 'unreachable', 'refused', 'bad_status', 'not_running', 'not_applicable']) {
      expect(codeKey(c), c).not.toBeNull();
    }
    expect(codeKey('something_new')).toBeNull();
  });
  it('every provider has a name, a note and steps that exist in the catalogue', () => {
    for (const p of PROVIDERS) {
      expect(en[PROVIDER_NAME[p]]).toBeTruthy();
      expect(en[PROVIDER_NOTE[p]]).toBeTruthy();
      expect(GUIDE_STEPS[p].length).toBeGreaterThan(2);
      for (const k of GUIDE_STEPS[p]) expect(en[k]).toBeTruthy();
    }
    expect(en['access.n_ngrok']).toMatch(/paid/);
    expect(en['access.box_body']).toMatch(/takes the dashboard down/);
  });
  it('shows the command to start it, and the Caddyfile that forwards to loopback only', () => {
    expect(serveCommand('cloudflare', 'https://ozbox.example.com/')).toBe('ozbox serve --public-url https://ozbox.example.com --tunnel cloudflare');
    expect(caddyfile('https://ozbox.example.com', '7878')).toBe('ozbox.example.com {\n\treverse_proxy 127.0.0.1:7878\n}');
  });
});

describe('the calls', () => {
  it('use the dashboard-access routes and put no token in a body', async () => {
    const seen: string[] = [];
    const api = createAccessApi(async (method, path, body) => {
      seen.push(`${method} ${path} ${JSON.stringify(body ?? null)}`);
      return {} as never;
    });
    await api.status();
    await api.saveTunnel({ provider: 'ngrok', public_url: 'https://ozbox.example.com' });
    await api.removeTunnel();
    await api.check();
    await api.startTunnel();
    await api.stopTunnel();
    await api.restartTunnel();
    expect(seen).toEqual([
      'GET /v1/dashboard-access null',
      'PUT /v1/dashboard-access/tunnel {"provider":"ngrok","public_url":"https://ozbox.example.com"}',
      'DELETE /v1/dashboard-access/tunnel null',
      'POST /v1/dashboard-access/check null',
      'POST /v1/dashboard-access/tunnel/start null',
      'POST /v1/dashboard-access/tunnel/stop null',
      'POST /v1/dashboard-access/tunnel/restart null',
    ]);
  });
});

describe('which controls the tunnel card offers', () => {
  const base = { provider: 'cloudflare', public_url: 'https://ozbox.example.com', public: true, token_secret: null, token_set: null, caddy: null } as const;
  const live = (state: 'running' | 'stopped' | 'failed') => ({ provider: 'cloudflare', public_url: base.public_url, port: 7878, state, code: null, restarts: 0, health: null, updated_ms: 0 }) as const;
  it('offers Start for a tunnel that is not up, and Stop and Restart for one that is', () => {
    expect(tunnelControls({ ...base, managed: false, live: null }, true)).toEqual({ start: true, stop: false, restart: false });
    expect(tunnelControls({ ...base, managed: true, live: live('stopped') }, true)).toEqual({ start: true, stop: false, restart: false });
    expect(tunnelControls({ ...base, managed: true, live: live('running') }, true)).toEqual({ start: false, stop: true, restart: true });
    // a tunnel that is failing is still being retried, so it can be stopped or restarted
    expect(tunnelControls({ ...base, managed: true, live: live('failed') }, true)).toEqual({ start: false, stop: true, restart: true });
  });
  it('offers nothing when the server cannot control it', () => {
    expect(tunnelControls({ ...base, managed: true, live: live('running') }, false)).toEqual({ start: false, stop: false, restart: false });
  });
  it('warns, in the words of the screen, that stopping can cut your own connection', () => {
    expect(en['access.stop_desc']).toMatch(/lose your connection/);
    expect(en['access.restart_desc']).toMatch(/cut off/);
  });
});
