import { describe, expect, it } from 'vitest';

import type { CodeStatus, ServiceStatus } from '../api/code';
import { addressProblem, addressSwitch, canRemove, guideKey, openWay, primaryAction, stateKey, waiting } from './code';
import { en } from '../i18n/en';

const svc = (state: ServiceStatus['state'], extra: Partial<ServiceStatus> = {}): ServiceStatus => ({
  service: 'ide',
  state,
  password_set: true,
  public_host: null,
  command: 'ozbox ide dev',
  enter: null,
  ...extra,
});

const status = (over: Partial<CodeStatus> = {}): CodeStatus => ({
  box: 'dev',
  box_state: 'running',
  probed: true,
  refreshing: false,
  error: null,
  linger: true,
  services: [],
  editors: [],
  mode: 'local',
  can_serve_public: false,
  tunnel: null,
  proxy_port: 7879,
  ...over,
});

describe('the Code panel', () => {
  it('offers set up, open or nothing from the service state', () => {
    expect(primaryAction(svc('not_set_up'))).toBe('set_up');
    expect(primaryAction(svc('stopped'))).toBe('set_up');
    expect(primaryAction(svc('running'))).toBe('open');
    expect(primaryAction(svc('unavailable'))).toBe('none');
    expect(primaryAction(svc('unknown'))).toBe('none');
  });

  it('removes only what is there', () => {
    expect(canRemove(svc('running'))).toBe(true);
    expect(canRemove(svc('stopped'))).toBe(true);
    expect(canRemove(svc('not_set_up'))).toBe(false);
    expect(canRemove(svc('unavailable'))).toBe(false);
  });

  it('opens on localhost on this computer, through the address on a shared machine, and never a stopped service', () => {
    expect(openWay(status(), svc('running'))).toEqual({ kind: 'local' });
    expect(openWay(status({ mode: 'public' }), svc('running', { public_host: 'ide.example.com', enter: '/code/enter?host=ide.example.com' }))).toEqual({ kind: 'address', path: '/code/enter?host=ide.example.com' });
    expect(openWay(status({ mode: 'public' }), svc('running'))).toEqual({ kind: 'none', reason: 'shared' });
    expect(openWay(status(), svc('stopped'))).toEqual({ kind: 'none', reason: 'not_running' });
  });

  it('turns the address switch on only when sign-in, the tunnel and the service allow it, and says which is missing', () => {
    expect(addressSwitch(status(), svc('running'))).toMatchObject({ enabled: false, why: 'needs_sign_in' });
    const ok = status({ can_serve_public: true, tunnel: { kind: 'cloudflare', supports_hosts: true }, mode: 'public' });
    expect(addressSwitch(ok, svc('running'))).toMatchObject({ on: false, enabled: true });
    expect(addressSwitch(ok, svc('stopped'))).toMatchObject({ enabled: false, why: 'not_running' });
    expect(addressSwitch({ ...ok, tunnel: { kind: 'ngrok', supports_hosts: false } }, svc('running'))).toMatchObject({ enabled: false, why: 'tunnel' });
    // once on it can always be turned off
    expect(addressSwitch(status(), svc('stopped', { public_host: 'ide.example.com' }))).toMatchObject({ on: true, enabled: true });
  });

  it('checks the shape of an address before asking the server', () => {
    expect(addressProblem('')).toBe('empty');
    expect(addressProblem('http://ide.example.com')).toBe('https');
    expect(addressProblem('https://nodots')).toBe('shape');
    expect(addressProblem('https://ide.example.com path')).toBe('shape');
    expect(addressProblem('https://ide.example.com')).toBeNull();
    expect(addressProblem('https://ide.example.com/')).toBeNull();
  });

  it('picks the guide for the tunnel and knows when to keep polling', () => {
    expect(guideKey('cloudflare')).toBe('cloudflare');
    expect(guideKey('caddy')).toBe('caddy');
    expect(guideKey('ngrok')).toBe('other');
    expect(guideKey(undefined)).toBe('other');
    expect(waiting(null)).toBe(true);
    expect(waiting(status({ probed: false }))).toBe(true);
    expect(waiting(status())).toBe(false);
  });

  it('has a message for every state and every plan step', () => {
    for (const s of ['running', 'stopped', 'not_set_up', 'unavailable', 'unknown'] as const) expect(en).toHaveProperty([stateKey(s)]);
    for (const k of ['set_up', 'password', 'remove', 'public_on', 'public_off', 'stop_session', 'stop_process']) expect(en).toHaveProperty([`code.step_${k}`]);
    for (const k of ['cloudflare', 'caddy', 'other']) expect(en).toHaveProperty([`code.guide_${k}`]);
    for (const k of ['empty', 'https', 'shape']) expect(en).toHaveProperty([`code.address_err_${k}`]);
    for (const k of ['needs_sign_in', 'tunnel', 'not_running']) expect(en).toHaveProperty([`code.address_${k}`]);
  });
});
