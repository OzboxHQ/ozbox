// The browser on the box: sessions, the live view, take-over, recordings and settings. The shapes are the ones `/v1/browser`
// answers with (see crates/ozbox-cli/src/serve/browser_routes.rs). Times are milliseconds since the Unix epoch.

import type { MetricsSource } from './types';

export type SessionState = 'running' | 'taken_over' | 'paused' | 'closed';

export interface Recording {
  session: string;
  box: string;
  started_ms: number;
  last_ms: number;
  ended_ms: number | null;
  device: string;
  run: string | null;
  state: SessionState;
  actions: number;
  paused_reason: string | null;
  live: boolean;
}

export interface BrowserSessions {
  live: { id: string; box: string }[];
  recordings: Recording[];
  /** `simulated` when the browser is the demo's stand-in. A server older than this field sends none. */
  source?: MetricsSource;
  /** Running boxes whose sessions could not be read, with the reason. A server older than this field sends none. */
  unreachable?: { name: string; reason: string }[];
}

export interface Frame {
  /** A JPEG, base64. */
  jpeg: string;
  page: string;
  control: 'agent' | 'person';
  /** The page's width in CSS pixels, so a click can be put back in page coordinates. */
  device: number;
  /** A dialog the page opened while you hold the browser: it waits for your answer. */
  dialog?: { type: string; message: string };
}

export interface SessionStatus {
  session: string;
  control: 'agent' | 'person';
  held_reason: string;
  actions: number;
  max_actions: number;
  minutes: number;
  max_minutes: number;
  device: string;
  /** Who took the browser over, when a person did. Only they send it input. */
  holder?: string;
}

export interface ReplayStep {
  n: number;
  ts_ms: number;
  actor: 'agent' | 'person';
  action: string;
  page: string;
  names: string[];
  risk: string;
  outcome: string;
  shot?: string;
  /** The approval request a person decided for this step. */
  approval?: string;
}

export interface Replay {
  meta: Omit<Recording, 'box' | 'live'>;
  steps: ReplayStep[];
}

export interface BrowserPolicy {
  safe_sites: string[];
  payments: 'refuse' | 'ask';
  proxy: string | null;
  retention_days: number;
  respect_robots: boolean;
  exempt_sites: string[];
  min_gap_ms: number;
  local_model_sites: string[];
  max_actions: number;
  max_minutes: number;
  max_sessions: number;
  max_download_bytes: number;
  wait_minutes: number;
  profile: string | null;
  /** Folders under /work a file may be uploaded from (default uploads). Never the home folder or a dotfolder. */
  upload_dirs: string[];
  /** The most memory one session's browser may use, in MiB. */
  memory_mb: number;
}

export type PointerEvent = { t: 'mouse'; kind: 'move' | 'down' | 'up' | 'wheel'; x: number; y: number; dy?: number };
export type KeyEvent = { t: 'key'; kind: 'press'; key: string } | { t: 'text'; text: string };
export type DialogEvent = { t: 'dialog'; accept: boolean };

type Req = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createBrowserApi(request: Req) {
  const id = encodeURIComponent;
  return {
    sessions: (box?: string, signal?: AbortSignal) => request<BrowserSessions>('GET', `/v1/browser/sessions${box ? `?box=${id(box)}` : ''}`, undefined, signal),
    open: (box: string, device: string) => request<{ id: string; box: string }>('POST', '/v1/browser/sessions', { box, device }),
    status: (session: string, signal?: AbortSignal) => request<SessionStatus>('GET', `/v1/browser/sessions/${id(session)}`, undefined, signal),
    frame: (session: string, signal?: AbortSignal) => request<Frame>('GET', `/v1/browser/sessions/${id(session)}/frame`, undefined, signal),
    input: (session: string, event: PointerEvent | KeyEvent | DialogEvent) => request<{ ok: boolean }>('POST', `/v1/browser/sessions/${id(session)}/input`, { event }),
    takeover: (session: string) => request<{ control: string }>('POST', `/v1/browser/sessions/${id(session)}/takeover`),
    handback: (session: string) => request<{ control: string }>('POST', `/v1/browser/sessions/${id(session)}/handback`),
    close: (session: string) => request<{ closed: boolean }>('POST', `/v1/browser/sessions/${id(session)}/close`),
    resume: (session: string, box: string) => request<{ id: string }>('POST', `/v1/browser/sessions/${id(session)}/resume`, { box }),
    replay: (box: string, session: string, signal?: AbortSignal) => request<Replay>('GET', `/v1/browser/recordings/${id(box)}/${id(session)}`, undefined, signal),
    settings: (project?: string, signal?: AbortSignal) =>
      request<{ settings: BrowserPolicy; projects: string[] }>('GET', `/v1/browser/settings${project ? `?project=${id(project)}` : ''}`, undefined, signal),
    saveSettings: (settings: BrowserPolicy, project?: string) => request<{ ok: boolean }>('PUT', '/v1/browser/settings', { settings, project }),
  };
}

export type BrowserApi = ReturnType<typeof createBrowserApi>;
