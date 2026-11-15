// The Code panel of a box: the web IDE and the desktop as services of the box, the editors that open it over SSH, and the
// changes the person can make (plan first, then apply). Nothing here ever carries a password: the server keeps it.

export type CodeService = 'ide' | 'desktop';

/** `unknown` until the box has answered; `unavailable` when the box's image has no program for it. */
export type ServiceState = 'running' | 'stopped' | 'not_set_up' | 'unavailable' | 'unknown';

export interface ServiceStatus {
  service: CodeService;
  state: ServiceState;
  password_set: boolean;
  /** The host name it is served on, when it has its own address. */
  public_host: string | null;
  command: string;
  /** A path on this dashboard that signs in to the address, when it has one. */
  enter: string | null;
}

export interface EditorEntry {
  id: string;
  name: string;
  /** A link that opens the box's folder, or null where none exists. */
  url: string | null;
  /** Whether the editor's own documentation describes that link. */
  documented: boolean;
  command: string;
}

export interface CodeStatus {
  box: string;
  box_state: string;
  probed: boolean;
  refreshing: boolean;
  error: string | null;
  linger: boolean | null;
  /** The Cloudflare tunnel running on the box as the box user's own service. Absent from a server that does not know it. */
  connector?: { state: ServiceState };
  services: ServiceStatus[];
  editors: EditorEntry[];
  /** `local`: the dashboard runs on this computer and can open a service on localhost. `public`: a shared machine. */
  mode: 'local' | 'public';
  can_serve_public: boolean;
  tunnel: { kind: string; supports_hosts: boolean } | null;
  proxy_port: number;
}

export type CodeAction = 'enable' | 'disable' | 'public_on' | 'public_off' | 'stop_session' | 'stop_process' | 'connector_on' | 'connector_off';

export interface TmuxSession {
  name: string;
  created_s: number;
  activity_s: number;
  attached: boolean;
  /** The program running in the session's active pane. */
  command: string;
}

export interface AgentProcess {
  pid: number;
  program: string;
  age_s: number;
}

export interface ListeningServer {
  port: number;
  pid: number;
  program: string;
}

export interface Procs {
  tmux: boolean;
  sessions: TmuxSession[];
  agents: AgentProcess[];
  servers: ListeningServer[];
}

export interface ProcsAnswer {
  probed: boolean;
  error: string | null;
  ps: Procs | null;
}

export interface CodePlanStep {
  code: 'set_up' | 'password' | 'remove' | 'public_on' | 'public_off' | 'stop_session' | 'stop_process' | 'connector_on' | 'connector_replace' | 'connector_off';
  program?: string;
  host?: string;
  name?: string;
  pid?: number;
}

export interface CodePlan {
  plan_id: string;
  box: string;
  service: CodeService;
  noop: boolean;
  changes_box: boolean;
  steps: CodePlanStep[];
}

export interface CodeJob {
  state: 'running' | 'done' | 'failed';
  error?: string;
}

export interface CodeApi {
  status(box: string, signal?: AbortSignal): Promise<CodeStatus>;
  processes(box: string, signal?: AbortSignal): Promise<ProcsAnswer>;
  plan(box: string, body: { service?: CodeService; action: CodeAction; address?: string; target?: string; token?: string }, signal?: AbortSignal): Promise<CodePlan>;
  apply(box: string, planId: string, signal?: AbortSignal): Promise<{ job_id: string }>;
  job(id: string, signal?: AbortSignal): Promise<CodeJob>;
  /** Open on localhost of the computer the dashboard runs on; returns the one-time sign-in address. */
  open(box: string, service: CodeService, signal?: AbortSignal): Promise<{ url: string }>;
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createCodeApi(request: Request): CodeApi {
  const base = (b: string) => `/v1/boxes/${encodeURIComponent(b)}/code`;
  return {
    status: (b, s) => request('GET', base(b), undefined, s),
    processes: (b, s) => request('GET', `${base(b)}/processes`, undefined, s),
    plan: (b, body, s) => request('POST', `${base(b)}/plan`, body, s),
    apply: (b, planId, s) => request('POST', `${base(b)}/apply`, { plan_id: planId }, s),
    job: (id, s) => request('GET', `/v1/code/jobs/${encodeURIComponent(id)}`, undefined, s),
    open: (b, service, s) => request('POST', `${base(b)}/open`, { service }, s),
  };
}
