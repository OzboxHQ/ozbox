import type { AlertSummary, TestRun } from './alert-types';
import type {
  ApplyJob,
  ApplyRequest,
  FleetChallenge,
  ApplyStarted,
  AppsStatus,
  CostResponse,
  Delivery,
  ModelTestResult,
  ModelsCatalog,
  ModelListResult,
  ModelPrice,
  ModelUsageResponse,
  LocalCatalog,
  LocalAiStatus,
  ProviderCheck,
  LocalAiPlan,
  ModelsStatus,
  RecentAlert,
  ActivityResponse,
  ApplyResponse,
  BoxImage,
  Approval,
  BoxRecord,
  Info,
  MetricsNow,
  MetricsSource,
  MetricsSeries,
  Operation,
  PlanResponse,
  SelfTest,
  SettingsResponse,
  Incident,
  Settings,
  SshEntry,
  Step,
  SuggestionsResponse,
  UsageRange,
  UsageResponse,
} from './types';

import { summaryQuery } from '../lib/alert-outcome';
import { ApiError } from './error';
import { createLimiter } from '../lib/limit';
import { createTransport, type Transport } from './transport';
import { createAccessApi, type AccessApi } from './access';
import { createBackupsApi, type BackupsApi } from './backups';
import { createBillApi, type BillApi } from './bill';
import { createSchedApi, type SchedApi } from './sched';
import { createChatApi, type ChatApi } from './chat';
import { createCodeApi, type CodeApi } from './code';
import { createFilesApi, type FilesApi } from './files';
import { createSetupApi, type SetupApi } from './setup';
import { createOrchApi, type OrchApi } from './orch';
import { createPeopleApi, type PeopleApi } from './people';
import { createPermApi, type PermApi } from './perm';
import { createAgentMcpApi, type AgentMcpApi } from './agent-mcp';
import { createBrowserApi, type BrowserApi } from './browser';
import { createMemoryApi, type MemoryApi } from './memory';
import { createApprovalRequestsApi, type ApprovalRequestsApi } from './approval-requests';
import { createSecretsApi, type SecretsApi } from './secrets';
import { createSubscriptionsApi, type SubscriptionsApi } from './subscriptions';
import { createTasksApi, type TasksApi } from './tasks';
import { createTelegramApi, type TelegramApi } from './telegram';
import { createToolsApi, type ToolsApi } from './tools';

export { ApiError };

/** The boxes, with how old the list is. The server answers a list from its last read when asking the cloud is slow. */
export interface BoxList {
  boxes: BoxRecord[];
  /** When the server read the list (ms since 1970), or null when it did not say. */
  asOf: number | null;
  /** A new read is running, so the list may be about to change. */
  refreshing: boolean;
  /** The last read failed, so this is the last list that could be read. */
  refreshFailed: boolean;
}

/** How long a first read of the boxes is waited for (the server answers `warming` until it lands) and how often it is asked. */
const WARMING_GIVE_UP_MS = 90_000;
const WARMING_ASK_MS = 1500;

export interface ApiClient {
  /** The one way this dashboard talks to the server: JSON, streams (the terminal), uploads and files. */
  transport: Transport;
  /** The box file browser's calls. */
  files: FilesApi;
  /** Agent runs: the task board, approval requests, their policy and spend limits. */
  tasks: TasksApi;
  secrets: SecretsApi;
  /** Change requests filed on the box (ADR 0041): list, decide with a passkey, deny, and the laptop keys. */
  approvalRequests: ApprovalRequestsApi;
  orch: OrchApi;
  perm: PermApi;
  /** Who can sign in and what each person may do. */
  people: PeopleApi;
  /** The browser on the box: sessions, live view, take-over, recordings and settings. */
  browser: BrowserApi;
  /** Whether coding agents on this box may use the Oz Box tools. */
  agentMcp: AgentMcpApi;
  /** A subscription sign-in an engine reads itself, on the owner's opt-in (ADR 0055). */
  subscriptions: SubscriptionsApi;
  /** Agent memory (notes agents propose and people approve) and reviewed skills. */
  memory: MemoryApi;
  /** Chat with coding agents: the person's transcript, sessions, approvals and linked chats. */
  chat: ChatApi;
  /** Telegram links and delegations (ADR 0050): a passkey opens a pairing window, confirms a link and delegates. */
  telegram: TelegramApi;
  /** The tool catalog, a box's tools, install jobs, agent requests and profiles. */
  tools: ToolsApi;
  /** How the dashboard is reached from outside, and its tunnel. */
  access: AccessApi;
  /** Backups: the policy, each box's snapshots and repository backups. */
  backups: BackupsApi;
  /** The real bill beside the estimate, the drift between them and the forgotten resources. */
  bill: BillApi;
  /** Scheduled runs and signed inbound webhooks. */
  sched: SchedApi;
  /** The IDE and desktop of a box. */
  code: CodeApi;
  /** First-run setup: sign-in check, permissions, region, state bucket, network, security. */
  setup: SetupApi;
  info(signal?: AbortSignal): Promise<Info>;
  /** Asks the provider now (a read-only list of its boxes). A provider that refuses is an ANSWER (`ok: false`), not an error. */
  providerCheck(signal?: AbortSignal): Promise<ProviderCheck>;
  listBoxes(signal?: AbortSignal): Promise<BoxRecord[]>;
  /** The same list with its age. While the server reads the cloud for the first time this keeps waiting instead of failing. */
  listBoxesView(signal?: AbortSignal): Promise<BoxList>;
  getBox(name: string, signal?: AbortSignal): Promise<BoxRecord>;
  metricsNow(name: string, signal?: AbortSignal): Promise<MetricsNow>;
  metricsSeries(name: string, since: Date, step: Step, signal?: AbortSignal): Promise<MetricsSeries>;
  /** Asks for a plan. Never changes anything. */
  plan(operation: Operation, signal?: AbortSignal, options?: { allowUnverifiedImage?: boolean; acceptNewSecretsStore?: boolean }): Promise<PlanResponse>;
  sshEntry(name: string, signal?: AbortSignal): Promise<SshEntry>;
  /** Make the dedicated SSH key on the computer that runs this server (a GET never does), then answer the entry. */
  createSshKey(name: string, signal?: AbortSignal): Promise<SshEntry>;
  usage(range: UsageRange, signal?: AbortSignal): Promise<UsageResponse>;
  suggestions(signal?: AbortSignal): Promise<SuggestionsResponse>;
  getSettings(signal?: AbortSignal): Promise<SettingsResponse>;
  /** Validated and saved by the server. Budgets and defaults are enforced there, not in this browser. */
  saveSettings(settings: Settings, signal?: AbortSignal): Promise<SettingsResponse>;
  selftest(name: string, signal?: AbortSignal): Promise<{ source: MetricsSource; result: SelfTest }>;
  /** The image a box runs and the newest one this account can see. Read-only. */
  boxImage(name: string, signal?: AbortSignal): Promise<BoxImage>;
  incidents(name: string, signal?: AbortSignal): Promise<{ source: MetricsSource; incidents: Incident[] }>;
  getPlan(id: string, signal?: AbortSignal): Promise<PlanResponse>;
  approvals(signal?: AbortSignal): Promise<{ items: Approval[]; /** Plans are kept in the server's memory, not on disk. */ persisted?: boolean; /** How long a plan stays open, in seconds. */ ttl_s?: number }>;
  activity(signal?: AbortSignal): Promise<ActivityResponse>;
  /** The live event stream (EventSource cannot send the token, so it is read with the transport). */
  eventsRequest(): { open(signal: AbortSignal): Promise<Response> };
  /** A picture or file the server holds, read with the sign-in (an <img> cannot send it). */
  fetchBlob(path: string, signal?: AbortSignal): Promise<Blob>;
  cost(signal?: AbortSignal): Promise<CostResponse>;
  refreshPrices(signal?: AbortSignal): Promise<CostResponse>;
  apps(signal?: AbortSignal): Promise<AppsStatus>;
  alerts(signal?: AbortSignal): Promise<{ entries: RecentAlert[] }>;
  /** Write-only: the value is sent once and never read back. */
  putSecret(name: string, value: string, signal?: AbortSignal): Promise<void>;
  deleteSecret(name: string, signal?: AbortSignal): Promise<void>;
  addWebhook(body: { id: string; label: string; url: string; secret: string }, signal?: AbortSignal): Promise<void>;
  removeWebhook(id: string, signal?: AbortSignal): Promise<void>;
  /** With a person, the chat that pairs with this code is linked to them. */
  startPairing(signal?: AbortSignal, person?: string): Promise<{ code: string; expires_in_s: number; bot: string }>;
  /** Link a paired chat to a person, or to nobody with null. */
  linkChat(id: number, person: string | null, signal?: AbortSignal): Promise<void>;
  unpairChat(id: number, signal?: AbortSignal): Promise<void>;
  testAlert(channel: string, signal?: AbortSignal, person?: string): Promise<Delivery>;
  /** Starts a test send and answers at once; read how each channel got on with `testRun`. */
  startTest(channel: string, signal?: AbortSignal, person?: string): Promise<TestRun>;
  testRun(id: string, signal?: AbortSignal): Promise<TestRun>;
  /** The alerts of one day (today when no date is given) with what became of each; of one person, in their time zone, when given. */
  alertSummary(date?: string, signal?: AbortSignal, person?: string): Promise<AlertSummary>;
  /** The public key a browser needs to subscribe to push. */
  pushKey(signal?: AbortSignal): Promise<string>;
  addPushDevice(body: { person: string; label: string; subscription: unknown }, signal?: AbortSignal): Promise<string>;
  removePushDevice(id: string, signal?: AbortSignal): Promise<void>;
  models(signal?: AbortSignal): Promise<ModelsStatus>;
  /** Sends one tiny request to the provider. The caller must have confirmed that it can cost money. */
  testModel(id: string, model: string | null, signal?: AbortSignal): Promise<ModelTestResult>;
  modelsCatalog(signal?: AbortSignal): Promise<ModelsCatalog>;
  /** Asks the provider which models these credentials can use. Free: no prompt is sent. */
  listModels(id: string, signal?: AbortSignal): Promise<ModelListResult>;
  modelPrice(id: string, model: string, signal?: AbortSignal): Promise<ModelPrice | null>;
  modelsUsage(days: number, signal?: AbortSignal): Promise<ModelUsageResponse>;
  localCatalog(signal?: AbortSignal): Promise<LocalCatalog>;
  localAiStatus(box: string, signal?: AbortSignal): Promise<LocalAiStatus>;
  localAiPlan(box: string, runtime: string, model: string, signal?: AbortSignal): Promise<LocalAiPlan>;
  localAiApply(box: string, plan: LocalAiPlan, signal?: AbortSignal, install?: boolean): Promise<{ provider_id: string; endpoint: string; model: string }>;
  /** Applies a plan this server issued. */
  apply(request: ApplyRequest, signal?: AbortSignal): Promise<ApplyResponse>;
  /** On a box's dashboard that manages the fleet: the passkey request for one issued plan (ADR 0040). */
  fleetChallenge(planId: string, signal?: AbortSignal): Promise<FleetChallenge>;
}

/** The most times an apply asks again while the box gets ready (about ten minutes). */
const APPLY_QUIESCE_ASKS = 300;

/** The answer while the box is ending its runs and saving its work, before the change itself is made. */
interface ApplyQuiescing {
  quiescing: true;
  retry_after_s?: number;
}

export interface ClientOptions {
  /** The local access token. Absent behind a sign-in. */
  token?: string;
  /** Behind a sign-in: the session's CSRF token (the cookie goes by itself). */
  csrf?: () => string;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  /** Waits between asks while a box is getting ready to be stopped (a test passes one that does not wait). */
  sleepImpl?: (ms: number) => Promise<void>;
  /** How often a running change is asked about, in ms (default 1000). */
  pollMs?: number;
  /** The clock (a test passes one it moves). */
  nowImpl?: () => number;
}

export function createApiClient(opts: ClientOptions): ApiClient {
  const base = opts.baseUrl ?? '';
  // The one transport: every call below, and the file browser and the terminal, go through it (G7 X7).
  const transport = createTransport({ ...(opts.token ? { token: opts.token } : {}), ...(opts.csrf ? { csrf: opts.csrf } : {}), baseUrl: base, ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}) });
  const request = transport.request;
  const fetchBlob = transport.blob;

  const box = (name: string) => `/v1/boxes/${encodeURIComponent(name)}`;
  const sleep = opts.sleepImpl ?? ((ms: number) => new Promise<void>((done) => setTimeout(done, ms)));
  const nowMs = opts.nowImpl ?? (() => Date.now());

  async function listBoxesView(signal?: AbortSignal): Promise<BoxList> {
    const began = nowMs();
    for (;;) {
      try {
        const { data, headers } = await transport.requestWithHeaders<BoxRecord[]>('GET', '/v1/boxes', signal);
        const asOf = Number(headers.get('X-Ozbox-Boxes-As-Of'));
        return {
          boxes: data,
          asOf: Number.isFinite(asOf) && asOf > 0 ? asOf : null,
          refreshing: headers.get('X-Ozbox-Boxes-Refreshing') === '1',
          refreshFailed: headers.get('X-Ozbox-Boxes-Refresh-Failed') === '1',
        };
      } catch (e) {
        // The first read of the cloud is still running: that is a wait, not a failure.
        if (!(e instanceof ApiError && e.code === 'warming') || nowMs() - began > WARMING_GIVE_UP_MS) throw e;
        await sleep(WARMING_ASK_MS);
        if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
      }
    }
  }

  // The calls that ask a box (usage, self-test, incidents) go a few at a time: see `createLimiter`.
  const perBox = createLimiter(3);
  const askBox = <T>(path: string, signal?: AbortSignal) => perBox(() => request<T>('GET', path, undefined, signal), signal);

  /** `POST /v1/apply` answers at once with a job for a change that takes time; this follows the job to its end, so a caller
   * gets the same answer (or the same error) the change itself gave. Other pages keep answering meanwhile. */
  async function applyAndWait(r: ApplyRequest, signal?: AbortSignal): Promise<ApplyResponse> {
    // A change that stops a box first gets the box ready on the server, which answers `quiescing` until it is done; asking
    // again continues the same change. The server's request loop is never held meanwhile. The change itself then runs as a
    // job, which is followed below.
    const waitReady = opts.sleepImpl ?? ((ms: number) => new Promise<void>((done) => setTimeout(done, ms)));
    let first: ApplyResponse | ApplyStarted | undefined;
    for (let i = 0; i < APPLY_QUIESCE_ASKS && first === undefined; i += 1) {
      const res = await request<ApplyResponse | ApplyStarted | ApplyQuiescing>('POST', '/v1/apply', r, signal);
      if ('quiescing' in res) await waitReady(Math.max(1, res.retry_after_s ?? 2) * 1000);
      else first = res;
    }
    if (first === undefined) {
      throw new ApiError(0, 'quiesce_timeout', 'The box is still getting ready to be stopped. It may already have ended its runs, but it has not been stopped. New runs are refused for a few minutes at most. Check on it, then try again.');
    }
    if (!('job_id' in first)) return first;
    const pause = (ms: number) =>
      new Promise<void>((done, fail) => {
        const id = setTimeout(done, ms);
        signal?.addEventListener('abort', () => {
          clearTimeout(id);
          fail(new DOMException('aborted', 'AbortError'));
        }, { once: true });
      });
    const poll = opts.pollMs ?? 1000;
    for (let wait = Math.min(400, poll); ; wait = poll) {
      await pause(wait);
      const job = await request<ApplyJob>('GET', `/v1/jobs/${encodeURIComponent(first.job_id)}`, undefined, signal);
      if (job.state === 'done' && job.result) return job.result;
      if (job.state === 'failed') {
        const f = job.failure ?? {};
        throw new ApiError(job.status ?? 502, f.code ?? 'error', f.message ?? f.error ?? 'The change failed.', f.fix ?? null, { ...f });
      }
    }
  }

  return {
    fetchBlob,
    transport,
    files: createFilesApi(transport),
    tasks: createTasksApi(request),
    secrets: createSecretsApi(request),
    approvalRequests: createApprovalRequestsApi(request),
    telegram: createTelegramApi(request),
    orch: createOrchApi(request),
    perm: createPermApi(request),
    people: createPeopleApi(request),
    browser: createBrowserApi(request),
    agentMcp: createAgentMcpApi(request),
    subscriptions: createSubscriptionsApi(request),
    memory: createMemoryApi(request),
    chat: createChatApi(request),
    tools: createToolsApi(request),
    access: createAccessApi(request),
    backups: createBackupsApi(request),
    bill: createBillApi(request),
    sched: createSchedApi(request),
    code: createCodeApi(request),
    setup: createSetupApi(request),
    info: (s) => request('GET', '/v1/info', undefined, s),
    providerCheck: (s) => request('GET', '/v1/provider/check', undefined, s),
    listBoxes: async (s) => (await listBoxesView(s)).boxes,
    listBoxesView,
    getBox: (n, s) => request('GET', box(n), undefined, s),
    metricsNow: (n, s) => askBox(`${box(n)}/metrics/now`, s),
    metricsSeries: (n, since, step, s) =>
      request('GET', `${box(n)}/metrics?since=${encodeURIComponent(since.toISOString())}&step=${step}`, undefined, s),
    sshEntry: (n, s) => request('GET', `${box(n)}/ssh`, undefined, s),
    createSshKey: (n, s) => request('POST', `${box(n)}/ssh`, {}, s),
    getPlan: (id, s) => request('GET', `/v1/plans/${encodeURIComponent(id)}`, undefined, s),
    approvals: (s) => request('GET', '/v1/approvals', undefined, s),
    activity: (s) => request('GET', '/v1/activity', undefined, s),
    eventsRequest: () => ({ open: (signal) => transport.send('GET', '/v1/events', { accept: 'text/event-stream', signal }) }),
    usage: (r, s) => request('GET', `/v1/usage?range=${r}`, undefined, s),
    suggestions: (s) => request('GET', '/v1/suggestions', undefined, s),
    getSettings: (s) => request('GET', '/v1/settings', undefined, s),
    saveSettings: (v, s) => request('PUT', '/v1/settings', v, s),
    selftest: (n, s) => askBox(`${box(n)}/selftest`, s),
    boxImage: (n, s) => request('GET', `${box(n)}/image`, undefined, s),
    incidents: (n, s) => askBox(`${box(n)}/incidents`, s),
    plan: (operation, s, o) =>
      request(
        'POST',
        '/v1/plans',
        { operation, ...(o?.allowUnverifiedImage ? { allow_unverified_image: true } : {}), ...(o?.acceptNewSecretsStore ? { accept_new_secrets_store: true } : {}) },
        s,
      ),
    apply: (r, s) => applyAndWait(r, s),
    fleetChallenge: (id, s) => request('POST', `/v1/fleet/plans/${encodeURIComponent(id)}/challenge`, {}, s),
    cost: (s) => request('GET', '/v1/cost', undefined, s),
    refreshPrices: (s) => request('POST', '/v1/cost/refresh', {}, s),
    apps: (s) => request('GET', '/v1/apps', undefined, s),
    alerts: (s) => request('GET', '/v1/alerts', undefined, s),
    putSecret: async (n, value, s) => {
      await request('PUT', `/v1/secrets/${encodeURIComponent(n)}`, { value }, s);
    },
    deleteSecret: async (n, s) => {
      await request('DELETE', `/v1/secrets/${encodeURIComponent(n)}`, undefined, s);
    },
    addWebhook: async (b, s) => {
      await request('POST', '/v1/apps/webhooks', b, s);
    },
    removeWebhook: async (id, s) => {
      await request('DELETE', `/v1/apps/webhooks/${encodeURIComponent(id)}`, undefined, s);
    },
    startPairing: (s, person) => request('POST', '/v1/apps/telegram/pairing', person ? { person } : {}, s),
    linkChat: async (id, person, s) => {
      await request('PUT', `/v1/apps/telegram/chats/${id}`, { person }, s);
    },
    unpairChat: async (id, s) => {
      await request('DELETE', `/v1/apps/telegram/chats/${id}`, undefined, s);
    },
    testAlert: async (channel, s, person) =>
      (await request<{ delivery: Delivery }>('POST', '/v1/alerts/test', person ? { channel, person } : { channel }, s)).delivery,
    startTest: (channel, s, person) => request('POST', '/v1/alerts/test', person ? { channel, person, async: true } : { channel, async: true }, s),
    testRun: (id, s) => request('GET', `/v1/alerts/tests/${encodeURIComponent(id)}`, undefined, s),
    alertSummary: (date, s, person) => request('GET', `/v1/alerts/summary${summaryQuery(date, person)}`, undefined, s),
    pushKey: async (s) => (await request<{ public_key: string }>('GET', '/v1/push/key', undefined, s)).public_key,
    addPushDevice: async (body, s) => (await request<{ id: string }>('POST', '/v1/push/devices', body, s)).id,
    removePushDevice: async (id, s) => {
      await request('DELETE', `/v1/push/devices/${encodeURIComponent(id)}`, undefined, s);
    },
    models: (s) => request('GET', '/v1/models', undefined, s),
    testModel: async (id, model, s) =>
      (await request<{ result: ModelTestResult }>('POST', `/v1/models/${encodeURIComponent(id)}/test`, model ? { confirm: true, model } : { confirm: true }, s)).result,
    modelsCatalog: (s) => request('GET', '/v1/models/catalog', undefined, s),
    listModels: async (id, s) => (await request<{ result: ModelListResult }>('POST', `/v1/models/${encodeURIComponent(id)}/list`, {}, s)).result,
    modelPrice: async (id, model, s) => (await request<{ price: ModelPrice | null }>('GET', `/v1/models/${encodeURIComponent(id)}/price?model=${encodeURIComponent(model)}`, undefined, s)).price,
    modelsUsage: (days, s) => request('GET', `/v1/models/usage?days=${days}`, undefined, s),
    localCatalog: (s) => request('GET', '/v1/models/local', undefined, s),
    localAiStatus: (box, s) => request('GET', `/v1/boxes/${encodeURIComponent(box)}/local-ai`, undefined, s),
    localAiPlan: async (box, runtime, model, s) => (await request<{ plan: LocalAiPlan }>('POST', `/v1/boxes/${encodeURIComponent(box)}/local-ai/plan`, { runtime, model }, s)).plan,
    localAiApply: (box, plan, s, install) => request('POST', `/v1/boxes/${encodeURIComponent(box)}/local-ai/apply`, { runtime: plan.runtime, model: plan.model, plan_hash: plan.hash, confirm: true, ...(install ? { install: true } : {}) }, s),
  };
}
