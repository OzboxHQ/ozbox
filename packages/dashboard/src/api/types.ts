import type { AlertOutcome, OutcomeStatus } from './alert-types';
import type { ChannelsStatus, EmailProvider, RoutingConfig, SmsConfig, SmtpConfig, WhatsappConfig } from './channel-types';
// These types mirror the JSON that `ozbox --json` and `ozbox serve` produce (crates/ozbox-core).

export type GpuKind = 'Small' | 'Large';
/** `"XS"`..`"XXL"`, or `{ "Gpu": "Small" | "Large" }`. */
export type Size = 'XS' | 'S' | 'M' | 'L' | 'XL' | 'XXL' | { Gpu: GpuKind };

export type BoxState =
  | 'creating'
  | 'running'
  | 'pausing'
  | 'paused'
  | 'resuming'
  | 'resizing'
  | 'destroying'
  /** The machine was removed in the middle of an upgrade; /work is kept. Finishing the upgrade (or destroying the box) is all that acts on it. */
  | 'instance_missing'
  | 'unknown';

export interface BoxSpec {
  name: string;
  size: Size;
  work_disk_gb: number;
  image: string | null;
  region: string | null;
  from_snapshot: string | null;
  labels: Record<string, string>;
}

export interface BoxRecord {
  spec: BoxSpec;
  state: BoxState;
  provider: string;
  provider_id: string | null;
  machine_type: string | null;
  snapshots: string[];
  created_at: string | null;
  last_activity_at: string | null;
}

export type Operation =
  | { op: 'create'; spec: BoxSpec }
  | { op: 'pause'; name: string }
  | { op: 'resume'; name: string }
  | { op: 'resize'; name: string; size: Size | null; work_disk_gb: number | null }
  | { op: 'snapshot'; name: string }
  | { op: 'clone'; from: string; to: string; snapshot?: string }
  | { op: 'delete_snapshot'; name: string; snapshot: string }
  | { op: 'restore_work'; name: string; snapshot: string }
  | { op: 'restic_backup'; name: string }
  | { op: 'restic_forget'; name: string; snapshot: string }
  | { op: 'restic_restore'; name: string; snapshot: string; in_place: boolean; from_box?: string }
  | { op: 'delete_old_work'; name: string; volume: string }
  | { op: 'restore_to_new_box'; from: string; to: string; snapshot: string }
  | { op: 'destroy'; name: string; final_snapshot: boolean }
  | { op: 'upgrade'; name: string; image: string };

export type Risk = 'low' | 'medium' | 'high';

export interface Change {
  kind: string;
  description: string;
  risk: Risk;
}

export interface Plan {
  operation: Operation;
  provider: string;
  changes: Change[];
  notes: string[];
  based_on: string;
}

/** `POST /v1/plans`. The plan is only a proposal; nothing has changed. */
export interface PlanResponse {
  plan_id: string;
  plan: Plan;
  box_name: string;
  max_risk: Risk | null;
  noop: boolean;
  requires_confirm_name: boolean;
  expires_in_s: number;
  /** An irreversible change needs the typed box name, and behind a sign-in also a passkey shown within the step-up window. */
  needs_passkey?: boolean;
}

export interface ApplyRequest {
  plan_id: string;
  plan?: Plan;
  confirm_name?: string;
}

/** One thing an upgrade did around the provider's change. */
export interface UpgradeStep {
  outcome: 'done' | 'skipped' | 'failed';
  detail: string;
}

export interface ApplyResponse {
  plan: Plan;
  applied: boolean;
  result: BoxRecord | null;
  /** Present after an upgrade: the image it moved to, and whether the box saved its work in progress first. */
  upgrade?: { image: string; checkpoint: UpgradeStep };
  /** Present after a resize that stopped the box: what its runs and its uncommitted work came to first. */
  quiesce?: UpgradeStep;
}

/** What `POST /v1/apply` answers for a change that runs in the background (create, resume, resize, upgrade, destroy). */
export interface ApplyStarted {
  job_id: string;
  job: ApplyJob;
}

/** A change to a box that the server is carrying out, or has finished. Kept in the server's memory while it runs. */
export interface ApplyJob {
  id: string;
  box: string;
  operation: string;
  started_ms: number;
  state: 'running' | 'done' | 'failed';
  /** With `state: 'done'`: what applying returned. */
  result?: ApplyResponse;
  /** With `state: 'failed'`: the HTTP status and the error body the change would have answered. */
  status?: number;
  failure?: { code?: string; message?: string; error?: string; fix?: string };
}

/** An image a box can be upgraded to. */
export interface ImageInfo {
  id: string;
  release: string | null;
  created: string | null;
  /** False wherever the release signature was not checked by the server; the page never shows it as verified. */
  signature_verified: boolean;
  /** Why the signature is, or is not, verified, in the server's words. Absent in older servers. */
  signature_detail?: string | null;
  /** False only where there are no signed releases to check (the demo provider): then nothing is said about a signature. Absent means true. */
  signature_applicable?: boolean;
}

/** `GET /v1/boxes/{name}/image`. */
export interface BoxImage {
  box_name: string;
  current: string | null;
  latest: ImageInfo | null;
  latest_error: string | null;
  /** Null when the box's current image is not known. */
  upgrade_available: boolean | null;
  /** Set when an earlier upgrade was interrupted; running Upgrade again finishes it. */
  unfinished_upgrade_to: string | null;
}

export interface GpuSample {
  index: number;
  util_pct: number;
  mem_used_bytes: number;
  mem_total_bytes: number;
}

export interface RunUsage {
  id: string;
  cpu_pct: number;
  mem_bytes: number;
  mem_max_bytes: number | null;
}

export interface MetricsSample {
  ts_ms: number;
  cpu_pct: number;
  mem_total_bytes: number;
  mem_available_bytes: number;
  swap_total_bytes: number;
  swap_free_bytes: number;
  psi_cpu_some_avg10: number;
  psi_mem_some_avg10: number;
  psi_io_some_avg10: number;
  disk_total_bytes: number;
  disk_free_bytes: number;
  disk_read_bps: number;
  disk_write_bps: number;
  net_rx_bps: number;
  net_tx_bps: number;
  gpus: GpuSample[];
  runs: RunUsage[];
}

/** Where numbers come from. `simulated` is the fake provider's synthetic usage. */
export type MetricsSource = 'simulated' | 'live';

export interface MetricsNow {
  source: MetricsSource;
  sample: MetricsSample;
}

export type Step = '5s' | '1m' | '1h';

export interface MetricsSeries {
  source: MetricsSource;
  step: Step;
  samples: MetricsSample[];
}

export interface SizeInfo {
  id: string;
  size: Size;
  vcpus: number;
  memory_gb: number;
  gpus: number;
  /** The machine this provider maps the size to and its monthly price from the price table; null where unknown. */
  quote?: { machine_type: string | null; monthly: number | null; currency: string | null };
}

/** Where the boxes the dashboard lists come from: a fleet it manages, this box alone, or made-up demo boxes. */
export interface FleetInfo {
  mode: 'connected' | 'this_box' | 'demo';
  connected: boolean;
  demo: boolean;
  /** Only when the fleet is not connected: the error code the fleet endpoints answer, the sentence, and the guide. */
  code?: string;
  message?: string;
  docs?: string;
}

export interface Info {
  version: string;
  provider: string;
  /** Absent from a server older than this field: treated as a real fleet, as before. */
  fleet?: FleetInfo;
  /** `simulated` for the demo provider, `live` when boxes are asked through their agent. */
  metrics: 'simulated' | 'live';
  secret_store?: string;
  /** True when the server will refuse a loosening (no sign-in, on a box): the review says so up front. */
  loosening_refused?: boolean;
  /** Boxes are reached at https://<name>.<domain>; null when none is configured. */
  domain: string | null;
  capabilities: { resize: string; online_disk_grow: boolean; disk_shrink: boolean; snapshots: boolean };
  sizes: SizeInfo[];
  /** First-run setup: whether the fleet has been set up, and whether a budget and alert channel gate creating. */
  setup?: { available: boolean; completed: boolean; needed: boolean; require_guardrails: boolean };
  /** The server's clock in the person's time zone, with UTC beside it. */
  clock?: { time_zone: string; now: string | null };
}

/** What the provider answered when asked just now. */
export interface ProviderCheck {
  /** `demo` for the simulated provider, `this_box` for a box's own dashboard, `connected` for a real cloud account. */
  mode: 'connected' | 'this_box' | 'demo';
  provider: string;
  /** The provider answered the question. For `demo` this is always true and means nothing: read `mode`. */
  ok: boolean;
  boxes: number | null;
  /** Where the provider looked (regions); empty where it has no such notion. */
  searched: string[];
  error: string | null;
  checked_ms: number;
  took_ms: number;
}

export interface Approval {
  plan_id: string;
  box_name: string;
  verb: string;
  max_risk: Risk | null;
  needs_passkey: boolean;
  changes: number;
  proposed_ms: number;
  expires_in_s: number;
}

export interface ActivityEntry {
  ts_ms: number;
  actor: string;
  action: string;
  box_name: string;
  risk: Risk | null;
  outcome: string;
}

export interface SshRoute {
  /** `aws-ssm` or `cloudflare`. */
  id: string;
  label: string;
  /** What must already be true on this computer for the route to work. */
  requirements: string;
  host: string;
  config: string;
  command: string;
}

export interface SshEntry {
  host: string;
  config: string;
  command: string;
  routes: SshRoute[];
  /** Whether the dedicated key exists on the computer that runs this server; `null` when it cannot say. */
  key_exists?: boolean | null;
}

export type UsageRange = '5s' | '1m' | '1h';

export interface Stat {
  mean: number;
  p95: number;
  max: number;
}

export interface UsagePoint {
  ts_ms: number;
  cpu_pct: number;
  mem_pct: number;
}

export interface BoxUsage {
  name: string;
  size: Size;
  labels: Record<string, string>;
  cpu: Stat | null;
  mem_pct: Stat | null;
  points: UsagePoint[];
  cost_month_est_usd: number | null;
}

export interface UsageGroup {
  value: string;
  boxes: string[];
  cpu_mean: number | null;
  mem_mean: number | null;
  cost_month_est_usd: number | null;
}

export interface RunRollup {
  id: string;
  box_name: string;
  cpu_mean: number;
  mem_peak_bytes: number;
  samples: number;
}

export interface UsageResponse {
  source: MetricsSource;
  range: UsageRange;
  step_ms: number;
  to_ms: number;
  boxes: BoxUsage[];
  /** Running boxes whose agent could not be reached, and why. */
  unreachable?: { name: string; reason: string }[];
  /** Running boxes that answered with no samples yet: not unreachable, just no data yet. */
  no_samples?: { name: string }[];
  /** Boxes shown from their last answer (as_of_ms) because a fresh read has not finished. */
  stale?: { name: string; as_of_ms: number }[];
  by_label: { key: string; groups: UsageGroup[] };
  by_run: RunRollup[];
  fleet: {
    cpu_mean: number | null;
    mem_mean: number | null;
    cost_month_est_usd: number | null;
    /** Where the prices came from: typed in Settings, the provider's price list, or both. */
    cost_source?: 'entered' | 'price_list' | 'mixed' | null;
    /** The cost leaves out a running box that gave nothing to price. */
    cost_partial?: boolean;
  };
}

export type Advice = { kind: 'downsize'; to: Size } | { kind: 'auto_pause'; idle_share: number };

export interface Suggestion {
  box_name: string;
  advice: Advice;
  reason: string;
  /** Estimated saving per month in US dollars; null when the price table has no price. */
  saving_month_usd: number | null;
}

export interface SuggestionItem {
  suggestion: Suggestion;
  /** What applying would plan. It goes through the normal plan, confirm, apply flow. */
  operation: Operation;
}

export interface SuggestionsResponse {
  source: MetricsSource;
  window_days: number;
  items: SuggestionItem[];
  /** Running boxes whose usage could not be read, with the reason. Never folded into an empty list. */
  unreachable?: { name: string; reason: string }[];
  /** Running boxes that have not reported usage yet. */
  no_samples?: { name: string }[];
}

/** What this server did, newest last. `since_start`: it is kept in memory and a restart clears it. */
export interface ActivityResponse {
  source: string;
  since_start: boolean;
  entries: ActivityEntry[];
}

export interface BudgetSettings {
  monthly_usd: number | null;
  alert_50: boolean;
  alert_80: boolean;
  alert_100: boolean;
  quiet_from: string;
  quiet_to: string;
  /** Fixed offset from UTC in minutes; quiet hours are read in this offset. */
  utc_offset_minutes: number;
  in_app: boolean;
  max_running_boxes: number | null;
  size_prices_usd: Record<string, number>;
  /** A day flagged when the bill and the estimate differ by this share and amount (kept as the server has them). */
  drift_alert_pct?: number;
  drift_alert_min_usd?: number;
}

export interface DefaultsSettings {
  size: Size;
  work_disk_gb: number;
  auto_pause_minutes: number;
  always_on: boolean;
  image_channel: 'stable' | 'next';
}

export interface EmailConfig {
  enabled: boolean;
  from: string;
  to: string[];
  provider: EmailProvider;
  reply_to: string;
  region: string | null;
  smtp: SmtpConfig;
  unsubscribed: string[];
}

export interface WebhookConfig {
  id: string;
  label: string;
  enabled: boolean;
  host: string;
}

export interface AppsConfig {
  email: EmailConfig;
  telegram: { enabled: boolean };
  slack: { enabled: boolean };
  webhooks: WebhookConfig[];
  sms: SmsConfig;
  whatsapp: WhatsappConfig;
  discord: { enabled: boolean };
  teams: { enabled: boolean };
  push: { enabled: boolean };
  /** Chat with coding agents from Slack and WhatsApp (Telegram's switch is `telegram`). */
  chat?: { slack: boolean; whatsapp: boolean };
}

export type ModelKind = 'anthropic' | 'openai' | 'openai_compatible' | 'google' | 'bedrock' | 'azure_openai' | 'vertex' | 'openrouter' | 'mistral' | 'groq' | 'together';
export type ModelJob = 'coding' | 'chat' | 'review';

export interface ModelProvider {
  id: string;
  kind: ModelKind;
  label: string;
  base_url: string | null;
  local_endpoint: boolean;
  monthly_cap_usd: number | null;
  /** AWS Bedrock: the region of the person's own account. */
  region: string | null;
  /** Azure OpenAI: the name of the person's own resource. */
  resource: string | null;
  /** A local endpoint that runs on one box. */
  hosted_on: string | null;
}

export interface ModelChoice {
  provider_id: string;
  model: string;
}

export interface EngineModel {
  provider_id: string;
  model: string;
  fallback: ModelChoice | null;
}

export interface ModelPriceOverride {
  input_per_mtok_usd: number;
  output_per_mtok_usd: number;
}

export interface ModelsConfig {
  providers: ModelProvider[];
  defaults: Record<ModelJob, ModelChoice | null>;
  engines: Record<string, EngineModel>;
  box_overrides: Record<string, Record<string, EngineModel>>;
  prices: Record<string, ModelPriceOverride>;
}

export interface ModelKindInfo {
  id: ModelKind;
  own_cloud: boolean;
  key_optional: boolean;
  suggested_models: string[];
}

export interface EngineInfo {
  id: string;
  label: string;
  kinds: ModelKind[];
}

/** Whether an engine can run on a person's own subscription instead of an API key (ADR 0054). Ids, codes and links only. */
export interface SubscriptionInfo {
  id: string;
  engine: string;
  engine_label: string;
  kind: 'subscription';
  /** `opt_in`: the engine reads the sign-in itself, so it is handed to its runs only after the owner turns that on (ADR 0055). */
  status: 'available' | 'opt_in' | 'planned' | 'not_offered';
  sign_in: 'device_code' | 'browser_only' | 'not_documented' | 'none';
  reason: string;
  /** The vendor's own documentation and terms the status rests on. */
  sources: string[];
  checked_on: string;
  /** This row has an opt-in in Settings, Models (ADR 0055). An older server leaves it out. */
  opt_in?: boolean;
}

export interface ModelsCatalog {
  kinds: ModelKindInfo[];
  engines: EngineInfo[];
  price_table_as_of: string;
  /** Added with ADR 0054; an older server leaves it out. */
  subscriptions?: SubscriptionInfo[];
}

/** A price in US dollars per million tokens. Always an estimate. */
export interface ModelPrice {
  input_per_mtok_usd: number;
  output_per_mtok_usd: number;
  origin: 'built_in' | 'entered' | 'local' | 'live';
  source: string;
  as_of: string | null;
  estimate: boolean;
  age_months: number | null;
  /** A condition the price carries, such as the context size it holds for. */
  note?: string;
  /** A live price: when it was read, in milliseconds since 1970. */
  read_at_ms?: number;
}

export interface ModelListResult {
  ok: boolean;
  status: number | null;
  latency_ms: number;
  detail: string;
  models: string[];
  priced: { id: string; price: ModelPrice | null }[];
}

export interface UsageTotals {
  input_tokens: number;
  output_tokens: number;
  cached_input_tokens: number;
  calls: number;
  est_cost_usd: number;
  unpriced_calls: number;
}

export interface UsageRow extends UsageTotals {
  key: string;
}

export interface ModelUsageSummary {
  days: number;
  estimate: boolean;
  total: UsageTotals;
  by_day: UsageRow[];
  by_provider: UsageRow[];
  by_model: UsageRow[];
  by_box: UsageRow[];
  by_engine: UsageRow[];
}

export interface ModelUsageResponse {
  usage: ModelUsageSummary;
  caps: { provider_id: string; cap_usd: number; spent_usd: number; reached: boolean }[];
  recorded: boolean;
  note: string;
}

export interface LocalModelInfo {
  runtime: 'ollama' | 'vllm';
  id: string;
  label: string;
  download_gb: number;
  gpu_gb: number;
}

export interface LocalCatalog {
  estimate: boolean;
  runtimes: { id: 'ollama' | 'vllm'; tool_id: string; port: number }[];
  models: LocalModelInfo[];
  registered: { id: string; label: string; hosted_on: string | null; base_url: string | null }[];
}

export interface LocalAiStatus {
  /** `simulated` when this server runs the demo provider: the GPUs, runtimes and downloads are made up. Absent from an older server. */
  source?: MetricsSource;
  box: string;
  gpus: number;
  gpu_memory_gb: number;
  work_disk_gb: number;
  runtimes: { id: 'ollama' | 'vllm'; tool_id: string; installed: boolean; models: string[]; endpoint: string; registered: boolean }[];
}

export interface LocalAiPlan {
  box_name: string;
  runtime: 'ollama' | 'vllm';
  model: string;
  label: string;
  download_gb: number;
  gpu_gb_needed: number;
  gpu_gb_available: number;
  /** `gpu`, or `cpu` on a box without a GPU (Ollama only). */
  compute: 'gpu' | 'cpu';
  /** The memory the model needs on this kind of box (GPU memory, or RAM without a GPU), and what the box has. */
  memory_gb_needed: number;
  memory_gb_available: number;
  work_disk_gb: number;
  disk_free_gb: number | null;
  fits_disk: boolean;
  fits_gpu: boolean;
  runtime_installed: boolean;
  install_tool: string | null;
  /** Only the runtime is missing: one click installs it, then downloads the model. */
  install_only: boolean;
  can_apply: boolean;
  blocked: string | null;
  endpoint: string;
  provider_id: string;
  estimate: boolean;
  hash: string;
}

/** Where the person is. Quiet hours and schedules follow the time zone, daylight saving included. */
export interface LocaleSettings {
  /** ISO 3166-1 alpha-2, or null when not chosen. */
  country_code: string | null;
  /** An IANA name such as Africa/Lagos, or null (UTC). */
  time_zone: string | null;
}

export interface Settings {
  locale: LocaleSettings;
  budget: BudgetSettings;
  defaults: DefaultsSettings;
  apps: AppsConfig;
  models: ModelsConfig;
  routing: RoutingConfig;
}

export interface PriceInfo {
  provider: string;
  source: string;
  region: string;
  currency: string;
  fetched_at_ms: number;
  age_s: number;
  stale: boolean;
}

export interface CostBox {
  name: string;
  state: BoxState;
  currency: string | null;
  source: 'entered' | 'price_list' | null;
  machine_hourly: number | null;
  run_rate_month: number | null;
  month_to_date: number | null;
  snapshots_unpriced: number;
}

/** An estimate from public prices and watched hours. Never the bill. */
export interface CostResponse {
  basis: 'estimate';
  note: string;
  prices: PriceInfo | null;
  price_error: string | null;
  entered_prices_used: boolean;
  currency: string | null;
  fleet: {
    run_rate_month: number | null;
    month_to_date: number | null;
    month_to_date_currency: string | null;
    observed_since_ms: number | null;
    unpriced: string[];
  };
  boxes: CostBox[];
}

export interface Delivery {
  channel: string;
  ok: boolean;
  detail: string;
  /** Whose routing rule sent it. */
  person?: string;
  /** More than 1 means it was retried after a failure. */
  attempts?: number;
}

export interface RecentAlert {
  ts_ms: number;
  key: string;
  kind: string;
  severity: 'normal' | 'urgent';
  box_name: string | null;
  title: string;
  body: string;
  deliveries: Delivery[];
  /** The alert as a whole. Absent on alerts recorded before outcomes were kept. */
  outcome?: OutcomeStatus;
  /** What the routing rules decided for each person. */
  outcomes?: AlertOutcome[];
}

export interface TelegramChat {
  id: number;
  name: string;
  /** The person (a key of routing.people) this chat belongs to; absent when it is linked to nobody. */
  person?: string | null;
}

export interface AppsStatus extends ChannelsStatus {
  store: string;
  /** False when the dashboard has no public address, so a chat app is sent words and no link. */
  public_url_set: boolean;
  email: { enabled: boolean; configured: boolean; provider: EmailProvider; reply_to: string; unsubscribed: number };
  telegram: {
    enabled: boolean;
    configured: boolean;
    bot: string | null;
    /** True when this "Telegram" is the server's local stand-in bot, not a real chat. */
    demo: boolean;
    chats: TelegramChat[];
    pairing: { active: boolean; expires_in_s: number } | null;
  };
  slack: { enabled: boolean; configured: boolean };
  webhooks: { id: string; label: string; host: string; enabled: boolean; configured: boolean }[];
  quiet_hours: { from: string; to: string; utc_offset_minutes: number; time_zone?: string | null };
}

export interface ModelsStatus {
  store: string;
  providers: { id: string; configured: boolean }[];
  spend_note: string;
}

export interface ModelTestResult {
  ok: boolean;
  status: number | null;
  latency_ms: number;
  detail: string;
}

export interface SettingsResponse {
  settings: Settings;
  /** False when the server has no settings file and keeps changes in memory only. */
  persisted: boolean;
}

export type CheckOutcome = { outcome: 'pass' } | { outcome: 'fail'; step: string; reason: string } | { outcome: 'unknown'; reason: string };
export type SelfTestCheck = { name: string } & CheckOutcome;

export interface SelfTest {
  ts_ms: number;
  ok: boolean;
  all_verified: boolean;
  checks: SelfTestCheck[];
}

export interface Incident {
  ts_ms: number;
  kind: string;
  detail: string;
}
