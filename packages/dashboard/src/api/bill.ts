// The real bill beside the estimate, the drift between them, the budget on the real figure, and the resources in the
// account that nothing uses. Shapes are the server's `/v1/cost/bill` and `/v1/cost/orphans` answers; fields are only
// ever added, never renamed.

export type BillProblemKind = 'tag_not_active' | 'access_denied' | 'not_enabled' | 'unsupported' | 'other';

export interface BillProblem {
  problem: BillProblemKind;
  /** Plain English from the server; never a credential. */
  message: string;
}

export type CauseKind =
  | 'untagged_box'
  | 'unmodelled_service'
  | 'unmodelled_in_ec2_other'
  | 'price_changed'
  | 'partly_watched'
  | 'discount_or_spot'
  | 'not_in_bill';

export interface DriftRow {
  date: string;
  /** `null` is spend that carries the managed tag but no box name. */
  box_name: string | null;
  estimate: number;
  real: number;
  diff: number;
  pct: number;
  causes: { kind: CauseKind; detail: string | null }[];
}

export interface DayTotal {
  date: string;
  /** The provider has not finished this day: shown, never compared. */
  partial: boolean;
  estimate: number | null;
  real: number | null;
}

export interface BoxTotal {
  box_name: string | null;
  estimate: number;
  real: number;
  diff: number;
  days: number;
}

export interface ServiceTotal {
  service: string;
  real: number;
}

export interface Reconciliation {
  currency: string;
  month: string;
  through: string | null;
  days: DayTotal[];
  boxes: BoxTotal[];
  services: ServiceTotal[];
  month_real: number;
  month_estimate: number;
  drift: DriftRow[];
}

export type BudgetBasis = 'bill' | 'estimate';

export interface BudgetFigure {
  monthly_usd: number | null;
  spent: number | null;
  currency: string | null;
  basis: BudgetBasis | null;
  real_through: string | null;
  percent: number | null;
  thresholds: { percent: number; on: boolean }[];
  fired: number[];
}

export interface ModelSpend {
  /** Always an estimate from token counts: no provider reports its own bill here. */
  basis: 'estimate';
  currency: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  est_cost_usd: number;
  unpriced_calls: number;
  by_model: { model: string; calls: number; est_cost_usd: number }[];
}

export interface BillResponse {
  provider: string;
  demo: boolean;
  month: string;
  basis: 'bill' | 'estimate';
  source: string | null;
  currency: string | null;
  fetched_at_ms: number | null;
  age_s: number | null;
  stale: boolean;
  problem: BillProblem | null;
  refreshing: boolean;
  last_attempt_ms: number | null;
  needs: { cost_allocation_tag: string; box_tag: string; lag_hours: number };
  drift_threshold: { percent: number; min: number };
  reconciliation: Reconciliation | null;
  estimate_boxes: { box: string; estimate: number; currency: string | null }[];
  budget: BudgetFigure;
  model_spend: ModelSpend;
}

export type OrphanKind = 'instance' | 'volume' | 'snapshot' | 'image';

export type OrphanReason =
  | 'no_managed_tag'
  | 'retired_work_disk'
  | 'work_disk_no_box'
  | 'unattached_volume'
  | 'snapshot_no_box'
  | 'snapshot_box_gone'
  | 'unsigned_image'
  | 'failed_image';

export interface OrphanItem {
  id: string;
  kind: OrphanKind;
  region: string;
  /** `untagged` looks like ours but is not tagged; `unused` is ours and no box uses it. */
  class: 'untagged' | 'unused';
  reason: OrphanReason;
  box_name: string | null;
  name: string | null;
  size_gb: number | null;
  created: string | null;
  month_cost: number | null;
  /** A snapshot is billed for what changed, so its figure is the most it can cost. */
  cost_is_most: boolean;
  deletable: boolean;
}

export interface OrphanScan {
  scanned_at_ms: number;
  regions: string[];
  currency: string | null;
  items: OrphanItem[];
  error: string | null;
  unsupported: boolean;
}

export interface ItemResult {
  id: string;
  ok: boolean;
  message: string | null;
}

export interface OrphansResponse {
  scan: OrphanScan | null;
  scanning: boolean;
  deleting: boolean;
  last_delete: { plan_id: string; at_ms: number; results: ItemResult[] } | null;
  month_cost: number | null;
}

export interface OrphanPlanResponse {
  plan_id: string;
  expires_in_s: number;
  risk: 'high';
  /** What must be typed to apply: the id for one resource, else `delete-N`. */
  requires_confirm_text: string;
  plan: { items: OrphanItem[]; confirm_text: string; month_cost: number | null; currency: string | null; based_on_ms: number };
}

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export interface BillApi {
  bill(signal?: AbortSignal): Promise<BillResponse>;
  /** Reads the provider again (the server refuses it more than every few minutes). */
  refreshBill(signal?: AbortSignal): Promise<BillResponse>;
  orphans(signal?: AbortSignal): Promise<OrphansResponse>;
  scanOrphans(signal?: AbortSignal): Promise<OrphansResponse>;
  planOrphans(ids: string[], signal?: AbortSignal): Promise<OrphanPlanResponse>;
  applyOrphans(planId: string, confirmText: string, signal?: AbortSignal): Promise<{ status: 'deleting'; count: number }>;
}

export function createBillApi(request: Request): BillApi {
  return {
    bill: (s) => request('GET', '/v1/cost/bill', undefined, s),
    refreshBill: (s) => request('POST', '/v1/cost/bill/refresh', {}, s),
    orphans: (s) => request('GET', '/v1/cost/orphans', undefined, s),
    scanOrphans: (s) => request('POST', '/v1/cost/orphans/scan', {}, s),
    planOrphans: (ids, s) => request('POST', '/v1/cost/orphans/plan', { ids }, s),
    applyOrphans: (planId, confirmText, s) => request('POST', '/v1/cost/orphans/apply', { plan_id: planId, confirm_text: confirmText }, s),
  };
}
