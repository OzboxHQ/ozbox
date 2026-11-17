import type { BoxRecord, EngineInfo, ModelKind, ModelPrice, ModelProvider, SubscriptionInfo, UsageRow } from '../api/types';
import type { MessageKey } from './i18n';

/** The provider types in the order a person picks from them. */
export const KINDS: ModelKind[] = ['anthropic', 'openai', 'google', 'bedrock', 'azure_openai', 'vertex', 'openrouter', 'mistral', 'groq', 'together', 'openai_compatible'];

export const KIND_LABEL: Record<ModelKind, MessageKey> = {
  anthropic: 'models.kind_anthropic',
  openai: 'models.kind_openai',
  openai_compatible: 'models.kind_compatible',
  google: 'models.kind_google',
  bedrock: 'models.kind_bedrock',
  azure_openai: 'models.kind_azure_openai',
  vertex: 'models.kind_vertex',
  openrouter: 'models.kind_openrouter',
  mistral: 'models.kind_mistral',
  groq: 'models.kind_groq',
  together: 'models.kind_together',
};

/** The set-up steps for each provider type, as catalogue keys. */
export const GUIDE_STEPS: Record<ModelKind, MessageKey[]> = {
  anthropic: ['models.guide_anthropic_1', 'models.guide_anthropic_2', 'models.guide_anthropic_3'],
  openai: ['models.guide_openai_1', 'models.guide_openai_2', 'models.guide_openai_3'],
  google: ['models.guide_google_1', 'models.guide_google_2', 'models.guide_google_3'],
  bedrock: ['models.guide_bedrock_1', 'models.guide_bedrock_2', 'models.guide_bedrock_3', 'models.guide_bedrock_4'],
  azure_openai: ['models.guide_azure_openai_1', 'models.guide_azure_openai_2', 'models.guide_azure_openai_3', 'models.guide_azure_openai_4'],
  vertex: ['models.guide_vertex_1', 'models.guide_vertex_2', 'models.guide_vertex_3', 'models.guide_vertex_4'],
  openrouter: ['models.guide_openrouter_1', 'models.guide_openrouter_2', 'models.guide_openrouter_3'],
  mistral: ['models.guide_mistral_1', 'models.guide_mistral_2', 'models.guide_mistral_3'],
  groq: ['models.guide_groq_1', 'models.guide_groq_2', 'models.guide_groq_3'],
  together: ['models.guide_together_1', 'models.guide_together_2', 'models.guide_together_3'],
  openai_compatible: ['models.guide_openai_compatible_1', 'models.guide_openai_compatible_2', 'models.guide_openai_compatible_3', 'models.guide_openai_compatible_4'],
};

/** Which extra fields a provider type takes. */
export function fieldsFor(kind: ModelKind): { region: boolean; resource: boolean; baseUrl: boolean; keyOptional: boolean; ownCloud: boolean } {
  return {
    region: kind === 'bedrock',
    resource: kind === 'azure_openai',
    baseUrl: kind === 'openai_compatible',
    keyOptional: kind === 'openai_compatible',
    ownCloud: kind === 'bedrock' || kind === 'azure_openai' || kind === 'vertex',
  };
}

export const REGION_RE = /^[a-z]{2}(-[a-z0-9]+){1,3}-\d$/;
export const RESOURCE_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
export const MODEL_RE = /^[A-Za-z0-9._:/-]{1,100}$/;

/** A price in US dollars per million tokens: two decimals, or none for a whole number. */
export function perMtok(n: number): string {
  return n % 1 === 0 ? n.toFixed(0) : n.toFixed(2);
}

export function usd(n: number): string {
  return n === 0 ? '0.00' : n < 0.01 ? '<0.01' : n.toFixed(2);
}

/** A built-in price (not a live one, which was just read) older than this many months is called old. */
export const STALE_MONTHS = 6;

export function priceIsStale(p: ModelPrice | null): boolean {
  return !!p && p.origin === 'built_in' && p.age_months !== null && p.age_months >= STALE_MONTHS;
}

/** Providers an engine can use, in the order the person set them up. */
export function providersFor(engine: EngineInfo | undefined, providers: ModelProvider[]): ModelProvider[] {
  return engine ? providers.filter((p) => engine.kinds.includes(p.kind)) : [];
}

export function tokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

/** The height of a day's bar, 0-100, against the busiest day (by cost, else by tokens). */
export function barPercent(row: UsageRow, rows: UsageRow[]): number {
  const max = Math.max(...rows.map((r) => r.est_cost_usd), 0);
  const maxTok = Math.max(...rows.map((r) => r.input_tokens + r.output_tokens), 0);
  if (max > 0) return Math.round((row.est_cost_usd / max) * 100);
  return maxTok > 0 ? Math.round(((row.input_tokens + row.output_tokens) / maxTok) * 100) : 0;
}

/** Boxes that have a GPU: their size is a `{ Gpu: ... }` object. */
export function gpuBoxes(boxes: BoxRecord[]): BoxRecord[] {
  return boxes.filter((b) => typeof b.spec.size === 'object');
}

/** The status of a subscription sign-in (ADR 0054), as catalogue keys. */
export const SUB_STATUS_LABEL: Record<SubscriptionInfo['status'], MessageKey> = {
  available: 'models.sub_status_available',
  opt_in: 'models.sub_status_opt_in',
  planned: 'models.sub_status_planned',
  not_offered: 'models.sub_status_not_offered',
};

export const SUB_SIGNIN_LABEL: Record<SubscriptionInfo['sign_in'], MessageKey> = {
  device_code: 'models.sub_signin_device_code',
  browser_only: 'models.sub_signin_browser_only',
  not_documented: 'models.sub_signin_not_documented',
  none: 'models.sub_signin_none',
};

function inCatalogue(key: string, has: (k: string) => boolean): MessageKey | null {
  return has(key) ? (key as MessageKey) : null;
}

/**
 * The rows to show, each with its message keys. A row the catalogue has no words for (a newer server) is left out rather
 * than shown without its reason: a status with no explanation could read as permission. Only https vendor links are kept.
 */
export function subscriptionRows(subs: SubscriptionInfo[] | undefined, has: (k: string) => boolean): { sub: SubscriptionInfo; plan: MessageKey; reason: MessageKey; links: string[] }[] {
  const out: { sub: SubscriptionInfo; plan: MessageKey; reason: MessageKey; links: string[] }[] = [];
  for (const sub of subs ?? []) {
    const plan = inCatalogue(`models.sub_plan_${sub.id.replace(/-/g, "_")}`, has);
    const reason = inCatalogue(`models.sub_reason_${sub.reason}`, has);
    if (!plan || !reason || !(sub.status in SUB_STATUS_LABEL)) continue;
    const links = sub.sources.filter((u) => {
      try {
        return new URL(u).protocol === 'https:';
      } catch {
        return false;
      }
    });
    out.push({ sub, plan, reason, links });
  }
  return out;
}

/** The typed confirmation for a subscription opt-in (ADR 0055): exactly the word shown, nothing else. */
export function optInConfirmed(typed: string, word: string): boolean {
  return word.length > 0 && typed === word;
}

/** The words for why a sign-in failed; an unknown reason falls back to the general one. */
export function signInFailedKey(reason: string | undefined, has: (k: string) => boolean): MessageKey {
  const k = `models.signin_failed_${reason ?? 'failed'}`;
  return (has(k) ? k : 'models.signin_failed_failed') as MessageKey;
}

/** Only an https link on the vendor's own host is shown as the sign-in page. */
export function vendorLink(link: string | undefined, hosts: readonly string[]): string | null {
  if (!link) return null;
  try {
    const u = new URL(link);
    const ok = u.protocol === 'https:' && hosts.some((h) => u.hostname === h || u.hostname.endsWith(`.${h}`));
    return ok ? u.toString() : null;
  } catch {
    return null;
  }
}
