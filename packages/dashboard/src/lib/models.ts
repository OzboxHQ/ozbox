import type { BoxRecord, EngineInfo, ModelKind, ModelPrice, ModelProvider, UsageRow } from '../api/types';
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
