import type { ModelProvider, EngineInfo } from '../api/types';
import type { DeliverTo, NewTask } from '../api/tasks';
import { MODEL_RE } from './models';
import { parseCount, parseDollars } from './tasks';

/** What the New task sheet holds while it is being filled in. */
export interface Draft {
  box: string;
  engine: string;
  prompt: string;
  skill: string;
  repo: string;
  branch: string;
  minutes: string;
  dollars: string;
  tokens: string;
  pr: boolean;
  alert: boolean;
  /** A provider for this run only; empty means the engine's own choice (Settings -> Models). */
  provider: string;
  model: string;
}

export type Errors = Partial<Record<keyof Draft, string>>;

/** The demo engine reads the settings of Claude Code, like the server does. */
export function settingsEngineId(engine: string): string {
  return engine === 'fake' ? 'claude-code' : engine;
}

/** The providers a person may pick for a run on this engine: only the kinds the engine can speak to. */
export function providersForRun(engines: EngineInfo[], engine: string, providers: ModelProvider[]): ModelProvider[] {
  const info = engines.find((e) => e.id === settingsEngineId(engine));
  return info ? providers.filter((p) => info.kinds.includes(p.kind)) : [];
}

/** The request a draft makes, or what is wrong with it (catalogue keys). */
export function draftToTask(d: Draft): { ok: true; value: NewTask } | { ok: false; errors: Errors } {
  const errors: Errors = {};
  if (d.box === '') errors.box = 'tasks.new_err_box';
  if (d.prompt.trim() === '' && d.skill.trim() === '') errors.prompt = 'tasks.new_err_prompt';
  const caps: NonNullable<NewTask['caps']> = {};
  if (d.minutes.trim() !== '') {
    const m = parseCount(d.minutes, 5);
    if (m === null || m === 0) errors.minutes = 'tasks.new_err_number';
    else caps.max_runtime_s = m * 60;
  }
  if (d.dollars.trim() !== '') {
    const c = parseDollars(d.dollars);
    if (c === null || c === 0) errors.dollars = 'tasks.new_err_dollars';
    else caps.max_spend_cents = c;
  }
  if (d.tokens.trim() !== '') {
    const k = parseCount(d.tokens);
    if (k === null || k === 0) errors.tokens = 'tasks.new_err_number';
    else caps.max_tokens = k;
  }
  const model = d.model.trim();
  if (d.provider !== '') {
    if (model === '') errors.model = 'tasks.new_err_model';
    else if (!MODEL_RE.test(model)) errors.model = 'tasks.new_err_model_chars';
  }
  if (Object.keys(errors).length > 0) return { ok: false, errors };
  const deliver: DeliverTo[] = [];
  if (d.pr) deliver.push('pull_request');
  if (d.alert) deliver.push('alert');
  const value: NewTask = { engine: d.engine, prompt: d.prompt.trim(), box: d.box };
  if (d.skill.trim()) value.skill = d.skill.trim();
  if (d.repo.trim()) value.repo = d.repo.trim();
  if (d.branch.trim()) value.branch = d.branch.trim();
  if (Object.keys(caps).length > 0) value.caps = caps;
  if (deliver.length > 0) value.deliver_to = deliver;
  // a model is sent only together with the provider it belongs to; a model with no provider is not a choice
  if (d.provider !== '') value.model = { provider_id: d.provider, model };
  return { ok: true, value };
}
