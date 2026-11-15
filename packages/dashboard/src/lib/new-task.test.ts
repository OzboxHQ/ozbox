import { describe, expect, it } from 'vitest';

import type { EngineInfo, ModelProvider } from '../api/types';
import { draftToTask, providersForRun, settingsEngineId, type Draft } from './new-task';

const draft = (over: Partial<Draft> = {}): Draft => ({
  box: 'alpha', engine: 'claude-code', prompt: 'fix the parser', skill: '', repo: '', branch: '', minutes: '', dollars: '', tokens: '',
  pr: false, alert: false, provider: '', model: '', ...over,
});

const provider = (id: string, kind: ModelProvider['kind']): ModelProvider => ({
  id, kind, label: id, base_url: null, local_endpoint: false, monthly_cap_usd: null, region: null, resource: null, hosted_on: null,
});

const engines: EngineInfo[] = [
  { id: 'claude-code', label: 'Claude Code', kinds: ['anthropic', 'bedrock', 'vertex'] },
  { id: 'codex', label: 'Codex CLI', kinds: ['openai', 'openai_compatible'] },
];

describe('a new task with a model for this run', () => {
  it('sends no model when the engine keeps its own choice', () => {
    const r = draftToTask(draft());
    expect(r.ok && r.value.model).toBeUndefined();
    // a model typed and then the provider put back to the default is not a choice either
    const r2 = draftToTask(draft({ model: 'claude-sonnet-4-5' }));
    expect(r2.ok && r2.value.model).toBeUndefined();
  });

  it('sends the provider and the model together', () => {
    const r = draftToTask(draft({ provider: 'anth', model: '  claude-sonnet-4-5 ' }));
    expect(r.ok && r.value.model).toEqual({ provider_id: 'anth', model: 'claude-sonnet-4-5' });
  });

  it('refuses a provider with no model, and a model with characters a name never has', () => {
    const none = draftToTask(draft({ provider: 'anth', model: '  ' }));
    expect(!none.ok && none.errors.model).toBe('tasks.new_err_model');
    for (const bad of ['a b', 'x;y', '$(id)', 'a'.repeat(101)]) {
      const r = draftToTask(draft({ provider: 'anth', model: bad }));
      expect(!r.ok && r.errors.model, bad).toBe('tasks.new_err_model_chars');
    }
    for (const good of ['claude-sonnet-4-5', 'gpt-4o', 'qwen2.5-coder:7b', 'Qwen/Qwen2.5-Coder-7B-Instruct', 'us.anthropic.claude-sonnet-4-5-v1:0']) {
      expect(draftToTask(draft({ provider: 'x', model: good })).ok, good).toBe(true);
    }
  });

  it('keeps the other fields it had', () => {
    const r = draftToTask(draft({ provider: 'anth', model: 'm', minutes: '30', dollars: '5', pr: true, repo: 'web' }));
    expect(r.ok && r.value).toMatchObject({ engine: 'claude-code', box: 'alpha', caps: { max_runtime_s: 1800, max_spend_cents: 500 }, deliver_to: ['pull_request'], repo: 'web', model: { provider_id: 'anth', model: 'm' } });
  });
});

describe('which providers a run may pick', () => {
  const all = [provider('anth', 'anthropic'), provider('oa', 'openai'), provider('bed', 'bedrock'), provider('local', 'openai_compatible')];

  it('offers only the kinds the engine can speak to, in the order they were set up', () => {
    expect(providersForRun(engines, 'claude-code', all).map((p) => p.id)).toEqual(['anth', 'bed']);
    expect(providersForRun(engines, 'codex', all).map((p) => p.id)).toEqual(['oa', 'local']);
  });

  it('treats the demo engine as Claude Code, as the server does', () => {
    expect(settingsEngineId('fake')).toBe('claude-code');
    expect(providersForRun(engines, 'fake', all).map((p) => p.id)).toEqual(['anth', 'bed']);
  });

  it('offers nothing for an engine it does not know', () => {
    expect(providersForRun(engines, 'nope', all)).toEqual([]);
    expect(providersForRun([], 'claude-code', all)).toEqual([]);
  });
});
