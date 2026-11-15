import type { ApplyResponse, PlanResponse, Size } from '../api/types';
import { validBoxName } from './tools';

/** The "Create a box" wizard as a pure state machine: name, size, region, profile and tools, options, the plan, then a
 * progress view that follows the box from creating to ready. Nothing here reaches the network. */
export type CreateStep = 'name' | 'size' | 'tools' | 'options' | 'review' | 'progress';

export const CREATE_STEPS: CreateStep[] = ['name', 'size', 'tools', 'options', 'review', 'progress'];

export interface CreateForm {
  name: string;
  size: Size;
  diskGb: number;
  region: string;
  profile: string | null;
  tools: string[];
  /** One `key=value` per line. */
  labels: string;
  autoPauseMinutes: number;
  alwaysOn: boolean;
}

export type Stage = 'creating' | 'booting' | 'self_test' | 'ready' | 'failed';

export type Review =
  | { phase: 'none' }
  | { phase: 'planning' }
  | { phase: 'review'; plan: PlanResponse }
  | { phase: 'applying'; plan: PlanResponse }
  /** The plan was refused: the reason is shown with what to do about it. */
  | { phase: 'refused'; code: string; message: string; fix: string | null };

export interface CreateState {
  step: CreateStep;
  form: CreateForm;
  review: Review;
  stage: Stage;
  /** The tools chosen for the box, waiting for its daemon; applied once, automatically. */
  toolsApplied: boolean;
  selfTestPassed: boolean | null;
  problem: string | null;
}

export const MIN_DISK_GB = 20;
export const MAX_DISK_GB = 65536;

export function initialCreate(defaults: { size: Size; diskGb: number; region?: string | null; autoPauseMinutes?: number; alwaysOn?: boolean }): CreateState {
  return {
    step: 'name',
    form: {
      name: '',
      size: defaults.size,
      diskGb: defaults.diskGb,
      region: defaults.region ?? '',
      profile: null,
      tools: [],
      labels: '',
      autoPauseMinutes: defaults.autoPauseMinutes ?? 90,
      alwaysOn: defaults.alwaysOn ?? false,
    },
    review: { phase: 'none' },
    stage: 'creating',
    toolsApplied: false,
    selfTestPassed: null,
    problem: null,
  };
}

export type CreateAction =
  | { type: 'set'; patch: Partial<CreateForm> }
  | { type: 'profile'; name: string | null; tools: string[]; size?: Size; diskGb?: number; alwaysOn?: boolean; autoPauseMinutes?: number }
  | { type: 'next' }
  | { type: 'back' }
  | { type: 'planning' }
  | { type: 'planned'; plan: PlanResponse }
  | { type: 'refused'; code: string; message: string; fix: string | null }
  | { type: 'apply' }
  | { type: 'applied'; response: ApplyResponse }
  | { type: 'failed'; message: string }
  | { type: 'stage'; stage: Stage }
  | { type: 'self_test'; passed: boolean }
  | { type: 'tools_applied' };

/** What stops the name from being used, as a message key; null when it is fine. */
export function nameProblem(name: string, existing: readonly string[]): 'create.name_required' | 'create.name_invalid' | 'create.name_taken' | null {
  if (name === '') return 'create.name_required';
  if (!validBoxName(name)) return 'create.name_invalid';
  if (existing.includes(name)) return 'create.name_taken';
  return null;
}

export function diskProblem(gb: number): boolean {
  return !Number.isInteger(gb) || gb < MIN_DISK_GB || gb > MAX_DISK_GB;
}

/** Parses the label lines. `bad` holds the lines that are not `key=value`. */
export function parseLabels(text: string): { labels: Record<string, string>; bad: string[] } {
  const labels: Record<string, string> = {};
  const bad: string[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const i = line.indexOf('=');
    if (i <= 0 || !/^[A-Za-z0-9_.:/-]{1,64}$/.test(line.slice(0, i).trim())) bad.push(line);
    else labels[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return { labels, bad };
}

export function canContinue(s: CreateState, existing: readonly string[]): boolean {
  switch (s.step) {
    case 'name':
      return nameProblem(s.form.name, existing) === null;
    case 'size':
      return !diskProblem(s.form.diskGb);
    case 'tools':
      return true;
    case 'options':
      return parseLabels(s.form.labels).bad.length === 0;
    case 'review':
      return s.review.phase === 'review' && !s.review.plan.noop;
    case 'progress':
      return false;
  }
}

/** The create request the plan endpoint takes. Labels carry the options the provider understands. */
export function toOperation(f: CreateForm): { op: 'create'; spec: { name: string; size: Size; work_disk_gb: number; image: null; region: string | null; from_snapshot: null; labels: Record<string, string> } } {
  const labels = parseLabels(f.labels).labels;
  // Auto-pause is a fleet default (Settings, Box defaults); only "always on" is a per-box choice.
  if (f.alwaysOn) labels['ozbox-always-on'] = 'true';
  return {
    op: 'create',
    spec: { name: f.name, size: f.size, work_disk_gb: f.diskGb, image: null, region: f.region.trim() === '' ? null : f.region.trim(), from_snapshot: null, labels },
  };
}

export function createReducer(s: CreateState, a: CreateAction): CreateState {
  switch (a.type) {
    case 'set':
      // Any change after the plan was made makes the plan stale. A change that is already being applied is not stale: it
      // runs in the background now, so something that sets the form while it runs (the tool list arriving) must not wipe
      // the review, or its answer would be ignored and the person would never see the box come up.
      return { ...s, form: { ...s.form, ...a.patch }, review: s.review.phase === 'applying' ? s.review : { phase: 'none' }, problem: null };
    case 'profile': {
      const patch: Partial<CreateForm> = { profile: a.name, tools: a.tools };
      if (a.size) patch.size = a.size;
      if (a.diskGb) patch.diskGb = a.diskGb;
      if (a.alwaysOn !== undefined) patch.alwaysOn = a.alwaysOn;
      if (a.autoPauseMinutes) patch.autoPauseMinutes = a.autoPauseMinutes;
      return { ...s, form: { ...s.form, ...patch }, review: { phase: 'none' } };
    }
    case 'next': {
      // The name is checked against existing boxes by the component through canContinue; here only order matters.
      const i = CREATE_STEPS.indexOf(s.step);
      const next = CREATE_STEPS[i + 1];
      return next && s.step !== 'review' && s.step !== 'progress' ? { ...s, step: next, problem: null } : s;
    }
    case 'back': {
      if (s.step === 'progress' || s.review.phase === 'applying') return s;
      const prev = CREATE_STEPS[CREATE_STEPS.indexOf(s.step) - 1];
      return prev ? { ...s, step: prev, review: s.step === 'review' ? { phase: 'none' } : s.review, problem: null } : s;
    }
    case 'planning':
      return { ...s, review: { phase: 'planning' }, problem: null };
    case 'planned':
      return s.review.phase === 'planning' ? { ...s, review: { phase: 'review', plan: a.plan } } : s;
    case 'refused':
      return { ...s, review: { phase: 'refused', code: a.code, message: a.message, fix: a.fix } };
    case 'apply':
      // Only a plan on screen, and one that changes something, can be applied.
      return s.review.phase === 'review' && !s.review.plan.noop ? { ...s, review: { phase: 'applying', plan: s.review.plan } } : s;
    case 'applied':
      return s.review.phase === 'applying' && a.response.applied ? { ...s, step: 'progress', stage: 'booting', review: { phase: 'none' } } : s;
    case 'failed':
      return { ...s, review: s.review.phase === 'applying' ? { phase: 'review', plan: s.review.plan } : s.review, problem: a.message };
    case 'stage':
      return s.step === 'progress' ? { ...s, stage: a.stage } : s;
    case 'self_test':
      return { ...s, selfTestPassed: a.passed, stage: a.passed ? 'ready' : 'failed' };
    case 'tools_applied':
      return { ...s, toolsApplied: true };
  }
}

/** Where a created box is, from what can be observed about it. */
export function stageOf(box: { state: string } | null, daemonReachable: boolean, selfTest: boolean | null): Stage {
  if (!box) return 'creating';
  if (box.state === 'creating') return 'creating';
  if (box.state !== 'running') return 'booting';
  if (!daemonReachable) return 'booting';
  if (selfTest === null) return 'self_test';
  return selfTest ? 'ready' : 'failed';
}

/** A refusal at plan time, in words: the reason and the fix. */
export function refusalFix(code: string): 'create.fix_budget' | 'create.fix_quota' | 'create.fix_subnet' | 'create.fix_guardrails' | 'create.fix_generic' {
  switch (code) {
    case 'refused':
      return 'create.fix_budget';
    case 'guardrails_missing':
      return 'create.fix_guardrails';
    case 'unsupported':
      return 'create.fix_quota';
    default:
      return 'create.fix_generic';
  }
}

/** A message that mentions a missing subnet is the one setup fixes. */
export function needsNetwork(message: string): boolean {
  return /subnet/i.test(message);
}

export const STAGE_ORDER: Stage[] = ['creating', 'booting', 'self_test', 'ready'];
