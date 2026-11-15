import type { CheckResult, Identity, Probe, RegionCandidate, SecurityItem, SetupPlan, SetupProvider } from '../api/setup';

/** The "Set up your fleet" stepper as a pure state machine. The component asks the server and dispatches what came back;
 * nothing here touches the network, so every rule (which steps a provider has, when Continue is allowed, that a plan is
 * shown before it is applied) is a unit test. */
export type StepId = 'provider' | 'sign_in' | 'permissions' | 'region' | 'bucket' | 'network' | 'guardrails' | 'locale' | 'security' | 'done';

const FLOWS: Record<SetupProvider, StepId[]> = {
  fake: ['provider', 'locale', 'done'],
  aws: ['provider', 'sign_in', 'permissions', 'region', 'bucket', 'network', 'guardrails', 'locale', 'security', 'done'],
  hcloud: ['provider', 'sign_in', 'region', 'guardrails', 'locale', 'security', 'done'],
};

export function stepsFor(provider: SetupProvider | null): StepId[] {
  return provider ? FLOWS[provider] : ['provider'];
}

export interface Problem {
  code: string;
  message: string;
  fix?: string | null;
}

export type PlanPhase =
  | { phase: 'none' }
  | { phase: 'planning' }
  /** The plan is on screen; nothing has been applied. */
  | { phase: 'review'; plan: SetupPlan }
  | { phase: 'applying'; plan: SetupPlan }
  | { phase: 'applied'; plan: SetupPlan };

export interface SetupState {
  step: StepId;
  provider: SetupProvider | null;
  profile: string;
  region: string;
  busy: boolean;
  problem: Problem | null;
  identity: Identity | null;
  signedIn: boolean;
  probes: Probe[] | null;
  permissionsOk: boolean;
  regions: RegionCandidate[] | null;
  suggestedRegion: string | null;
  bucket: PlanPhase;
  network: PlanPhase;
  budgetSet: boolean;
  alertReady: boolean;
  localeSaved: boolean;
  security: SecurityItem[] | null;
  securityBlocking: boolean;
  mfaAck: boolean;
  completed: boolean;
}

export const initialState: SetupState = {
  step: 'provider',
  provider: null,
  profile: '',
  region: '',
  busy: false,
  problem: null,
  identity: null,
  signedIn: false,
  probes: null,
  permissionsOk: false,
  regions: null,
  suggestedRegion: null,
  bucket: { phase: 'none' },
  network: { phase: 'none' },
  budgetSet: false,
  alertReady: false,
  localeSaved: false,
  security: null,
  securityBlocking: false,
  mfaAck: false,
  completed: false,
};

export type SetupAction =
  | { type: 'provider'; provider: SetupProvider }
  | { type: 'profile'; value: string }
  | { type: 'region'; value: string }
  | { type: 'busy' }
  | { type: 'failed'; problem: Problem }
  | { type: 'signed_in'; identity: Identity | null }
  | { type: 'permissions'; probes: Probe[]; ok: boolean }
  | { type: 'regions'; candidates: RegionCandidate[]; suggested: string | null }
  | { type: 'planning'; which: 'bucket' | 'network' }
  | { type: 'planned'; which: 'bucket' | 'network'; plan: SetupPlan }
  | { type: 'apply'; which: 'bucket' | 'network' }
  | { type: 'applied'; which: 'bucket' | 'network' }
  | { type: 'guardrails'; budgetSet: boolean; alertReady: boolean }
  | { type: 'locale_saved' }
  | { type: 'security'; items: SecurityItem[]; blocking: boolean }
  | { type: 'ack'; value: boolean }
  | { type: 'finished' }
  | { type: 'next' }
  | { type: 'back' }
  | { type: 'reset' };

/** Whether the person may move on from the current step. */
export function canContinue(s: SetupState): boolean {
  if (s.busy) return false;
  switch (s.step) {
    case 'provider':
      return s.provider !== null;
    case 'sign_in':
      return s.signedIn;
    case 'permissions':
      return s.permissionsOk;
    case 'region':
      return s.region !== '';
    case 'bucket':
      return s.bucket.phase === 'applied';
    case 'network':
      return s.network.phase === 'applied';
    case 'guardrails':
      return s.budgetSet && s.alertReady;
    case 'locale':
      return s.localeSaved;
    case 'security':
      return !s.securityBlocking && s.security !== null && s.mfaAck;
    case 'done':
      return false;
  }
}

/** The state of a plan step when the person has not changed anything: a plan that is already satisfied counts as done. */
function afterPlanned(plan: SetupPlan): PlanPhase {
  return plan.noop ? { phase: 'applied', plan } : { phase: 'review', plan };
}

export function setupReducer(s: SetupState, a: SetupAction): SetupState {
  switch (a.type) {
    case 'provider':
      // A different provider starts over: what was checked belongs to the other one.
      return a.provider === s.provider ? s : { ...initialState, provider: a.provider, profile: s.profile };
    case 'profile':
      return { ...s, profile: a.value, signedIn: false, identity: null, probes: null, permissionsOk: false, problem: null };
    case 'region':
      return { ...s, region: a.value, bucket: { phase: 'none' }, network: { phase: 'none' }, problem: null };
    case 'busy':
      return { ...s, busy: true, problem: null };
    case 'failed':
      return { ...s, busy: false, problem: a.problem, bucket: failPlan(s.bucket), network: failPlan(s.network) };
    case 'signed_in':
      return { ...s, busy: false, problem: null, signedIn: true, identity: a.identity };
    case 'permissions':
      return { ...s, busy: false, problem: null, probes: a.probes, permissionsOk: a.ok };
    case 'regions':
      return { ...s, busy: false, problem: null, regions: a.candidates, suggestedRegion: a.suggested, region: s.region || a.suggested || '' };
    case 'planning':
      return { ...s, busy: true, problem: null, [a.which]: { phase: 'planning' } };
    case 'planned':
      return { ...s, busy: false, [a.which]: afterPlanned(a.plan) };
    case 'apply': {
      const cur = s[a.which];
      // Only a plan that is on screen can be applied. Anything else is ignored.
      return cur.phase === 'review' ? { ...s, busy: true, problem: null, [a.which]: { phase: 'applying', plan: cur.plan } } : s;
    }
    case 'applied': {
      const cur = s[a.which];
      return cur.phase === 'applying' ? { ...s, busy: false, [a.which]: { phase: 'applied', plan: cur.plan } } : s;
    }
    case 'guardrails':
      return { ...s, budgetSet: a.budgetSet, alertReady: a.alertReady };
    case 'locale_saved':
      return { ...s, localeSaved: true };
    case 'security':
      return { ...s, busy: false, problem: null, security: a.items, securityBlocking: a.blocking };
    case 'ack':
      return { ...s, mfaAck: a.value };
    case 'finished':
      return { ...s, busy: false, completed: true, step: 'done' };
    case 'next': {
      if (!canContinue(s)) return s;
      const steps = stepsFor(s.provider);
      const next = steps[steps.indexOf(s.step) + 1];
      return next ? { ...s, step: next, problem: null } : s;
    }
    case 'back': {
      if (s.busy || s.step === 'done') return s;
      const steps = stepsFor(s.provider);
      const prev = steps[steps.indexOf(s.step) - 1];
      return prev ? { ...s, step: prev, problem: null } : s;
    }
    case 'reset':
      return initialState;
  }
}

/** A failed apply goes back to review: the plan is still what was shown, and it can be tried again. */
function failPlan(p: PlanPhase): PlanPhase {
  if (p.phase === 'applying') return { phase: 'review', plan: p.plan };
  if (p.phase === 'planning') return { phase: 'none' };
  return p;
}

export function stepNumber(s: SetupState): { n: number; of: number } {
  const steps: StepId[] = stepsFor(s.provider).filter((x) => x !== 'done');
  return { n: Math.min(steps.indexOf(s.step) + 1 || steps.length, steps.length), of: steps.length };
}

/** What a check answered, in the shape the reducer takes. */
export function fromCheck(kind: 'sign_in' | 'permissions' | 'regions' | 'security', r: CheckResult): SetupAction {
  switch (kind) {
    case 'sign_in':
      return { type: 'signed_in', identity: r.identity ?? null };
    case 'permissions':
      return { type: 'permissions', probes: r.report?.probes ?? [], ok: r.report?.ok === true };
    case 'regions':
      return { type: 'regions', candidates: r.report?.candidates ?? [], suggested: r.report?.suggested ?? null };
    case 'security':
      return { type: 'security', items: r.report?.items ?? [], blocking: r.report?.blocking === true };
  }
}

/** Money for a plan's estimate; an unknown figure is an em dash, never a made-up zero. */
export function estimateLabel(usd: number | null): string {
  return usd === null ? '—' : usd === 0 ? '$0' : `about $${usd.toFixed(2)}/month`;
}
