import { ApiError } from '../api/error';
import type { ApplyRequest, ApplyResponse, FleetChallenge } from '../api/types';
import { STEP_UP_CODE } from './step-up';
import type { AssertionJson, RequestJson } from './webauthn';

/** The code a box's dashboard that manages the fleet answers when an apply has no passkey over its plan (ADR 0040). */
export const FLEET_PASSKEY_CODE = 'fleet_passkey_required';

/** The refusals a fleet change from a box's dashboard can meet before it changes anything; each is shown as the server
 * words it, and none is retried on its own. */
export const FLEET_REFUSAL_CODES = ['change_window_required', 'change_window_expired', 'fleet_this_box', 'fleet_plan_spent', 'fleet_from_your_computer'] as const;

/** Whether this failed apply can go through once the owner confirms the plan with a passkey. */
export function needsFleetPasskey(e: unknown): boolean {
  return e instanceof ApiError && e.code === FLEET_PASSKEY_CODE;
}

/** The same apply, carrying the passkey assertion made over its plan's challenge. */
export function withFleetAssertion(req: ApplyRequest, assertion: AssertionJson): ApplyRequest {
  return { ...req, fleet_assertion: assertion };
}

/** What one apply may need besides the server: a fresh passkey for a change that cannot be undone (step-up), and on a box's
 * dashboard that manages the fleet, the owner's passkey over this exact plan. */
export interface ApplyDeps {
  apply(req: ApplyRequest): Promise<ApplyResponse>;
  askStepUp(): Promise<boolean>;
  fleetChallenge(planId: string): Promise<FleetChallenge>;
  getPasskey(options: RequestJson): Promise<AssertionJson>;
}

/**
 * Apply one issued plan. A refusal that a person can answer is answered once, and the SAME plan is tried again: a step-up
 * (a passkey shown a moment ago), then the fleet passkey (the server's challenge for this plan, signed in the browser). A
 * refused challenge (no change window, this box) is the error shown; a closed passkey prompt leaves the first refusal.
 */
export function applyWithGates(req: ApplyRequest, deps: ApplyDeps): Promise<ApplyResponse> {
  const withPasskey = (e: unknown): Promise<ApplyResponse> =>
    deps
      .fleetChallenge(req.plan_id)
      .then((c) => deps.getPasskey(c.options).catch(() => Promise.reject(e)))
      .then((a) => deps.apply(withFleetAssertion(req, a)));
  return deps.apply(req).catch((e: unknown) => {
    if (e instanceof ApiError && e.code === STEP_UP_CODE) {
      return deps.askStepUp().then((ok) =>
        ok
          ? deps.apply(req).catch((e2: unknown) => (needsFleetPasskey(e2) ? withPasskey(e2) : Promise.reject(e2)))
          : Promise.reject(e),
      );
    }
    if (needsFleetPasskey(e)) return withPasskey(e);
    return Promise.reject(e);
  });
}
