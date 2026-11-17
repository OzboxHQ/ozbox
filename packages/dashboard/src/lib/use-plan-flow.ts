import { useCallback, useEffect, useReducer } from 'react';

import { ApiError, type ApiClient } from '../api/client';
import type { Operation, PlanResponse } from '../api/types';
import { applyWithGates } from './fleet-apply';
import { askStepUp } from './step-up';
import { getPasskey } from './webauthn';
import { applyRequest, flowReducer, idle, type FlowAction, type FlowState } from './plan-flow';

function describe(e: unknown): { message: string; code: string; detail?: string } {
  if (e instanceof ApiError) {
    const reason = e.details['signature_detail'];
    return { message: e.message, code: e.code, ...(typeof reason === 'string' ? { detail: reason } : {}) };
  }
  return { message: 'Something went wrong. Nothing was changed.', code: 'error' };
}

/** Drives plan, review, apply against the server. A change happens only after `confirm`. */
export function usePlanFlow(client: ApiClient, onApplied: () => void) {
  const [state, dispatch] = useReducer(flowReducer, idle as FlowState);

  useEffect(() => {
    if (state.phase !== 'planning') return;
    const ctl = new AbortController();
    client
      .plan(
        state.operation,
        ctl.signal,
        state.allowUnverified || state.acceptNewStore
          ? { ...(state.allowUnverified ? { allowUnverifiedImage: true } : {}), ...(state.acceptNewStore ? { acceptNewSecretsStore: true } : {}) }
          : undefined,
      )
      .then((plan) => dispatch({ type: 'planned', plan }))
      .catch((e: unknown) => {
        if (!ctl.signal.aborted) dispatch({ type: 'failed', ...describe(e) });
      });
    return () => ctl.abort();
  }, [state, client]);

  const phase = state.phase;
  useEffect(() => {
    if (phase !== 'applying') return;
    const req = applyRequest(state);
    if (!req) return;
    let live = true;
    // Behind a sign-in, an irreversible change first needs a fresh passkey; when it is shown, the same plan is tried again.
    applyWithGates(req, { apply: (r) => client.apply(r), askStepUp, fleetChallenge: (id) => client.fleetChallenge(id), getPasskey })
      .then((response) => {
        if (live) dispatch({ type: 'applied', response });
        onApplied();
      })
      .catch((e: unknown) => {
        if (live) dispatch({ type: 'failed', ...describe(e) });
      });
    return () => {
      live = false;
    };
    // The request is built from `state` once, when the phase becomes `applying`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase]);

  const begin = useCallback(
    (operation: Operation, allowUnverified?: boolean, acceptNewStore?: boolean) =>
      dispatch({ type: 'start', operation, ...(allowUnverified ? { allowUnverified: true } : {}), ...(acceptNewStore ? { acceptNewStore: true } : {}) }),
    [],
  );
  const open = useCallback((plan: PlanResponse) => dispatch({ type: 'loaded', plan }), []);
  return { state, dispatch: dispatch as (a: FlowAction) => void, begin, open };
}
