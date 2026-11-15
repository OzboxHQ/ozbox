import type { ApplyRequest, ApplyResponse, Operation, PlanResponse, Size } from '../api/types';

/** The plan-then-apply flow, as a pure state machine. A button never mutates: it asks for a plan, shows it, and only
 * an explicit confirmation (with the box name typed for a change that cannot be undone) applies it. */
export type FlowState =
  | { phase: 'idle' }
  | { phase: 'planning'; operation: Operation; allowUnverified?: boolean; acceptNewStore?: boolean }
  | { phase: 'review'; operation: Operation; plan: PlanResponse; typed: string }
  | { phase: 'applying'; operation: Operation; plan: PlanResponse; typed: string }
  | { phase: 'done'; plan: PlanResponse; response: ApplyResponse }
  | { phase: 'error'; operation: Operation | null; message: string; code: string; detail?: string };

export type FlowAction =
  /** `allowUnverified` is for an upgrade to an image whose release signature could not be verified: the person asked for it by name. */
  | { type: 'start'; operation: Operation; allowUnverified?: boolean; acceptNewStore?: boolean }
  | { type: 'planned'; plan: PlanResponse }
  /** Open an already-issued plan (from the approvals inbox) straight into review. */
  | { type: 'loaded'; plan: PlanResponse }
  | { type: 'typed'; text: string }
  | { type: 'confirm' }
  | { type: 'applied'; response: ApplyResponse }
  /** `detail` is the server's own reason when it gave one in a field of its own (an image refused as unverified). */
  | { type: 'failed'; message: string; code: string; detail?: string }
  | { type: 'cancel' };

export const idle: FlowState = { phase: 'idle' };

export function canConfirm(state: FlowState): boolean {
  if (state.phase !== 'review') return false;
  const { plan, typed } = state;
  if (plan.noop) return false;
  return !plan.requires_confirm_name || typed === plan.box_name;
}

export function flowReducer(state: FlowState, action: FlowAction): FlowState {
  switch (action.type) {
    case 'start':
      return state.phase === 'idle' || state.phase === 'error' || state.phase === 'done'
        ? {
            phase: 'planning',
            operation: action.operation,
            ...(action.allowUnverified ? { allowUnverified: true } : {}),
            ...(action.acceptNewStore ? { acceptNewStore: true } : {}),
          }
        : state;
    case 'planned':
      return state.phase === 'planning'
        ? { phase: 'review', operation: state.operation, plan: action.plan, typed: '' }
        : state;
    case 'loaded':
      return state.phase === 'idle' ? { phase: 'review', operation: action.plan.plan.operation, plan: action.plan, typed: '' } : state;
    case 'typed':
      return state.phase === 'review' ? { ...state, typed: action.text } : state;
    case 'confirm':
      return state.phase === 'review' && canConfirm(state)
        ? { phase: 'applying', operation: state.operation, plan: state.plan, typed: state.typed }
        : state;
    case 'applied':
      return state.phase === 'applying' ? { phase: 'done', plan: state.plan, response: action.response } : state;
    case 'failed':
      return state.phase === 'planning' || state.phase === 'applying' || state.phase === 'review'
        ? { phase: 'error', operation: 'operation' in state ? state.operation : null, message: action.message, code: action.code, ...(action.detail === undefined ? {} : { detail: action.detail }) }
        : state;
    case 'cancel':
      // A change in flight cannot be taken back by closing the window.
      return state.phase === 'applying' ? state : idle;
  }
}

/** The body for `POST /v1/apply`: the issued plan's id, and the typed name only when it was required. */
export function applyRequest(state: FlowState): ApplyRequest | null {
  if (state.phase !== 'applying') return null;
  const req: ApplyRequest = { plan_id: state.plan.plan_id, plan: state.plan.plan };
  if (state.plan.requires_confirm_name) req.confirm_name = state.typed;
  return req;
}

/** The server's code for an upgrade it refused because the image's release signature could not be verified. */
export const IMAGE_UNVERIFIED_CODE = 'image_unverified';

/** The server's code for an upgrade it refused because the box's secrets store would not survive it, or the box could not be
 * asked; the person may accept a new store by name (`accept_new_secrets_store`), the same as the command's flag. */
export const SECRETS_STORE_LOST_CODE = 'secrets_store_lost';

export const ops = {
  pause: (name: string): Operation => ({ op: 'pause', name }),
  resume: (name: string): Operation => ({ op: 'resume', name }),
  snapshot: (name: string): Operation => ({ op: 'snapshot', name }),
  resize: (name: string, size: Size): Operation => ({ op: 'resize', name, size, work_disk_gb: null }),
  destroy: (name: string, finalSnapshot: boolean): Operation => ({ op: 'destroy', name, final_snapshot: finalSnapshot }),
  /** `image` is an image id, or `latest`, which the server turns into the id it found before it plans. */
  upgrade: (name: string, image: string): Operation => ({ op: 'upgrade', name, image }),
  cloneFrom: (from: string, to: string, snapshot: string): Operation => ({ op: 'clone', from, to, snapshot }),
  deleteSnapshot: (name: string, snapshot: string): Operation => ({ op: 'delete_snapshot', name, snapshot }),
  restoreWork: (name: string, snapshot: string): Operation => ({ op: 'restore_work', name, snapshot }),
  resticBackup: (name: string): Operation => ({ op: 'restic_backup', name }),
  resticForget: (name: string, snapshot: string): Operation => ({ op: 'restic_forget', name, snapshot }),
  resticRestore: (name: string, snapshot: string, inPlace: boolean): Operation => ({ op: 'restic_restore', name, snapshot, in_place: inPlace }),
  /** A repository backup of `from`, restored into a new box `to`: one plan that creates it, restores and checks it. */
  restoreToNewBox: (from: string, to: string, snapshot: string): Operation => ({ op: 'restore_to_new_box', from, to, snapshot }),
  deleteOldWork: (name: string, volume: string): Operation => ({ op: 'delete_old_work', name, volume }),
};

export function riskLabel(risk: 'low' | 'medium' | 'high'): string {
  switch (risk) {
    case 'low':
      return 'Low risk';
    case 'medium':
      return 'Costs money or interrupts work';
    case 'high':
      return 'Cannot be undone';
  }
}
