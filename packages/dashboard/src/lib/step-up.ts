/**
 * A change that cannot be undone asks for a passkey shown within the last few minutes. When the server answers
 * `step_up_required`, the caller asks here; the sign-in layer (if there is one) opens its prompt and settles the promise.
 * With no handler (the local-token dashboard) there is nothing to ask and the original error stands.
 */
type Handler = () => Promise<boolean>;

let handler: Handler | null = null;

export function setStepUpHandler(h: Handler | null): void {
  handler = h;
}

export const STEP_UP_CODE = 'step_up_required';

/** `true` when the person confirmed and the request can be tried again. */
export async function askStepUp(): Promise<boolean> {
  return handler ? handler() : false;
}
