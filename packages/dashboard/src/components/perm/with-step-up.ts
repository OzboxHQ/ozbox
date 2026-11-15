import { ApiError } from '../../api/client';
import { askStepUp, STEP_UP_CODE } from '../../lib/step-up';

/** Run a change; when the server asks for a fresh passkey, ask for it and try once more. */
export async function withStepUp<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (e) {
    if (e instanceof ApiError && e.code === STEP_UP_CODE && (await askStepUp())) return run();
    throw e;
  }
}
