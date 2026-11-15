import { afterEach, describe, expect, it } from 'vitest';

import { askStepUp, setStepUpHandler } from './step-up';

afterEach(() => setStepUpHandler(null));

describe('step-up', () => {
  it('has nothing to ask without a sign-in layer', async () => {
    expect(await askStepUp()).toBe(false);
  });
  it('settles with what the prompt decided', async () => {
    setStepUpHandler(() => Promise.resolve(true));
    expect(await askStepUp()).toBe(true);
    setStepUpHandler(() => Promise.resolve(false));
    expect(await askStepUp()).toBe(false);
  });
});
