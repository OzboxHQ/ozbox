import { describe, expect, it } from 'vitest';

import { ApiError } from '../api/error';
import { returnMessage, signInMessage } from './auth-errors';

describe('sign-in messages', () => {
  it('only fixed return codes produce text, and nothing from the address is echoed', () => {
    expect(returnMessage('?signin=not_allowed')).toContain('allow-list');
    expect(returnMessage('?signin=<script>alert(1)</script>')).toBeNull();
    expect(returnMessage('')).toBeNull();
  });
  it('a closed passkey prompt is quiet and a rate limit is explained', () => {
    expect(signInMessage(new DOMException('x', 'NotAllowedError'))).toContain('closed');
    expect(signInMessage(new ApiError(429, 'too_many_attempts', 'x'))).toContain('Too many');
    expect(signInMessage(new ApiError(401, 'passkey_refused', 'That passkey was not accepted.'))).toBe('That passkey was not accepted.');
    expect(signInMessage(new Error('boom'))).toContain('Could not sign in');
  });
});
