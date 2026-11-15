import { describe, expect, it } from 'vitest';

import { authHeaders } from './auth-headers';

describe('authHeaders', () => {
  it('uses the bearer token when there is one', () => {
    expect(authHeaders({ token: 'abc' }, 'GET')).toEqual({ Authorization: 'Bearer abc' });
    expect(authHeaders({ token: 'abc' }, 'POST')).toEqual({ Authorization: 'Bearer abc' });
  });
  it('sends the CSRF token on a change but not on a read, and never a bearer', () => {
    const c = { csrf: () => 'tok' };
    expect(authHeaders(c, 'GET')).toEqual({});
    expect(authHeaders(c, 'post')).toEqual({ 'X-Ozbox-CSRF': 'tok' });
    expect(authHeaders(c, 'DELETE')).toEqual({ 'X-Ozbox-CSRF': 'tok' });
  });
  it('sends nothing before there is a session', () => {
    expect(authHeaders({ csrf: () => '' }, 'POST')).toEqual({});
    expect(authHeaders({}, 'POST')).toEqual({});
  });
});
