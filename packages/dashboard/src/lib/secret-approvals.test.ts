import { describe, expect, it } from 'vitest';

import { APPROVAL_SCOPES } from '../api/secrets';
import { formError, mintBody, type ApprovalForm } from './secret-approvals';

const base: ApprovalForm = {
  scope: 'import',
  project: 'app',
  env: 'staging',
  which: 'cloudflare',
  guardWhat: 'egress',
  digest: '0123456789abcdef',
  keyId: 'laptop',
  vaultWhat: 'declaration',
};

describe('secret approvals', () => {
  // A security review (2026-11-11) found the page could not mint two scopes the box asks for.
  it('offers every scope the box accepts, including laptop keys and the box vault', () => {
    expect(APPROVAL_SCOPES).toContain('signer-enroll');
    expect(APPROVAL_SCOPES).toContain('box-secrets');
  });

  it('binds each scope the way the box checks it', () => {
    expect(mintBody({ ...base, scope: 'signer-enroll', keyId: 'work-laptop' })).toEqual({ scope: 'signer-enroll', project: 'work-laptop', env: '' });
    expect(mintBody({ ...base, scope: 'box-secrets' })).toEqual({ scope: 'box-secrets', project: 'declaration', env: 'd-0123456789abcdef' });
    expect(mintBody({ ...base, scope: 'box-secrets', vaultWhat: 'clear' })).toEqual({ scope: 'box-secrets', project: 'declaration', env: '' });
    expect(mintBody({ ...base, scope: 'box-secrets', vaultWhat: 'bao-token' })).toEqual({ scope: 'box-secrets', project: 'bao-token', env: '' });
    expect(mintBody({ ...base, scope: 'host-guard', guardWhat: 'patch' })).toEqual({ scope: 'host-guard', project: 'patch', env: '0123456789abcdef' });
    expect(mintBody({ ...base, scope: 'tunnel-token', which: 'ide' })).toEqual({ scope: 'tunnel-token', project: 'ide', env: '' });
    expect(mintBody(base)).toEqual({ scope: 'import', project: 'app', env: 'staging' });
    expect(mintBody({ ...base, scope: 'policy' })).toEqual({ scope: 'policy', project: 'app', env: '' });
    expect(mintBody({ ...base, scope: 'guard-override' })).toEqual({ scope: 'guard-override', project: '', env: '' });
  });

  it('says what is missing before asking', () => {
    expect(formError({ ...base, scope: 'signer-enroll', keyId: 'Bad Key' })).toBe('secrets.err_key');
    expect(formError({ ...base, scope: 'box-secrets', digest: 'nope' })).toBe('secrets.err_digest');
    expect(formError({ ...base, scope: 'box-secrets', vaultWhat: 'bao-token', digest: '' })).toBeNull();
    expect(formError({ ...base, env: '' })).toBe('secrets.err_env');
  });
});
