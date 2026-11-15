// What the Secret approvals page asks the box's secrets service for, from what the person chose. Pure, so each scope's
// binding (the project and environment the service checks the code against) is tested without a page.
import type { ApprovalScope, MintRequest } from '../api/secrets';
import type { MessageKey } from './i18n';

export type Which = 'cloudflare' | 'ngrok' | 'ide';
export type GuardWhat = 'egress' | 'patch';
export type VaultWhat = 'declaration' | 'clear' | 'bao-token';

export interface ApprovalForm {
  scope: ApprovalScope;
  project: string;
  env: string;
  which: Which;
  guardWhat: GuardWhat;
  /** The 16 hexadecimal characters of a change code, as the plan printed them. */
  digest: string;
  keyId: string;
  vaultWhat: VaultWhat;
}

export const SEG = /^[a-z0-9][a-z0-9-]{0,31}$/;
export const DIGEST = /^[0-9a-f]{16}$/;

/** Which fields a scope needs. */
export function needs(f: Pick<ApprovalForm, 'scope' | 'vaultWhat'>) {
  return {
    project: f.scope === 'import' || f.scope === 'policy',
    env: f.scope === 'import',
    digest: f.scope === 'host-guard' || (f.scope === 'box-secrets' && f.vaultWhat === 'declaration'),
    key: f.scope === 'signer-enroll',
  };
}

/** The message key of the first thing wrong with the form, or null. */
export function formError(f: ApprovalForm): MessageKey | null {
  const n = needs(f);
  if (n.project && !SEG.test(f.project)) return 'secrets.err_project';
  if (n.env && !SEG.test(f.env)) return 'secrets.err_env';
  if (n.digest && !DIGEST.test(f.digest)) return 'secrets.err_digest';
  if (n.key && !SEG.test(f.keyId)) return 'secrets.err_key';
  return null;
}

/**
 * The request: each scope bound the way the box checks it.
 * - host-guard: project egress|patch, env the change code;
 * - signer-enroll: project the key's name (an enrolment or a revocation of that key);
 * - box-secrets: project declaration with env d-<change code> for a new declaration, project declaration for removing it,
 *   project bao-token for placing the vault token;
 * - tunnel-token: project the tunnel; import: project and environment; policy: project.
 */
export function mintBody(f: ApprovalForm): MintRequest {
  const n = needs(f);
  switch (f.scope) {
    case 'host-guard':
      return { scope: f.scope, project: f.guardWhat, env: f.digest };
    case 'signer-enroll':
      return { scope: f.scope, project: f.keyId, env: '' };
    case 'box-secrets':
      return f.vaultWhat === 'declaration'
        ? { scope: f.scope, project: 'declaration', env: `d-${f.digest}` }
        : { scope: f.scope, project: f.vaultWhat === 'clear' ? 'declaration' : 'bao-token', env: '' };
    case 'tunnel-token':
      return { scope: f.scope, project: f.which, env: '' };
    default:
      return { scope: f.scope, project: n.project ? f.project : '', env: n.env ? f.env : '' };
  }
}
