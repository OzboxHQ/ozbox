import type { ReactNode } from 'react';

import type { Capability, Role } from '../api/people';
import { t, type MessageKey } from '../lib/i18n';
import { CAPABILITY_WORDS } from '../lib/roles';
import { useCan } from '../lib/use-can';

export const ROLE_LABEL: Record<Role, MessageKey> = { owner: 'roles.owner', member: 'roles.member', viewer: 'roles.viewer' };
export const ROLE_HELP: Record<Role, MessageKey> = { owner: 'roles.owner_help', member: 'roles.member_help', viewer: 'roles.viewer_help' };

/**
 * What a page offers a role that may not change it: the page stays readable, every control in it is disabled (a disabled
 * fieldset disables its buttons, inputs and selects), and one line says why. The server refuses the same requests, so this
 * is courtesy, not the boundary.
 */
export function ReadOnlyScope({ cap, children }: { cap: Capability; children: ReactNode }) {
  const { can, role } = useCan();
  if (can(cap)) return <>{children}</>;
  return (
    <>
      <p role="status" data-testid="read-only-notice" className="rounded-md border bg-muted/50 px-3 py-2 text-sm text-muted-foreground">
        {t('roles.read_only', { role: t(ROLE_LABEL[role]).toLowerCase() })}
      </p>
      <fieldset disabled data-testid="read-only-scope" className="m-0 min-w-0 border-0 p-0">
        {children}
      </fieldset>
    </>
  );
}

/** A short reason in place of a control the role may not use. */
export function CannotNote({ cap, what }: { cap: Capability; what?: MessageKey }) {
  const { role } = useCan();
  return (
    <p data-testid="cannot-note" className="text-sm text-muted-foreground">
      {t('roles.cannot', { role: t(ROLE_LABEL[role]).toLowerCase(), what: what ? t(what) : CAPABILITY_WORDS[cap] })}
    </p>
  );
}
