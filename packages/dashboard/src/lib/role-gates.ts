import type { Capability } from '../api/people';
import type { MessageKey } from './i18n';

/**
 * Which pages' writes a role is offered (G7, X8). The server decides every request (`serve/roles.rs`); this lists what that
 * table asks for, so a page offers a viewer nothing it would only be refused and says why once.
 *   - memory: notes are agents' files, so writing one is `use_boxes` (members and owners);
 *   - skills: a skill is code an agent may run, so reviewing and installing one is `change_settings` (owners);
 *   - orchestrations: every change is a run, so `start_runs` (members and owners);
 *   - usage: applying a suggestion plans and applies a change to a box (`BoxChange`), which members and owners hold as `use_boxes`;
 *   - bill: reading the bill and scanning for forgotten resources are a use of the cloud account (`RunStart`), `start_runs`;
 *     deleting what a scan found is `manage_costs` (owners), asked separately by the orphans card.
 */
export type GatedPage = 'memory' | 'skills' | 'orchestrations' | 'usage' | 'bill';

export const PAGE_CAPABILITY: Record<GatedPage, Capability> = {
  memory: 'use_boxes',
  skills: 'change_settings',
  orchestrations: 'start_runs',
  usage: 'use_boxes',
  bill: 'start_runs',
};

/** The words that finish "a viewer cannot ...", for the page's own action rather than the capability's generic one. */
export const PAGE_CANNOT: Record<GatedPage, MessageKey> = {
  memory: 'roles.cannot_mem',
  skills: 'roles.cannot_skills',
  orchestrations: 'roles.cannot_orch',
  usage: 'roles.cannot_usage',
  bill: 'roles.cannot_bill',
};

/** Whether the person may change things on `page`: every write control on it is shown only when this is true. */
export function mayWrite(page: GatedPage, can: (c: Capability) => boolean): boolean {
  return can(PAGE_CAPABILITY[page]);
}
