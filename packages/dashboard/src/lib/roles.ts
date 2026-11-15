import type { Capabilities, Capability, Role } from '../api/people';

export const CAPABILITIES: Capability[] = ['watch_browser', 'control_browser', 'approve', 'start_runs', 'use_boxes', 'change_settings', 'manage_costs', 'manage_people'];

/** A dashboard with no sign-in has one person, its operator, who may do everything. */
export const EVERYTHING: Capabilities = Object.fromEntries(CAPABILITIES.map((c) => [c, true])) as Capabilities;

/**
 * What the dashboard shows a person: the server's list, read defensively. A name the server did not send is `false`, so
 * an older or newer server never turns a button on by accident. The server decides every request either way; this only
 * decides what is offered.
 */
export function capabilitiesOf(raw: Partial<Record<string, boolean>> | undefined | null): Capabilities {
  return Object.fromEntries(CAPABILITIES.map((c) => [c, raw?.[c] === true])) as Capabilities;
}

export function isRole(v: unknown): v is Role {
  return v === 'owner' || v === 'member' || v === 'viewer';
}

/** The words that finish "Your role (viewer) cannot ...", one per capability. */
export const CAPABILITY_WORDS: Record<Capability, string> = {
  watch_browser: 'watch a browser session',
  control_browser: 'take over a browser',
  approve: 'decide approvals',
  start_runs: 'start runs',
  use_boxes: 'use a terminal, the files or the IDE of a box',
  change_settings: 'change settings, permissions or the secrets policy',
  manage_costs: 'manage costs',
  manage_people: 'change who can do what',
};
