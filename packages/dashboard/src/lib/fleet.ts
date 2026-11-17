import type { Info } from '../api/types';
import type { Route } from './router';

export type FleetMode = 'connected' | 'this_box' | 'demo' | 'managed';

/** The mode the server reported; `null` while it has not answered (nothing is claimed either way). */
export function fleetMode(info: Info | null): FleetMode | null {
  if (!info) return null;
  return info.fleet?.mode ?? 'connected';
}

/** Whether every box on screen is made up, so every page must say so. */
export function isDemo(info: Info | null): boolean {
  return fleetMode(info) === 'demo';
}

/** Whether this dashboard sees only the box it runs on, so changing or pricing a fleet is not possible from here. */
export function fleetNotConnected(info: Info | null): boolean {
  return fleetMode(info) === 'this_box';
}

/** Whether this is a box's dashboard that manages the fleet through roles of its own (ADR 0040): every change it makes
 * needs a change window opened from the owner's computer and the owner's passkey over that exact plan. */
export function managedFromThisBox(info: Info | null): boolean {
  return fleetMode(info) === 'managed';
}

/** The pages that show a fleet (its boxes, its cost, its bill) and so say the fleet is not connected. */
const FLEET_PAGES: ReadonlySet<Route['page']> = new Set(['fleet', 'boxes', 'usage', 'bill']);

export function showsFleetNotice(route: Route): boolean {
  return FLEET_PAGES.has(route.page);
}

/** The error code every fleet-only endpoint answers on a box. */
export const FLEET_NOT_CONNECTED = 'fleet_not_connected';
