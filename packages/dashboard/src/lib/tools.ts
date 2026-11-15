import type { Catalog, CatalogTool, JobStep, ToolState } from '../api/tools';

export type ToolStatus = 'installed' | 'available' | 'unavailable' | 'client';

export interface ToolRow {
  tool: CatalogTool;
  state: ToolState | undefined;
  status: ToolStatus;
}

export function statusOf(tool: CatalogTool, state: ToolState | undefined): ToolStatus {
  if (tool.verification === 'client_managed') return 'client';
  if (!tool.verified) return 'unavailable';
  return state?.installed ? 'installed' : 'available';
}

/** Whether a tool matches what someone typed: its name, id, description or group, ignoring case. */
export function matches(tool: CatalogTool, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [tool.name, tool.id, tool.description].some((s) => s.toLowerCase().includes(q));
}

export interface ToolGroup {
  id: string;
  name: string;
  rows: ToolRow[];
}

/** The catalog as groups of rows (empty groups left out), filtered by a search and, optionally, a bundle. */
export function groupRows(catalog: Catalog, states: ToolState[], query: string, bundle: string | null): ToolGroup[] {
  const byId = new Map(states.map((s) => [s.id, s]));
  const only = bundle ? new Set(catalog.bundles.find((b) => b.id === bundle)?.tools ?? []) : null;
  return catalog.groups
    .map((g) => ({
      id: g.id,
      name: g.name,
      rows: catalog.tools
        .filter((t) => t.group === g.id && matches(t, query) && (!only || only.has(t.id)))
        .map((tool) => {
          const state = byId.get(tool.id);
          return { tool, state, status: statusOf(tool, state) };
        }),
    }))
    .filter((g) => g.rows.length > 0);
}

/** A tool can be ticked for installation when it is verified, not on the box, and not handled by a client. */
export function selectable(row: ToolRow): boolean {
  return row.status === 'available';
}

export function toggle(selection: ReadonlySet<string>, id: string): Set<string> {
  const next = new Set(selection);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  return next;
}

/** The ids of a bundle that can still be installed on this box. */
export function bundleSelectable(catalog: Catalog, states: ToolState[], bundleId: string): string[] {
  const installed = new Set(states.filter((s) => s.installed).map((s) => s.id));
  return (catalog.bundles.find((b) => b.id === bundleId)?.tools ?? []).filter((id) => !installed.has(id));
}

/** Whether every installable member of a bundle is ticked (a bundle with nothing left to install counts as ticked). */
export function bundleTicked(catalog: Catalog, states: ToolState[], selection: ReadonlySet<string>, bundleId: string): boolean {
  const left = bundleSelectable(catalog, states, bundleId);
  return left.every((id) => selection.has(id));
}

export function sizeLabel(mb: number): string {
  if (mb <= 0) return '0 MB';
  return mb >= 1000 ? `${(mb / 1000).toFixed(1)} GB` : `${mb} MB`;
}

export function jobProgress(steps: JobStep[]): { done: number; total: number; failed: boolean } {
  return { done: steps.filter((s) => s.state === 'ok').length, total: steps.length, failed: steps.some((s) => s.state === 'failed') };
}

export function isFinished(state: string): boolean {
  return state === 'succeeded' || state === 'failed';
}

/** Profile names are ids: lowercase letters, digits and hyphens. */
export function validProfileName(name: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/.test(name);
}

export function validBoxName(name: string): boolean {
  return /^[a-z](?:[a-z0-9-]{0,38}[a-z0-9])?$/.test(name) && !name.includes('--');
}
