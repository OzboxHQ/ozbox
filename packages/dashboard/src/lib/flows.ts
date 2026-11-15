/** Opening the two big flows from anywhere (a button, the palette, an empty state) without threading props through
 * every page: the host listens for this event. */
/** `sandbox` opens setup with the free sandbox already chosen. */
export type FlowKind = 'create' | 'setup' | 'sandbox';

export const FLOW_EVENT = 'ozbox:open-flow';

export function openFlow(kind: FlowKind): void {
  window.dispatchEvent(new CustomEvent<FlowKind>(FLOW_EVENT, { detail: kind }));
}
