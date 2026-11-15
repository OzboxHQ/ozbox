// Coding agents on this box using the Oz Box tools. The shape `/v1/agent-mcp` answers with (see
// crates/ozbox-cli/src/serve/agent_mcp_routes.rs). Times are milliseconds since the Unix epoch.

export interface AgentMcpEngine {
  id: string;
  name: string;
}

export interface AgentMcpState {
  /** False off a box (there is no door to open) and on a box whose dashboard has not opened it yet. */
  available: boolean;
  enabled?: boolean;
  /** Who last changed it: the name that goes on every approval an agent's call asks for. */
  by?: string;
  at_ms?: number;
  /** Until when terminal agents may use the person's standing permissions (auto mode, box grants); 0 or absent is never. */
  standing_until_ms?: number;
  /** False when the setting is in force but could not be written (it is then off only until the dashboard restarts). */
  saved?: boolean;
  /** Agent sessions that hold a live token right now. */
  sessions?: number;
  engines?: AgentMcpEngine[];
}

type Req = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createAgentMcpApi(request: Req) {
  return {
    get: (signal?: AbortSignal) => request<AgentMcpState>('GET', '/v1/agent-mcp', undefined, signal),
    /** Turning it on needs a passkey shown a moment ago (a `step_up_required` answer is for the caller to resolve). */
    set: (enabled: boolean) => request<AgentMcpState>('PUT', '/v1/agent-mcp', { enabled }),
    /** Standing permissions for terminal agents: on (a loosening, needs a passkey; 30 minutes unless said) or off (needs nothing). */
    standing: (on: boolean, minutes?: number) => request<AgentMcpState>('PUT', '/v1/agent-mcp', { standing: on, minutes }),
  };
}

export type AgentMcpApi = ReturnType<typeof createAgentMcpApi>;
