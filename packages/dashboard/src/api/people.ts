// Who can sign in and what each person may do (ADR 0039). The shapes are the ones `/v1/people` answers with (see
// crates/ozbox-cli/src/serve/roles.rs).

export type Role = 'owner' | 'member' | 'viewer';
export const ROLES: Role[] = ['owner', 'member', 'viewer'];

/** What a role may do, by the name the server gives it. */
export type Capability = 'watch_browser' | 'control_browser' | 'approve' | 'start_runs' | 'use_boxes' | 'change_settings' | 'manage_costs' | 'manage_people';
export type Capabilities = Record<Capability, boolean>;

export interface Person {
  id: string;
  label: string;
  role: Role;
}

export interface PeopleView {
  mode: 'session' | 'token';
  me: { id: string; role: Role };
  people: Person[];
  roles: Role[];
  can: Capabilities;
}

type Req = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createPeopleApi(request: Req) {
  return {
    list: (signal?: AbortSignal) => request<PeopleView>('GET', '/v1/people', undefined, signal),
    setRole: (id: string, role: Role) => request<{ id: string; role: Role; was: Role }>('PUT', `/v1/people/${encodeURIComponent(id)}/role`, { role }),
  };
}

export type PeopleApi = ReturnType<typeof createPeopleApi>;
