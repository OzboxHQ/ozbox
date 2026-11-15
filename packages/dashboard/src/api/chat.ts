// The dashboard's chat with coding agents: the transcript of the signed-in person's chat, their sessions, the approvals
// waiting for them, and what is linked. The shapes are the ones `/v1/chat` answers with (see
// crates/ozbox-cli/src/serve/chat_routes.rs). The same conversation model serves Telegram, Slack and WhatsApp.

import type { MetricsSource } from './types';
import type { ApprovalRequest, Task } from './tasks';

export interface ChatLine {
  seq: number;
  ts_ms: number;
  who: 'you' | 'agent' | 'system';
  text: string;
  buttons: { label: string; value: string }[];
}

/** What the chat follows: a supervised session, or a live terminal session (experimental). */
export type ChatBind = { kind: 'task'; id: string } | { kind: 'terminal'; box_name: string; session: string; force: boolean } | null;

export interface ChatLinkRow {
  id: string;
  name: string;
}

export interface ChatChannels {
  telegram: { enabled: boolean; chats: number };
  slack: { enabled: boolean; configured: boolean; links: ChatLinkRow[] };
  whatsapp: { enabled: boolean; configured: boolean; links: ChatLinkRow[] };
}

export interface ChatOverview {
  person: string;
  bound: ChatBind;
  sessions: Task[];
  approvals: ApprovalRequest[];
  messages: ChatLine[];
  last_seq: number;
  channels: ChatChannels;
  /** `simulated` when this server is a demo: the agent answering is a stand-in. */
  source: MetricsSource;
  /** False when the server keeps no task store: a session cannot start. */
  runs_available: boolean;
  /** False when the dashboard has no public address, so a chat app is sent words and no link. */
  public_url_set: boolean;
  /** Where the dashboard transcript is kept, how much of it, and who sees it. */
  transcript: { kept: 'memory'; lines: number; visible_to: 'you' };
}

type Req = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body?: unknown, signal?: AbortSignal) => Promise<T>;

export function createChatApi(request: Req) {
  return {
    overview: (after = 0, s?: AbortSignal) => request<ChatOverview>('GET', `/v1/chat?after=${after}`, undefined, s),
    send: (text: string) => request<{ accepted: boolean }>('POST', '/v1/chat/messages', { text }),
    bind: (task: string | null) => request<{ bound: ChatBind }>('POST', '/v1/chat/bind', { task }),
    pairing: (channel: 'slack' | 'whatsapp') => request<{ channel: string; code: string; expires_in_s: number }>('POST', '/v1/chat/pairing', { channel }),
    unlink: (channel: 'slack' | 'whatsapp', id: string) => request<{ removed: boolean }>('DELETE', `/v1/chat/links/${channel}/${encodeURIComponent(id)}`),
    redeem: (token: string) => request<{ approval_id: string; pending: boolean; approval: ApprovalRequest }>('POST', '/v1/chat/links/redeem', { token }),
  };
}

export type ChatApi = ReturnType<typeof createChatApi>;
