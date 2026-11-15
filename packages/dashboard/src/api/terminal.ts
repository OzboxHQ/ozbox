/** One browser terminal: open a session, read its output stream, send input in order, close. */
import { dataFrame, encodeFrame, F, FrameReader, resizeFrame } from '../lib/terminal-protocol';
import { errorFrom } from './error';
import type { Transport } from './transport';

export interface TerminalHandlers {
  onReady(): void;
  onData(bytes: Uint8Array): void;
  /** The shell ended (the person typed `exit`, or the session was idle too long). */
  onExit(): void;
  /** The server could not open it. `fatal` means retrying will not help. */
  onError(message: string, fatal: boolean): void;
  /** The connection ended without an exit: the network or the server went away. */
  onLost(): void;
}

/** What a terminal is told about where it is connected, before any output arrives. */
export interface TerminalTarget {
  box: string;
  /** `simulated`: a demo shell on the computer that runs the server, never the box's own. */
  source: 'live' | 'simulated';
  /** What the shell runs as, in words: the box user for a real box, a demo shell for a simulated one. */
  runs_as: 'box_user' | 'demo';
}

export interface TerminalConnection {
  send(text: string): void;
  resize(cols: number, rows: number): void;
  close(): Promise<void>;
}

/** `attach`: attach that existing tmux session of the box user's instead of the shared one. `onTarget` hears who the server says it opened. */
export async function openTerminal(box: string, cols: number, rows: number, h: TerminalHandlers, tr: Transport, attach?: string, onTarget?: (t: TerminalTarget) => void): Promise<TerminalConnection> {
  const req = (method: string, path: string, body?: BodyInit, ctype?: string, signal?: AbortSignal, keepalive = false): Promise<Response> =>
    tr.send(method, path, { ...(body !== undefined ? { body } : {}), ...(ctype ? { contentType: ctype } : {}), ...(signal ? { signal } : {}), ...(keepalive ? { keepalive: true } : {}) });

  // The open call is JSON like any other: a refusal and an unreachable server read the same here as everywhere.
  const opened = await tr.request<{ session: string; target?: TerminalTarget }>('POST', `/v1/boxes/${encodeURIComponent(box)}/terminal`, attach ? { cols, rows, session: attach } : { cols, rows });
  const { session } = opened;
  if (opened.target) onTarget?.(opened.target);

  const ctl = new AbortController();
  let ended = false;
  let ready = false;
  const finish = () => {
    ended = true;
    ctl.abort();
  };

  // Input goes one call at a time, in order; keystrokes typed while a call is in flight are joined into the next one.
  let queue: Uint8Array[] = [];
  let sending = false;
  const flush = async () => {
    if (sending || ended || !ready) return;
    sending = true;
    try {
      while (queue.length > 0 && !ended) {
        // One call carries at most 48 KiB, well under what the server accepts in a request.
        let size = 0;
        let n = 0;
        while (n < queue.length && (n === 0 || size + (queue[n]?.length ?? 0) <= 48 * 1024)) size += queue[n++]?.length ?? 0;
        const parts = queue.slice(0, n);
        queue = queue.slice(n);
        const body = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
        let at = 0;
        for (const p of parts) {
          body.set(p, at);
          at += p.length;
        }
        const r = await req('POST', `/v1/terminal/${session}/input`, body, 'application/octet-stream');
        if (!r.ok) {
          if (r.status === 404 || r.status === 410) h.onLost();
          finish();
          return;
        }
      }
    } catch {
      if (!ended) {
        finish();
        h.onLost();
      }
    } finally {
      sending = false;
    }
  };
  const push = (frame: Uint8Array) => {
    // A frame is at most 64 KiB; a paste larger than that is split.
    queue.push(frame);
    void flush();
  };

  void (async () => {
    try {
      const out = await req('GET', `/v1/terminal/${session}/output`, undefined, undefined, ctl.signal);
      if (!out.ok || !out.body) {
        const e = await errorFrom(out);
        h.onError(e.message, e.status !== 0 && e.status < 500 && e.status !== 429);
        finish();
        return;
      }
      const reader = out.body.getReader();
      const frames = new FrameReader();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        for (const f of frames.push(value)) {
          if (f.type === F.READY) {
            ready = true;
            h.onReady();
            void flush();
          } else if (f.type === F.DATA) h.onData(f.payload);
          else if (f.type === F.EXIT) {
            finish();
            h.onExit();
            return;
          } else if (f.type === F.ERROR) {
            let message = 'The terminal could not be opened.';
            let fatal = true;
            try {
              const j = JSON.parse(new TextDecoder().decode(f.payload)) as { message?: string; code?: string };
              if (j.message) message = j.message;
              fatal = j.code === 'unsupported';
            } catch {
              // keep the generic message
            }
            finish();
            h.onError(message, fatal);
            return;
          }
        }
      }
      if (!ended) {
        finish();
        h.onLost();
      }
    } catch {
      if (!ended) {
        finish();
        h.onLost();
      }
    }
  })();

  return {
    send: (text) => {
      const bytes = new TextEncoder().encode(text);
      for (let i = 0; i < bytes.length; i += 32 * 1024) push(encodeFrame(F.DATA, bytes.slice(i, i + 32 * 1024)));
    },
    resize: (c, r) => push(resizeFrame(c, r)),
    close: async () => {
      const was = ended;
      finish();
      if (was) return;
      try {
        // keepalive: the request still goes out while the page is being closed or left.
        await req('DELETE', `/v1/terminal/${session}`, undefined, undefined, undefined, true);
      } catch {
        // the server forgets an abandoned session by itself
      }
    },
  };
}

export { dataFrame };
