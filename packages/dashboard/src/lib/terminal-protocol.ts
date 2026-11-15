/** The terminal's wire format and the small rules around it. Pure: no DOM, no network. */

/** Frames: `[type u8][length u32 big-endian][payload]`. The same ones the box speaks, plus three from the server. */
export const F = { NOOP: 0, DATA: 1, RESIZE: 2, CLOSE: 3, EXIT: 4, READY: 5, ERROR: 6 } as const;

export interface Frame {
  type: number;
  payload: Uint8Array;
}

export const MAX_FRAME = 64 * 1024;

export function encodeFrame(type: number, payload: Uint8Array = new Uint8Array(0)): Uint8Array {
  if (payload.length > MAX_FRAME) throw new Error('frame too large');
  const out = new Uint8Array(5 + payload.length);
  out[0] = type;
  new DataView(out.buffer).setUint32(1, payload.length);
  out.set(payload, 5);
  return out;
}

export const resizeFrame = (cols: number, rows: number): Uint8Array => {
  const p = new Uint8Array(4);
  const v = new DataView(p.buffer);
  v.setUint16(0, Math.max(1, Math.min(65535, Math.floor(cols))));
  v.setUint16(2, Math.max(1, Math.min(65535, Math.floor(rows))));
  return encodeFrame(F.RESIZE, p);
};

export const dataFrame = (text: string): Uint8Array => encodeFrame(F.DATA, new TextEncoder().encode(text));

/** Reassembles frames from arbitrary chunks of the response body. */
export class FrameReader {
  private buf = new Uint8Array(0);

  push(chunk: Uint8Array): Frame[] {
    const joined = new Uint8Array(this.buf.length + chunk.length);
    joined.set(this.buf, 0);
    joined.set(chunk, this.buf.length);
    this.buf = joined;
    const frames: Frame[] = [];
    for (;;) {
      if (this.buf.length < 5) break;
      const len = new DataView(this.buf.buffer, this.buf.byteOffset).getUint32(1);
      if (len > MAX_FRAME) throw new Error('frame too large');
      if (this.buf.length < 5 + len) break;
      frames.push({ type: this.buf[0] ?? 0, payload: this.buf.slice(5, 5 + len) });
      this.buf = this.buf.slice(5 + len);
    }
    return frames;
  }
}

/** Seconds to wait before reconnect attempt `n` (1-based): 1, 2, 4, 8, 15, then 15. */
export function backoffMs(attempt: number): number {
  return Math.min(15_000, 1000 * 2 ** Math.max(0, attempt - 1));
}

export const MAX_RECONNECTS = 8;

/** What the screen shows. */
export type TermState = 'connecting' | 'live' | 'reconnecting' | 'ended' | 'failed';

export type TermEvent =
  | { type: 'ready' }
  | { type: 'lost' }
  | { type: 'exit' }
  | { type: 'error'; fatal: boolean }
  | { type: 'retry' };

export function nextState(state: TermState, e: TermEvent, attempt: number): TermState {
  switch (e.type) {
    case 'ready':
      return 'live';
    case 'exit':
      return 'ended';
    case 'error':
      // A fatal error (not permitted, no terminal on this box) stops. Another one (all places taken, the box agent
      // starting) is tried again after a pause, up to the limit.
      return e.fatal ? 'failed' : state === 'ended' ? state : attempt >= MAX_RECONNECTS ? 'failed' : 'reconnecting';
    case 'lost':
      return state === 'ended' || state === 'failed' ? state : attempt >= MAX_RECONNECTS ? 'failed' : 'reconnecting';
    case 'retry':
      return state === 'reconnecting' ? 'connecting' : state;
  }
}

/** Keys of the phone key bar. */
export const KEYS = {
  esc: '\x1b',
  tab: '\t',
  up: '\x1b[A',
  down: '\x1b[B',
  right: '\x1b[C',
  left: '\x1b[D',
} as const;

/** With Ctrl armed, the next single character becomes its control code (`c` -> 0x03); anything else passes through. */
export function applyCtrl(data: string): string {
  if (data.length !== 1) return data;
  const c = data.charCodeAt(0);
  if (c >= 0x40 && c <= 0x7e) return String.fromCharCode(c & 0x1f);
  if (data === ' ') return '\x00';
  return data;
}

/** Only web addresses open from the terminal's links. */
export function safeLink(raw: string): string | null {
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null;
  } catch {
    return null;
  }
}

export const FONT_SIZES = [11, 12, 13, 14, 16, 18, 20] as const;

export function stepFont(current: number, dir: 1 | -1): number {
  const i = FONT_SIZES.findIndex((s) => s >= current);
  const at = i === -1 ? FONT_SIZES.length - 1 : i;
  return FONT_SIZES[Math.max(0, Math.min(FONT_SIZES.length - 1, at + dir))] ?? 13;
}
