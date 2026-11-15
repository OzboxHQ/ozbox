/** A minimal reader for a server-sent event stream. Pure parsing here; the fetch loop is in `startEvents`. */

export interface SseEvent {
  event: string;
  data: string;
}

/** Split buffered text into complete events; returns the events and the unfinished remainder. */
export function parseSse(buffer: string): { events: SseEvent[]; rest: string } {
  const events: SseEvent[] = [];
  const parts = buffer.replace(/\r\n/g, '\n').split('\n\n');
  const rest = parts.pop() ?? '';
  for (const block of parts) {
    let event = 'message';
    const data: string[] = [];
    for (const line of block.split('\n')) {
      if (line.startsWith(':')) continue; // a comment: the keepalive
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) data.push(line.slice(5).trim());
    }
    if (block.split('\n').some((l) => !l.startsWith(':') && l.trim() !== '')) events.push({ event, data: data.join('\n') });
  }
  return { events, rest };
}

export interface EventsSource {
  /** Opens the stream through the dashboard's one transport (so it carries the sign-in like every other call). */
  open(signal: AbortSignal): Promise<Response>;
}

/** Keep a stream open, reconnecting with a pause, until `signal` aborts. */
export function startEvents(source: EventsSource, onEvent: (e: SseEvent) => void, signal: AbortSignal): void {
  const loop = async () => {
    while (!signal.aborted) {
      try {
        const res = await source.open(signal);
        if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const { events, rest } = parseSse(buf);
          buf = rest;
          events.forEach(onEvent);
        }
      } catch {
        if (signal.aborted) return;
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
  };
  void loop();
}
