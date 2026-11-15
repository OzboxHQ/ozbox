import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

/**
 * A fake Telegram: the Bot API's `getMe`, `getUpdates`, `getWebhookInfo`, `sendMessage` and `deleteMessage` on a loopback port,
 * with scripted updates and scripted 409 and 429 answers. `ozbox serve` is pointed at it with `OZBOX_TELEGRAM_API_BASE` (the
 * server accepts that variable for a loopback address only), so the program under test is the one that ships and it talks real
 * HTTP to this. It never sees a real token.
 */
export interface FakeTelegram {
  /** `http://127.0.0.1:<port>`, for `OZBOX_TELEGRAM_API_BASE`. */
  url: string;
  /** A person with this Telegram user id writes to the bot in a private chat. Returns the update id. */
  say(from: number, text: string, opts?: { dateSeconds?: number; extra?: Record<string, unknown> }): number;
  /** Everything the bot sent: chat, text and message id. */
  sent(): { chat: number; text: string; id: number }[];
  deleted(): number[];
  /** Every call's method and query, never the token. */
  calls(): string[];
  /** The next `n` polls answer 409 (another reader, or a webhook). */
  conflicts(n: number): void;
  rateLimited(n: number): void;
  setWebhook(url: string | null): void;
  flag(name: 'can_join_groups' | 'can_read_all_group_messages' | 'supports_inline_queries', on: boolean): void;
  close(): Promise<void>;
}

const BOT_ID = 7_000_000_002;

export async function startFakeTelegram(port = 0): Promise<FakeTelegram> {
  const updates: { update_id: number; message: Record<string, unknown> }[] = [];
  const sent: { chat: number; text: string; id: number }[] = [];
  const deleted: number[] = [];
  const calls: string[] = [];
  const flags = { can_join_groups: false, can_read_all_group_messages: false, supports_inline_queries: false };
  let nextUpdate = 100;
  let nextMessage = 1000;
  let conflicts = 0;
  let limited = 0;
  let webhook: string | null = null;

  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const readBody = (req: IncomingMessage) =>
    new Promise<Record<string, unknown>>((done) => {
      let buf = '';
      req.on('data', (d: Buffer) => (buf += d.toString()));
      req.on('end', () => {
        try {
          done(buf ? (JSON.parse(buf) as Record<string, unknown>) : {});
        } catch {
          done({});
        }
      });
    });

  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://x');
      const m = /^\/bot[^/]+\/([A-Za-z]+)$/.exec(url.pathname);
      if (!m) return json(res, 404, {});
      const method = m[1] ?? '';
      calls.push(`${method}?${url.searchParams.toString()}`);
      const body = await readBody(req);
      if (method === 'getMe') return json(res, 200, { ok: true, result: { id: BOT_ID, is_bot: true, username: 'oz_fleet_bot', ...flags } });
      if (method === 'getWebhookInfo') return json(res, 200, { ok: true, result: { url: webhook ?? '' } });
      if (method === 'getUpdates') {
        if (conflicts > 0) {
          conflicts -= 1;
          return json(res, 409, { ok: false, error_code: 409 });
        }
        if (limited > 0) {
          limited -= 1;
          return json(res, 429, { ok: false, error_code: 429, parameters: { retry_after: 1 } });
        }
        const offset = Number(url.searchParams.get('offset') ?? 0);
        const limit = Math.max(1, Math.min(100, Number(url.searchParams.get('limit') ?? 100)));
        // the vendor forgets what is below the offset
        while (updates.length > 0 && (updates[0]?.update_id ?? 0) < offset) updates.shift();
        // a long poll, kept short here: wait up to a second for something to arrive
        const until = Date.now() + 1000;
        while (updates.length === 0 && Date.now() < until) await new Promise((r) => setTimeout(r, 50));
        return json(res, 200, { ok: true, result: updates.slice(0, limit) });
      }
      if (method === 'sendMessage') {
        nextMessage += 1;
        sent.push({ chat: Number(body['chat_id']), text: String(body['text'] ?? ''), id: nextMessage });
        return json(res, 200, { ok: true, result: { message_id: nextMessage } });
      }
      if (method === 'deleteMessage') {
        deleted.push(Number(body['message_id']));
        return json(res, 200, { ok: true, result: true });
      }
      return json(res, 404, {});
    })();
  });
  await new Promise<void>((done) => server.listen(port, '127.0.0.1', done));
  const addr = server.address();
  const bound = typeof addr === 'object' && addr ? addr.port : port;

  return {
    url: `http://127.0.0.1:${bound}`,
    say(from, text, opts = {}) {
      const id = nextUpdate++;
      updates.push({
        update_id: id,
        message: {
          message_id: id,
          date: opts.dateSeconds ?? Math.floor(Date.now() / 1000),
          text,
          chat: { id: from, type: 'private', first_name: 'Ada' },
          from: { id: from, is_bot: false, first_name: 'Ada' },
          ...(opts.extra ?? {}),
        },
      });
      return id;
    },
    sent: () => [...sent],
    deleted: () => [...deleted],
    calls: () => [...calls],
    conflicts(n) {
      conflicts = n;
    },
    rateLimited(n) {
      limited = n;
    },
    setWebhook(u) {
      webhook = u;
    },
    flag(name, on) {
      flags[name] = on;
    },
    close: () => new Promise<void>((done) => server.close(() => done())),
  };
}
