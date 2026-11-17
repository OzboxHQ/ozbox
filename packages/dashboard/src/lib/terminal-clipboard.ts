/**
 * Copy and paste in the dashboard's terminal: the keymap and the OSC 52 rules. Pure: the browser is passed in.
 *
 * One keymap per computer, the same as the browser IDE's terminal (the CLI ships that one):
 *
 * |            | macOS                   | Windows and Linux                                           |
 * |------------|-------------------------|-------------------------------------------------------------|
 * | copy       | Cmd+C                   | Ctrl+C while text is selected, Ctrl+Shift+C, Ctrl+Insert   |
 * | interrupt  | Ctrl+C                  | Ctrl+C with nothing selected                                |
 * | paste      | Cmd+V                   | Ctrl+V, Ctrl+Shift+V, Shift+Insert                          |
 *
 * Paste is always the browser's own paste (a `paste` event): it needs no permission in any browser and the terminal brackets
 * multi-line text for the shell. Left alone, the terminal would turn Ctrl+V into the shell's literal-next key (^V) and paste
 * nothing, which is what Windows and Linux people met before.
 *
 * Copy is the browser's own copy for the keys whose browser default is copy (Cmd+C, Ctrl+C, Ctrl+Insert), and a copy the
 * page makes for Ctrl+Shift+C, whose browser default opens the developer tools.
 *
 * A program on the box (tmux's mouse selection, copy mode, an editor) copies with an OSC 52 sequence. The page writes it to
 * the clipboard only while the person has just pressed a key or clicked (the browser's own user-activation rule, and ours
 * where the browser has none); otherwise it asks, with a Copy button. A request to READ the clipboard is never answered: a
 * program on the box never sees what is on the person's clipboard.
 */

export type ClipboardKeyAction =
  /** Let the terminal have the key (Ctrl+C as the interrupt, everything else). */
  | 'terminal'
  /** Let the browser copy the selection (its default for this key); the terminal must not see it. */
  | 'browser-copy'
  /** The page copies the selection itself and stops the browser's default for this key. */
  | 'page-copy'
  /** Let the browser paste (its default for this key); the terminal must not see it. */
  | 'browser-paste';

export interface KeyLike {
  type: string;
  key: string;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  metaKey: boolean;
}

/** Is this a Mac keyboard (Cmd for copy and paste)? An iPad with a keyboard says Mac too, and uses Cmd. */
export function isMacPlatform(nav: { platform?: string; userAgent?: string; userAgentData?: { platform?: string } } | undefined): boolean {
  const p = nav?.userAgentData?.platform || nav?.platform || nav?.userAgent || '';
  return /mac|iphone|ipad|ipod/i.test(p);
}

/** What one key press means for the clipboard. Only `keydown` decides; the rest go to the terminal. */
export function clipboardKeyAction(ev: KeyLike, ctx: { mac: boolean; hasSelection: boolean }): ClipboardKeyAction {
  if (ev.type !== 'keydown') return 'terminal';
  const k = ev.key.length === 1 ? ev.key.toLowerCase() : ev.key;
  if (ctx.mac) {
    if (ev.metaKey && !ev.ctrlKey && !ev.altKey && !ev.shiftKey) {
      if (k === 'c') return ctx.hasSelection ? 'browser-copy' : 'terminal';
      if (k === 'v') return 'browser-paste';
    }
    return 'terminal';
  }
  if (ev.metaKey || ev.altKey) return 'terminal';
  if (ev.ctrlKey && ev.shiftKey) {
    if (k === 'c') return ctx.hasSelection ? 'page-copy' : 'terminal';
    if (k === 'v') return 'browser-paste';
    return 'terminal';
  }
  if (ev.ctrlKey) {
    if (k === 'c') return ctx.hasSelection ? 'browser-copy' : 'terminal';
    if (k === 'v') return 'browser-paste';
    if (k === 'Insert') return ctx.hasSelection ? 'browser-copy' : 'terminal';
    return 'terminal';
  }
  if (ev.shiftKey && k === 'Insert') return 'browser-paste';
  return 'terminal';
}

/** Most text one OSC 52 copy may carry (after decoding). Longer is refused with a message, never cut short silently. */
export const MAX_OSC52_CHARS = 1_000_000;

export type Osc52 =
  | { kind: 'write'; text: string }
  /** `?`: a program asks what is on the clipboard. Never answered. */
  | { kind: 'query' }
  /** An empty payload or text that is not base64: nothing to do. */
  | { kind: 'ignore' }
  | { kind: 'too_large'; chars: number };

/** Read the data of an OSC 52 sequence (`Pc;Pd`): a selection name, then base64 text, `?` or nothing. */
export function parseOsc52(data: string): Osc52 {
  const semi = data.indexOf(';');
  if (semi < 0) return { kind: 'ignore' };
  const payload = data.slice(semi + 1);
  if (payload === '?') return { kind: 'query' };
  if (payload === '') return { kind: 'ignore' };
  // a quick bound before decoding anything: base64 is 4 characters for every 3 bytes
  const roughChars = Math.floor((payload.length * 3) / 4);
  if (roughChars > MAX_OSC52_CHARS * 4) return { kind: 'too_large', chars: roughChars };
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(payload) || payload.length % 4 === 1) return { kind: 'ignore' };
  let bytes: Uint8Array;
  try {
    const bin = atob(payload);
    bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return { kind: 'ignore' };
  }
  const text = new TextDecoder().decode(bytes);
  if (text.length > MAX_OSC52_CHARS) return { kind: 'too_large', chars: text.length };
  return text ? { kind: 'write', text } : { kind: 'ignore' };
}

/**
 * Tracks the person's own key presses and clicks, so a copy from the box is written only right after one. A browser with
 * `navigator.userActivation` is asked; one without it (older Firefox) gets the same rule from this record: five seconds,
 * the length Firefox itself allows.
 */
export const ACTIVATION_MS = 5_000;

export function hasRecentActivation(
  userActivation: { isActive?: boolean } | undefined | null,
  lastGestureAt: number,
  now: number,
): boolean {
  if (userActivation && typeof userActivation.isActive === 'boolean') return userActivation.isActive;
  return lastGestureAt > 0 && now - lastGestureAt <= ACTIVATION_MS;
}

/** What to do with a copy a program on the box asked for. */
export type Osc52Decision = { kind: 'write'; text: string } | { kind: 'ask'; text: string } | { kind: 'too_large'; chars: number } | { kind: 'nothing' };

export function decideOsc52(parsed: Osc52, activeNow: boolean): Osc52Decision {
  if (parsed.kind === 'write') return activeNow ? { kind: 'write', text: parsed.text } : { kind: 'ask', text: parsed.text };
  if (parsed.kind === 'too_large') return { kind: 'too_large', chars: parsed.chars };
  return { kind: 'nothing' };
}

/** The lines on the terminal's screen, for the Copy box (where a phone or a tablet selects text with a long press). */
export function screenText(lines: string[]): string {
  const trimmed = lines.map((l) => l.replace(/\s+$/, ''));
  while (trimmed.length && trimmed[trimmed.length - 1] === '') trimmed.pop();
  while (trimmed.length && trimmed[0] === '') trimmed.shift();
  return trimmed.join('\n');
}
