/**
 * Reading the clipboard for the terminal's Paste button. Pure: the clipboard is passed in.
 *
 * The async Clipboard API is not the same in every browser, which is why a bare `readText()` failed for people on Firefox:
 *  - Chrome asks for the `clipboard-read` permission once.
 *  - Safari and Firefox 125 and later show a small "Paste" bubble that the person must click; dismissing it rejects.
 *  - Firefox before 125 has no `readText` at all, and a locked-down profile (`dom.events.asyncClipboard.readText` off)
 *    behaves the same.
 * A keyboard paste (Ctrl or Cmd+V) always works, in every browser, because the person is the one pasting.
 * So the button tries the API, and when the browser will not hand the text over, it opens a box the person pastes into.
 * A paste is never dropped without saying so.
 */

export type ClipboardRead =
  | { kind: 'text'; text: string }
  | { kind: 'empty' }
  /** The browser has no `readText`, or refused it (permission, dismissed bubble, insecure page). The caller offers the manual box. */
  | { kind: 'manual' };

export interface ClipboardLike {
  readText?: () => Promise<string>;
}

/** Longest paste the terminal takes in one go; a larger one is refused with a message rather than flooding the shell. */
export const MAX_PASTE_CHARS = 1_000_000;

export async function readClipboardText(clipboard: ClipboardLike | undefined | null): Promise<ClipboardRead> {
  if (!clipboard || typeof clipboard.readText !== 'function') return { kind: 'manual' };
  try {
    const text = await clipboard.readText();
    return text ? { kind: 'text', text } : { kind: 'empty' };
  } catch {
    return { kind: 'manual' };
  }
}

/** What to do with text on its way to the shell. */
export type PasteDecision = { kind: 'send'; text: string } | { kind: 'empty' } | { kind: 'too_large'; chars: number };

export function decidePaste(text: string): PasteDecision {
  if (!text) return { kind: 'empty' };
  if (text.length > MAX_PASTE_CHARS) return { kind: 'too_large', chars: text.length };
  return { kind: 'send', text };
}
