/**
 * The one way the dashboard writes to the person's clipboard. Pure: the browser's clipboard and activation are passed in.
 *
 * Two rules every copy follows:
 *  - Only on the person's own click or key press. A copy with no gesture behind it is refused here, even in a browser that
 *    would allow it (Chrome lets a focused page write at any time), so nothing lands on the clipboard by itself.
 *  - A secret (a webhook signing secret, a one-time code, a connection snippet with a token in it, a share link that is its
 *    own key) is copied only from a button that says Copy next to it, and the person is told it is now on their clipboard,
 *    where other apps can read it. The page cannot clear it afterwards without reading the clipboard, which it never does,
 *    so it says to copy something else once it has been pasted.
 *
 * Reading the clipboard is not here: only the terminal's Paste button reads it, and only when pressed.
 */

export type CopyKind = 'text' | 'secret';

export type CopyResult = 'copied' | 'failed' | 'no_gesture';

export interface ClipboardWriter {
  writeText?: (text: string) => Promise<void>;
}

export interface ActivationLike {
  isActive?: boolean;
}

export async function writeClipboard(
  text: string,
  clipboard: ClipboardWriter | undefined | null,
  activation: ActivationLike | undefined | null,
): Promise<CopyResult> {
  // a browser that reports activation is held to it; one that does not (older Firefox) enforces it itself
  if (activation && activation.isActive === false) return 'no_gesture';
  if (!clipboard || typeof clipboard.writeText !== 'function') return 'failed';
  try {
    await clipboard.writeText(text);
    return 'copied';
  } catch {
    return 'failed';
  }
}

/** The browser's own clipboard and activation, for callers in components. */
export function browserClipboard(): { clipboard: ClipboardWriter | undefined; activation: ActivationLike | undefined } {
  if (typeof navigator === 'undefined') return { clipboard: undefined, activation: undefined };
  const nav = navigator as Navigator & { userActivation?: ActivationLike };
  return { clipboard: nav.clipboard, activation: nav.userActivation };
}

/** Copy on a click: call this synchronously from the click handler (before any `await`), so the gesture still counts. */
export function copyOnClick(text: string): Promise<CopyResult> {
  const { clipboard, activation } = browserClipboard();
  return writeClipboard(text, clipboard, activation);
}
