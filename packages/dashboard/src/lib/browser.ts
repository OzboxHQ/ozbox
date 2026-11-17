import type { PointerEvent } from '../api/browser';

/** A browser approval as a person should read it: where, what it would do, and the fields with secrets masked. */
export interface BrowserApproval {
  tool: string;
  reason: string;
  host: string;
  action: string;
  /** Where it would go: the host and path a form is sent to, a site, a file. Empty when the approval does not say. */
  dest: string;
  /** A short check of what was shown. If the page changes what the step is aimed at, the browser refuses the approval. */
  check: string;
  fields: { name: string; value: string; masked: boolean }[];
}

const MASKED = '[masked]';
// the approvals layer hides a value named like a secret on its own, so either word means the value is not shown
const HIDDEN = '[hidden]';

/**
 * The approval text is `browser.<tool>: <reason> on <host>: <action> -> <destination> (check <hex>) [name=value, ...]`, the
 * destination, check and fields each optional (see `approval_summary` in browser_tools.rs). Field names never hold `=`, `,`
 * or brackets: the worker replaces them, so a page cannot make one field look like two.
 */
export function parseBrowserApproval(text: string): BrowserApproval | null {
  const m = /^browser\.(browser_\w+): (.*?) on ([^:\s]*): (\w+)(?: -> (\S+))?(?: \(check ([0-9a-f]+)\))?(?: \[(.*)\])?$/s.exec(text);
  if (!m) return null;
  const [, tool, reason, host, action, dest, check, rest] = m;
  const fields = (rest ?? '')
    .split(/, (?=[\w.-]+=)/)
    .filter((p) => p.length > 0)
    .map((p) => {
      const i = p.indexOf('=');
      const value = i < 0 ? '' : p.slice(i + 1);
      return { name: i < 0 ? p : p.slice(0, i), value, masked: value === MASKED || value === HIDDEN };
    });
  return { tool: tool ?? '', reason: reason ?? '', host: host ?? '', action: action ?? '', dest: dest ?? '', check: check ?? '', fields };
}

/** A click on the picture, put back in the page's own coordinates (the picture is scaled to fit its box). */
export function toPagePoint(ev: { clientX: number; clientY: number }, img: { getBoundingClientRect(): DOMRect; naturalWidth: number }, pageWidth: number): Pick<PointerEvent, 'x' | 'y'> {
  const r = img.getBoundingClientRect();
  const scale = pageWidth / Math.max(r.width, 1);
  return { x: Math.round((ev.clientX - r.left) * scale), y: Math.round((ev.clientY - r.top) * scale) };
}

/** The key name the worker understands for a keyboard event, or null when it is a modifier on its own. */
export function keyName(e: { key: string; ctrlKey: boolean; metaKey: boolean; altKey: boolean }): string | null {
  if (['Shift', 'Control', 'Alt', 'Meta', 'CapsLock'].includes(e.key)) return null;
  const mods = [e.ctrlKey ? 'Control' : '', e.altKey ? 'Alt' : '', e.metaKey ? 'Meta' : ''].filter(Boolean);
  const base = e.key === ' ' ? 'Space' : e.key;
  return [...mods, base].join('+');
}

/**
 * Whether the live view's page is the browser's empty start page (`about:blank`, which the server names `about:`). Its picture
 * is plain white, so the live view says that nothing is open yet instead of showing a white box.
 */
export function isBlankPage(page: string | undefined): boolean {
  return page === 'about:' || page === 'about:blank';
}
