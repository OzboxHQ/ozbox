import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useApp } from '../../App';
import { ApiError } from '../../api/error';
import { openTerminal, type TerminalConnection, type TerminalTarget } from '../../api/terminal';
import { SourceNote } from '../source-badge';
import { t } from '../../lib/i18n';
import { decidePaste, readClipboardText } from '../../lib/terminal-paste';
import { browserClipboard, copyOnClick, writeClipboard } from '../../lib/clipboard';
import { clipboardKeyAction, decideOsc52, hasRecentActivation, isMacPlatform, MAX_OSC52_CHARS, parseOsc52, screenText } from '../../lib/terminal-clipboard';
import { CopySheet } from './copy-sheet';
import { PasteSheet } from './paste-sheet';
import { applyCtrl, backoffMs, KEYS, MAX_RECONNECTS, nextState, safeLink, stepFont, type TermState } from '../../lib/terminal-protocol';

const FONT_KEY = 'ozbox.term.font';

function savedFont(): number {
  try {
    const v = Number(window.localStorage.getItem(FONT_KEY));
    return Number.isFinite(v) && v >= 10 && v <= 24 ? v : 13;
  } catch {
    return 13;
  }
}

/** Lines of the screen (and its scrollback) the Copy box shows at most. */
const COPY_BOX_LINES = 2_000;

/** A copy a program on the box asked for and the browser would not take without a click: offered with a Copy button. */
function offerCopy(text: string) {
  toast(t('terminal.osc_ask', { chars: text.length.toLocaleString() }), {
    duration: 15_000,
    action: {
      label: t('terminal.osc_ask_action'),
      onClick: () => {
        void copyOnClick(text).then((r) => toast(r === 'copied' ? t('terminal.osc_copied') : t('terminal.copy_failed')));
      },
    },
  });
}

/** The control style for this screen: 44 px on touch widths, compact from lg. */
const BAR_BUTTON = 'h-11 min-w-11 px-3 lg:h-8 lg:min-w-8 lg:px-2';

/** `session`: attach one of the box user's existing tmux sessions (the Code panel's Open) instead of the shared terminal. */
export function TerminalView({ box, className, session }: { box: string; className?: string; session?: string }) {
  const { client } = useApp();
  const host = useRef<HTMLDivElement | null>(null);
  const term = useRef<Terminal | null>(null);
  const conn = useRef<TerminalConnection | null>(null);
  const ctrl = useRef(false);
  const [state, setState] = useState<TermState>('connecting');
  const [reason, setReason] = useState('');
  const [wait, setWait] = useState(0);
  const [ctrlOn, setCtrlOn] = useState(false);
  const [font, setFont] = useState(savedFont);
  const [epoch, setEpoch] = useState(0);
  // Who the server says it opened: the box, and whether the shell is real or a demo. Set when a connection opens, kept while it is lost.
  const [target, setTarget] = useState<TerminalTarget | null>(null);
  const [manualPaste, setManualPaste] = useState(false);
  // The Copy box's text, when it is open.
  const [copyBox, setCopyBox] = useState<string | null>(null);
  const mac = isMacPlatform(typeof navigator === 'undefined' ? undefined : navigator);

  // The paste box closing hands the keyboard back to the shell in the same commit that removes the box. The dialog's own
  // focus return runs a timer later, and a key typed in between (Enter, to run the pasted line) went to the page, not the shell.
  const pasteWasOpen = useRef(false);
  useLayoutEffect(() => {
    if (pasteWasOpen.current && !manualPaste) term.current?.focus();
    pasteWasOpen.current = manualPaste;
  }, [manualPaste]);
  const copyWasOpen = useRef(false);
  useLayoutEffect(() => {
    if (copyWasOpen.current && copyBox === null) term.current?.focus();
    copyWasOpen.current = copyBox !== null;
  }, [copyBox]);

  const send = useCallback((text: string) => {
    conn.current?.send(ctrl.current ? applyCtrl(text) : text);
    if (ctrl.current) {
      ctrl.current = false;
      setCtrlOn(false);
    }
  }, []);

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const xterm = new Terminal({
      cursorBlink: true,
      fontSize: savedFont(),
      scrollback: 5000,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      theme: { background: '#0b0d10', foreground: '#e6e6e6' },
      // with a program that uses the mouse (tmux), Option-drag on a Mac selects here, as Shift-drag does elsewhere
      macOptionClickForcesSelection: true,
    });
    const fit = new FitAddon();
    xterm.loadAddon(fit);
    xterm.loadAddon(
      new WebLinksAddon((_e, uri) => {
        const safe = safeLink(uri);
        if (safe) window.open(safe, '_blank', 'noopener,noreferrer');
      }),
    );
    xterm.open(el);
    term.current = xterm;

    // Copy and paste keys, one keymap per computer (see lib/terminal-clipboard.ts). Paste is always the browser's own.
    const isMac = isMacPlatform(navigator);
    let clearAfterCopy = false;
    xterm.attachCustomKeyEventHandler((ev) => {
      const action = clipboardKeyAction(ev, { mac: isMac, hasSelection: xterm.hasSelection() });
      if (action === 'terminal') return true;
      if (action === 'page-copy') {
        ev.preventDefault();
        const sel = xterm.getSelection();
        const { clipboard, activation } = browserClipboard();
        void writeClipboard(sel, clipboard, activation).then((r) => {
          if (r === 'copied') xterm.clearSelection();
          else toast(t('terminal.copy_failed'));
        });
        return false;
      }
      // Ctrl+C that copied clears the selection, so the next Ctrl+C stops the running command again.
      if (action === 'browser-copy' && !isMac) clearAfterCopy = true;
      return false;
    });
    const afterCopy = () => {
      if (!clearAfterCopy) return;
      clearAfterCopy = false;
      window.setTimeout(() => xterm.clearSelection(), 0);
    };
    el.addEventListener('copy', afterCopy);

    // The person's own key presses and clicks: a copy a program on the box asks for is written only right after one.
    let lastGesture = 0;
    const gesture = () => {
      lastGesture = Date.now();
    };
    el.addEventListener('keydown', gesture, true);
    el.addEventListener('pointerdown', gesture, true);
    // OSC 52 from the box: tmux's mouse selection and copy mode, an editor's yank. Written, asked about, or refused for size;
    // a request to read the clipboard is swallowed and never answered.
    const osc52 = xterm.parser.registerOscHandler(52, (data) => {
      const { clipboard, activation } = browserClipboard();
      const d = decideOsc52(parseOsc52(data), hasRecentActivation(activation, lastGesture, Date.now()));
      if (d.kind === 'write') {
        void writeClipboard(d.text, clipboard, activation).then((r) => (r === 'copied' ? toast(t('terminal.osc_copied')) : offerCopy(d.text)));
      } else if (d.kind === 'ask') offerCopy(d.text);
      else if (d.kind === 'too_large') toast(t('terminal.osc_too_large', { chars: d.chars.toLocaleString(), max: MAX_OSC52_CHARS.toLocaleString() }));
      return true;
    });
    const refit = () => {
      try {
        fit.fit();
        conn.current?.resize(xterm.cols, xterm.rows);
      } catch {
        // not laid out yet
      }
    };
    refit();
    const observer = new ResizeObserver(refit);
    observer.observe(el);
    const typed = xterm.onData(send);

    let attempt = 0;
    let timer: number | undefined;
    let disposed = false;
    let current: TerminalConnection | null = null;
    let status: TermState = 'connecting';
    const set = (next: TermState) => {
      status = next;
      setState(next);
    };

    const schedule = () => {
      attempt += 1;
      const ms = backoffMs(attempt);
      setWait(Math.ceil(ms / 1000));
      conn.current = null;
      timer = window.setTimeout(() => {
        set(nextState(status, { type: 'retry' }, attempt));
        void connect();
      }, ms);
    };

    const connect = async (): Promise<void> => {
      if (disposed) return;
      set('connecting');
      setTarget(null);
      xterm.reset();
      try {
        const c = await openTerminal(
          box,
          xterm.cols,
          xterm.rows,
          {
            onReady: () => {
              attempt = 0;
              set(nextState(status, { type: 'ready' }, attempt));
              conn.current = current;
              refit();
              xterm.focus();
            },
            onData: (b) => xterm.write(b),
            onExit: () => set(nextState(status, { type: 'exit' }, attempt)),
            onError: (message, fatal) => {
              setReason(message);
              set(nextState(status, { type: 'error', fatal }, attempt));
              if (!fatal && status === 'reconnecting') schedule();
            },
            onLost: () => {
              set(nextState(status, { type: 'lost' }, attempt));
              if (status === 'reconnecting') schedule();
            },
          },
          client.transport,
          session,
          setTarget,
        );
        current = c;
        if (disposed) void c.close();
      } catch (e) {
        if (disposed) return;
        const fatal = e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 429;
        setReason(e instanceof Error ? e.message : '');
        set(nextState(status, { type: 'error', fatal }, attempt));
        // A first connect that failed for a reason that may pass (the box agent starting, a dropped network) tries again.
        if (!fatal && attempt < MAX_RECONNECTS) {
          set('reconnecting');
          schedule();
        }
      }
    };
    void connect();
    // Closing or leaving the page ends the session now, so it does not hold one of the box's places.
    const leave = () => void current?.close();
    window.addEventListener('pagehide', leave);

    return () => {
      window.removeEventListener('pagehide', leave);
      el.removeEventListener('copy', afterCopy);
      el.removeEventListener('keydown', gesture, true);
      el.removeEventListener('pointerdown', gesture, true);
      osc52.dispose();
      disposed = true;
      window.clearTimeout(timer);
      observer.disconnect();
      typed.dispose();
      void current?.close();
      conn.current = null;
      xterm.dispose();
      term.current = null;
    };
  }, [box, client, send, epoch, session]);

  const changeFont = (dir: 1 | -1) => {
    const next = stepFont(font, dir);
    setFont(next);
    try {
      window.localStorage.setItem(FONT_KEY, String(next));
    } catch {
      // not kept
    }
    const x = term.current;
    if (x) x.options.fontSize = next;
  };

  /** Copy: the selection when there is one; otherwise the Copy box with the screen's text, where anyone can select. */
  const copy = async () => {
    const x = term.current;
    const sel = x?.getSelection() ?? '';
    if (!sel) {
      const b = x?.buffer.active;
      const lines: string[] = [];
      if (b) for (let i = Math.max(0, b.length - COPY_BOX_LINES); i < b.length; i++) lines.push(b.getLine(i)?.translateToString(true) ?? '');
      setCopyBox(screenText(lines));
      return;
    }
    const r = await copyOnClick(sel);
    toast(r === 'copied' ? t('terminal.copied') : r === 'no_gesture' ? t('clipboard.no_gesture') : t('terminal.copy_failed'));
  };

  /** Text on its way to the shell: sent, or said why not. Never dropped quietly. */
  const sendPaste = (text: string) => {
    const d = decidePaste(text);
    if (d.kind === 'send') term.current?.paste(d.text);
    else if (d.kind === 'empty') toast(t('terminal.paste_empty'));
    else toast(t('terminal.paste_too_large', { chars: d.chars.toLocaleString() }));
    term.current?.focus();
  };

  const paste = async () => {
    const r = await readClipboardText(navigator.clipboard);
    if (r.kind === 'text') sendPaste(r.text);
    else if (r.kind === 'empty') toast(t('terminal.paste_empty'));
    // The browser would not hand the text over (Firefox before 125, a refused permission, a dismissed bubble): paste into a box.
    else setManualPaste(true);
  };

  const status =
    state === 'connecting'
      ? t('terminal.connecting')
      : state === 'live'
        ? t('terminal.live')
        : state === 'reconnecting'
          ? t('terminal.reconnecting', { seconds: wait })
          : state === 'ended'
            ? t('terminal.ended')
            : t('terminal.failed', { reason: reason || '…' });

  const targetLine = !target
    ? t('terminal.target_connecting', { box })
    : target.source === 'simulated'
      ? t('terminal.target_demo', { box })
      : state === 'live'
        ? t('terminal.target_live', { box })
        : state === 'connecting'
          ? t('terminal.target_connecting', { box })
          : t('terminal.target_lost', { box });

  return (
    <div className={cn('flex min-h-0 flex-col gap-2', className)} data-testid="terminal">
      <SourceNote source={target?.source} what="terminal" />
      <p className="text-sm font-medium" data-testid="terminal-target" data-source={target?.source ?? 'unknown'} data-runs-as={target?.runs_as ?? 'unknown'}>
        {targetLine}
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <p role="status" className="min-w-0 flex-1 text-sm text-muted-foreground" data-testid="terminal-status" data-state={state}>
          {status}
        </p>
        {(state === 'ended' || state === 'failed') && (
          <Button size="sm" className={BAR_BUTTON} onClick={() => setEpoch((n) => n + 1)}>
            {t('terminal.reconnect')}
          </Button>
        )}
        <Button variant="outline" size="sm" className={BAR_BUTTON} onClick={() => changeFont(-1)} aria-label={t('terminal.font_smaller')}>
          A−
        </Button>
        <Button variant="outline" size="sm" className={BAR_BUTTON} onClick={() => changeFont(1)} aria-label={t('terminal.font_larger')}>
          A+
        </Button>
        <Button variant="outline" size="sm" className={BAR_BUTTON} onClick={() => void copy()}>
          {t('terminal.copy')}
        </Button>
        <Button variant="outline" size="sm" className={BAR_BUTTON} onClick={() => void paste()}>
          {t('terminal.paste')}
        </Button>
      </div>
      <div
        ref={host}
        role="group"
        aria-label={t('terminal.screen', { name: box })}
        className="min-h-[280px] flex-1 overflow-hidden rounded-md border bg-[#0b0d10] p-1"
        data-testid="terminal-screen"
      />
      <div role="toolbar" aria-label={t('terminal.keys')} className="flex flex-wrap gap-2 lg:hidden" data-testid="terminal-keys">
        <Button variant="outline" className={BAR_BUTTON} onClick={() => send(KEYS.esc)}>
          {t('terminal.key_esc')}
        </Button>
        <Button variant="outline" className={BAR_BUTTON} onClick={() => send(KEYS.tab)}>
          {t('terminal.key_tab')}
        </Button>
        <Button
          variant={ctrlOn ? 'default' : 'outline'}
          className={BAR_BUTTON}
          aria-pressed={ctrlOn}
          onClick={() => {
            ctrl.current = !ctrl.current;
            setCtrlOn(ctrl.current);
          }}
        >
          {t('terminal.key_ctrl')}
        </Button>
        <Button variant="outline" className={BAR_BUTTON} aria-label={t('terminal.key_left')} onClick={() => send(KEYS.left)}>
          ←
        </Button>
        <Button variant="outline" className={BAR_BUTTON} aria-label={t('terminal.key_down')} onClick={() => send(KEYS.down)}>
          ↓
        </Button>
        <Button variant="outline" className={BAR_BUTTON} aria-label={t('terminal.key_up')} onClick={() => send(KEYS.up)}>
          ↑
        </Button>
        <Button variant="outline" className={BAR_BUTTON} aria-label={t('terminal.key_right')} onClick={() => send(KEYS.right)}>
          →
        </Button>
      </div>
      <p className="text-xs text-muted-foreground" data-testid="terminal-keys-help">
        {t(mac ? 'terminal.keys_mac' : 'terminal.keys_other')}
      </p>
      <p className="text-xs text-muted-foreground">{t('terminal.note')}</p>
      {copyBox !== null && (
        <CopySheet
          text={copyBox}
          onClose={() => setCopyBox(null)}
          returnFocus={() => term.current?.focus()}
          onCopyAll={() => {
            void copyOnClick(copyBox).then((r) => {
              toast(r === 'copied' ? t('terminal.copied') : r === 'no_gesture' ? t('clipboard.no_gesture') : t('terminal.copy_failed'));
              if (r === 'copied') setCopyBox(null);
            });
          }}
        />
      )}
      {manualPaste && (
        <PasteSheet
          onClose={() => setManualPaste(false)}
          returnFocus={() => term.current?.focus()}
          onSend={(text) => {
            setManualPaste(false);
            sendPaste(text);
          }}
        />
      )}
    </div>
  );
}
