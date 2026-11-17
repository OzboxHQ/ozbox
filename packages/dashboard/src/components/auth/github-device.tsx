import { useEffect, useRef, useState } from 'react';

import { Button } from '@/components/ui/button';
import type { GithubStart, SessionApi, SessionStatus } from '../../api/session';
import { signInMessage } from '../../lib/auth-errors';
import { t } from '../../lib/i18n';
import { copyAndSay } from '../../lib/copy-and-say';

/** GitHub's device flow: show the code, let the person approve on GitHub, poll at the pace the server sets. */
export function GithubDevice({ api, onStatus, onCancel }: { api: SessionApi; onStatus: (s: SessionStatus) => void; onCancel: () => void }) {
  const [start, setStart] = useState<GithubStart | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const stop = useRef(false);

  useEffect(() => {
    stop.current = false;
    let timer: number | undefined;
    const poll = (flow: string, seconds: number) => {
      timer = window.setTimeout(async () => {
        if (stop.current) return;
        try {
          const r = await api.githubPoll(flow);
          if ('state' in r) return onStatus(r);
          if (r.status === 'pending' || r.status === 'slow_down') {
            setNote(r.status === 'slow_down' ? t('auth.github_slow') : null);
            return poll(flow, r.interval);
          }
          setError(r.status === 'denied' ? t('auth.github_denied') : t('auth.github_expired'));
        } catch (e) {
          setError(signInMessage(e));
        }
      }, seconds * 1000);
    };
    void api
      .githubStart()
      .then((s) => {
        if (stop.current) return;
        setStart(s);
        poll(s.flow, s.interval);
      })
      .catch((e: unknown) => setError(signInMessage(e)));
    return () => {
      stop.current = true;
      window.clearTimeout(timer);
    };
  }, [api, onStatus]);

  // Only GitHub's own address is offered as a link.
  const href = start && start.verification_uri.startsWith('https://github.com/') ? start.verification_uri : null;

  return (
    <section aria-labelledby="gh-title" className="space-y-3 rounded-lg border p-4" data-testid="github-device">
      <h2 id="gh-title" className="text-base font-semibold">
        {t('auth.github_heading')}
      </h2>
      {start && href && (
        <>
          <p className="text-sm">{t('auth.github_step1')}</p>
          <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center break-all text-primary underline-offset-4 hover:underline">
            {href}
          </a>
          <p className="text-sm">{t('auth.github_step2')}</p>
          <div className="flex flex-wrap items-center gap-2">
            <code className="rounded-md bg-muted px-3 py-2 font-mono text-xl tracking-widest" data-testid="github-user-code">
              {start.user_code}
            </code>
            <Button
              variant="outline"
              className="h-11 lg:h-9"
              onClick={() => {
                // the code is shown on the page and typed on GitHub; it is not a secret
                void copyAndSay(start.user_code, { done: t('auth.github_copied'), failed: t('openin.copy_failed', { what: start.user_code }) }).then(setCopied);
              }}
            >
              {copied ? t('auth.github_copied') : t('auth.github_copy')}
            </Button>
          </div>
        </>
      )}
      {!error && (
        <p role="status" className="text-sm text-muted-foreground">
          {note ?? t('auth.github_waiting')}
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button variant="ghost" className="h-11 lg:h-9" onClick={onCancel}>
        {t('auth.github_cancel')}
      </Button>
    </section>
  );
}
