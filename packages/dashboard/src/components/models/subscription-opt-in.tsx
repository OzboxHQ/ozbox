import { useEffect, useId, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ApiError } from '../../api/client';
import type { RevokeResult, SignInState, SubscriptionOptInState } from '../../api/subscriptions';
import { useApp } from '../../App';
import { en } from '../../i18n/en';
import { t } from '../../lib/i18n';
import { optInConfirmed, signInFailedKey, vendorLink } from '../../lib/models';
import { withStepUp } from '../perm/with-step-up';

const has = (k: string) => k in en;
/** The vendor hosts a sign-in link may point at (the server checks the same list). */
const LINK_HOSTS = ['openai.com', 'chatgpt.com'] as const;

function message(e: unknown): string {
  return e instanceof ApiError ? e.message : t('common.request_failed');
}

/**
 * The owner's opt-in for one engine that must read its own subscription sign-in (ADR 0055). Off by default. Turning it on
 * shows exactly what an agent could read, needs the word typed back and a passkey; signing in runs the vendor's own device
 * sign-in (the link and code come from the vendor); revoking deletes it here and points at the vendor's page to revoke it
 * there too.
 */
export function SubscriptionOptIn({ state, reload }: { state: SubscriptionOptInState; reload: () => void }) {
  const { client } = useApp();
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [flow, setFlow] = useState<SignInState | null>(null);
  const [asking, setAsking] = useState(false);
  const [revoked, setRevoked] = useState<RevokeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputId = useId();
  const warnId = useId();
  const polling = flow?.sign_in === 'starting' || flow?.sign_in === 'waiting';

  useEffect(() => {
    if (!polling) return;
    const ctl = new AbortController();
    const timer = setInterval(() => {
      client.subscriptions
        .signInState(state.id, ctl.signal)
        .then((f) => {
          setFlow(f);
          if (f.sign_in === 'done') {
            toast.success(t('models.signin_done'));
            reload();
          }
        })
        .catch(() => undefined);
    }, 1500);
    return () => {
      clearInterval(timer);
      ctl.abort();
    };
  }, [client, polling, reload, state.id]);

  async function act(run: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await run();
    } catch (e) {
      const m = message(e);
      setError(m);
      toast.error(m);
    } finally {
      setBusy(false);
    }
  }

  const turnOn = () =>
    act(async () => {
      await withStepUp(() => client.subscriptions.optIn(state.id, typed));
      setTyped('');
      setRevoked(null);
      toast.success(t('models.optin_turned_on'));
      reload();
    });

  const signIn = () =>
    act(async () => {
      await withStepUp(() => client.subscriptions.startSignIn(state.id));
      setFlow({ id: state.id, sign_in: 'starting' });
    });

  async function revoke() {
    try {
      const r = await client.subscriptions.revoke(state.id);
      setRevoked(r);
      setFlow(null);
      toast.success(t('models.revoked'));
      reload();
    } catch (e) {
      toast.error(message(e));
      throw e;
    }
  }

  const link = vendorLink(flow?.link, LINK_HOSTS);
  return (
    <div className="space-y-3 rounded-md border border-dashed p-3" data-testid={`subscription-optin-${state.id}`}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={state.opted_in ? 'default' : 'outline'} data-testid="optin-state">
          {state.opted_in ? t('models.optin_on') : t('models.optin_off')}
        </Badge>
        {state.signed_in ? <Badge variant="secondary">{t('models.optin_signed_in')}</Badge> : null}
      </div>

      {!state.opted_in ? (
        <>
          <div id={warnId} className="space-y-2 rounded-md border border-destructive/50 bg-destructive/5 p-3" data-testid="optin-warning">
            <h4 className="text-sm font-semibold">{t('models.optin_warning_title')}</h4>
            <p className="text-sm">{t('models.optin_warning')}</p>
            <p className="text-xs text-muted-foreground">{t('models.optin_controls')}</p>
          </div>
          <div className="space-y-1">
            <Label htmlFor={inputId}>{t('models.optin_type', { word: state.confirm })}</Label>
            <Input
              id={inputId}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              aria-describedby={warnId}
              className="max-lg:h-11"
              value={typed}
              disabled={busy}
              onChange={(e) => setTyped(e.target.value)}
              data-testid="optin-confirm"
            />
          </div>
          <Button
            className="w-full max-lg:h-11 sm:w-auto"
            disabled={busy || !optInConfirmed(typed, state.confirm)}
            onClick={() => void turnOn()}
            data-testid="optin-turn-on"
          >
            {t('models.optin_turn_on')}
          </Button>
        </>
      ) : (
        <>
          <p className="text-xs text-muted-foreground">{t('models.optin_on_note')}</p>
          {!state.signed_in && !polling ? (
            <Button className="w-full max-lg:h-11 sm:w-auto" disabled={busy} onClick={() => void signIn()} data-testid="signin-start">
              {t('models.signin_start')}
            </Button>
          ) : null}
          <div aria-live="polite" className="space-y-2">
            {flow?.sign_in === 'starting' ? <p className="text-sm">{t('models.signin_starting')}</p> : null}
            {flow?.sign_in === 'waiting' && link && flow.code ? (
              <div className="space-y-2 rounded-md border p-3" data-testid="signin-waiting">
                <p className="text-sm">{t('models.signin_waiting')}</p>
                <a
                  href={link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex min-h-11 items-center text-sm font-medium underline underline-offset-2 lg:min-h-0"
                >
                  {t('models.signin_open')}
                </a>
                <p className="text-xs text-muted-foreground">{t('models.signin_code')}</p>
                <p className="select-all break-all font-mono text-2xl font-semibold tracking-widest" data-testid="signin-code">
                  {flow.code}
                </p>
              </div>
            ) : null}
            {flow?.sign_in === 'failed' ? (
              <p role="alert" className="text-sm text-destructive">
                {t('models.signin_failed', { reason: t(signInFailedKey(flow.reason, has)) })}
              </p>
            ) : null}
          </div>
          <Button variant="destructive" className="w-full max-lg:h-11 sm:w-auto" disabled={busy} onClick={() => setAsking(true)} data-testid="optin-revoke">
            {t('models.revoke')}
          </Button>
        </>
      )}

      {revoked ? (
        <div role="status" className="space-y-1 rounded-md border p-3 text-sm" data-testid="revoked-note">
          <p>{t('models.revoked')}</p>
          {revoked.runs_holding.length > 0 ? (
            <p>{t('models.revoked_runs', { n: revoked.runs_holding.length, ids: revoked.runs_holding.join(', ') })}</p>
          ) : null}
          {revoked.revoke_at.startsWith('https://') ? (
            <a href={revoked.revoke_at} target="_blank" rel="noopener noreferrer" className="inline-flex min-h-11 items-center font-medium underline underline-offset-2 lg:min-h-0">
              {t('models.revoke_at')}
            </a>
          ) : null}
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="text-sm text-destructive" data-testid="optin-error">
          {error}
        </p>
      ) : null}

      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        title={t('models.revoke_title')}
        description={t('models.revoke_body')}
        confirmLabel={t('models.revoke')}
        destructive
        onConfirm={revoke}
      />
    </div>
  );
}
