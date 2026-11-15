import { useCallback, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError } from '../api/error';
import type { Account, PasskeyInfo } from '../api/session';
import { PeopleCard } from '../components/auth/people-card';
import { TotpSetup } from '../components/auth/totp-setup';
import { AppPage, EmptyState, PageHeader } from '../components/page';
import { signInMessage } from '../lib/auth-errors';
import { fmtRelative } from '../lib/format';
import { t } from '../lib/i18n';
import { useSession } from '../lib/session-context';
import { askStepUp, STEP_UP_CODE } from '../lib/step-up';
import { useAsync } from '../lib/use-async';
import { createPasskey } from '../lib/webauthn';

/** Run an action; if it needs a fresh passkey, ask for one and try once more. */
async function withStepUp<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (e) {
    if (e instanceof ApiError && e.code === STEP_UP_CODE && (await askStepUp())) return run();
    throw e;
  }
}

const BTN = 'h-11 lg:h-9';

function GithubSetup({ account, onSaved }: { account: Account; onSaved: () => void }) {
  const session = useSession();
  const [id, setId] = useState(account.providers.github.client_id ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!session) return null;
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await withStepUp(() => session.api.setGithub(id.trim()));
      toast(t('account.saved'));
      onSaved();
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <p className="text-sm text-muted-foreground">{t('ghsetup.intro')}</p>
      <ol className="list-decimal space-y-2 pl-5 text-sm">
        <li>{t('ghsetup.step1')}</li>
        <li>
          {t('ghsetup.step2')} <code className="break-all rounded bg-muted px-1">{account.public_origin}</code>
        </li>
        <li>{t('ghsetup.step3')}</li>
        <li>{t('ghsetup.step4')}</li>
      </ol>
      <div className="space-y-1">
        <Label htmlFor="gh-client">{t('ghsetup.client_label')}</Label>
        <Input id="gh-client" value={id} onChange={(e) => setId(e.target.value)} autoComplete="off" className="h-11 font-mono lg:h-10" />
      </div>
      <p className="text-xs text-muted-foreground">{t('ghsetup.note')}</p>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" className={BTN} disabled={busy || !id.trim()}>
        {t('ghsetup.save')}
      </Button>
    </form>
  );
}

function GoogleSetup({ account, onSaved }: { account: Account; onSaved: () => void }) {
  const session = useSession();
  const [id, setId] = useState(account.providers.google.client_id ?? '');
  const [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!session) return null;
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await withStepUp(() => session.api.setGoogle(id.trim(), secret));
      setSecret('');
      toast(t('account.saved'));
      onSaved();
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <p className="text-sm text-muted-foreground">{t('gosetup.intro')}</p>
      <ol className="list-decimal space-y-2 pl-5 text-sm">
        <li>{t('gosetup.step1')}</li>
        <li>
          {t('gosetup.step2')} <code className="break-all rounded bg-muted px-1">{account.callback_url}</code>
        </li>
        <li>{t('gosetup.step3')}</li>
      </ol>
      <div className="space-y-1">
        <Label htmlFor="go-client">{t('gosetup.client_label')}</Label>
        <Input id="go-client" value={id} onChange={(e) => setId(e.target.value)} autoComplete="off" className="h-11 font-mono lg:h-10" />
      </div>
      <div className="space-y-1">
        <Label htmlFor="go-secret">{t('gosetup.secret_label')}</Label>
        <Input className="h-11 lg:h-10" id="go-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" />
        {account.providers.google.secret_set && <p className="text-xs text-muted-foreground">{t('gosetup.secret_set')}</p>}
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" className={BTN} disabled={busy || !id.trim() || (!secret && !account.providers.google.secret_set)}>
        {t('gosetup.save')}
      </Button>
    </form>
  );
}

export function AccountPage() {
  const session = useSession();
  const [version, setVersion] = useState(0);
  const account = useAsync<Account>((s) => (session ? session.api.account(s) : Promise.reject(new Error('no session'))), [session, version]);
  const [removing, setRemoving] = useState<PasskeyInfo | null>(null);
  const [sheet, setSheet] = useState<'github' | 'google' | 'totp' | null>(null);
  const [passkeyName, setPasskeyName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reload = useCallback(() => setVersion((v) => v + 1), []);

  // Without a sign-in (a dashboard opened with an access link) there is no account: say so rather than show a blank page.
  if (!session)
    return (
      <AppPage>
        <PageHeader title={t('account.title')} description={t('account.description')} />
        <div className="mt-4" data-testid="account-needs-signin">
          <EmptyState title={t('account.needs_signin')}>{t('account.needs_signin_body')}</EmptyState>
        </div>
      </AppPage>
    );
  const { api } = session;
  const a = account.data;

  const addPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      await withStepUp(async () => {
        const o = await api.registerOptions();
        const cred = await createPasskey(o.options);
        await api.registerVerify(o.ceremony, cred, passkeyName.trim());
      });
      setPasskeyName('');
      toast(t('account.passkey_added'));
      await session.refresh();
      reload();
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AppPage width="form">
      <PageHeader title={t('account.title')} description={t('account.description')} actions={<Button variant="outline" className={BTN} onClick={() => void session.signOut(false)}>{t('account.signout')}</Button>} />
      {account.error && !a && (
        <p role="alert" className="text-sm text-destructive">
          {account.error.message}
        </p>
      )}
      {!a && !account.error && <Skeleton className="h-40 w-full" />}
      {a && (
        <>
          <p className="text-sm text-muted-foreground">{t('account.signed_in_as', { name: a.user.label ?? a.user.id })}</p>

          <Card className="space-y-3 p-4" aria-labelledby="acct-passkeys">
            <h2 id="acct-passkeys" className="text-base font-semibold">
              {t('account.passkeys')}
            </h2>
            {a.passkeys.length === 0 && <p className="text-sm text-muted-foreground">{t('account.passkeys_empty')}</p>}
            <ul className="divide-y">
              {a.passkeys.map((p) => (
                <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{p.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {t('account.created', { when: fmtRelative(new Date(p.created_ms).toISOString()) })}, {t('account.last_used', { when: fmtRelative(new Date(p.last_used_ms).toISOString()) })}
                    </p>
                  </div>
                  <Button variant="outline" className={BTN} onClick={() => setRemoving(p)}>
                    {t('account.passkey_remove')}
                  </Button>
                </li>
              ))}
            </ul>
            <div className="flex flex-wrap items-end gap-2">
              <div className="min-w-0 flex-1 space-y-1">
                <Label htmlFor="new-passkey-name">{t('auth.enroll_passkey_name')}</Label>
                <Input className="h-11 lg:h-10" id="new-passkey-name" value={passkeyName} maxLength={40} onChange={(e) => setPasskeyName(e.target.value)} autoComplete="off" />
              </div>
              <Button className={BTN} disabled={busy} onClick={() => void addPasskey()} data-testid="add-passkey">
                {t('account.passkey_add')}
              </Button>
            </div>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
          </Card>

          <Card className="space-y-3 p-4" aria-labelledby="acct-totp">
            <div className="flex items-center justify-between gap-2">
              <h2 id="acct-totp" className="text-base font-semibold">
                {t('totp.heading')}
              </h2>
              <Badge variant={a.totp ? 'default' : 'secondary'}>{a.totp ? t('totp.on') : t('totp.off')}</Badge>
            </div>
            {a.totp ? (
              <Button
                variant="outline"
                className={BTN}
                onClick={() =>
                  void withStepUp(() => api.totpRemove())
                    .then(reload)
                    .catch((e: unknown) => setError(signInMessage(e)))
                }
              >
                {t('totp.remove')}
              </Button>
            ) : (
              <Button variant="outline" className={BTN} onClick={() => setSheet('totp')}>
                {t('totp.start')}
              </Button>
            )}
          </Card>

          <Card className="space-y-3 p-4" aria-labelledby="acct-methods">
            <h2 id="acct-methods" className="text-base font-semibold">
              {t('account.methods')}
            </h2>
            <p className="text-sm text-muted-foreground">{t('account.methods_body')}</p>
            <ul className="divide-y text-sm">
              <li className="flex items-center justify-between gap-2 py-2">
                <span>{t('account.github')}</span>
                <span className="flex items-center gap-2">
                  <Badge variant={a.providers.github.client_id ? 'default' : 'secondary'}>{a.providers.github.client_id ? t('account.configured') : t('account.not_configured')}</Badge>
                  {a.can_configure_providers && (
                    <Button variant="outline" className={BTN} onClick={() => setSheet('github')}>
                      {t('account.setup_github')}
                    </Button>
                  )}
                </span>
              </li>
              <li className="flex items-center justify-between gap-2 py-2">
                <span>{t('account.google')}</span>
                <span className="flex items-center gap-2">
                  <Badge variant={a.providers.google.client_id && a.providers.google.secret_set ? 'default' : 'secondary'}>
                    {a.providers.google.client_id && a.providers.google.secret_set ? t('account.configured') : t('account.not_configured')}
                  </Badge>
                  {a.can_configure_providers && (
                    <Button variant="outline" className={BTN} onClick={() => setSheet('google')}>
                      {t('account.setup_google')}
                    </Button>
                  )}
                </span>
              </li>
              {a.providers.access && (
                <li className="flex items-center justify-between gap-2 py-2">
                  <span>{t('account.access')}</span>
                  <Badge>{a.providers.access.team_domain}</Badge>
                </li>
              )}
            </ul>
          </Card>

          <Card className="space-y-3 p-4" aria-labelledby="acct-sessions">
            <h2 id="acct-sessions" className="text-base font-semibold">
              {t('account.sessions')}
            </h2>
            <ul className="divide-y">
              {a.sessions.map((s) => (
                <li key={s.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                  <div className="min-w-0 text-sm">
                    <p className="font-medium">{s.current ? t('account.session_current') : t('account.session_via', { via: s.via })}</p>
                    <p className="text-xs text-muted-foreground">{t('account.session_seen', { when: fmtRelative(new Date(s.last_seen_ms).toISOString()) })}</p>
                  </div>
                  {!s.current && (
                    <Button
                      variant="outline"
                      className={BTN}
                      onClick={() =>
                        void api
                          .revokeSession(s.id)
                          .then(reload)
                          .catch((e: unknown) => setError(signInMessage(e)))
                      }
                    >
                      {t('account.session_revoke')}
                    </Button>
                  )}
                </li>
              ))}
            </ul>
            <Button variant="outline" className={BTN} onClick={() => void session.signOut(true)}>
              {t('account.signout_all')}
            </Button>
          </Card>

          <PeopleCard people={a.people} meId={a.user.id} onChanged={reload} />

          <ConfirmDialog
            open={!!removing}
            onOpenChange={(o) => !o && setRemoving(null)}
            title={t('account.passkey_remove_title')}
            description={t('account.passkey_remove_body')}
            confirmLabel={t('account.passkey_remove')}
            destructive
            onConfirm={async () => {
              if (!removing) return;
              try {
                await withStepUp(() => api.removePasskey(removing.id));
                toast(t('account.passkey_removed'));
                setRemoving(null);
                await session.refresh();
                reload();
              } catch (e) {
                toast.error(signInMessage(e));
                throw e;
              }
            }}
          />

          <PanelSheet open={sheet !== null} onOpenChange={(o) => !o && setSheet(null)}>
            <PanelSheetContent size="compact">
              <PanelSheetHeader>
                <PanelSheetTitle>{sheet === 'github' ? t('ghsetup.title') : sheet === 'google' ? t('gosetup.title') : t('totp.heading')}</PanelSheetTitle>
                <PanelSheetDescription>{' '}</PanelSheetDescription>
              </PanelSheetHeader>
              <PanelSheetBody>
                {sheet === 'github' && <GithubSetup account={a} onSaved={() => { setSheet(null); reload(); }} />}
                {sheet === 'google' && <GoogleSetup account={a} onSaved={() => { setSheet(null); reload(); }} />}
                {sheet === 'totp' && (
                  <TotpSetup
                    api={api}
                    ask={withStepUp}
                    onDone={() => {
                      setSheet(null);
                      void session.refresh().then(reload);
                    }}
                  />
                )}
              </PanelSheetBody>
              <PanelSheetFooter>
                <Button variant="outline" className={BTN} onClick={() => setSheet(null)}>
                  {t('common.close')}
                </Button>
              </PanelSheetFooter>
            </PanelSheetContent>
          </PanelSheet>
        </>
      )}
    </AppPage>
  );
}
