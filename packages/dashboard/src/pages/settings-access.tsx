import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import type { AccessStatus, CheckResult, SavedTunnel, TunnelProvider } from '../api/access';
import { ApiError } from '../api/client';
import { useApp } from '../App';
import { withStepUp } from '../components/perm/with-step-up';
import { SecretField } from '../components/secret-field';
import {
  GUIDE_STEPS,
  PROVIDERS,
  PROVIDER_NAME,
  PROVIDER_NOTE,
  caddyfile,
  codeKey,
  formFromSaved,
  isProtected,
  tunnelControls,
  serveCommand,
  toRequest,
  tokenSecretName,
  tunnelView,
  validate,
  type AccessForm,
} from '../lib/access-flow';
import { fmtRelative } from '../lib/format';
import { t } from '../lib/i18n';
import { useAsync } from '../lib/use-async';

const errorText = (e: unknown) => (e instanceof ApiError ? e.message : t('access.save_failed'));

function FieldError({ id, msg }: { id: string; msg?: string }) {
  return msg ? (
    <p id={id} role="alert" className="text-sm text-destructive">
      {msg}
    </p>
  ) : null;
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="break-words text-sm font-medium">{children}</dd>
    </div>
  );
}

function GuideSheet({
  provider,
  saved,
  open,
  onOpenChange,
  onSaved,
}: {
  provider: TunnelProvider;
  saved: SavedTunnel | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: (s: AccessStatus) => void;
}) {
  const { client } = useApp();
  const [form, setForm] = useState<AccessForm>(() => formFromSaved(saved?.provider === provider ? saved : null));
  const [errors, setErrors] = useState<Partial<Record<keyof AccessForm, string>>>({});
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const set = (k: keyof AccessForm) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const tokenName = tokenSecretName(provider);
  const name = t(PROVIDER_NAME[provider]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const found = validate(provider, form);
    setErrors(Object.fromEntries(Object.entries(found).map(([k, v]) => [k, t(v)])));
    if (Object.keys(found).length > 0) return;
    setBusy(true);
    setFailure(null);
    try {
      // replacing the token is a tunnel change like the save below: behind a sign-in the server asks for a fresh passkey first
      if (tokenName && form.token !== '') await withStepUp(() => client.putSecret(tokenName, form.token.trim()));
      const next = await withStepUp(() => client.access.saveTunnel(toRequest(provider, form)));
      setForm((f) => ({ ...f, token: '' }));
      toast.success(t('access.saved'));
      onSaved(next);
      onOpenChange(false);
    } catch (err) {
      setFailure(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <PanelSheet open={open} onOpenChange={onOpenChange}>
      <PanelSheetContent data-testid={`access-guide-${provider}`}>
        <form noValidate className="flex min-h-0 flex-1 flex-col" onSubmit={submit}>
          <PanelSheetHeader>
            <PanelSheetTitle>{t('access.guide_title', { provider: name })}</PanelSheetTitle>
            <PanelSheetDescription>{t('access.guide_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-5">
            {failure ? (
              <Alert variant="destructive" role="alert">
                <AlertDescription>{failure}</AlertDescription>
              </Alert>
            ) : null}
            <section aria-labelledby={`ag-${provider}-steps`} className="space-y-2">
              <h3 id={`ag-${provider}-steps`} className="text-sm font-semibold">
                {t('access.steps')}
              </h3>
              <ol className="list-decimal space-y-1.5 pl-5 text-sm text-muted-foreground">
                {GUIDE_STEPS[provider].map((k) => (
                  <li key={k}>{t(k)}</li>
                ))}
              </ol>
            </section>
            {provider === 'caddy' ? (
              <section aria-labelledby="ag-caddyfile" className="space-y-1">
                <h3 id="ag-caddyfile" className="text-sm font-semibold">
                  {t('access.caddyfile_title')}
                </h3>
                <pre className="overflow-x-auto rounded-md border bg-muted p-3 text-xs" tabIndex={0}>
                  {caddyfile(form.publicUrl, form.remotePort)}
                </pre>
              </section>
            ) : null}
            <div className="space-y-1">
              <Label htmlFor="ag-url">{t('access.field_url')}</Label>
              <Input id="ag-url" inputMode="url" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.publicUrl} aria-describedby="ag-url-hint ag-url-err" value={form.publicUrl} onChange={set('publicUrl')} />
              <p id="ag-url-hint" className="text-xs text-muted-foreground">
                {t('access.field_url_hint')}
              </p>
              <FieldError id="ag-url-err" msg={errors.publicUrl} />
            </div>
            {provider === 'caddy' ? (
              <>
                <div className="space-y-1">
                  <Label htmlFor="ag-host">{t('access.field_ssh_host')}</Label>
                  <Input id="ag-host" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.sshHost} value={form.sshHost} onChange={set('sshHost')} />
                  <p className="text-xs text-muted-foreground">{t('access.field_ssh_host_hint')}</p>
                  <FieldError id="ag-host-err" msg={errors.sshHost} />
                </div>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1">
                    <Label htmlFor="ag-user">{t('access.field_ssh_user')}</Label>
                    <Input id="ag-user" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.sshUser} value={form.sshUser} onChange={set('sshUser')} />
                    <FieldError id="ag-user-err" msg={errors.sshUser} />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="ag-port">{t('access.field_ssh_port')}</Label>
                    <Input id="ag-port" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.sshPort} value={form.sshPort} onChange={set('sshPort')} />
                    <FieldError id="ag-port-err" msg={errors.sshPort} />
                  </div>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="ag-key">{t('access.field_key')}</Label>
                  <Input id="ag-key" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.keyFile} value={form.keyFile} onChange={set('keyFile')} />
                  <p className="text-xs text-muted-foreground">{t('access.field_key_hint')}</p>
                  <FieldError id="ag-key-err" msg={errors.keyFile} />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="ag-rport">{t('access.field_remote_port')}</Label>
                  <Input id="ag-rport" inputMode="numeric" autoComplete="off" className="max-lg:h-11" aria-invalid={!!errors.remotePort} value={form.remotePort} onChange={set('remotePort')} />
                  <p className="text-xs text-muted-foreground">{t('access.field_remote_port_hint')}</p>
                  <FieldError id="ag-rport-err" msg={errors.remotePort} />
                </div>
              </>
            ) : null}
            {tokenName ? <SecretField id="ag-token" label={provider === 'cloudflare' ? t('access.field_token_cloudflare') : t('access.field_token_ngrok')} hint={t('access.field_token_hint')} value={form.token} onChange={(e) => setForm((f) => ({ ...f, token: e.target.value }))} /> : null}
            <section aria-labelledby="ag-next" className="space-y-1">
              <h3 id="ag-next" className="text-sm font-semibold">
                {t('access.next_title')}
              </h3>
              <pre className="overflow-x-auto rounded-md border bg-muted p-3 text-xs" tabIndex={0} data-testid="access-serve-command">
                {serveCommand(provider, form.publicUrl)}
              </pre>
              <p className="text-xs text-muted-foreground">{t('access.restart_note')}</p>
            </section>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('access.cancel')}
            </Button>
            <Button type="submit" disabled={busy}>
              {busy ? t('access.saving') : t('access.save')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

const STATE_LABEL = { running: 'access.state_running', stopped: 'access.state_stopped', failed: 'access.state_failed', unmanaged: 'access.state_unmanaged' } as const;

function SavedCard({ saved, canControl, onGuide, onChanged }: { saved: SavedTunnel; canControl: boolean; onGuide: (p: TunnelProvider) => void; onChanged: (s: AccessStatus) => void }) {
  const { client } = useApp();
  const [checking, setChecking] = useState(false);
  const [health, setHealth] = useState<CheckResult['health'] | null>(null);
  const [removing, setRemoving] = useState(false);
  const [confirm, setConfirm] = useState<'stop' | 'restart' | null>(null);
  const [busy, setBusy] = useState(false);
  const view = tunnelView(saved);
  const controls = tunnelControls(saved, canControl);
  const live = saved.live;
  const shown = health ?? live?.health ?? null;
  const whyKey = codeKey(live?.code ?? null);
  const check = async () => {
    setChecking(true);
    try {
      const r = await client.access.check();
      setHealth(r.health);
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setChecking(false);
    }
  };
  const control = async (action: 'start' | 'stop' | 'restart') => {
    const next = await withStepUp(() => (action === 'start' ? client.access.startTunnel() : action === 'stop' ? client.access.stopTunnel() : client.access.restartTunnel()));
    toast.success(t(action === 'start' ? 'access.started' : action === 'stop' ? 'access.stopped' : 'access.restarted'));
    setHealth(null);
    onChanged(next);
  };
  const start = async () => {
    setBusy(true);
    try {
      await control('start');
    } catch (e) {
      toast.error(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card className="space-y-3 p-4" data-testid="access-tunnel-card">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('access.tunnel_title')}</h2>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={check} disabled={checking} data-testid="access-check">
            {checking ? t('access.checking') : t('access.check')}
          </Button>
          {controls.start ? (
            <Button size="sm" className="max-lg:h-11" onClick={start} disabled={busy} data-testid="access-start">
              {t('access.start')}
            </Button>
          ) : null}
          {controls.restart ? (
            <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setConfirm('restart')} data-testid="access-restart">
              {t('access.restart')}
            </Button>
          ) : null}
          {controls.stop ? (
            <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setConfirm('stop')} data-testid="access-stop">
              {t('access.stop')}
            </Button>
          ) : null}
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => onGuide(saved.provider)}>
            {t('access.change')}
          </Button>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setRemoving(true)}>
            {t('access.remove')}
          </Button>
        </div>
      </div>
      <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Row label={t(PROVIDER_NAME[saved.provider])}>
          <Badge variant={saved.public ? 'secondary' : 'outline'}>{saved.public ? t('access.public') : t('access.private')}</Badge>
        </Row>
        <Row label={t('access.address')}>{saved.public_url}</Row>
        <Row label={t('access.state')}>
          <span data-testid="access-state">{t(STATE_LABEL[view])}</span>
          {whyKey ? <span className="block text-xs font-normal text-muted-foreground">{t(whyKey)}</span> : null}
        </Row>
        {saved.token_set !== null ? <Row label={t('access.field_token')}>{saved.token_set ? t('access.token_saved') : t('access.token_not_saved')}</Row> : null}
        {live ? <Row label={t('access.restarts')}>{live.restarts}</Row> : null}
        <Row label={t('access.health')}>
          <span data-testid="access-health">
            {shown === null ? t('access.health_never') : shown.ok ? t('access.health_ok') : t('access.health_bad', { why: t(codeKey(shown.code) ?? 'access.code_bad_answer') })}
            {shown ? <span className="block text-xs font-normal text-muted-foreground">{fmtRelative(new Date(shown.checked_ms).toISOString())}</span> : null}
          </span>
        </Row>
      </dl>
      {view === 'unmanaged' ? <p className="text-xs text-muted-foreground">{t('access.unmanaged_note')}</p> : null}
      <div className="space-y-1">
        <p className="text-xs text-muted-foreground">{t('access.run_command')}</p>
        <pre className="overflow-x-auto rounded-md border bg-muted p-3 text-xs" tabIndex={0}>
          {serveCommand(saved.provider, saved.public_url)}
        </pre>
      </div>
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={t(confirm === 'restart' ? 'access.restart_title' : 'access.stop_title')}
        description={t(confirm === 'restart' ? 'access.restart_desc' : 'access.stop_desc')}
        confirmLabel={t(confirm === 'restart' ? 'access.restart' : 'access.stop')}
        destructive={confirm === 'stop'}
        onConfirm={async () => {
          const action = confirm;
          if (!action) return;
          try {
            await control(action);
            setConfirm(null);
          } catch (e) {
            toast.error(errorText(e));
            throw e;
          }
        }}
      />
      <ConfirmDialog
        open={removing}
        onOpenChange={setRemoving}
        title={t('access.remove_title')}
        description={t('access.remove_desc')}
        confirmLabel={t('access.remove')}
        destructive
        onConfirm={async () => {
          try {
            const next = await withStepUp(() => client.access.removeTunnel());
            toast.success(t('access.removed'));
            onChanged(next);
            setRemoving(false);
          } catch (e) {
            toast.error(errorText(e));
            throw e;
          }
        }}
      />
    </Card>
  );
}

/** Settings, Dashboard access: how the dashboard is reached from outside, and the tunnel that carries it. */
export function AccessSection() {
  const { client } = useApp();
  const status = useAsync((s) => client.access.status(s), [client], 15_000);
  const [override, setOverride] = useState<AccessStatus | null>(null);
  const [guide, setGuide] = useState<TunnelProvider | null>(null);
  const a = override ?? status.data;
  if (status.error && !a) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {status.error.message}
      </p>
    );
  }
  if (!a) return <Skeleton className="h-40 w-full" aria-label={t('access.loading')} />;
  const saved = a.tunnel;
  const done = (s: AccessStatus) => {
    setOverride(s);
    status.reload();
  };
  return (
    <div className="space-y-4" data-testid="access-section">
      <p className="text-sm text-muted-foreground">{t('access.intro')}</p>
      <Card className="space-y-3 p-4" data-testid="access-mode-card">
        <h2 className="text-sm font-semibold">{t('access.mode_title')}</h2>
        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Row label={t('access.mode_title')}>{a.mode === 'public' ? t('access.mode_public') : t('access.mode_token')}</Row>
          {a.public_url ? <Row label={t('access.address')}>{a.public_url}</Row> : null}
          {a.mode === 'public' ? (
            <Row label={t('access.methods')}>
              <span className="flex flex-wrap gap-1.5">
                {a.strong_methods.map((m) => (
                  <Badge key={m} variant="secondary">
                    {m === 'passkey' ? t('access.method_passkey') : t('access.method_cloudflare_access')}
                  </Badge>
                ))}
                {a.strong_methods.length === 0 ? t('access.methods_none') : null}
              </span>
            </Row>
          ) : null}
        </dl>
        {a.mode === 'token' ? <p className="text-xs text-muted-foreground">{t('access.token_mode_note')}</p> : null}
        {!isProtected(a) ? (
          <Alert variant="destructive" role="alert">
            <AlertDescription>{t('access.methods_none')}</AlertDescription>
          </Alert>
        ) : null}
      </Card>
      {saved ? (
        <SavedCard key={saved.provider + saved.public_url} saved={saved} canControl={a.can_control === true} onGuide={setGuide} onChanged={done} />
      ) : (
        <Card className="space-y-3 p-4" data-testid="access-providers">
          <h2 className="text-sm font-semibold">{t('access.choose')}</h2>
          <p className="text-sm text-muted-foreground">{a.can_save ? t('access.none_saved') : t('access.cannot_save')}</p>
          <ul className="divide-y rounded-md border">
            {PROVIDERS.map((p) => (
              <li key={p} className="flex flex-wrap items-center justify-between gap-2 p-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{t(PROVIDER_NAME[p])}</p>
                  <p className="text-xs text-muted-foreground">{t(PROVIDER_NOTE[p])}</p>
                </div>
                <Button variant="outline" size="sm" className="max-lg:h-11" disabled={!a.can_save} onClick={() => setGuide(p)} data-testid={`access-setup-${p}`}>
                  {t('access.set_up')}
                </Button>
              </li>
            ))}
          </ul>
        </Card>
      )}
      {guide ? <GuideSheet key={guide} provider={guide} saved={saved} open onOpenChange={(o) => !o && setGuide(null)} onSaved={done} /> : null}
      <Card className="space-y-1 p-4" data-testid="access-box-note">
        <h2 className="text-sm font-semibold">{t('access.box_title')}</h2>
        <p className="text-sm text-muted-foreground">{t('access.box_body')}</p>
      </Card>
    </div>
  );
}
