import { useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import type { CodeAction, CodePlan, CodeService, CodeStatus, Procs, ServiceState, ServiceStatus } from '../api/code';
import type { BoxRecord } from '../api/types';
import { useApp } from '../App';
import { addressProblem, addressSwitch, canRemove, guideKey, openWay, stateKey, waiting } from '../lib/code';
import { t } from '../lib/i18n';
import { copyAndSay } from '../lib/copy-and-say';
import { isMacPlatform } from '../lib/terminal-clipboard';
import { useAsync } from '../lib/use-async';
import { fmtRelative } from '../lib/format';
import { EmptyState } from './page';

function copy(text: string) {
  return copyAndSay(text, { done: t('code.copied'), failed: t('openin.copy_failed', { what: text }) });
}

const serviceName = (s: CodeService) => t(s === 'ide' ? 'code.svc_ide' : 'code.svc_desktop');

/** The plan, shown before anything changes, and followed to its end once applied. */
function PlanSheet({ box, plan, onClose, onDone }: { box: string; plan: CodePlan; onClose: () => void; onDone: () => void }) {
  const { client } = useApp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => () => void (alive.current = false), []);

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      const { job_id } = await client.code.apply(box, plan.plan_id);
      for (let i = 0; i < 120 && alive.current; i++) {
        const j = await client.code.job(job_id);
        if (j.state === 'done') {
          toast.success(t('code.applied'));
          onDone();
          return;
        }
        if (j.state === 'failed') throw new Error(j.error ?? '');
        await new Promise((r) => setTimeout(r, 1000));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const text = (s: CodePlan['steps'][number]) => t(`code.step_${s.code}`, { program: s.program ?? '', host: s.host ?? '', name: s.name ?? '', pid: String(s.pid ?? '') });
  return (
    <PanelSheet open onOpenChange={(o) => !o && !busy && onClose()}>
      <PanelSheetContent size="compact" data-testid="code-plan-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('code.plan_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('code.plan_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {plan.steps.length === 0 ? (
            <p className="text-sm">{t('code.plan_nothing')}</p>
          ) : (
            <ul aria-label={t('code.plan_steps')} className="list-disc space-y-2 pl-5 text-sm">
              {plan.steps.map((s) => (
                <li key={s.code}>{text(s)}</li>
              ))}
            </ul>
          )}
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {t('code.apply_failed', { error })}
            </p>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className="max-lg:h-11" disabled={busy} onClick={onClose}>
            {t('code.close')}
          </Button>
          {plan.steps.length > 0 && (
            <Button className="max-lg:h-11" disabled={busy} onClick={() => void apply()}>
              {busy ? t('code.applying') : t('code.apply')}
            </Button>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

/** The tunnel token: asked once, sent to the server in the plan request, never shown again. */
function TokenSheet({ onClose, onPlan }: { onClose: () => void; onPlan: (token: string) => Promise<void> }) {
  const [value, setValue] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    const token = value.trim();
    if (!token) return setProblem(t('code.connector_token_err'));
    setProblem(null);
    setBusy(true);
    try {
      await onPlan(token);
      setValue('');
    } catch (e) {
      setProblem(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="code-token-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{t('code.connector_title_sheet')}</PanelSheetTitle>
            <PanelSheetDescription>{t('code.connector_sheet_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="code-token">{t('code.connector_token')}</Label>
              <Input id="code-token" type="password" autoComplete="off" spellCheck={false} value={value} onChange={(e) => setValue(e.target.value)} aria-describedby="code-token-hint" aria-invalid={problem ? true : undefined} className="max-lg:h-11" />
              <p id="code-token-hint" className="text-xs text-muted-foreground">
                {t('code.connector_token_hint')}
              </p>
              {problem && (
                <p role="alert" className="text-sm text-destructive">
                  {problem}
                </p>
              )}
            </div>
            <p className="text-sm">{t('code.connector_route')}</p>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" className="max-lg:h-11" onClick={onClose}>
              {t('code.close')}
            </Button>
            <Button type="submit" className="max-lg:h-11" disabled={busy}>
              {t('code.review')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function ConnectorCard({ state, onSetUp, onRemove }: { state: ServiceState; onSetUp: () => void; onRemove: () => void }) {
  const on = state === 'running' || state === 'stopped';
  return (
    <section aria-labelledby="code-connector" className="space-y-3 rounded-md border p-4" data-testid="code-connector">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <h2 id="code-connector" className="text-lg font-semibold">
            {t('code.connector_title')}
          </h2>
          <p className="text-sm text-muted-foreground">{t('code.connector_desc')}</p>
        </div>
        <Badge variant={state === 'running' ? 'default' : 'secondary'} data-testid="code-state-connector">
          {t(stateKey(state))}
        </Badge>
      </div>
      {state === 'unavailable' ? (
        <p className="text-sm text-muted-foreground">{t('code.connector_not_available')}</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          <Button className="max-lg:h-11" onClick={onSetUp} disabled={state === 'unknown'}>
            {t(on ? 'code.connector_replace' : 'code.connector_set_up')}
          </Button>
          {on && (
            <Button variant="outline" className="max-lg:h-11" onClick={onRemove}>
              {t('code.connector_remove')}
            </Button>
          )}
        </div>
      )}
    </section>
  );
}

/** Ask for the address, show where the tunnel is told about it, then go to the plan. */
function AddressSheet({ service, status, onClose, onPlan }: { service: CodeService; status: CodeStatus; onClose: () => void; onPlan: (address: string) => Promise<void> }) {
  const [value, setValue] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const guide = guideKey(status.tunnel?.kind);
  const submit = async () => {
    const p = addressProblem(value);
    if (p) return setProblem(t(`code.address_err_${p}`));
    setProblem(null);
    setBusy(true);
    try {
      await onPlan(value.trim());
    } catch (e) {
      setProblem(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="code-address-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{t('code.address_title', { service: serviceName(service) })}</PanelSheetTitle>
            <PanelSheetDescription>{t('code.address_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-4">
            <div className="space-y-1">
              <Label htmlFor="code-address">{t('code.address_field')}</Label>
              <Input id="code-address" inputMode="url" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} aria-describedby="code-address-hint" aria-invalid={problem ? true : undefined} className="max-lg:h-11" />
              <p id="code-address-hint" className="text-xs text-muted-foreground">
                {t('code.address_hint')}
              </p>
              {problem && (
                <p role="alert" className="text-sm text-destructive">
                  {problem}
                </p>
              )}
            </div>
            <div className="space-y-1 rounded-md border p-3">
              <h3 className="text-sm font-semibold">{t('code.guide_title')}</h3>
              <p className="text-sm">{t(`code.guide_${guide}`, { port: String(status.proxy_port) })}</p>
            </div>
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" className="max-lg:h-11" onClick={onClose}>
              {t('code.close')}
            </Button>
            <Button type="submit" className="max-lg:h-11" disabled={busy}>
              {t('code.review')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function ServiceCard({ box, status, svc, onPlan, onAddress }: { box: string; status: CodeStatus; svc: ServiceStatus; onPlan: (service: CodeService, action: CodeAction) => void; onAddress: (service: CodeService) => void }) {
  const { client } = useApp();
  const [opening, setOpening] = useState(false);
  const name = serviceName(svc.service);
  const way = openWay(status, svc);
  const sw = addressSwitch(status, svc);
  const open = async () => {
    if (way.kind === 'address') {
      window.open(way.path, '_blank', 'noopener');
      return;
    }
    setOpening(true);
    try {
      const { url } = await client.code.open(box, svc.service);
      window.open(url, '_blank', 'noopener');
    } catch (e) {
      toast.error(t('code.open_failed', { error: e instanceof Error ? e.message : String(e) }));
    } finally {
      setOpening(false);
    }
  };
  const hintId = `code-switch-hint-${svc.service}`;
  return (
    <Card className="space-y-3 p-4" data-testid={`code-svc-${svc.service}`}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <h3 className="text-base font-semibold">{name}</h3>
          <p className="text-sm text-muted-foreground">{t(svc.service === 'ide' ? 'code.svc_ide_desc' : 'code.svc_desktop_desc')}</p>
        </div>
        <Badge variant={svc.state === 'running' ? 'default' : 'secondary'} data-testid={`code-state-${svc.service}`}>
          {t(stateKey(svc.state))}
        </Badge>
      </div>
      <div className="flex flex-wrap gap-2">
        {(svc.state === 'not_set_up' || svc.state === 'stopped') && (
          <Button className="max-lg:h-11" aria-label={t('code.set_up_label', { service: name })} onClick={() => onPlan(svc.service, 'enable')}>
            {t('code.set_up')}
          </Button>
        )}
        {svc.state === 'running' && way.kind !== 'none' && (
          <Button className="max-lg:h-11" aria-label={t('code.open_label', { service: name })} disabled={opening} onClick={() => void open()}>
            {opening ? t('code.opening') : t('code.open')}
          </Button>
        )}
        {canRemove(svc) && (
          <Button variant="outline" className="max-lg:h-11" aria-label={t('code.remove_label', { service: name })} onClick={() => onPlan(svc.service, 'disable')}>
            {t('code.remove')}
          </Button>
        )}
      </div>
      {svc.state === 'running' && way.kind === 'none' && way.reason === 'shared' && <p className="text-xs text-muted-foreground">{t('code.shared_machine')}</p>}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">{t('code.command')}</span>
        <code className="rounded border bg-muted px-2 py-1 font-mono text-xs">{svc.command}</code>
        <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => void copy(svc.command)}>
          {t('code.copy')}
        </Button>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
        <div className="min-w-0">
          <p className="text-sm font-medium" id={`code-switch-label-${svc.service}`}>
            {t('code.address')}
          </p>
          <p id={hintId} className="text-xs text-muted-foreground">
            {sw.on ? t('code.address_on', { host: svc.public_host ?? '' }) : sw.enabled ? t('code.address_off') : t(sw.why === 'needs_sign_in' ? 'code.address_needs_sign_in' : sw.why === 'tunnel' ? 'code.address_tunnel' : 'code.address_not_running')}
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={sw.on}
          aria-label={t('code.address_switch', { service: name })}
          aria-describedby={hintId}
          disabled={!sw.enabled}
          onClick={() => (sw.on ? onPlan(svc.service, 'public_off') : onAddress(svc.service))}
          className="inline-flex h-11 min-w-11 items-center justify-center rounded-full border px-3 text-xs font-semibold disabled:opacity-50 aria-checked:border-primary aria-checked:bg-primary aria-checked:text-primary-foreground"
        >
          {sw.on ? t('code.on') : t('code.off')}
        </button>
      </div>
    </Card>
  );
}

function ageText(s: number): string {
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

/** What is running on the box that you started. Stop is planned and applied like every other change; Open goes to the web terminal. */
function RunningPanel({ box, onStop, onAttach }: { box: string; onStop: (action: CodeAction, target: string) => void; onAttach: (name: string) => void }) {
  const { client } = useApp();
  const [fast, setFast] = useState(false);
  // While the box has not been read since a change (a stop just applied), look again every second rather than every five.
  const answer = useAsync((s) => client.code.processes(box, s), [client, box], fast ? 1000 : 5000);
  const probed = answer.data?.probed;
  useEffect(() => setFast(probed === false), [probed]);
  const ps: Procs | null = answer.data?.ps ?? null;
  const empty = ps && ps.sessions.length === 0 && ps.agents.length === 0 && ps.servers.length === 0;
  return (
    <section aria-labelledby="code-running" className="space-y-3" data-testid="code-running">
      <div>
        <h2 id="code-running" className="text-lg font-semibold">
          {t('code.running')}
        </h2>
        <p className="text-sm text-muted-foreground">{t('code.running_desc')}</p>
      </div>
      {!ps && !answer.data?.error && <p className="text-sm text-muted-foreground">{t('code.running_checking')}</p>}
      {answer.data?.error && (
        <p role="alert" className="text-sm text-destructive">
          {t('code.probe_failed', { error: answer.data.error })}
        </p>
      )}
      {ps && !ps.tmux && <p className="text-sm text-muted-foreground">{t('code.running_no_tmux')}</p>}
      {empty && <p className="text-sm text-muted-foreground">{t('code.running_nothing')}</p>}
      {ps && ps.sessions.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">{t('code.sessions')}</h3>
          <ul className="space-y-2">
            {ps.sessions.map((s) => (
              <li key={s.name} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3" data-testid={`code-session-${s.name}`}>
                <div className="min-w-0">
                  <p className="text-sm font-medium">
                    {s.name} <Badge variant="secondary">{t(s.attached ? 'code.session_attached' : 'code.session_detached')}</Badge>
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {t('code.session_running', { command: s.command })} · {t('code.session_active', { when: fmtRelative(new Date(s.activity_s * 1000).toISOString()) })}
                  </p>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" className="max-lg:h-11" aria-label={t('code.attach_label', { name: s.name })} onClick={() => onAttach(s.name)}>
                    {t('code.attach')}
                  </Button>
                  <Button size="sm" variant="outline" className="max-lg:h-11" aria-label={t('code.stop_label', { name: t('code.stop_session_name', { name: s.name }) })} onClick={() => onStop('stop_session', s.name)}>
                    {t('code.stop')}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">{t('code.running_restart_note')}</p>
        </div>
      )}
      {ps && ps.agents.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">{t('code.agents')}</h3>
          <ul className="space-y-2">
            {ps.agents.map((a) => (
              <li key={a.pid} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3" data-testid={`code-agent-${a.pid}`}>
                <p className="text-sm">
                  {a.program} <span className="text-xs text-muted-foreground">{t('code.agent_age', { age: ageText(a.age_s) })}</span>
                </p>
                <Button size="sm" variant="outline" className="max-lg:h-11" aria-label={t('code.stop_label', { name: t('code.stop_process_name', { program: a.program, pid: String(a.pid) }) })} onClick={() => onStop('stop_process', String(a.pid))}>
                  {t('code.stop')}
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}
      {ps && ps.servers.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">{t('code.servers')}</h3>
          <ul className="space-y-2">
            {ps.servers.map((s) => (
              <li key={`${s.port}-${s.pid}`} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3" data-testid={`code-server-${s.port}`}>
                <p className="text-sm">
                  {t('code.server_line', { port: String(s.port) })} <span className="text-xs text-muted-foreground">{s.program}</span>
                </p>
                <Button size="sm" variant="outline" className="max-lg:h-11" aria-label={t('code.stop_label', { name: t('code.stop_process_name', { program: s.program, pid: String(s.pid) }) })} onClick={() => onStop('stop_process', String(s.pid))}>
                  {t('code.stop')}
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

/** A box's Code panel: the web IDE and the desktop in the browser, and the editors that open it over SSH. */
export function CodeTab({ box, onOpenTerminal }: { box: BoxRecord; onOpenTerminal?: (session: string) => void }) {
  const { client } = useApp();
  const name = box.spec.name;
  const [fast, setFast] = useState(true);
  const status = useAsync((s) => client.code.status(name, s), [client, name], fast ? 2000 : 8000);
  const data = status.data;
  useEffect(() => setFast(waiting(data)), [data]);
  const [plan, setPlan] = useState<CodePlan | null>(null);
  const [address, setAddress] = useState<CodeService | null>(null);
  const [tokenSheet, setTokenSheet] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (box.state !== 'running') return <EmptyState title={t('boxpage.not_running')}>{t('code.not_running')}</EmptyState>;
  if (!data && !status.error) return <Skeleton className="h-48 w-full" />;
  if (status.error && !data) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{t('code.probe_failed', { error: status.error.message })}</AlertDescription>
      </Alert>
    );
  }
  if (!data) return null;

  const stopPlan = (action: CodeAction, target: string) => {
    setErr(null);
    void client.code
      .plan(name, { action, target })
      .then(setPlan)
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)));
  };
  const attach = (session: string) => {
    // The web terminal attaches that session itself; nothing to copy.
    onOpenTerminal?.(session);
  };

  const makePlan = async (service: CodeService, action: CodeAction, addr?: string) => {
    setErr(null);
    const p = await client.code.plan(name, { service, action, ...(addr ? { address: addr } : {}) });
    setAddress(null);
    setPlan(p);
  };

  return (
    <div className="space-y-6" data-testid="code-tab">
      <p className="text-sm text-muted-foreground">{t('code.description')}</p>
      {data.error && (
        <Alert variant="destructive">
          <AlertDescription className="flex flex-wrap items-center gap-2">
            <span>{t('code.probe_failed', { error: data.error })}</span>
            <Button variant="outline" size="sm" className="max-lg:h-11" onClick={status.reload}>
              {t('code.retry')}
            </Button>
          </AlertDescription>
        </Alert>
      )}
      {data.probed && data.linger === false && (
        <Alert>
          <AlertDescription>{t('code.no_linger')}</AlertDescription>
        </Alert>
      )}
      {err && (
        <p role="alert" className="text-sm text-destructive">
          {err}
        </p>
      )}
      <section aria-labelledby="code-services" className="space-y-3">
        <h2 id="code-services" className="text-lg font-semibold">
          {t('code.services')}
        </h2>
        {waiting(data) && !data.error ? <p className="text-sm text-muted-foreground">{t('code.checking')}</p> : null}
        <div className="grid gap-4 lg:grid-cols-2">
          {data.services.map((s) => (
            <ServiceCard key={s.service} box={name} status={data} svc={s} onPlan={(sv, a) => void makePlan(sv, a).catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))} onAddress={setAddress} />
          ))}
        </div>
      </section>
      {data.connector && <ConnectorCard state={data.connector.state} onSetUp={() => setTokenSheet(true)} onRemove={() => stopPlan('connector_off', '')} />}
      <section aria-labelledby="code-browser" className="space-y-2 rounded-md border p-4" data-testid="code-browser-note">
        <h2 id="code-browser" className="text-base font-semibold">
          {t('code.browser_title')}
        </h2>
        <p className="text-sm" data-testid="code-browser-keys">{t(isMacPlatform(typeof navigator === 'undefined' ? undefined : navigator) ? 'code.browser_keys_mac' : 'code.browser_keys_other')}</p>
        <p className="text-sm">{t('code.browser_tmux')}</p>
        <p className="text-sm">{t('code.browser_chromium')}</p>
        <p className="text-sm">{t('code.browser_firefox')}</p>
        <p className="text-sm">{t('code.browser_safari')}</p>
        <p className="text-sm">{t('code.browser_desktop')}</p>
      </section>
      <RunningPanel box={name} onStop={stopPlan} onAttach={attach} />
      <section aria-labelledby="code-editors" className="space-y-3">
        <div>
          <h2 id="code-editors" className="text-lg font-semibold">
            {t('code.editors')}
          </h2>
          <p className="text-sm text-muted-foreground">{t('code.editors_desc')}</p>
          <p className="text-sm text-muted-foreground" data-testid="code-keybindings-note">
            {t('code.editors_keybindings_note')}
          </p>
        </div>
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {data.editors.map((e) => (
            <li key={e.id} className="space-y-2 rounded-md border p-3" data-testid={`code-editor-${e.id}`}>
              <p className="text-sm font-medium">{e.name}</p>
              <div className="flex flex-wrap gap-2">
                {e.url && (
                  <Button asChild className="max-lg:h-11">
                    <a href={e.url}>{t('code.editor_open', { editor: e.name })}</a>
                  </Button>
                )}
                <Button variant="outline" size="sm" className="max-lg:h-11" aria-label={`${t('code.copy')}: ${e.command}`} onClick={() => void copy(e.command)}>
                  {t('code.copy')}
                </Button>
              </div>
              <code className="block break-all font-mono text-xs">{e.command}</code>
              <p className="text-xs text-muted-foreground">{e.url ? (e.documented ? '' : t('code.editor_unverified')) : t('code.editor_no_link')}</p>
            </li>
          ))}
        </ul>
      </section>
      {tokenSheet && (
        <TokenSheet
          onClose={() => setTokenSheet(false)}
          onPlan={async (token) => {
            setErr(null);
            const p = await client.code.plan(name, { action: 'connector_on', token });
            setTokenSheet(false);
            setPlan(p);
          }}
        />
      )}
      {address && <AddressSheet service={address} status={data} onClose={() => setAddress(null)} onPlan={(a) => makePlan(address, 'public_on', a)} />}
      {plan && (
        <PlanSheet
          box={name}
          plan={plan}
          onClose={() => setPlan(null)}
          onDone={() => {
            setPlan(null);
            status.reload();
          }}
        />
      )}
    </div>
  );
}
