import { useEffect, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import type { RegionCandidate, SetupPlan } from '../../api/setup';
import { useApp } from '../../App';
import { t } from '../../lib/i18n';
import { estimateLabel, type PlanPhase, type SetupAction, type SetupState } from '../../lib/setup-flow';
import { hrefs, navigate } from '../../lib/router';
import { useAsync } from '../../lib/use-async';
import { useSettings } from '../../lib/use-settings';
import { LocaleEditor } from '../locale-editor';
import { ChannelGuide } from './channel-guide';
import { ChangeList } from './plan-view';
import { toProblem } from './problem-note';

type Dispatch = (a: SetupAction) => void;

export function ProviderStep({ s, dispatch }: { s: SetupState; dispatch: Dispatch }) {
  const options = [
    { id: 'fake', name: t('setup.provider_fake'), desc: t('setup.provider_fake_desc') },
    { id: 'aws', name: t('setup.provider_aws'), desc: t('setup.provider_aws_desc') },
    { id: 'hcloud', name: t('setup.provider_hcloud'), desc: t('setup.provider_hcloud_desc') },
  ] as const;
  return (
    <div role="radiogroup" aria-label={t('setup.providers_label')} className="space-y-2">
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          role="radio"
          aria-checked={s.provider === o.id}
          data-testid={`provider-${o.id}`}
          onClick={() => dispatch({ type: 'provider', provider: o.id })}
          className={`flex min-h-11 w-full flex-col items-start gap-1 rounded-md border p-3 text-left text-sm ${s.provider === o.id ? 'border-primary bg-accent' : 'hover:bg-accent/60'}`}
        >
          <span className="font-semibold">{o.name}</span>
          <span className="text-muted-foreground">{o.desc}</span>
        </button>
      ))}
    </div>
  );
}

export function SignInStep({ s, dispatch, onCheck, hcloudToken }: { s: SetupState; dispatch: Dispatch; onCheck: () => void; hcloudToken: boolean }) {
  const aws = s.provider === 'aws';
  return (
    <div className="space-y-3">
      {aws ? (
        <>
          <p className="text-sm text-muted-foreground">{t('setup.sign_in_how')}</p>
          <div className="space-y-1">
            <Label htmlFor="setup-profile">{t('setup.profile')}</Label>
            <Input id="setup-profile" className="h-11 lg:h-10" value={s.profile} autoComplete="off" onChange={(e) => dispatch({ type: 'profile', value: e.target.value })} aria-describedby="setup-profile-hint" />
            <p id="setup-profile-hint" className="text-xs text-muted-foreground">
              {t('setup.profile_hint')}
            </p>
          </div>
        </>
      ) : (
        <p className="text-sm text-muted-foreground" data-testid="hcloud-token-note">
          {hcloudToken ? t('setup.hcloud_token_have') : t('setup.hcloud_token_missing')}
        </p>
      )}
      <Button type="button" variant="outline" className="max-lg:h-11" disabled={s.busy} onClick={onCheck}>
        {s.busy ? t('flow.working') : t('setup.check_sign_in')}
      </Button>
      {s.signedIn && (
        <p role="status" className="text-sm font-medium" data-testid="signed-in">
          {s.identity ? t('setup.signed_in_as', { arn: s.identity.arn }) : t('setup.hcloud_token_have')}
        </p>
      )}
    </div>
  );
}

const PROBE_BADGE = { allowed: 'outline', denied: 'destructive', unknown: 'secondary' } as const;
const PROBE_TEXT = { allowed: 'setup.perm_allowed', denied: 'setup.perm_denied', unknown: 'setup.perm_unknown' } as const;

export function PermissionsStep({ s, onCheck }: { s: SetupState; onCheck: () => void }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">{t('setup.permissions_how')}</p>
      <Button type="button" variant="outline" className="max-lg:h-11" disabled={s.busy} onClick={onCheck}>
        {s.busy ? t('flow.working') : t('setup.check_permissions')}
      </Button>
      {s.probes && (
        <ul className="space-y-1.5" aria-label={t('setup.step_permissions')}>
          {s.probes.map((p) => (
            <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-2 text-sm" data-testid={`probe-${p.id}`}>
              <span>{p.label}</span>
              <Badge variant={PROBE_BADGE[p.state]}>{t(PROBE_TEXT[p.state])}</Badge>
            </li>
          ))}
        </ul>
      )}
      {s.probes && !s.permissionsOk && <p className="text-sm text-destructive">{t('setup.perm_fix')}</p>}
    </div>
  );
}

function sizesLabel(c: RegionCandidate): string {
  return c.offers_sizes === true ? t('setup.region_sizes_yes') : c.offers_sizes === false ? t('setup.region_sizes_no') : t('setup.region_sizes_unknown');
}

export function RegionStep({ s, dispatch, onMeasure, locations }: { s: SetupState; dispatch: Dispatch; onMeasure: () => void; locations: string[] }) {
  const aws = s.provider === 'aws';
  return (
    <div className="space-y-3">
      {aws ? (
        <>
          <p className="text-sm text-muted-foreground">{t('setup.region_how')}</p>
          <Button type="button" variant="outline" className="max-lg:h-11" disabled={s.busy} onClick={onMeasure}>
            {s.busy ? t('setup.measuring') : t('setup.measure')}
          </Button>
          {s.regions === null ? (
            <p className="text-sm text-muted-foreground">{t('setup.region_none')}</p>
          ) : (
            <div role="radiogroup" aria-label={t('setup.region_pick')} className="space-y-1.5">
              {s.regions.map((c) => (
                <button
                  key={c.region}
                  type="button"
                  role="radio"
                  aria-checked={s.region === c.region}
                  data-testid={`region-${c.region}`}
                  onClick={() => dispatch({ type: 'region', value: c.region })}
                  className={`flex min-h-11 w-full flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-1.5 text-left text-sm ${s.region === c.region ? 'border-primary bg-accent' : 'hover:bg-accent/60'}`}
                >
                  <span className="font-medium">
                    {c.region} <span className="font-normal text-muted-foreground">({c.name})</span>
                    {c.region === s.suggestedRegion && <Badge className="ml-2">{t('setup.region_suggested')}</Badge>}
                  </span>
                  <span className="text-xs text-muted-foreground">{`${c.ms === null ? '—' : t('setup.region_ms', { ms: c.ms })} · ${sizesLabel(c)}`}</span>
                </button>
              ))}
            </div>
          )}
        </>
      ) : null}
      {!aws && locations.length > 0 && (
        <div role="radiogroup" aria-label={t('setup.region_hcloud')} className="flex flex-wrap gap-2">
          {locations.map((l) => (
            <button key={l} type="button" role="radio" aria-checked={s.region === l} onClick={() => dispatch({ type: 'region', value: l })} className={`min-h-11 rounded-md border px-3 text-sm ${s.region === l ? 'border-primary bg-accent' : 'hover:bg-accent/60'}`}>
              {l}
            </button>
          ))}
        </div>
      )}
      <div className="space-y-1">
        <Label htmlFor="setup-region">{t('setup.region_manual')}</Label>
        <Input id="setup-region" className="h-11 lg:h-10" value={s.region} autoComplete="off" onChange={(e) => dispatch({ type: 'region', value: e.target.value.trim() })} />
      </div>
    </div>
  );
}

/** A plan step: review first, apply second, and the same screen shows it done. */
export function PlanStep({ which, phase, onPlan, onApply, how }: { which: 'bucket' | 'network'; phase: PlanPhase; onPlan: () => void; onApply: () => void; how: string }) {
  const plan: SetupPlan | null = phase.phase === 'review' || phase.phase === 'applying' || phase.phase === 'applied' ? phase.plan : null;
  return (
    <div className="space-y-3" data-testid={`step-${which}`}>
      <p className="text-sm text-muted-foreground">{how}</p>
      {(phase.phase === 'none' || phase.phase === 'planning') && (
        <Button type="button" variant="outline" className="max-lg:h-11" disabled={phase.phase === 'planning'} onClick={onPlan}>
          {phase.phase === 'planning' ? t('setup.planning') : t('setup.review_plan')}
        </Button>
      )}
      {plan && (
        <section className="space-y-2" aria-label={plan.summary}>
          <h3 className="text-sm font-semibold">{plan.summary}</h3>
          {plan.noop ? <p className="text-sm">{t('setup.already')}</p> : <ChangeList changes={plan.changes} label={t('setup.plan_changes')} />}
          {plan.notes.map((n) => (
            <p key={n} className="text-xs text-muted-foreground">
              {n}
            </p>
          ))}
          <p className="text-sm font-medium">{t('flow.estimate', { amount: estimateLabel(plan.estimate_usd_month) })}</p>
          {phase.phase === 'review' && (
            <Button type="button" className="max-lg:h-11" onClick={onApply} data-testid={`apply-${which}`}>
              {t('setup.apply')}
            </Button>
          )}
          {phase.phase === 'applying' && (
            <Button type="button" className="max-lg:h-11" disabled>
              {t('setup.applying')}
            </Button>
          )}
          {phase.phase === 'applied' && (
            <p role="status" className="text-sm font-medium">
              {plan.noop ? t('setup.already') : t('setup.applied')}
            </p>
          )}
        </section>
      )}
    </div>
  );
}

const EMAIL_RE = /^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/;

/** Budget and alerts: the guard rail. Email is set up here; every channel is the person's own, with its own key. */
export function GuardrailsStep({ dispatch }: { dispatch: Dispatch }) {
  const { client, info } = useApp();
  const status = useAsync((sig) => client.setup.status(sig), [client], 4000);
  const { settings, save, reload } = useSettings();
  const [budget, setBudget] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [key, setKey] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const g = status.data?.guardrails;
  useEffect(() => {
    if (g) dispatch({ type: 'guardrails', budgetSet: g.budget_set, alertReady: g.alert_ready });
  }, [g?.budget_set, g?.alert_ready]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (settings && budget === '' && settings.budget.monthly_usd) setBudget(String(settings.budget.monthly_usd));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings === null]);
  if (!settings) return <Skeleton className="h-40 w-full" />;
  const amount = Number(budget);
  const budgetOk = budget.trim() !== '' && Number.isFinite(amount) && amount > 0;
  const emailOk = EMAIL_RE.test(from) && to.split(',').every((a) => EMAIL_RE.test(a.trim()));
  return (
    <div className="space-y-5">
      <p className="text-sm text-muted-foreground">{t('setup.gate_note')}</p>
      <section className="space-y-2" aria-label={t('setup.budget')}>
        <Label htmlFor="setup-budget">{t('setup.budget')}</Label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input id="setup-budget" inputMode="decimal" className="h-11 lg:h-10" value={budget} onChange={(e) => setBudget(e.target.value)} aria-describedby="setup-budget-hint" aria-invalid={budget !== '' && !budgetOk} />
          <Button
            type="button"
            variant="outline"
            className="max-lg:h-11"
            disabled={!budgetOk || busy}
            onClick={async () => {
              setBusy(true);
              const err = await save({ ...settings, budget: { ...settings.budget, monthly_usd: amount } });
              setBusy(false);
              if (err) setError(err);
              else {
                setError(null);
                toast.success(t('setup.budget_saved'));
                status.reload();
              }
            }}
          >
            {t('setup.budget_save')}
          </Button>
        </div>
        <p id="setup-budget-hint" className="text-xs text-muted-foreground">
          {budget !== '' && !budgetOk ? t('setup.budget_invalid') : t('setup.budget_hint')}
        </p>
      </section>
      <section className="space-y-3" aria-label={t('setup.alerts_title')}>
        <h3 className="text-sm font-semibold">{t('setup.alerts_title')}</h3>
        <p className="text-xs text-muted-foreground">{t('setup.alerts_how', { store: info?.secret_store ?? '—' })}</p>
        <p role="status" className="text-sm font-medium" data-testid="alerts-status">
          {g && g.alert_ready ? t('setup.alerts_ready', { channels: g.channels.join(', ') }) : t('setup.alerts_none')}
        </p>
        <ChannelGuide channel="email" />
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <Label htmlFor="setup-email-from">{t('setup.email_from')}</Label>
            <Input id="setup-email-from" type="email" className="h-11 lg:h-10" value={from} autoComplete="off" onChange={(e) => setFrom(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="setup-email-to">{t('setup.email_to')}</Label>
            <Input id="setup-email-to" className="h-11 lg:h-10" value={to} autoComplete="off" onChange={(e) => setTo(e.target.value)} />
          </div>
        </div>
        <div className="space-y-1">
          <Label htmlFor="setup-email-key">{t('setup.email_key')}</Label>
          <Input id="setup-email-key" type="password" autoComplete="off" className="h-11 lg:h-10" value={key} onChange={(e) => setKey(e.target.value)} />
        </div>
        {(from !== '' || to !== '') && !emailOk && <p className="text-xs text-destructive">{t('setup.email_invalid')}</p>}
        <Button
          type="button"
          variant="outline"
          className="max-lg:h-11"
          disabled={!emailOk || key.trim() === '' || busy}
          onClick={async () => {
            setBusy(true);
            setError(null);
            try {
              // The key goes straight into the secret store and is never read back.
              await client.putSecret('email-api-key', key.trim());
              setKey('');
              const err = await save({ ...settings, apps: { ...settings.apps, email: { ...settings.apps.email, provider: 'resend', enabled: true, from: from.trim(), to: to.split(',').map((a) => a.trim()) } } });
              if (err) setError(err);
              else {
                toast.success(t('setup.email_saved'));
                reload();
                status.reload();
              }
            } catch (e) {
              setError(toProblem(e).message);
            }
            setBusy(false);
          }}
        >
          {t('setup.email_save')}
        </Button>
        <ChannelGuide channel="telegram" />
        <ChannelGuide channel="slack" />
        <ChannelGuide channel="webhook" />
        <p className="text-xs text-muted-foreground">{t('setup.alerts_more')}</p>
        <Button type="button" variant="outline" className="max-lg:h-11" onClick={() => navigate(hrefs.settings('apps'))}>
          {t('setup.open_apps')}
        </Button>
      </section>
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function LocaleStep({ dispatch }: { dispatch: Dispatch }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">{t('setup.locale_how')}</p>
      <LocaleEditor idPrefix="setup-locale" onSaved={() => dispatch({ type: 'locale_saved' })} />
    </div>
  );
}

export function SecurityStep({ s, dispatch, onRun }: { s: SetupState; dispatch: Dispatch; onRun: () => void }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">{t('setup.security_how')}</p>
      <Button type="button" variant="outline" className="max-lg:h-11" disabled={s.busy} onClick={onRun}>
        {s.busy ? t('flow.working') : t('setup.run_security')}
      </Button>
      {s.security && (
        <ul className="space-y-1.5" aria-label={t('setup.step_security')}>
          {s.security.map((i) => (
            <li key={i.id} className="flex flex-col gap-1 rounded-md border p-2 text-sm sm:flex-row sm:items-center sm:justify-between" data-testid={`sec-${i.id}`}>
              <span>{i.message}</span>
              <Badge variant={i.state === 'fail' ? 'destructive' : i.state === 'pass' ? 'outline' : 'secondary'}>{i.state === 'fail' ? t('setup.sec_fail') : i.state === 'pass' ? t('setup.sec_pass') : t('setup.sec_remind')}</Badge>
            </li>
          ))}
        </ul>
      )}
      {s.security && !s.securityBlocking && (
        <div className="flex min-h-11 items-center gap-3">
          <TouchCheckbox id="setup-ack" checked={s.mfaAck} onCheckedChange={(c) => dispatch({ type: 'ack', value: c === true })} />
          <Label htmlFor="setup-ack">{t('setup.ack_two_factor')}</Label>
        </div>
      )}
    </div>
  );
}
