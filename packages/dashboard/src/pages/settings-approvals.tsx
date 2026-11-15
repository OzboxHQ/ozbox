import { useState } from 'react';
import { toast } from 'sonner';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Progress } from '@/components/ui/progress';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ApiError, type ApiClient } from '../api/client';
import { ACTION_KINDS, type ActionKind, type ApprovalPolicy, type SpendCaps, type SpendLedger } from '../api/tasks';
import { useApp } from '../App';
import { withStepUp } from '../components/perm/with-step-up';
import { FieldError } from '../components/sched-bits';
import { capsLoosen, capsToForm, EXPIRY_CHOICES, formToCaps, formToPolicy, policyChanges, policyLoosens, policyToForm, usedPct, type CapsForm, type PolicyForm } from '../lib/approval-policy';
import { t } from '../lib/i18n';
import { fmtCents, KIND_KEY } from '../lib/tasks';
import { useAsync } from '../lib/use-async';

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="break-words text-sm font-medium">{value}</dd>
    </div>
  );
}

const kindName = (k: ActionKind) => t(KIND_KEY[k]);
const listText = (v: string[]) => (v.length === 0 ? t('policy.none') : v.join(', '));
const expiryText = (s: number) => {
  const c = EXPIRY_CHOICES.find((e) => e.seconds === s);
  return c ? t(c.label as 'policy.expiry_1h') : `${s} s`;
};

/** Edit the policy in a sheet; saving goes through a review of exactly what changes. */
function PolicySheet({ client, current, onClose, onSaved }: { client: ApiClient; current: ApprovalPolicy; onClose: () => void; onSaved: () => void }) {
  const { info } = useApp();
  const [form, setForm] = useState<PolicyForm>(policyToForm(current));
  const [next, setNext] = useState<ApprovalPolicy | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const toggle = (field: 'ask' | 'step_up', k: ActionKind, on: boolean) => setForm((f) => ({ ...f, [field]: on ? [...f[field], k] : f[field].filter((x) => x !== k) }));

  function review() {
    const r = formToPolicy(form);
    if (!r.ok) return setErr(t(r.error as 'policy.err_branches'));
    setErr(null);
    setNext(r.value);
  }

  async function save() {
    if (!next) return;
    setBusy(true);
    try {
      // asking for less needs a fresh passkey behind a sign-in; the server decides and refuses without one
      await withStepUp(() => client.tasks.savePolicy(next));
      toast.success(t('policy.saved'));
      onSaved();
      onClose();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t('common.save_failed'));
      setNext(null);
    } finally {
      setBusy(false);
    }
  }

  const changes = next ? policyChanges(current, next, kindName) : [];
  const show = (key: string, v: string) => {
    if (v === '') return t('policy.empty_value');
    if (key === 'policy.f_expiry') return expiryText(Number(v));
    if (key === 'policy.f_threshold') return fmtCents(Number(v));
    if (key === 'policy.f_requester') return v === 'true' ? t('policy.yes') : t('policy.no');
    return v;
  };
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="policy-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{next ? t('policy.review_title') : t('policy.edit_policy')}</PanelSheetTitle>
          <PanelSheetDescription>{t('policy.desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {err ? (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{err}</AlertDescription>
            </Alert>
          ) : null}
          {next ? (
            <section aria-label={t('policy.review_title')} data-testid="policy-review">
              {changes.length === 0 ? <p className="text-sm">{t('policy.review_none')}</p> : null}
              {next && policyLoosens(current, next) ? (
                <p role="status" data-testid="policy-loosens" className="mb-2 text-sm font-medium">
                  {t(info?.loosening_refused ? 'policy.loosens_refused' : 'policy.loosens_note')}
                </p>
              ) : null}
              <ul className="space-y-2 text-sm">
                {changes.map((c) => (
                  <li key={c.key} className="break-words">
                    {t('policy.review_line', { what: t(c.key as 'policy.f_ask'), from: show(c.key, c.from), to: show(c.key, c.to) })}
                  </li>
                ))}
              </ul>
            </section>
          ) : (
            <>
              <fieldset className="space-y-1">
                <legend className="text-sm font-medium">{t('policy.ask_group')}</legend>
                {ACTION_KINDS.map((k) => (
                  <div key={k} className="flex items-center gap-1">
                    <TouchCheckbox id={`pa-${k}`} checked={form.ask.includes(k)} onCheckedChange={(c) => toggle('ask', k, c === true)} />
                    <Label htmlFor={`pa-${k}`}>{kindName(k)}</Label>
                  </div>
                ))}
              </fieldset>
              <div className="space-y-1">
                <Label htmlFor="pa-branches">{t('policy.f_branches')}</Label>
                <Textarea id="pa-branches" rows={4} value={form.protected_branches} onChange={(e) => setForm({ ...form, protected_branches: e.target.value })} />
                <p className="text-xs text-muted-foreground">{t('policy.branches_hint')}</p>
              </div>
              <div className="space-y-1">
                <Label htmlFor="pa-commands">{t('policy.f_commands')}</Label>
                <Textarea id="pa-commands" rows={6} value={form.ask_commands} onChange={(e) => setForm({ ...form, ask_commands: e.target.value })} />
                <p className="text-xs text-muted-foreground">{t('policy.commands_hint')}</p>
              </div>
              <div className="space-y-1">
                <Label htmlFor="pa-threshold">{t('policy.threshold_label')}</Label>
                <Input id="pa-threshold" inputMode="decimal" autoComplete="off" className="max-lg:h-11" value={form.spend_threshold} onChange={(e) => setForm({ ...form, spend_threshold: e.target.value })} />
                <p className="text-xs text-muted-foreground">{t('policy.threshold_hint')}</p>
              </div>
              <div className="space-y-1">
                <Label htmlFor="pa-expiry">{t('policy.expiry_label')}</Label>
                <Select value={String(form.expiry_s)} onValueChange={(v) => setForm({ ...form, expiry_s: Number(v) })}>
                  <SelectTrigger id="pa-expiry">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {EXPIRY_CHOICES.map((c) => (
                      <SelectItem key={c.seconds} value={String(c.seconds)}>
                        {t(c.label as 'policy.expiry_1h')}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="pa-approvers">{t('policy.f_approvers')}</Label>
                <Textarea id="pa-approvers" rows={3} value={form.approvers} onChange={(e) => setForm({ ...form, approvers: e.target.value })} />
                <p className="text-xs text-muted-foreground">{t('policy.approvers_hint')}</p>
              </div>
              <div className="flex items-center gap-1">
                <TouchCheckbox id="pa-requester" checked={form.allow_requester} onCheckedChange={(c) => setForm({ ...form, allow_requester: c === true })} />
                <Label htmlFor="pa-requester">{t('policy.f_requester')}</Label>
              </div>
              <fieldset className="space-y-1">
                <legend className="text-sm font-medium">{t('policy.step_group')}</legend>
                <p className="text-xs text-muted-foreground">{t('policy.step_hint')}</p>
                {ACTION_KINDS.map((k) => (
                  <div key={k} className="flex items-center gap-1">
                    <TouchCheckbox id={`ps-${k}`} checked={form.step_up.includes(k)} onCheckedChange={(c) => toggle('step_up', k, c === true)} />
                    <Label htmlFor={`ps-${k}`}>{kindName(k)}</Label>
                  </div>
                ))}
              </fieldset>
            </>
          )}
        </PanelSheetBody>
        <PanelSheetFooter>
          {next ? (
            <>
              <Button variant="outline" className="max-lg:h-11" disabled={busy} onClick={() => setNext(null)}>
                {t('policy.back')}
              </Button>
              <Button className="max-lg:h-11" disabled={busy || changes.length === 0} onClick={save}>
                {t('policy.save')}
              </Button>
            </>
          ) : (
            <>
              <Button variant="outline" className="max-lg:h-11" onClick={onClose}>
                {t('common.cancel')}
              </Button>
              <Button className="max-lg:h-11" onClick={review}>
                {t('policy.review')}
              </Button>
            </>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function CapsSheet({ client, current, onClose, onSaved }: { client: ApiClient; current: SpendCaps; onClose: () => void; onSaved: () => void }) {
  const { info } = useApp();
  const [form, setForm] = useState<CapsForm>(capsToForm(current));
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function save() {
    const r = formToCaps(form);
    if (!r.ok) return setErr(t(r.error as 'caps.err_fleet'));
    setErr(null);
    setBusy(true);
    try {
      await withStepUp(() => client.tasks.saveCaps(r.value));
      toast.success(t('policy.saved'));
      onSaved();
      onClose();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t('common.save_failed'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="caps-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('caps.title_sheet')}</PanelSheetTitle>
          <PanelSheetDescription>{t('caps.hint')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {err ? <FieldError msg={err} /> : null}
          {(() => {
            const r = formToCaps(form);
            return r.ok && capsLoosen(current, r.value) ? (
              <p role="status" data-testid="caps-loosens" className="text-sm font-medium">
                {t(info?.loosening_refused ? 'caps.loosens_refused' : 'caps.loosens_note')}
              </p>
            ) : null;
          })()}
          <div className="space-y-1">
            <Label htmlFor="cp-fleet">{t('caps.fleet_label')}</Label>
            <Input id="cp-fleet" inputMode="decimal" autoComplete="off" className="max-lg:h-11" value={form.fleet} onChange={(e) => setForm({ ...form, fleet: e.target.value })} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="cp-person">{t('caps.person_label')}</Label>
            <Input id="cp-person" inputMode="decimal" autoComplete="off" className="max-lg:h-11" value={form.person} onChange={(e) => setForm({ ...form, person: e.target.value })} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="cp-over">{t('caps.overrides_label')}</Label>
            <Textarea id="cp-over" rows={4} value={form.overrides} onChange={(e) => setForm({ ...form, overrides: e.target.value })} />
            <p className="text-xs text-muted-foreground">{t('caps.overrides_hint')}</p>
          </div>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className="max-lg:h-11" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button className="max-lg:h-11" disabled={busy} onClick={save}>
            {t('common.save')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function LimitLine({ label, spent, limit }: { label: string; spent: number; limit: number | null }) {
  const pct = usedPct(spent, limit);
  return (
    <div className="space-y-1">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-medium">{limit === null ? `${t('caps.none')} · ${t('caps.used', { spent: fmtCents(spent) })}` : t('caps.used_of', { spent: fmtCents(spent), limit: fmtCents(limit), pct: pct ?? 0 })}</p>
      {pct !== null ? <Progress value={pct} aria-label={label} className="h-2" /> : null}
    </div>
  );
}

/** Settings, Approvals: what agents must ask about, who answers, and the monthly spend limits. */
export function ApprovalsSection() {
  const { client } = useApp();
  const policy = useAsync((s) => client.tasks.policy(s), [client]);
  const caps = useAsync((s) => client.tasks.caps(s), [client]);
  const [editPolicy, setEditPolicy] = useState(false);
  const [editCaps, setEditCaps] = useState(false);
  const p = policy.data;
  const c = caps.data;
  const unavailable = (policy.error instanceof ApiError && policy.error.status === 501) || (caps.error instanceof ApiError && caps.error.status === 501);
  if (unavailable) return <p className="text-sm text-muted-foreground">{t('tasks.unavailable_body')}</p>;
  if ((policy.error && !p) || (caps.error && !c)) return <p role="alert" className="text-sm text-destructive">{(policy.error ?? caps.error)?.message}</p>;
  if (!p || !c) return <Skeleton className="h-40 w-full" />;
  const ledger: SpendLedger = c.ledger;
  return (
    <div className="space-y-4">
      <Card className="space-y-3 p-4">
        <div className="flex items-start justify-between gap-2">
          <h2 className="text-sm font-semibold">{t('policy.card_ask')}</h2>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setEditPolicy(true)}>
            {t('policy.edit_policy')}
          </Button>
        </div>
        <dl className="grid gap-3 sm:grid-cols-2">
          <Row label={t('policy.f_ask')} value={listText(p.ask.map(kindName))} />
          <Row label={t('policy.f_step_up')} value={listText(p.step_up.map(kindName))} />
          <Row label={t('policy.f_branches')} value={listText(p.protected_branches)} />
          <Row label={t('policy.f_commands')} value={listText(p.ask_commands)} />
          <Row label={t('policy.threshold_label')} value={p.spend_threshold_cents === null ? t('policy.no_threshold') : fmtCents(p.spend_threshold_cents)} />
          <Row label={t('policy.expiry_label')} value={expiryText(p.expiry_s)} />
        </dl>
        <h3 className="pt-1 text-sm font-semibold">{t('policy.card_who')}</h3>
        <dl className="grid gap-3 sm:grid-cols-2">
          <Row label={t('policy.f_approvers')} value={p.approvers.length === 0 ? t('policy.anyone') : p.approvers.join(', ')} />
          <Row label={t('policy.f_requester')} value={p.allow_requester ? t('policy.yes') : t('policy.no')} />
        </dl>
      </Card>
      <Card className="space-y-3 p-4">
        <div className="flex items-start justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold">{t('caps.title')}</h2>
            <p className="text-xs text-muted-foreground">{t('caps.month', { month: ledger.month || '-' })}</p>
          </div>
          <Button variant="outline" size="sm" className="max-lg:h-11" onClick={() => setEditCaps(true)}>
            {t('policy.edit_limits')}
          </Button>
        </div>
        <div className="space-y-3">
          <LimitLine label={t('caps.fleet')} spent={ledger.fleet_cents} limit={c.caps.fleet_monthly_cents} />
          <LimitLine label={t('caps.person')} spent={Math.max(0, ...Object.values(ledger.by_person))} limit={c.caps.person_monthly_cents} />
          {Object.entries(c.caps.per_person).map(([who, limit]) => (
            <LimitLine key={who} label={t('caps.person_own', { who })} spent={ledger.by_person[who] ?? 0} limit={limit} />
          ))}
        </div>
        <p className="text-xs text-muted-foreground">{t('caps.hint')}</p>
      </Card>
      {editPolicy ? <PolicySheet client={client} current={p} onClose={() => setEditPolicy(false)} onSaved={policy.reload} /> : null}
      {editCaps ? <CapsSheet client={client} current={c.caps} onClose={() => setEditCaps(false)} onSaved={caps.reload} /> : null}
    </div>
  );
}
