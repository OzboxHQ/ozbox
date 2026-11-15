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
import { Progress } from '@/components/ui/progress';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { TAP_ACTION, TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { useApp } from '../App';
import { ApiError, type ApiClient } from '../api/client';
import type { FeatureState, MergeState, Orch, OrchFeature, OrchMessage, OrchState, OrchSummary } from '../api/orch';
import { AppLink, AppPage, EmptyState, PageHeader } from '../components/page';
import { CannotNote } from '../components/role-scope';
import { SourceNote } from '../components/source-badge';
import { fmtRelative } from '../lib/format';
import { t, type MessageKey } from '../lib/i18n';
import { mayWrite, PAGE_CANNOT, PAGE_CAPABILITY } from '../lib/role-gates';
import { hrefs } from '../lib/router';
import { fmtCents } from '../lib/tasks';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

const FEATURE_KEY: Record<FeatureState, MessageKey> = {
  planned: 'orch.f_planned',
  starting: 'orch.f_starting',
  working: 'orch.f_working',
  blocked: 'orch.f_blocked',
  ready_to_merge: 'orch.f_ready_to_merge',
  in_queue: 'orch.f_in_queue',
  merged: 'orch.f_merged',
  conflict_returned: 'orch.f_conflict_returned',
  paused: 'orch.f_paused',
  stopped: 'orch.f_stopped',
  failed: 'orch.f_failed',
};

const MERGE_KEY: Record<MergeState, MessageKey> = {
  waiting: 'orch.m_waiting',
  rebasing: 'orch.m_rebasing',
  testing: 'orch.m_testing',
  awaiting_approval: 'orch.m_awaiting_approval',
  merging: 'orch.m_merging',
  merged: 'orch.m_merged',
  conflict: 'orch.m_conflict',
  tests_failed: 'orch.m_tests_failed',
  failed: 'orch.m_failed',
};

const ORCH_KEY: Record<OrchState, MessageKey> = {
  active: 'orch.state_active',
  paused: 'orch.state_paused',
  done: 'orch.state_done',
  stopped: 'orch.state_stopped',
};

const APPROVAL_KEY = { none: 'orch.approval_none', conductor: 'orch.approval_conductor', person: 'orch.approval_person' } as const;

const message = (e: unknown, fallback: MessageKey) => (e instanceof ApiError ? e.message : t(fallback));

function spendLine(spent: number, cap: number | null): string {
  return cap === null ? t('orch.spend_nocap', { spent: fmtCents(spent) }) : t('orch.spend_of', { spent: fmtCents(spent), cap: fmtCents(cap) });
}

/** Orchestrations: the list, and one orchestration's features, questions, messages, contracts and merge queue. */
export function OrchestrationsPage() {
  const { client } = useApp();
  const { can } = useCan();
  const write = mayWrite('orchestrations', can);
  const [selected, setSelected] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const list = useAsync((s) => client.orch.list(s), [client], 4000);
  const boxes = useAsync((s) => client.listBoxes(s), [client], 15000);
  const unavailable = list.error instanceof ApiError && list.error.status === 501;
  const items = list.data?.items ?? [];

  return (
    <AppPage>
      <PageHeader
        title={t('orch.title')}
        description={t('orch.desc')}
        actions={
          <>
            {write ? (
              <>
                <Button variant="outline" className={`w-full sm:w-auto ${TAP_ACTION}`} onClick={() => setConnecting(true)}>
                  {t('orch.connect')}
                </Button>
                <Button className={`w-full sm:w-auto ${TAP_ACTION}`} onClick={() => setStarting(true)} disabled={unavailable}>
                  {t('orch.start')}
                </Button>
              </>
            ) : null}
          </>
        }
      />
      {write ? null : <CannotNote cap={PAGE_CAPABILITY.orchestrations} what={PAGE_CANNOT.orchestrations} />}
      <SourceNote source={list.data?.source} what="orch" />
      {list.error && !unavailable ? <Alert variant="destructive" role="alert" data-testid="orch-list-error"><AlertDescription>{t('orch.list_failed', { why: list.error.message })}</AlertDescription></Alert> : null}
      {unavailable ? <EmptyState title={t('orch.unavailable')}>{t('orch.unavailable_body')}</EmptyState> : null}
      {!list.data && !list.error ? <Skeleton className="h-32 w-full" /> : null}
      {list.data && items.length === 0 ? <EmptyState title={t('orch.none')}>{t('orch.none_body')}</EmptyState> : null}
      {selected ? (
        <Detail key={selected} client={client} write={write} id={selected} onBack={() => setSelected(null)} boxNames={(boxes.data ?? []).filter((b) => b.state === 'running').map((b) => b.spec.name)} />
      ) : (
        <ul className="space-y-3" aria-label={t('orch.list_label')} data-testid="orch-list">
          {items.map((o) => (
            <li key={o.id}>
              <Summary o={o} onOpen={() => setSelected(o.id)} />
            </li>
          ))}
        </ul>
      )}
      {starting ? (
        <StartSheet
          client={client}
          boxes={(boxes.data ?? []).map((b) => b.spec.name)}
          simulated={list.data?.source === 'simulated'}
          onClose={() => setStarting(false)}
          onStarted={(id) => {
            setStarting(false);
            list.reload();
            setSelected(id);
          }}
        />
      ) : null}
      {connecting ? <ConnectSheet client={client} onClose={() => setConnecting(false)} /> : null}
    </AppPage>
  );
}

function Summary({ o, onOpen }: { o: OrchSummary; onOpen: () => void }) {
  return (
    <Card className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between" data-testid="orch-card">
      <div className="min-w-0 space-y-1">
        <p className="break-words text-sm font-medium">{o.goal}</p>
        <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
          <Badge variant={o.state === 'active' ? 'secondary' : 'outline'}>{t(ORCH_KEY[o.state])}</Badge>
          {o.needs_you ? <Badge variant="destructive">{t('orch.needs_you')}</Badge> : null}
          <span>{o.features === 1 ? t('orch.feature_one') : t('orch.features_n', { n: o.features })}</span>
          <span>{t('orch.on_box', { box: o.conductor_box })}</span>
          <span>{spendLine(o.spent_cents, o.cap_cents)}</span>
        </div>
      </div>
      <Button variant="outline" className={`w-full sm:w-auto ${TAP_ACTION}`} onClick={onOpen}>
        {t('orch.open')}
      </Button>
    </Card>
  );
}

function Detail({ client, write, id, onBack, boxNames }: { client: ApiClient; write: boolean; id: string; onBack: () => void; boxNames: string[] }) {
  const o = useAsync((s) => client.orch.get(id, s), [client, id], 3000);
  const [confirmStop, setConfirmStop] = useState(false);
  const [moving, setMoving] = useState<OrchFeature | null>(null);
  const [addUsd, setAddUsd] = useState('');
  const d = o.data;

  async function run(f: () => Promise<unknown>, ok: MessageKey) {
    try {
      await f();
      toast.success(t(ok));
      o.reload();
    } catch (e) {
      toast.error(message(e, 'orch.action_failed'));
      throw e;
    }
  }

  if (!d) return o.error ? <Alert variant="destructive" role="alert"><AlertDescription>{o.error.message}</AlertDescription></Alert> : <Skeleton className="h-64 w-full" />;
  const open = d.state === 'active' || d.state === 'paused';
  // the controls below change a run, so they belong to a role that may start one
  const act = write && open;
  const pct = d.cap_cents ? Math.min(100, Math.round((d.spent_cents / d.cap_cents) * 100)) : 0;
  const forYou = d.approvals.filter((a) => a.needs_person).length;

  return (
    <div className="space-y-5" data-testid="orch-detail">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-1">
          <Button variant="link" className="h-auto p-0 max-lg:min-h-11" onClick={onBack}>
            {t('orch.back')}
          </Button>
          <h2 className="break-words text-lg font-semibold">{d.goal}</h2>
          <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
            <Badge variant={d.state === 'active' ? 'secondary' : 'outline'}>{t(ORCH_KEY[d.state])}</Badge>
            <span>{t('orch.on_box', { box: d.conductor_box })}</span>
            {d.paused_reason ? <span>{t('orch.paused_reason', { why: d.paused_reason })}</span> : null}
          </div>
        </div>
        {act ? (
          <div className="flex w-full flex-wrap gap-2 sm:w-auto">
            {d.state === 'active' ? (
              <Button variant="outline" className={`flex-1 sm:flex-none ${TAP_ACTION}`} onClick={() => run(() => client.orch.pause(id), 'orch.paused_ok')}>
                {t('orch.pause')}
              </Button>
            ) : (
              <Button variant="outline" className={`flex-1 sm:flex-none ${TAP_ACTION}`} onClick={() => run(() => client.orch.resume(id), 'orch.resumed_ok')}>
                {t('orch.resume')}
              </Button>
            )}
            <Button variant="destructive" className={`flex-1 sm:flex-none ${TAP_ACTION}`} onClick={() => setConfirmStop(true)}>
              {t('orch.stop')}
            </Button>
          </div>
        ) : null}
      </div>

      <Card className="space-y-3 p-4" aria-label={t('orch.budget')}>
        <h3 className="text-sm font-semibold">{t('orch.budget')}</h3>
        <p className="text-sm">{spendLine(d.spent_cents, d.cap_cents)}</p>
        {d.cap_cents ? <Progress value={pct} aria-label={t('orch.budget')} /> : null}
        <p className="text-xs text-muted-foreground">{t('orch.policy_line', { workers: d.policy.max_workers, subs: d.policy.max_sub_agents, approval: t(APPROVAL_KEY[d.policy.merge_approval]) })}</p>
        {d.policy.notes.map((n) => (
          <p key={n} className="text-xs text-muted-foreground">{t('orch.policy_note', { note: n })}</p>
        ))}
        {act ? (
          <form
            className="flex flex-col gap-2 sm:flex-row sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              const n = Number(addUsd);
              if (!Number.isFinite(n) || n <= 0) return;
              run(() => client.orch.addBudget(id, n), 'orch.budget_raised').then(() => setAddUsd(''), () => undefined);
            }}
          >
            <div className="space-y-1">
              <Label htmlFor="orch-add-budget">{t('orch.budget_add_label')}</Label>
              <Input id="orch-add-budget" inputMode="decimal" className="max-lg:h-11 sm:w-48" value={addUsd} onChange={(e) => setAddUsd(e.target.value)} />
            </div>
            <Button type="submit" variant="outline" className={TAP_ACTION} disabled={!addUsd}>
              {t('orch.budget_add')}
            </Button>
          </form>
        ) : null}
      </Card>

      <Questions client={client} d={d} write={write} reload={o.reload} />

      <Card className="space-y-3 p-4" data-testid="orch-approvals">
        <h3 className="text-sm font-semibold">{t('orch.approvals')}</h3>
        {d.approvals.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('orch.approvals_none')}</p>
        ) : (
          <>
            <p className="text-sm">{t('orch.approvals_for_you', { n: forYou })}</p>
            <ul className="space-y-1 text-sm">
              {d.approvals.map((a) => (
                <li key={a.id} className="break-words">
                  <span className="font-mono text-xs">{a.action}</span>
                </li>
              ))}
            </ul>
            <AppLink href={hrefs.approvals} className="inline-flex min-h-11 items-center text-sm text-primary underline-offset-4 hover:underline lg:min-h-0">
              {t('orch.approvals_go')}
            </AppLink>
          </>
        )}
      </Card>

      <section className="space-y-2" aria-label={t('orch.features')} data-testid="orch-features">
        <h3 className="text-sm font-semibold">{t('orch.features')}</h3>
        {d.features.length === 0 ? <p className="text-sm text-muted-foreground">{t('orch.features_none')}</p> : null}
        <ul className="space-y-3">
          {d.features.map((f) => (
            <li key={f.id}>
              <FeatureCard
                f={f}
                write={write}
                onVerb={(v) => run(() => client.orch.feature(id, f.id, v), 'orch.feature_ok')}
                onQueue={() => run(() => client.orch.queue(id, f.id), 'orch.queued_ok')}
                onMove={() => setMoving(f)}
              />
            </li>
          ))}
        </ul>
      </section>

      <Card className="space-y-3 p-4" data-testid="orch-merge">
        <h3 className="text-sm font-semibold">{t('orch.merge')}</h3>
        {d.merge_queue.length === 0 ? <p className="text-sm text-muted-foreground">{t('orch.merge_none')}</p> : null}
        <ol className="space-y-1 text-sm">
          {d.merge_queue.map((m) => (
            <li key={`${m.feature_id}-${m.queued_ms}`} className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{d.features.find((f) => f.id === m.feature_id)?.title ?? m.feature_id}</span>
              <Badge variant="outline">{t(MERGE_KEY[m.state])}</Badge>
              {m.detail ? <span className="break-words text-xs text-muted-foreground">{m.detail}</span> : null}
            </li>
          ))}
        </ol>
      </Card>

      <Card className="space-y-3 p-4" data-testid="orch-contracts">
        <h3 className="text-sm font-semibold">{t('orch.contracts')}</h3>
        {d.contracts.length === 0 ? <p className="text-sm text-muted-foreground">{t('orch.contracts_none')}</p> : null}
        <ul className="space-y-1 text-sm">
          {d.contracts.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{c.name}</span>
              <Badge variant="outline">{t('orch.contract_line', { v: c.version })}</Badge>
              {c.agreed ? null : <Badge variant="secondary">{t('orch.contract_draft')}</Badge>}
            </li>
          ))}
        </ul>
      </Card>

      <Messages client={client} d={d} write={write} reload={o.reload} />

      <ConfirmDialog
        open={confirmStop}
        onOpenChange={setConfirmStop}
        title={t('orch.stop_title')}
        description={t('orch.stop_body')}
        confirmLabel={t('orch.stop_confirm')}
        destructive
        onConfirm={() => run(() => client.orch.stop(id), 'orch.stopped_ok')}
      />
      {moving ? <MoveSheet client={client} id={id} f={moving} boxes={boxNames} onClose={() => setMoving(null)} onDone={() => { setMoving(null); o.reload(); }} /> : null}
    </div>
  );
}

function FeatureCard({ f, write, onVerb, onQueue, onMove }: { f: OrchFeature; write: boolean; onVerb: (v: 'pause' | 'resume' | 'stop') => void; onQueue: () => void; onMove: () => void }) {
  const live = ['planned', 'starting', 'working', 'blocked', 'conflict_returned'].includes(f.state);
  const back = ['paused', 'stopped', 'failed'].includes(f.state);
  return (
    <Card className="space-y-2 p-4" data-testid="orch-feature">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-1">
          <p className="break-words text-sm font-medium">{f.title}</p>
          <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
            <Badge variant="outline">{t(FEATURE_KEY[f.state])}</Badge>
            <span>{t('orch.on_box', { box: f.box })}</span>
            <span className="break-all">{t('orch.branch', { branch: f.branch })}</span>
            <span>{fmtCents(f.spent_cents)}</span>
            <span>{t('orch.sub_agents', { n: f.sub_agents })}</span>
          </div>
          <p className="break-words text-xs text-muted-foreground">{f.claims.length ? `${t('orch.col_claims')}: ${f.claims.join(', ')}` : t('orch.no_claims')}</p>
          {f.after.length ? <p className="text-xs text-muted-foreground">{t('orch.waits_for', { after: f.after.join(', ') })}</p> : null}
        </div>
        <div className="flex w-full flex-wrap gap-2 sm:w-auto">
          {write && f.state === 'ready_to_merge' ? (
            <Button className={`flex-1 sm:flex-none ${TAP_ACTION}`} aria-label={t('orch.feature_queue', { title: f.title })} onClick={onQueue}>
              {t('orch.merge')}
            </Button>
          ) : null}
          {write && live ? (
            <Button variant="outline" className={`flex-1 sm:flex-none ${TAP_ACTION}`} aria-label={t('orch.feature_pause', { title: f.title })} onClick={() => onVerb('pause')}>
              {t('orch.pause')}
            </Button>
          ) : null}
          {write && back ? (
            <Button variant="outline" className={`flex-1 sm:flex-none ${TAP_ACTION}`} aria-label={t('orch.feature_resume', { title: f.title })} onClick={() => onVerb('resume')}>
              {t('orch.resume')}
            </Button>
          ) : null}
          {write && (live || back) ? (
            <Button variant="outline" className={`flex-1 sm:flex-none ${TAP_ACTION}`} aria-label={t('orch.feature_reassign', { title: f.title })} onClick={onMove}>
              {t('orch.col_box')}
            </Button>
          ) : null}
          {write && live ? (
            <Button variant="outline" className={`flex-1 sm:flex-none ${TAP_ACTION}`} aria-label={t('orch.feature_stop', { title: f.title })} onClick={() => onVerb('stop')}>
              {t('orch.stop')}
            </Button>
          ) : null}
        </div>
      </div>
    </Card>
  );
}

function Questions({ client, d, write, reload }: { client: ApiClient; d: Orch; write: boolean; reload: () => void }) {
  const [text, setText] = useState<Record<number, string>>({});
  async function answer(q: OrchMessage) {
    try {
      await client.orch.answer(d.id, q.seq, (text[q.seq] ?? '').trim());
      toast.success(t('orch.answered_ok'));
      reload();
    } catch (e) {
      toast.error(message(e, 'orch.action_failed'));
    }
  }
  return (
    <Card className="space-y-3 p-4" data-testid="orch-questions">
      <h3 className="text-sm font-semibold">{t('orch.questions')}</h3>
      {d.open_questions.length === 0 ? <p className="text-sm text-muted-foreground">{t('orch.questions_none')}</p> : null}
      <ul className="space-y-3">
        {d.open_questions.map((q) => (
          <li key={q.seq} className="space-y-2" data-testid="orch-question">
            <p className="break-words text-sm">{q.text}</p>
            <Badge variant={q.needs_person ? 'destructive' : 'outline'}>{q.needs_person ? t('orch.for_you') : t('orch.for_conductor')}</Badge>
            {write ? (
              <>
                <div className="space-y-1">
                  <Label htmlFor={`orch-answer-${q.seq}`}>{t('orch.answer_label', { from: q.from })}</Label>
                  <Textarea id={`orch-answer-${q.seq}`} rows={2} value={text[q.seq] ?? ''} onChange={(e) => setText((x) => ({ ...x, [q.seq]: e.target.value }))} />
                </div>
                <Button className={TAP_ACTION} disabled={!(text[q.seq] ?? '').trim()} onClick={() => answer(q)}>
                  {t('orch.answer_send')}
                </Button>
              </>
            ) : null}
          </li>
        ))}
      </ul>
    </Card>
  );
}

function Messages({ client, d, write, reload }: { client: ApiClient; d: Orch; write: boolean; reload: () => void }) {
  const [feature, setFeature] = useState('');
  const [text, setText] = useState('');
  const recent = d.messages.slice(-20).reverse();
  const canSend = write && d.features.length !== 0 && d.state === 'active';
  async function send() {
    try {
      await client.orch.message(d.id, feature, text.trim());
      toast.success(t('orch.sent_ok'));
      setText('');
      reload();
    } catch (e) {
      toast.error(message(e, 'orch.action_failed'));
    }
  }
  return (
    <Card className="space-y-3 p-4" data-testid="orch-messages">
      <h3 className="text-sm font-semibold">{t('orch.messages')}</h3>
      {recent.length === 0 ? <p className="text-sm text-muted-foreground">{t('orch.messages_none')}</p> : null}
      <ul className="space-y-2">
        {recent.map((m) => (
          <li key={m.seq} className="text-sm">
            <p className="text-xs text-muted-foreground">
              {t('orch.message_line', { from: m.from, to: m.to })} · {fmtRelative(new Date(m.ts_ms).toISOString())}
            </p>
            <p className="break-words">{m.text}</p>
          </li>
        ))}
      </ul>
      {canSend ? (
        <div className="space-y-2">
          <p className="text-xs font-medium">{t('orch.send_label')}</p>
          <div className="space-y-1">
            <Label htmlFor="orch-send-feature">{t('orch.send_feature')}</Label>
            <Select value={feature} onValueChange={setFeature}>
              <SelectTrigger id="orch-send-feature" className="max-lg:h-11 sm:w-64">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {d.features.map((f) => (
                  <SelectItem key={f.id} value={f.id}>
                    {f.title}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="orch-send-text">{t('orch.send_text')}</Label>
            <Textarea id="orch-send-text" rows={2} value={text} onChange={(e) => setText(e.target.value)} />
          </div>
          <Button variant="outline" className={TAP_ACTION} disabled={!feature || !text.trim()} onClick={send}>
            {t('orch.send')}
          </Button>
        </div>
      ) : null}
    </Card>
  );
}

function MoveSheet({ client, id, f, boxes, onClose, onDone }: { client: ApiClient; id: string; f: OrchFeature; boxes: string[]; onClose: () => void; onDone: () => void }) {
  const [box, setBox] = useState('');
  const [err, setErr] = useState<string | null>(null);
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent size="compact" data-testid="orch-move-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('orch.reassign_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('orch.reassign_body')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          <div className="space-y-1">
            <Label htmlFor="orch-move-box">{t('orch.reassign_label')}</Label>
            <Select value={box} onValueChange={setBox}>
              <SelectTrigger id="orch-move-box" className="max-lg:h-11">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {boxes.filter((b) => b !== f.box).map((b) => (
                  <SelectItem key={b} value={b}>
                    {b}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            className={TAP_ACTION_DEFAULT}
            disabled={!box}
            onClick={async () => {
              try {
                await client.orch.reassign(id, f.id, box);
                onDone();
              } catch (e) {
                setErr(message(e, 'orch.action_failed'));
              }
            }}
          >
            {t('orch.reassign_go')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function StartSheet({ client, boxes, simulated, onClose, onStarted }: { client: ApiClient; boxes: string[]; simulated: boolean; onClose: () => void; onStarted: (id: string) => void }) {
  const [goal, setGoal] = useState('');
  const [box, setBox] = useState('');
  const [workers, setWorkers] = useState('');
  const [subs, setSubs] = useState('');
  const [cap, setCap] = useState('');
  const [rules, setRules] = useState('');
  const [conduct, setConduct] = useState(false);
  const [errs, setErrs] = useState<{ goal?: boolean; box?: boolean }>({});
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const num = (s: string) => (s.trim() === '' ? undefined : Number(s));

  async function go() {
    const e = { goal: !goal.trim(), box: !box };
    setErrs(e);
    if (e.goal || e.box) return;
    setBusy(true);
    setErr(null);
    try {
      // the demo's simulated agent is the only engine it has
      const text = [simulated && !rules.includes('engine:') ? '---\nengine: fake\n---' : '', rules].filter(Boolean).join('\n');
      const r = await client.orch.start({
        goal: goal.trim(),
        conductor_box: box,
        rules: text || undefined,
        max_workers: num(workers),
        max_sub_agents: num(subs),
        max_spend_usd: num(cap),
        start_conductor: conduct,
      });
      toast.success(t('orch.new_ok'));
      onStarted(r.id);
    } catch (x) {
      setErr(message(x, 'orch.action_failed'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="orch-start-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('orch.new_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('orch.new_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          <div className="space-y-1">
            <Label htmlFor="orch-goal">{t('orch.new_goal')}</Label>
            <Textarea id="orch-goal" rows={3} value={goal} aria-invalid={errs.goal} onChange={(e) => setGoal(e.target.value)} />
            {errs.goal ? <p role="alert" className="text-xs text-destructive">{t('orch.new_err_goal')}</p> : null}
          </div>
          <div className="space-y-1">
            <Label htmlFor="orch-box">{t('orch.new_box')}</Label>
            <Select value={box} onValueChange={setBox}>
              <SelectTrigger id="orch-box" className="max-lg:h-11" aria-invalid={errs.box}>
                <SelectValue placeholder={t('orch.new_box_pick')} />
              </SelectTrigger>
              <SelectContent>
                {boxes.map((b) => (
                  <SelectItem key={b} value={b}>
                    {b}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errs.box ? <p role="alert" className="text-xs text-destructive">{t('orch.new_err_box')}</p> : null}
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1">
              <Label htmlFor="orch-workers">{t('orch.new_workers')}</Label>
              <Input id="orch-workers" inputMode="numeric" className="max-lg:h-11" value={workers} onChange={(e) => setWorkers(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="orch-subs">{t('orch.new_subs')}</Label>
              <Input id="orch-subs" inputMode="numeric" className="max-lg:h-11" value={subs} onChange={(e) => setSubs(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="orch-cap">{t('orch.new_cap')}</Label>
              <Input id="orch-cap" inputMode="decimal" className="max-lg:h-11" value={cap} onChange={(e) => setCap(e.target.value)} />
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="orch-rules">{t('orch.new_rules')}</Label>
            <Textarea id="orch-rules" rows={5} className="font-mono text-xs" value={rules} onChange={(e) => setRules(e.target.value)} />
            <p className="text-xs text-muted-foreground">{t('orch.new_rules_help')}</p>
          </div>
          <div className="flex items-center gap-1">
            <TouchCheckbox id="orch-conduct" checked={conduct} onCheckedChange={(c) => setConduct(c === true)} />
            <Label htmlFor="orch-conduct">{t('orch.new_conduct')}</Label>
          </div>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button className={TAP_ACTION_DEFAULT} disabled={busy} onClick={go}>
            {t('orch.new_go')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function ConnectSheet({ client, onClose }: { client: ApiClient; onClose: () => void }) {
  const [tok, setTok] = useState<{ url: string; token: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  async function make() {
    try {
      setTok(await client.orch.token());
    } catch (e) {
      setErr(message(e, 'orch.action_failed'));
    }
  }
  const snippet = JSON.stringify({ mcpServers: { ozbox: { type: 'http', url: tok?.url ?? '', headers: { Authorization: `Bearer ${tok?.token ?? ''}` } } } }, null, 2);
  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="orch-connect-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('orch.connect_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('orch.connect_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          {err ? <Alert variant="destructive" role="alert"><AlertDescription>{err}</AlertDescription></Alert> : null}
          <p className="text-sm">{t('orch.connect_note')}</p>
          {tok ? (
            <div className="space-y-2">
              <Label htmlFor="orch-mcp-snippet">{t('orch.connect_snippet')}</Label>
              <Textarea id="orch-mcp-snippet" readOnly rows={9} className="font-mono text-xs" value={snippet} data-testid="orch-mcp-snippet" />
              <Button variant="outline" className={TAP_ACTION} onClick={() => (navigator.clipboard?.writeText(snippet) ?? Promise.reject(new Error('no clipboard'))).then(() => toast.success(t('orch.copied')), () => toast.error(t('orch.copy_failed')))}>
                {t('orch.copy')}
              </Button>
            </div>
          ) : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>
            {t('common.close')}
          </Button>
          {tok ? null : (
            <Button className={TAP_ACTION_DEFAULT} onClick={make}>
              {t('orch.connect_make')}
            </Button>
          )}
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
