import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Skeleton } from '@/components/ui/skeleton';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { ApiError } from '../../api/client';
import type { OrphanItem, OrphanPlanResponse, OrphansResponse } from '../../api/bill';
import { useApp } from '../../App';
import { mayWrite } from '../../lib/role-gates';
import { useCan } from '../../lib/use-can';
import { CannotNote } from '../role-scope';
import { chooseable, confirmMatches, kindText, lockedText, money, reasonText, totalCost, ageText } from '../../lib/bill';
import { ABSENT } from '../../lib/format';
import { t } from '../../lib/i18n';
import { askStepUp, STEP_UP_CODE } from '../../lib/step-up';
import { useAsync } from '../../lib/use-async';

type Phase = { name: 'planning' } | { name: 'review'; plan: OrphanPlanResponse } | { name: 'deleting' } | { name: 'failed'; message: string };

function costText(i: OrphanItem, currency: string | null): string {
  if (i.month_cost === null) return ABSENT;
  const c = money(i.month_cost, currency);
  return i.cost_is_most ? t('orph.cost_most', { cost: c }) : c;
}

/** Plan, then apply: the plan names what will go, and the words to type are shown beside the box they go in. */
function DeleteSheet({ ids, currency, onClose, onDone }: { ids: string[]; currency: string | null; onClose: () => void; onDone: () => void }) {
  const { client } = useApp();
  const [phase, setPhase] = useState<Phase>({ name: 'planning' });
  const [typed, setTyped] = useState('');

  useEffect(() => {
    const ctl = new AbortController();
    client.bill
      .planOrphans(ids, ctl.signal)
      .then((plan) => setPhase({ name: 'review', plan }))
      .catch((e: unknown) => {
        if (!ctl.signal.aborted) setPhase({ name: 'failed', message: e instanceof ApiError ? e.message : t('orph.plan_failed') });
      });
    return () => ctl.abort();
  }, [client, ids]);

  const apply = async (plan: OrphanPlanResponse) => {
    setPhase({ name: 'deleting' });
    const attempt = () => client.bill.applyOrphans(plan.plan_id, typed.trim());
    try {
      try {
        await attempt();
      } catch (e) {
        // Behind a sign-in, an irreversible change first needs a fresh passkey; the same plan is then tried again.
        if (e instanceof ApiError && e.code === STEP_UP_CODE && (await askStepUp())) await attempt();
        else throw e;
      }
      toast.success(t('orph.deleting'));
      onDone();
    } catch (e) {
      setPhase({ name: 'failed', message: e instanceof ApiError ? e.message : t('orph.apply_failed') });
    }
  };

  const review = phase.name === 'review' ? phase.plan : null;
  const busy = phase.name === 'planning' || phase.name === 'deleting';
  return (
    <PanelSheet open onOpenChange={(o) => !o && !busy && onClose()}>
      <PanelSheetContent size="compact" data-testid="orphans-sheet">
        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(e) => {
            e.preventDefault();
            if (review && confirmMatches(typed, review.requires_confirm_text)) void apply(review);
          }}
        >
          <PanelSheetHeader>
            <PanelSheetTitle>{t('orph.sheet_title', { n: ids.length })}</PanelSheetTitle>
            <PanelSheetDescription>{t('orph.sheet_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <PanelSheetBody className="space-y-3">
            {phase.name === 'planning' ? <p role="status" className="text-sm">{t('orph.planning')}</p> : null}
            {phase.name === 'deleting' ? <p role="status" className="text-sm">{t('orph.deleting')}</p> : null}
            {phase.name === 'failed' ? <p role="alert" className="text-sm text-destructive">{phase.message}</p> : null}
            {review ? (
              <>
                <ul className="space-y-1 text-sm" aria-label={t('orph.sheet_title', { n: review.plan.items.length })}>
                  {review.plan.items.map((i) => (
                    <li key={i.id} className="break-all">
                      <span className="font-medium">{i.id}</span> · {kindText(i.kind)} · {reasonText(i.reason)}
                    </li>
                  ))}
                </ul>
                {review.plan.month_cost !== null ? <p className="text-sm">{t('orph.sheet_cost', { cost: money(review.plan.month_cost, currency) })}</p> : null}
                <p className="text-sm text-muted-foreground">{t('orph.sheet_may_hold')}</p>
                <div className="space-y-1">
                  <Label htmlFor="orph-confirm">{t('orph.confirm_label', { text: review.requires_confirm_text })}</Label>
                  <Input id="orph-confirm" autoComplete="off" autoCapitalize="none" spellCheck={false} className="max-lg:h-11" value={typed} disabled={busy} onChange={(e) => setTyped(e.target.value)} />
                </div>
              </>
            ) : null}
          </PanelSheetBody>
          <PanelSheetFooter>
            <Button type="button" variant="outline" className="max-lg:h-11" disabled={busy} onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" variant="destructive" className="max-lg:h-11" disabled={!review || busy || !confirmMatches(typed, review.requires_confirm_text)}>
              {t('orph.confirm_button')}
            </Button>
          </PanelSheetFooter>
        </form>
      </PanelSheetContent>
    </PanelSheet>
  );
}

function Rows({ data, selected, toggle, mayChoose }: { data: OrphansResponse; selected: Set<string>; toggle: (id: string) => void; mayChoose: boolean }) {
  const scan = data.scan;
  if (!scan) return null;
  const currency = scan.currency;
  return (
    <div className="overflow-x-auto" tabIndex={0} role="region" aria-label={t('orph.table')}>
      <table className="w-full min-w-[46rem] text-left text-sm" data-testid="orphans-table">
        <caption className="sr-only">{t('orph.table')}</caption>
        <thead>
          <tr className="text-xs text-muted-foreground">
            <th scope="col" className="w-12 py-1 pr-2 font-medium">{t('orph.col_select')}</th>
            <th scope="col" className="py-1 pr-2 font-medium">{t('orph.col_resource')}</th>
            <th scope="col" className="py-1 pr-2 font-medium">{t('orph.col_kind')}</th>
            <th scope="col" className="py-1 pr-2 font-medium">{t('orph.col_why')}</th>
            <th scope="col" className="py-1 pr-2 text-right font-medium">{t('orph.col_size')}</th>
            <th scope="col" className="py-1 text-right font-medium">{t('orph.col_cost')}</th>
          </tr>
        </thead>
        <tbody>
          {scan.items.map((i) => {
            const locked = lockedText(i);
            return (
              <tr key={i.id} className="border-t align-top" data-testid={`orphan-${i.id}`}>
                <td className="py-1 pr-2">
                  {i.deletable && mayChoose ? (
                    <TouchCheckbox checked={selected.has(i.id)} onCheckedChange={() => toggle(i.id)} aria-label={t('orph.select_row', { id: i.id })} />
                  ) : null}
                </td>
                <th scope="row" className="py-2 pr-2 font-normal">
                  <span className="break-all font-medium">{i.id}</span>
                  {i.box_name ? <span className="block text-xs text-muted-foreground">{i.box_name}</span> : null}
                </th>
                <td className="py-2 pr-2">{kindText(i.kind)}</td>
                <td className="py-2 pr-2">
                  {reasonText(i.reason)}
                  {locked ? <span className="block text-xs text-muted-foreground">{locked}</span> : null}
                </td>
                <td className="py-2 pr-2 text-right tabular-nums">{i.size_gb === null ? ABSENT : `${i.size_gb} GB`}</td>
                <td className="py-2 text-right tabular-nums">{costText(i, currency)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Resources that look like Oz Box's but are untagged, and disks and snapshots nothing uses, with what each costs. */
export function OrphansCard() {
  const { client } = useApp();
  const q = useAsync<OrphansResponse>((s) => client.bill.orphans(s), [client], 6_000);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [sheet, setSheet] = useState<string[] | null>(null);
  const [asking, setAsking] = useState(false);
  const { can } = useCan();
  const mayScan = mayWrite('bill', can);
  const mayDelete = can('manage_costs');
  const data = q.data;
  const items = useMemo(() => data?.scan?.items ?? [], [data]);

  // A resource that disappeared from the scan cannot stay chosen.
  useEffect(() => {
    setSelected((prev) => {
      const live = new Set(items.filter((i) => i.deletable).map((i) => i.id));
      const next = new Set([...prev].filter((id) => live.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [items]);

  if (!data) return q.error ? <p role="alert" className="text-sm text-destructive">{q.error.message}</p> : <Skeleton className="h-40 w-full" />;
  const scan = data.scan;
  const busy = data.scanning || data.deleting || asking;
  const chosen = items.filter((i) => selected.has(i.id));
  const total = totalCost(items);
  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const scanNow = async () => {
    setAsking(true);
    try {
      await client.bill.scanOrphans();
      q.reload();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('common.request_failed'));
    } finally {
      setAsking(false);
    }
  };

  return (
    <Card className="space-y-3 p-4" data-testid="orphans-card">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">{t('orph.title')}</h2>
          <p className="mt-1 text-sm text-muted-foreground">{t('orph.desc')}</p>
        </div>
        {mayScan ? (
          <Button variant="outline" className="w-full sm:w-auto max-lg:h-11" disabled={busy || scan?.unsupported === true} onClick={scanNow}>
            {data.scanning ? t('orph.scanning') : t('orph.scan')}
          </Button>
        ) : null}
      </div>
      {scan ? <p className="text-xs text-muted-foreground">{t('orph.scanned', { age: ageText(Math.max(0, (Date.now() - scan.scanned_at_ms) / 1000)) })}</p> : <p className="text-sm">{t('orph.never')}</p>}
      {scan?.unsupported ? <p role="status" className="text-sm">{t('orph.unsupported')}</p> : null}
      {scan?.error && !scan.unsupported ? <p role="status" className="text-sm text-destructive">{t('orph.error', { why: scan.error })}</p> : null}
      {scan && !scan.unsupported && items.length === 0 && !scan.error ? <p className="text-sm" data-testid="orphans-none">{t('orph.none')}</p> : null}
      {items.length > 0 ? (
        <>
          <Rows data={data} selected={selected} toggle={toggle} mayChoose={mayDelete} />
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1 text-sm">
              {total !== null ? <p className="font-medium tabular-nums">{t('orph.total', { cost: money(total, scan?.currency) })}</p> : null}
              <p className="text-xs text-muted-foreground">{t('orph.select_hint')}</p>
            </div>
            {mayDelete ? (
              <Button variant="destructive" className="w-full sm:w-auto max-lg:h-11" disabled={busy || chosen.length === 0 || chooseable(chosen).length !== chosen.length} onClick={() => setSheet(chosen.map((i) => i.id))}>
                {t('orph.delete_selected', { n: chosen.length })}
              </Button>
            ) : (
              <CannotNote cap="manage_costs" what="roles.cannot_orph" />
            )}
          </div>
        </>
      ) : null}
      {data.last_delete ? (
        <div className="space-y-1 border-t pt-3 text-sm" data-testid="orphans-last-delete">
          <h3 className="text-xs font-medium text-muted-foreground">{t('orph.last_delete')}</h3>
          <p>
            {data.last_delete.results.every((r) => r.ok)
              ? t('orph.deleted_all', { n: data.last_delete.results.length })
              : t('orph.deleted_some', { ok: data.last_delete.results.filter((r) => r.ok).length, n: data.last_delete.results.length })}
          </p>
          <ul className="space-y-0.5 text-xs text-muted-foreground">
            {data.last_delete.results
              .filter((r) => !r.ok)
              .map((r) => (
                <li key={r.id} className="break-words">{t('orph.left_alone', { id: r.id, why: r.message ?? '' })}</li>
              ))}
          </ul>
        </div>
      ) : null}
      {data.deleting ? <Badge variant="outline">{t('orph.deleting')}</Badge> : null}
      {sheet ? (
        <DeleteSheet
          ids={sheet}
          currency={scan?.currency ?? null}
          onClose={() => setSheet(null)}
          onDone={() => {
            setSheet(null);
            setSelected(new Set());
            q.reload();
          }}
        />
      ) : null}
    </Card>
  );
}
