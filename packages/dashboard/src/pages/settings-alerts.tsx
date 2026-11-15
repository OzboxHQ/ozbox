import { useEffect, useState, useSyncExternalStore } from 'react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Spinner } from '@/components/ui/spinner';
import type { AlertSummary, TestItem } from '../api/alert-types';
import type { RecentAlert, SettingsResponse } from '../api/types';
import { useApp } from '../App';
import { channelName, fmtOffset, isOutcome, lastDays, outcomeLabel, outcomeLine, outcomeVariant, testItemLabel } from '../lib/alert-outcome';
import { ABSENT } from '../lib/format';
import { formatWithUtc } from '../lib/locale';
import { t } from '../lib/i18n';
import { shownFor, testSendStore } from '../lib/test-send-store';
import { useAsync } from '../lib/use-async';

function ItemState({ item }: { item: TestItem }) {
  if (item.status === 'pending') {
    return (
      <Badge variant="outline" className="gap-1">
        <Spinner className="h-3 w-3" aria-hidden="true" />
        {t('test.pending')}
      </Badge>
    );
  }
  return item.status === 'sent' ? <Badge variant="secondary">{t('test.sent')}</Badge> : <Badge variant="destructive">{t('test.failed')}</Badge>;
}

/** Each channel of the latest test send from a card, pending until it answers. Shown on the card the test came from. */
export function TestResults({ channel, prefix }: { channel?: string; prefix?: string }) {
  const all = useSyncExternalStore(testSendStore.subscribe, testSendStore.get);
  const hit = shownFor(all, { ...(channel !== undefined ? { channel } : {}), ...(prefix !== undefined ? { prefix } : {}) });
  if (!hit) return null;
  const { run, timedOut } = hit.shown;
  return (
    <div className="space-y-2 rounded-md border p-3 text-sm" data-testid="test-results">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-xs font-semibold">{t('test.title')}</h3>
        <Button type="button" variant="outline" size="sm" className="max-lg:h-11" onClick={() => testSendStore.clear(hit.key)}>
          {t('common.close')}
        </Button>
      </div>
      <ul className="space-y-2" aria-label={t('test.title')} aria-live="polite">
        {run.items.map((i, n) => (
          <li key={`${i.channel}-${i.person ?? ''}-${n}`} className="flex flex-wrap items-center gap-x-2 gap-y-1" data-testid="test-item" data-status={i.status}>
            <span>{testItemLabel(i)}</span>
            <ItemState item={i} />
            {i.status === 'failed' && i.detail ? <span className="text-xs text-muted-foreground" data-testid="test-detail">{i.detail}</span> : null}
          </li>
        ))}
      </ul>
      {timedOut ? <p className="text-xs text-muted-foreground">{t('test.timeout')}</p> : null}
    </div>
  );
}

/** What became of one alert: the whole, then a line per person with the channels. Old alerts read as an em dash. */
export function OutcomeBlock({ alert }: { alert: RecentAlert }) {
  const overall = isOutcome(alert.outcome) ? alert.outcome : null;
  return (
    <div className="space-y-1 text-xs" data-testid="alert-outcome" data-outcome={overall ?? 'none'}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground">{t('outcome.label')}:</span>
        {overall ? (
          <Badge variant={outcomeVariant(overall)}>{outcomeLabel(overall)}</Badge>
        ) : (
          <span>
            <span aria-hidden="true">{ABSENT}</span>
            <span className="sr-only">{t('outcome.unknown')}</span>
          </span>
        )}
      </div>
      {alert.outcomes && alert.outcomes.length > 0 ? (
        <ul className="space-y-0.5 text-muted-foreground">
          {alert.outcomes.map((o, n) => (
            <li key={`${o.person ?? ''}-${n}`}>{outcomeLine(o, t('summary.everyone'))}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

/** The value of the person select that means no one in particular. */
const EVERYONE = '__everyone__';

function SummaryBody({ onClose }: { onClose: () => void }) {
  const { client, info } = useApp();
  const [date, setDate] = useState<string | undefined>(undefined);
  const [today, setToday] = useState<string | null>(null);
  // Everyone's day follows the fleet's time zone; a person's own day follows theirs, so their "today" is asked for afresh.
  const [person, setPerson] = useState<string>(EVERYONE);
  const who = person === EVERYONE ? undefined : person;
  const people = useAsync<SettingsResponse>((s) => client.getSettings(s), [client]);
  const ids = Object.keys(people.data?.settings.routing.people ?? {}).sort();
  const data = useAsync<AlertSummary>((s) => client.alertSummary(date, s, who), [client, date, who]);
  useEffect(() => {
    // Only an answer for the person now chosen may name today (the one before it was for someone else's zone).
    if (data.data && today === null && date === undefined && (data.data.person ?? EVERYONE) === person) setToday(data.data.date);
  }, [data.data, today, date, person]);
  const choosePerson = (p: string) => {
    setPerson(p);
    setDate(undefined);
    setToday(null);
  };
  const days = today ? lastDays(today) : [];
  const shown = date ?? data.data?.date ?? '';
  const s = data.data;
  return (
    <>
      <PanelSheetHeader>
        <PanelSheetTitle>{t('summary.title')}</PanelSheetTitle>
        <PanelSheetDescription>{t('summary.help')}</PanelSheetDescription>
      </PanelSheetHeader>
      <PanelSheetBody className="space-y-4">
        <div className="space-y-1">
          <Label htmlFor="summary-person">{t('summary.person')}</Label>
          <Select value={person} onValueChange={choosePerson}>
            <SelectTrigger id="summary-person" data-testid="summary-person" className="max-lg:h-11">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={EVERYONE}>{t('summary.person_all')}</SelectItem>
              {ids.map((id) => (
                <SelectItem key={id} value={id}>
                  {id}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="summary-day">{t('summary.day')}</Label>
          <Select value={shown} onValueChange={setDate} disabled={days.length === 0}>
            <SelectTrigger id="summary-day" data-testid="summary-day" className="max-lg:h-11">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {days.map((d) => (
                <SelectItem key={d} value={d}>
                  {d}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {s ? <p className="text-xs text-muted-foreground" data-testid="summary-zone">{s.time_zone ? t('summary.zone', { zone: s.time_zone }) : t('summary.zone_offset', { offset: fmtOffset(s.utc_offset_minutes) })}</p> : null}
        </div>
        {data.error && !s ? <p role="alert" className="text-sm text-destructive">{t('summary.load_failed')}</p> : null}
        {data.loading && !s ? <Skeleton className="h-24 w-full" /> : null}
        {s ? (
          <>
            <p className="text-sm" data-testid="summary-counts">
              {t('summary.counts', { delivered: s.counts.delivered, held: s.counts.held_quiet + s.counts.held_limit, not_sent: s.counts.not_sent, failed: (s.counts.failed ?? 0) + (s.counts.partial ?? 0), retrying: s.counts.retrying ?? 0, unknown: s.counts.unknown })}
            </p>
            {s.items.length === 0 ? (
              <p className="text-sm text-muted-foreground" data-testid="summary-none">{t('summary.none')}</p>
            ) : (
              <ul className="space-y-2" aria-label={t('summary.title')} data-testid="summary-items">
                {s.items.map((i, n) => (
                  <li key={`${i.key}-${i.person ?? ''}-${n}`} className="space-y-1 rounded-md border p-3 text-sm" data-testid="summary-item" data-status={i.status ?? 'none'}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{i.title}</span>
                      {i.severity === 'urgent' ? <Badge variant="destructive">{t('apps.urgent')}</Badge> : null}
                      {i.status ? (
                        <Badge variant={outcomeVariant(i.status)}>{outcomeLabel(i.status)}</Badge>
                      ) : (
                        <span>
                          <span aria-hidden="true">{ABSENT}</span>
                          <span className="sr-only">{t('outcome.unknown')}</span>
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {formatWithUtc(i.ts_ms, info?.clock?.time_zone)}
                      {i.person ? ` · ${i.person}` : ''}
                      {i.channels.length > 0 ? ` · ${i.channels.map(channelName).join(', ')}` : ''}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </>
        ) : null}
      </PanelSheetBody>
      <PanelSheetFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          {t('common.close')}
        </Button>
      </PanelSheetFooter>
    </>
  );
}

/** One day's alerts and what became of each, in a sheet. */
export function SummarySheet({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <PanelSheet open={open} onOpenChange={onOpenChange}>
      <PanelSheetContent data-testid="summary-sheet">{open ? <SummaryBody onClose={() => onOpenChange(false)} /> : null}</PanelSheetContent>
    </PanelSheet>
  );
}
