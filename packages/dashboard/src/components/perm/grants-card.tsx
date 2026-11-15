import { useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ApiError, type ApiClient } from '../../api/client';
import { GRANT_SCOPES, type Grant, type PermView, type Scope } from '../../api/perm';
import { t, type MessageKey } from '../../lib/i18n';
import { EMPTY_GRANT, grantBody, grantProblem, minutesLeft, splitGrants, type GrantForm } from '../../lib/perm';
import { FieldError } from '../sched-bits';
import { withStepUp } from './with-step-up';

function factorText(g: Grant): string {
  if (g.factor_is_real) return t('perm.grant_factor_real');
  return g.factor === 'typed_confirmation' ? t('perm.grant_factor_typed') : t('perm.grant_factor_none');
}

export function GrantsCard({ client, view, reload }: { client: ApiClient; view: PermView; reload: () => void }) {
  const { active, past } = splitGrants(view.grants);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<GrantForm>(EMPTY_GRANT);
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [toRevoke, setToRevoke] = useState<Grant | null>(null);
  const problem = tried ? grantProblem(form, view.max_grant_minutes, view.signed_in) : null;
  const set = (patch: Partial<GrantForm>) => setForm((f) => ({ ...f, ...patch }));

  async function submit() {
    setTried(true);
    if (grantProblem(form, view.max_grant_minutes, view.signed_in)) return;
    setBusy(true);
    try {
      const g = await withStepUp(() => client.perm.grant(grantBody(form, view.signed_in)));
      toast.success(t('perm.grant_made', { minutes: Math.round((g.expires_ms - g.created_ms) / 60_000) }));
      setOpen(false);
      setForm(EMPTY_GRANT);
      setTried(false);
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('perm.grant_failed'));
    } finally {
      setBusy(false);
      reload();
    }
  }

  return (
    <Card className="space-y-3 p-4" data-testid="perm-grants">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold">{t('perm.grants_title')}</h2>
          <p className="text-xs text-muted-foreground">{t('perm.grants_desc')}</p>
        </div>
        <Button className="w-full max-lg:h-11 sm:w-auto" onClick={() => setOpen(true)} data-testid="perm-grant-add">
          {t('perm.grant_add')}
        </Button>
      </div>
      {active.length === 0 ? <p className="text-sm text-muted-foreground">{t('perm.grants_none')}</p> : null}
      <ul className="space-y-2" aria-label={t('perm.grants_list')}>
        {active.map((g) => (
          <li key={g.id} className="flex flex-col gap-2 rounded-md border p-3 sm:flex-row sm:items-center sm:justify-between" data-testid="perm-grant" data-state={g.state}>
            <div className="min-w-0 space-y-1">
              <p className="break-words text-sm font-medium">
                {t(`perm.scope_${g.scope}` as MessageKey)} {g.scope_id}
                <span className="ml-2 text-xs font-normal text-muted-foreground">{g.actions.join(' ')}</span>
              </p>
              <p className="break-words text-xs text-muted-foreground">{g.reason}</p>
              <div className="flex flex-wrap items-center gap-1.5">
                <Badge>{t('perm.grant_left', { n: minutesLeft(g, view.now_ms) })}</Badge>
                <Badge variant="outline">{t('perm.grant_by', { who: g.granted_by })}</Badge>
                <Badge variant={g.factor_is_real ? 'secondary' : 'outline'}>{factorText(g)}</Badge>
                {g.allow_unattended ? <Badge variant="destructive">{t('perm.grant_unattended_badge')}</Badge> : null}
              </div>
            </div>
            <Button variant="outline" className="w-full max-lg:h-11 sm:w-auto" onClick={() => setToRevoke(g)}>
              {t('perm.grant_revoke')}
            </Button>
          </li>
        ))}
      </ul>
      {past.length > 0 ? (
        <div className="space-y-1.5">
          <h3 className="text-xs font-semibold text-muted-foreground">{t('perm.grants_past')}</h3>
          <ul className="space-y-1" aria-label={t('perm.grants_past')}>
            {past.slice(0, 8).map((g) => (
              <li key={g.id} className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground" data-testid="perm-grant-past" data-state={g.state}>
                <Badge variant="outline">{t(`perm.grant_state_${g.state}` as MessageKey)}</Badge>
                <span className="break-words">
                  {t(`perm.scope_${g.scope}` as MessageKey)} {g.scope_id}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <ConfirmDialog
        open={!!toRevoke}
        onOpenChange={(o) => !o && setToRevoke(null)}
        title={t('perm.grant_revoke_title')}
        description={t('perm.grant_revoke_body', { scope: toRevoke ? `${toRevoke.scope} ${toRevoke.scope_id}` : '' })}
        confirmLabel={t('perm.grant_revoke')}
        destructive
        onConfirm={async () => {
          if (!toRevoke) return;
          try {
            await client.perm.revoke(toRevoke.id);
            toast.success(t('perm.grant_revoked'));
            setToRevoke(null);
          } catch (e) {
            toast.error(e instanceof ApiError ? e.message : t('perm.grant_revoke_failed'));
            throw e;
          } finally {
            reload();
          }
        }}
      />

      <PanelSheet open={open} onOpenChange={(o) => !o && setOpen(false)}>
        <PanelSheetContent size="compact" data-testid="perm-grant-sheet">
          <PanelSheetHeader>
            <PanelSheetTitle>{t('perm.grant_sheet_title')}</PanelSheetTitle>
            <PanelSheetDescription>{t('perm.grant_sheet_desc')}</PanelSheetDescription>
          </PanelSheetHeader>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
            className="flex min-h-0 flex-1 flex-col"
          >
            <PanelSheetBody className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="grant-scope">{t('perm.grant_scope')}</Label>
                <Select value={form.scope} onValueChange={(v) => set({ scope: v as Scope })}>
                  <SelectTrigger id="grant-scope">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {GRANT_SCOPES.map((x) => (
                      <SelectItem key={x} value={x}>
                        {t(`perm.scope_${x}` as MessageKey)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="grant-scope-id">{t('perm.grant_scope_id')}</Label>
                <Input id="grant-scope-id" className="max-lg:h-11" autoComplete="off" autoCapitalize="none" spellCheck={false} value={form.scopeId} aria-invalid={problem === 'scope_id'} onChange={(e) => set({ scopeId: e.target.value })} />
                <FieldError msg={problem === 'scope_id' ? t('perm.grant_scope_id_invalid') : undefined} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="grant-reason">{t('perm.grant_reason')}</Label>
                <Input id="grant-reason" className="max-lg:h-11" autoComplete="off" maxLength={300} value={form.reason} aria-invalid={problem === 'reason'} aria-describedby="grant-reason-hint" onChange={(e) => set({ reason: e.target.value })} />
                <p id="grant-reason-hint" className="text-xs text-muted-foreground">
                  {t('perm.grant_reason_hint')}
                </p>
                <FieldError msg={problem === 'reason' ? t('perm.grant_reason_invalid') : undefined} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="grant-minutes">{t('perm.grant_minutes')}</Label>
                <Input id="grant-minutes" className="max-lg:h-11" inputMode="numeric" autoComplete="off" value={form.minutes} aria-invalid={problem === 'minutes'} aria-describedby="grant-minutes-hint" onChange={(e) => set({ minutes: e.target.value })} />
                <p id="grant-minutes-hint" className="text-xs text-muted-foreground">
                  {t('perm.grant_minutes_hint', { max: view.max_grant_minutes })}
                </p>
                <FieldError msg={problem === 'minutes' ? t('perm.grant_minutes_invalid') : undefined} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="grant-actions">{t('perm.grant_actions')}</Label>
                <Input id="grant-actions" className="max-lg:h-11" autoComplete="off" autoCapitalize="none" spellCheck={false} value={form.actions} aria-invalid={problem === 'actions'} aria-describedby="grant-actions-hint" onChange={(e) => set({ actions: e.target.value })} />
                <p id="grant-actions-hint" className="text-xs text-muted-foreground">
                  {t('perm.grant_actions_hint')}
                </p>
                <FieldError msg={problem === 'actions' ? t('perm.grant_actions_invalid') : undefined} />
              </div>
              <div className="flex items-center gap-3">
                <Checkbox id="grant-unattended" checked={form.allowUnattended} onCheckedChange={(c) => set({ allowUnattended: c === true })} className="h-5 w-5 max-lg:h-11 max-lg:w-11 max-lg:rounded-md" />
                <Label htmlFor="grant-unattended">{t('perm.grant_unattended')}</Label>
              </div>
              {view.signed_in ? (
                <p className="text-sm text-muted-foreground">{t('perm.grant_signed_in_note')}</p>
              ) : (
                <div className="space-y-1.5">
                  <Label htmlFor="grant-confirm">{t('perm.grant_confirm')}</Label>
                  <Input id="grant-confirm" className="max-lg:h-11" autoComplete="off" autoCapitalize="none" spellCheck={false} value={form.confirm} aria-invalid={problem === 'confirm'} aria-describedby="grant-confirm-hint" onChange={(e) => set({ confirm: e.target.value })} />
                  <p id="grant-confirm-hint" className="text-xs text-muted-foreground">
                    {t('perm.grant_confirm_hint')}
                  </p>
                  <FieldError msg={problem === 'confirm' ? t('perm.grant_confirm_invalid') : undefined} />
                </div>
              )}
            </PanelSheetBody>
            <PanelSheetFooter>
              <Button type="button" variant="outline" className="max-lg:h-11" onClick={() => setOpen(false)}>
                {t('perm.cancel')}
              </Button>
              <Button type="submit" className="max-lg:h-11" disabled={busy}>
                {t('perm.grant_submit')}
              </Button>
            </PanelSheetFooter>
          </form>
        </PanelSheetContent>
      </PanelSheet>
    </Card>
  );
}
