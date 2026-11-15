import { useState } from 'react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ApiError, type ApiClient } from '../../api/client';
import { EFFECTS, ENVIRONMENTS, MODES, SCOPES, type Environment, type Mode, type PermSettings, type Rule } from '../../api/perm';
import { t, type MessageKey } from '../../lib/i18n';
import { newRule, ruleProblem, withMode, withoutRule, withRule } from '../../lib/perm';
import { FieldError } from '../sched-bits';
import { withStepUp } from './with-step-up';

const ANY = '__any__';

async function save(client: ApiClient, next: PermSettings, ok: MessageKey, reload: () => void): Promise<boolean> {
  try {
    await withStepUp(() => client.perm.save(next));
    toast.success(t(ok));
    return true;
  } catch (e) {
    toast.error(e instanceof ApiError ? e.message : t('perm.save_failed'));
    return false;
  } finally {
    reload();
  }
}

export function ModeCard({ client, settings, reload }: { client: ApiClient; settings: PermSettings; reload: () => void }) {
  const [mode, setMode] = useState<Mode>(settings.default_mode);
  const [busy, setBusy] = useState(false);
  const dirty = mode !== settings.default_mode;
  return (
    <Card className="space-y-3 p-4" data-testid="perm-mode">
      <div>
        <h2 className="text-sm font-semibold">{t('perm.mode_title')}</h2>
        <p className="text-xs text-muted-foreground">{t('perm.mode_desc')}</p>
      </div>
      <div className="max-w-sm space-y-1.5">
        <Label htmlFor="perm-mode">{t('perm.mode_label')}</Label>
        <Select value={mode} onValueChange={(v) => setMode(v as Mode)}>
          <SelectTrigger id="perm-mode" data-testid="perm-mode-select">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {MODES.map((m) => (
              <SelectItem key={m} value={m}>
                {t(`perm.mode_${m}` as MessageKey)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <p className="text-sm text-muted-foreground" data-testid="perm-mode-help">
        {t(`perm.mode_${mode}_help` as MessageKey)}
      </p>
      <Button
        className="w-full max-lg:h-11 sm:w-auto"
        disabled={!dirty || busy}
        onClick={async () => {
          setBusy(true);
          await save(client, withMode(settings, mode), 'perm.mode_saved', reload);
          setBusy(false);
        }}
      >
        {t('perm.mode_save')}
      </Button>
    </Card>
  );
}

function scopeText(r: Rule): string {
  return r.scope === 'person' && !r.scope_id ? t('perm.rule_for_everyone') : `${t(`perm.scope_${r.scope}` as MessageKey).toLowerCase()} ${r.scope_id ?? ''}`.trim();
}

function conditions(r: Rule): string {
  return [r.command && `command ${r.command}`, r.path && `path ${r.path}`, r.env && r.env, r.tool && `tool ${r.tool}`, r.server && `server ${r.server}`].filter(Boolean).join(', ');
}

export function RulesCard({ client, settings, reload }: { client: ApiClient; settings: PermSettings; reload: () => void }) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<Rule>(newRule());
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const problem = tried ? ruleProblem(draft) : null;
  const set = (patch: Partial<Rule>) => setDraft((d) => ({ ...d, ...patch }));

  async function submit() {
    setTried(true);
    if (ruleProblem(draft)) return;
    setBusy('add');
    const ok = await save(client, withRule(settings, draft), 'perm.rule_saved', reload);
    setBusy(null);
    if (ok) {
      setOpen(false);
      setDraft(newRule());
      setTried(false);
    }
  }

  return (
    <Card className="space-y-3 p-4" data-testid="perm-rules">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold">{t('perm.rules_title')}</h2>
          <p className="text-xs text-muted-foreground">{t('perm.rules_desc')}</p>
        </div>
        <Button className="w-full max-lg:h-11 sm:w-auto" onClick={() => setOpen(true)} data-testid="perm-rule-add">
          {t('perm.rule_add')}
        </Button>
      </div>
      {settings.rules.length === 0 ? <p className="text-sm text-muted-foreground">{t('perm.rules_none')}</p> : null}
      <ul className="space-y-2" aria-label={t('perm.rule_list')}>
        {settings.rules.map((r) => (
          <li key={r.id} className="flex flex-col gap-2 rounded-md border p-3 sm:flex-row sm:items-center sm:justify-between" data-testid="perm-rule" data-effect={r.effect}>
            <div className="min-w-0 space-y-1">
              <p className="break-words text-sm font-medium">{t('perm.rule_summary', { effect: t(`perm.effect_${r.effect}` as MessageKey), action: r.action, scope: scopeText(r) })}</p>
              {conditions(r) ? <p className="break-words text-xs text-muted-foreground">{t('perm.rule_conditions', { text: conditions(r) })}</p> : null}
              {r.note ? <p className="break-words text-xs text-muted-foreground">{r.note}</p> : null}
            </div>
            <Button
              variant="outline"
              className="w-full max-lg:h-11 sm:w-auto"
              disabled={busy === r.id}
              onClick={async () => {
                setBusy(r.id);
                await save(client, withoutRule(settings, r.id), 'perm.rule_deleted', reload);
                setBusy(null);
              }}
            >
              {t('perm.rule_delete')}
            </Button>
          </li>
        ))}
      </ul>

      <PanelSheet open={open} onOpenChange={(o) => !o && setOpen(false)}>
        <PanelSheetContent size="compact" data-testid="perm-rule-sheet">
          <PanelSheetHeader>
            <PanelSheetTitle>{t('perm.rule_sheet_title')}</PanelSheetTitle>
            <PanelSheetDescription>{t('perm.rule_sheet_desc')}</PanelSheetDescription>
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
                <Label htmlFor="rule-effect">{t('perm.rule_effect')}</Label>
                <Select value={draft.effect} onValueChange={(v) => set({ effect: v as Rule['effect'] })}>
                  <SelectTrigger id="rule-effect">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {EFFECTS.map((x) => (
                      <SelectItem key={x} value={x}>
                        {t(`perm.effect_${x}` as MessageKey)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rule-action">{t('perm.rule_action')}</Label>
                <Input id="rule-action" className="max-lg:h-11" autoComplete="off" autoCapitalize="none" spellCheck={false} value={draft.action} aria-invalid={problem === 'action'} aria-describedby="rule-action-hint" onChange={(e) => set({ action: e.target.value })} />
                <p id="rule-action-hint" className="text-xs text-muted-foreground">
                  {t('perm.rule_action_hint')}
                </p>
                <FieldError msg={problem === 'action' ? t('perm.rule_action_invalid') : undefined} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rule-scope">{t('perm.rule_scope')}</Label>
                <Select value={draft.scope} onValueChange={(v) => set({ scope: v as Rule['scope'] })}>
                  <SelectTrigger id="rule-scope">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SCOPES.map((x) => (
                      <SelectItem key={x} value={x}>
                        {t(`perm.scope_${x}` as MessageKey)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {draft.scope !== 'person' ? (
                <div className="space-y-1.5">
                  <Label htmlFor="rule-scope-id">{t('perm.rule_scope_id')}</Label>
                  <Input id="rule-scope-id" className="max-lg:h-11" autoComplete="off" autoCapitalize="none" spellCheck={false} value={draft.scope_id ?? ''} aria-invalid={problem === 'scope_id'} onChange={(e) => set({ scope_id: e.target.value })} />
                  <FieldError msg={problem === 'scope_id' ? t('perm.rule_scope_invalid') : undefined} />
                </div>
              ) : null}
              <div className="space-y-1.5">
                <Label htmlFor="rule-command">{t('perm.rule_command')}</Label>
                <Input id="rule-command" className="max-lg:h-11" autoComplete="off" autoCapitalize="none" spellCheck={false} value={draft.command ?? ''} aria-describedby="rule-command-hint" onChange={(e) => set({ command: e.target.value })} />
                <p id="rule-command-hint" className="text-xs text-muted-foreground">
                  {t('perm.rule_command_hint')}
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rule-tool">{t('perm.rule_tool')}</Label>
                <Input id="rule-tool" className="max-lg:h-11" autoComplete="off" autoCapitalize="none" spellCheck={false} value={draft.tool ?? ''} aria-describedby="rule-tool-hint" onChange={(e) => set({ tool: e.target.value })} />
                <p id="rule-tool-hint" className="text-xs text-muted-foreground">
                  {t('perm.rule_tool_hint')}
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rule-server">{t('perm.rule_server')}</Label>
                <Input id="rule-server" className="max-lg:h-11" autoComplete="off" autoCapitalize="none" spellCheck={false} value={draft.server ?? ''} aria-describedby="rule-server-hint" onChange={(e) => set({ server: e.target.value })} />
                <p id="rule-server-hint" className="text-xs text-muted-foreground">
                  {t('perm.rule_server_hint')}
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rule-env">{t('perm.rule_env')}</Label>
                <Select value={draft.env ?? ANY} onValueChange={(v) => set({ env: v === ANY ? null : (v as Environment) })}>
                  <SelectTrigger id="rule-env">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ANY}>{t('perm.env_any')}</SelectItem>
                    {ENVIRONMENTS.map((x) => (
                      <SelectItem key={x} value={x}>
                        {t(`perm.env_${x}` as MessageKey)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rule-note">{t('perm.rule_note')}</Label>
                <Input id="rule-note" className="max-lg:h-11" autoComplete="off" value={draft.note} maxLength={200} onChange={(e) => set({ note: e.target.value })} />
              </div>
            </PanelSheetBody>
            <PanelSheetFooter>
              <Button type="button" variant="outline" className="max-lg:h-11" onClick={() => setOpen(false)}>
                {t('perm.cancel')}
              </Button>
              <Button type="submit" className="max-lg:h-11" disabled={busy === 'add'}>
                {t('perm.rule_add')}
              </Button>
            </PanelSheetFooter>
          </form>
        </PanelSheetContent>
      </PanelSheet>
    </Card>
  );
}
