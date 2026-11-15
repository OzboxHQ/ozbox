import { useEffect, useMemo, useState } from 'react';

import { Input } from '@/components/ui/input';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import type { BoxRecord } from '../api/types';
import { filterItems, type PaletteItem } from '../lib/palette';
import { t, type MessageKey } from '../lib/i18n';
import type { FlowKind } from '../lib/flows';
import { hrefs, SETTINGS_SECTIONS, type SettingsSection } from '../lib/router';
import type { ActionKind } from './box-action-sheets';

const GROUP_KEY: Record<PaletteItem['group'], MessageKey> = { Pages: 'palette.group_pages', Boxes: 'palette.group_boxes', Actions: 'palette.group_actions' };

export type PaletteRun = { kind: 'go'; href: string } | { kind: 'action'; box: string; action: ActionKind } | { kind: 'flow'; flow: FlowKind };


/** One palette entry per Settings section, keyed by section so a section added to the router cannot be left out (the type refuses it). */
export const SETTINGS_LABEL: Record<SettingsSection, MessageKey> = {
  general: 'palette.settings_general',
  providers: 'nav.settings_providers',
  budgets: 'nav.settings_budgets',
  backups: 'palette.settings_backups',
  apps: 'nav.settings_apps',
  access: 'palette.settings_access',
  approvals: 'palette.settings_approvals',
  'secret-approvals': 'palette.settings_secret_approvals',
  approvers: 'nav.settings_approvers',
  models: 'nav.settings_models',
  defaults: 'nav.settings_defaults',
  members: 'nav.settings_members',
};

const SETTINGS_PAGES: { label: MessageKey; href: string }[] = SETTINGS_SECTIONS.map((section) => ({ label: SETTINGS_LABEL[section], href: hrefs.settings(section) }));

const PAGES: { label: MessageKey; href: string }[] = [
  { label: 'nav.fleet', href: hrefs.fleet },
  { label: 'nav.boxes', href: hrefs.boxes },
  { label: 'nav.tasks', href: hrefs.tasks },
  { label: 'nav.orchestrations', href: hrefs.orchestrations },
  { label: 'nav.memory', href: hrefs.memory },
  { label: 'nav.skills', href: hrefs.skills },
  { label: 'nav.chat', href: hrefs.chat },
  { label: 'nav.approvals', href: hrefs.approvals },
  { label: 'nav.usage', href: hrefs.usage },
  { label: 'nav.bill', href: hrefs.bill },
  { label: 'nav.activity', href: hrefs.activity },
  ...SETTINGS_PAGES,
];

export function buildItems(boxes: BoxRecord[]): { item: PaletteItem; run: PaletteRun }[] {
  const out: { item: PaletteItem; run: PaletteRun }[] = PAGES.map((p) => ({ item: { id: `page:${p.href}`, label: t(p.label), hint: t('palette.go_to_page'), group: 'Pages' }, run: { kind: 'go', href: p.href } }));
  out.push(
    { item: { id: 'flow:create', label: t('flow.create_box'), hint: t('palette.flow_hint'), group: 'Actions' }, run: { kind: 'flow', flow: 'create' } },
    { item: { id: 'flow:setup', label: t('flow.setup_fleet'), hint: t('palette.flow_hint'), group: 'Actions' }, run: { kind: 'flow', flow: 'setup' } },
  );
  for (const b of boxes) {
    const n = b.spec.name;
    out.push({ item: { id: `box:${n}`, label: n, hint: t('palette.open_box', { state: b.state }), group: 'Boxes' }, run: { kind: 'go', href: hrefs.box(n) } });
    if (b.state === 'running') out.push({ item: { id: `tools:${n}`, label: t('palette.tools_of', { name: n }), hint: t('palette.tools_hint'), group: 'Pages' }, run: { kind: 'go', href: hrefs.tools(n) } });
    const acts: [ActionKind, string][] = b.state === 'running' ? [['pause', t('menu.pause')]] : b.state === 'paused' ? [['resume', t('menu.resume')]] : [];
    if (b.state === 'instance_missing') acts.push(['upgrade', t('menu.finish_upgrade')], ['destroy', t('palette.verb_destroy')]);
    else acts.push(['snapshot', t('menu.snapshot')], ['resize', t('palette.verb_resize')], ['destroy', t('palette.verb_destroy')]);
    for (const [action, verb] of acts) {
      out.push({ item: { id: `act:${action}:${n}`, label: t('palette.action_label', { verb, name: n }), hint: t('palette.flow_hint'), group: 'Actions' }, run: { kind: 'action', box: n, action } });
    }
  }
  return out;
}

/** Jump to a page or box, or start an action. An action still shows its plan and asks before anything changes. */
export function CommandPalette({ open, onOpenChange, boxes, onRun }: { open: boolean; onOpenChange: (o: boolean) => void; boxes: BoxRecord[]; onRun: (r: PaletteRun) => void }) {
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const all = useMemo(() => buildItems(boxes), [boxes]);
  const shown = useMemo(() => {
    const keep = new Set(filterItems(all.map((a) => a.item), q).map((i) => i.id));
    return all.filter((a) => keep.has(a.item.id)).slice(0, 40);
  }, [all, q]);
  useEffect(() => {
    if (open) {
      setQ('');
      setActive(0);
    }
  }, [open]);
  const idx = Math.min(active, Math.max(0, shown.length - 1));
  const run = (r: PaletteRun) => {
    onOpenChange(false);
    onRun(r);
  };
  return (
    <PanelSheet open={open} onOpenChange={onOpenChange}>
      <PanelSheetContent size="compact" data-testid="palette">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('palette.title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('palette.description')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          <Input
            autoFocus
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={shown[idx] ? `pal-${shown[idx].item.id}` : undefined}
            aria-label={t('palette.search')}
            placeholder={t('palette.placeholder')}
            className="max-lg:h-11"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(0);
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActive(Math.min(idx + 1, shown.length - 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActive(Math.max(idx - 1, 0));
              } else if (e.key === 'Enter' && shown[idx]) {
                e.preventDefault();
                run(shown[idx].run);
              }
            }}
          />
          {shown.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('palette.nothing')}</p>
          ) : (
            <ul id="palette-list" role="listbox" aria-label={t('palette.results')} className="space-y-1">
              {shown.map((a, i) => (
                <li key={a.item.id} id={`pal-${a.item.id}`} role="option" aria-selected={i === idx}>
                  <button
                    type="button"
                    tabIndex={-1}
                    onClick={() => run(a.run)}
                    className={`flex min-h-11 w-full flex-col items-start justify-center rounded-md px-3 py-1 text-left text-sm outline-none ${i === idx ? 'bg-accent' : 'hover:bg-accent/60'}`}
                  >
                    <span className="font-medium">{a.item.label}</span>
                    <span className="text-xs text-muted-foreground">{`${t(GROUP_KEY[a.item.group])} · ${a.item.hint}`}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </PanelSheetBody>
      </PanelSheetContent>
    </PanelSheet>
  );
}
