import { useMemo, useRef, useState } from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { TAP_ACTION_DEFAULT } from '@/components/ui/tap-target';
import { Textarea } from '@/components/ui/textarea';
import { TouchCheckbox } from '@/components/ui/touch-checkbox';
import { useApp } from '../../App';
import { ApiError } from '../../api/client';
import type { SkillItem, StoreInfo } from '../../api/memory';
import { t } from '../../lib/i18n';
import { checkSkill, composeSkillMd, pickedPaths, readFrontMatter } from '../../lib/skill-compose';
import { problemMessage } from '../../lib/skills';

type Mode = 'write' | 'upload';

/** A file input may carry the folder attribute; React's types do not know it. */
const FOLDER_ATTR = { webkitdirectory: '' } as Record<string, string>;

async function readPicked(list: FileList): Promise<Record<string, string>> {
  const arr = Array.from(list);
  const paths = pickedPaths(arr);
  const out: Record<string, string> = {};
  for (const [i, f] of arr.entries()) out[paths[i] ?? f.name] = await f.text();
  return out;
}

/** Add a skill to the library: written on the page, or uploaded as files. Checked here for the words, and again by the server. */
export function AddSkillSheet({ skills, store, onClose, onDone }: { skills: SkillItem[]; store: StoreInfo | undefined; onClose: () => void; onDone: (item: SkillItem) => void }) {
  const { client } = useApp();
  const [mode, setMode] = useState<Mode>('write');
  const [f, setF] = useState({ name: '', description: '', version: '1', license: '', instructions: '' });
  const [picked, setPicked] = useState<Record<string, string>>({});
  const [touched, setTouched] = useState(false);
  const [replace, setReplace] = useState(false);
  const [shadow, setShadow] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const folder = useRef<HTMLInputElement>(null);
  const loose = useRef<HTMLInputElement>(null);

  const files = useMemo(() => {
    if (mode === 'upload') return picked;
    const extra = { ...picked };
    delete extra['SKILL.md'];
    return { ...extra, 'SKILL.md': composeSkillMd(f) };
  }, [mode, f, picked]);
  const name = readFrontMatter(files['SKILL.md'] ?? '').name;
  const existing = skills.find((s) => s.name === name);
  const problems = touched || Object.keys(picked).length > 0 ? checkSkill(files) : [];
  const needsReplace = existing?.source === 'library';
  const needsShadow = existing?.source === 'bundled';
  const ready = checkSkill(files).length === 0 && (!needsReplace || replace) && (!needsShadow || shadow);

  const pick = async (list: FileList | null) => {
    if (!list || list.length === 0) return;
    setErr(null);
    setPicked(await readPicked(list));
    setTouched(true);
  };
  const set = <K extends keyof typeof f>(k: K, v: string) => {
    setF({ ...f, [k]: v });
    setTouched(true);
  };

  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="skill-add-sheet">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('skills.add_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('skills.add_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-3">
          {store && !store.persisted ? <Alert data-testid="skill-add-not-kept"><AlertDescription>{t('skills.add_not_kept')}</AlertDescription></Alert> : null}
          {err ? <Alert variant="destructive" role="alert" data-testid="skill-add-error"><AlertDescription>{err}</AlertDescription></Alert> : null}
          <div className="space-y-1">
            <Label htmlFor="sk-how">{t('skills.add_how')}</Label>
            <Select value={mode} onValueChange={(v) => { setMode(v as Mode); setReplace(false); setShadow(false); }}>
              <SelectTrigger id="sk-how" className="max-lg:h-11">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="write">{t('skills.add_write')}</SelectItem>
                <SelectItem value="upload">{t('skills.add_upload')}</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {mode === 'write' ? (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="sk-name">{t('skills.f_name')}</Label>
                <Input id="sk-name" className="max-lg:h-11" value={f.name} onChange={(e) => set('name', e.target.value)} autoComplete="off" aria-describedby="sk-name-help" />
                <p id="sk-name-help" className="text-xs text-muted-foreground">{t('skills.f_name_help')}</p>
              </div>
              <div className="space-y-1">
                <Label htmlFor="sk-desc">{t('skills.f_description')}</Label>
                <Input id="sk-desc" className="max-lg:h-11" value={f.description} onChange={(e) => set('description', e.target.value)} autoComplete="off" aria-describedby="sk-desc-help" />
                <p id="sk-desc-help" className="text-xs text-muted-foreground">{t('skills.f_description_help')}</p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label htmlFor="sk-version">{t('skills.f_version')}</Label>
                  <Input id="sk-version" className="max-lg:h-11" value={f.version} onChange={(e) => set('version', e.target.value)} autoComplete="off" />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="sk-license">{t('skills.f_license')}</Label>
                  <Input id="sk-license" className="max-lg:h-11" value={f.license} onChange={(e) => set('license', e.target.value)} autoComplete="off" placeholder={t('skills.f_license_example')} />
                </div>
              </div>
              <div className="space-y-1">
                <Label htmlFor="sk-body">{t('skills.f_instructions')}</Label>
                <Textarea id="sk-body" rows={10} className="font-mono text-xs" value={f.instructions} onChange={(e) => set('instructions', e.target.value)} />
              </div>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">{t('skills.f_upload_help')}</p>
          )}
          <div className="space-y-1">
            <p className="text-sm font-medium">{mode === 'write' ? t('skills.f_extra') : t('skills.f_upload')}</p>
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => folder.current?.click()}>{t('skills.f_upload_folder')}</Button>
              <Button type="button" variant="outline" className={TAP_ACTION_DEFAULT} onClick={() => loose.current?.click()}>{t('skills.f_upload_files')}</Button>
              {Object.keys(picked).length > 0 ? <Button type="button" variant="ghost" className={TAP_ACTION_DEFAULT} onClick={() => setPicked({})}>{t('skills.f_clear')}</Button> : null}
            </div>
            <input ref={folder} type="file" className="sr-only" tabIndex={-1} aria-label={t('skills.f_upload_folder')} data-testid="skill-pick-folder" multiple {...FOLDER_ATTR} onChange={(e) => { void pick(e.target.files); e.target.value = ''; }} />
            <input ref={loose} type="file" className="sr-only" tabIndex={-1} aria-label={t('skills.f_upload_files')} data-testid="skill-pick-files" multiple onChange={(e) => { void pick(e.target.files); e.target.value = ''; }} />
            {Object.keys(picked).length > 0 ? (
              <p className="text-xs" data-testid="skill-picked">{t('skills.f_picked', { n: Object.keys(picked).length })}: {Object.keys(picked).join(', ')}</p>
            ) : null}
          </div>
          {needsReplace ? (
            <div className="flex items-start gap-1" data-testid="skill-add-replace">
              <TouchCheckbox id="sk-replace" checked={replace} onCheckedChange={(c) => setReplace(c === true)} />
              <Label htmlFor="sk-replace" className="pt-3 lg:pt-0.5">{t('skills.add_replace', { v: existing?.version ?? '' })}</Label>
            </div>
          ) : null}
          {needsShadow ? (
            <div className="flex items-start gap-1" data-testid="skill-add-shadow">
              <TouchCheckbox id="sk-shadow" checked={shadow} onCheckedChange={(c) => setShadow(c === true)} />
              <Label htmlFor="sk-shadow" className="pt-3 lg:pt-0.5">{t('skills.add_shadow')}</Label>
            </div>
          ) : null}
          {problems.length > 0 ? (
            <ul className="list-disc space-y-1 pl-5 text-sm text-destructive" role="alert" data-testid="skill-add-problems">
              {problems.map((p, i) => {
                const m = problemMessage(p);
                return <li key={i}>{t(m.key, m.vars)}</li>;
              })}
            </ul>
          ) : null}
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className={TAP_ACTION_DEFAULT} onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            className={TAP_ACTION_DEFAULT}
            disabled={!ready || busy}
            onClick={async () => {
              setBusy(true);
              try {
                const item = await client.memory.addSkill({
                  files,
                  via: mode === 'write' ? 'page_editor' : 'page_upload',
                  ...(needsReplace && existing ? { replaces: existing.hash } : {}),
                  ...(needsShadow ? { shadow_bundled: true } : {}),
                });
                onDone(item);
              } catch (e) {
                setErr(e instanceof ApiError ? e.message : t('skills.failed'));
                setBusy(false);
              }
            }}
          >
            {t('skills.add_go')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}
