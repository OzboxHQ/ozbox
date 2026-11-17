import { useEffect, useState } from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { PanelSheet, PanelSheetBody, PanelSheetContent, PanelSheetDescription, PanelSheetFooter, PanelSheetHeader, PanelSheetTitle } from '@/components/ui/panel-sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ApiError } from '../api/client';
import type { ApprovalScope, ApprovalUse, Minted } from '../api/secrets';
import { formError, mintBody, needs, type GuardWhat, type VaultWhat, type Which } from '../lib/secret-approvals';
import { APPROVAL_SCOPES } from '../api/secrets';
import { useApp } from '../App';
import { withStepUp } from '../components/perm/with-step-up';
import { t, type MessageKey } from '../lib/i18n';
import { copyAndSay } from '../lib/copy-and-say';
import { useAsync } from '../lib/use-async';

const SCOPE_CHOICE: Record<ApprovalScope, MessageKey> = {
  import: 'secrets.scope_import',
  policy: 'secrets.scope_policy',
  'tunnel-token': 'secrets.scope_tunnel',
  'guard-override': 'secrets.scope_guard',
  'signer-enroll': 'secrets.scope_signer',
  'setup-code': 'secrets.scope_setup_code',
  'kek-export': 'secrets.scope_kek_export',
  'box-secrets': 'secrets.scope_box_secrets',
  'host-guard': 'secrets.scope_host_guard',
  'dashboard-auth': 'secrets.scope_dashboard_auth',
};

const SCOPE_NAME: Record<string, MessageKey> = {
  import: 'secrets.scope_name_import',
  policy: 'secrets.scope_name_policy',
  'tunnel-token': 'secrets.scope_name_tunnel_token',
  'guard-override': 'secrets.scope_name_guard_override',
  'signer-enroll': 'secrets.scope_name_signer',
  'setup-code': 'secrets.scope_name_setup_code',
  'kek-export': 'secrets.scope_name_kek_export',
  'box-secrets': 'secrets.scope_name_box_secrets',
  'host-guard': 'secrets.scope_name_host_guard',
  'dashboard-auth': 'secrets.scope_name_dashboard_auth',
};

/** The scopes this form makes a code for. A laptop key is never added with a code made here: the box's service refuses it, so the
 *  choice is not offered (phase 2 re-check NL8); a note says what to do instead. */
const MINTABLE = APPROVAL_SCOPES.filter((k) => k !== 'signer-enroll');

const scopeName = (s: string): string => (SCOPE_NAME[s] ? t(SCOPE_NAME[s]) : s);

const howName = (v: string): string => (v === 'dashboard-stepup' ? t('secrets.how_dashboard_stepup') : v === 'bootstrap' ? t('secrets.how_bootstrap') : t('secrets.how_none'));
const resultName = (o: ApprovalUse['outcome']): string => t(o === 'minted' ? 'secrets.result_minted' : o === 'allowed' ? 'secrets.result_allowed' : 'secrets.result_refused');

function leftText(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/** The code, shown once. Closing the sheet drops it from memory: nothing here stores or fetches it again. */
function CodeSheet({ minted, onClose }: { minted: Minted; onClose: () => void }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  const left = minted.expires_at_ms - now;
  const target = [minted.project, minted.env].filter((x) => x !== '').join(' / ');

  function copy() {
    return copyAndSay(minted.code, { kind: 'secret', done: t('secrets.copied'), failed: t('secrets.copy_failed') });
  }

  return (
    <PanelSheet open onOpenChange={(o) => !o && onClose()}>
      <PanelSheetContent data-testid="approval-sheet" size="compact">
        <PanelSheetHeader>
          <PanelSheetTitle>{t('secrets.sheet_title')}</PanelSheetTitle>
          <PanelSheetDescription>{t('secrets.sheet_desc')}</PanelSheetDescription>
        </PanelSheetHeader>
        <PanelSheetBody className="space-y-4">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground" id="approval-code-label">{t('secrets.code')}</p>
            <code aria-labelledby="approval-code-label" data-testid="approval-code" className="block select-all break-all rounded-md border bg-muted px-3 py-3 text-center font-mono text-lg tracking-wider">
              {minted.code}
            </code>
          </div>
          <dl className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <dt className="text-xs text-muted-foreground">{t('secrets.for')}</dt>
              <dd className="font-medium" data-testid="approval-for">{[scopeName(minted.scope), target].filter((x) => x !== '').join(' · ')}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">{t('secrets.expires_in')}</dt>
              <dd className="font-medium" data-testid="approval-expiry">{left > 0 ? leftText(left) : t('secrets.expired')}</dd>
            </div>
          </dl>
          <p className="text-xs text-muted-foreground">{t('secrets.single_use')}</p>
        </PanelSheetBody>
        <PanelSheetFooter>
          <Button variant="outline" className="max-lg:h-11" onClick={() => void copy()} data-testid="approval-copy">
            {t('secrets.copy')}
          </Button>
          <Button className="max-lg:h-11" onClick={onClose} data-testid="approval-done">
            {t('secrets.done')}
          </Button>
        </PanelSheetFooter>
      </PanelSheetContent>
    </PanelSheet>
  );
}

export function SecretApprovalsSection() {
  const { client } = useApp();
  const status = useAsync((signal) => client.secrets.approvals(signal), [client], 10_000);
  const [scope, setScope] = useState<ApprovalScope>('import');
  const [project, setProject] = useState('');
  const [env, setEnv] = useState('');
  const [which, setWhich] = useState<Which>('cloudflare');
  const [guardWhat, setGuardWhat] = useState<GuardWhat>('egress');
  const [digest, setDigest] = useState('');
  const [keyId] = useState('laptop');
  const [vaultWhat, setVaultWhat] = useState<VaultWhat>('declaration');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [minted, setMinted] = useState<Minted | null>(null);

  if (status.error && !status.data) return <p role="alert" className="text-sm text-destructive">{status.error.message}</p>;
  if (!status.data) return <Skeleton className="h-40 w-full" aria-label={t('secrets.loading')} />;
  const s = status.data;
  const form = { scope, project, env, which, guardWhat, digest, keyId, vaultWhat };
  const need = needs(form);
  const needsProject = need.project;
  const needsEnv = need.env;

  async function create() {
    const wrong = formError(form);
    if (wrong) return setErr(t(wrong));
    setErr(null);
    setBusy(true);
    try {
      const body = mintBody(form);
      setMinted(await withStepUp(() => client.secrets.mint(body)));
      status.reload();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t('secrets.err_failed'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4" data-testid="secret-approvals-section">
      <Card className="space-y-3 p-4">
        <h2 className="text-sm font-semibold">{t('secrets.title')}</h2>
        <p className="text-sm text-muted-foreground">{t('secrets.intro_short')}</p>
        {!s.available ? (
          <Alert data-testid="secrets-not-available">
            <AlertDescription>{t('secrets.not_available')}</AlertDescription>
          </Alert>
        ) : !s.signed_in ? (
          <Alert data-testid="secrets-need-sign-in">
            <AlertDescription>{t('secrets.need_sign_in')}</AlertDescription>
          </Alert>
        ) : (
          <p className="text-sm" data-testid="secrets-enrolment">{s.enrolled ? t('secrets.enrolled') : t('secrets.not_enrolled')}</p>
        )}
      </Card>

      {s.available && s.signed_in ? (
        <Card className="space-y-4 p-4">
          <h2 className="text-sm font-semibold">{t('secrets.new_title')}</h2>
          {err ? (
            <Alert variant="destructive" role="alert">
              <AlertDescription>{err}</AlertDescription>
            </Alert>
          ) : null}
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1">
              <Label htmlFor="sa-scope">{t('secrets.scope')}</Label>
              <Select value={scope} onValueChange={(v) => setScope(v as ApprovalScope)}>
                <SelectTrigger id="sa-scope" className="max-lg:h-11" data-testid="approval-scope">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {MINTABLE.map((k) => (
                    <SelectItem key={k} value={k}>
                      {t(SCOPE_CHOICE[k])}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {needsProject ? (
              <div className="space-y-1">
                <Label htmlFor="sa-project">{t('secrets.project')}</Label>
                <Input id="sa-project" className="max-lg:h-11" autoComplete="off" value={project} onChange={(e) => setProject(e.target.value.trim())} />
                <p className="text-xs text-muted-foreground">{t('secrets.project_hint')}</p>
              </div>
            ) : null}
            {needsEnv ? (
              <div className="space-y-1">
                <Label htmlFor="sa-env">{t('secrets.env')}</Label>
                <Input id="sa-env" className="max-lg:h-11" autoComplete="off" value={env} onChange={(e) => setEnv(e.target.value.trim())} />
                <p className="text-xs text-muted-foreground">{t(scope === 'dashboard-auth' ? 'secrets.dashboard_auth_hint' : 'secrets.env_hint')}</p>
              </div>
            ) : null}
            {scope === 'host-guard' ? (
              <>
                <div className="space-y-1">
                  <Label htmlFor="sa-guard">{t('secrets.guard_what')}</Label>
                  <Select value={guardWhat} onValueChange={(v) => setGuardWhat(v as GuardWhat)}>
                    <SelectTrigger id="sa-guard" className="max-lg:h-11">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="egress">{t('secrets.guard_egress')}</SelectItem>
                      <SelectItem value="patch">{t('secrets.guard_patch')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label htmlFor="sa-digest">{t('secrets.guard_digest')}</Label>
                  <Input id="sa-digest" className="max-lg:h-11" autoComplete="off" value={digest} onChange={(e) => setDigest(e.target.value.trim().toLowerCase())} />
                  <p className="text-xs text-muted-foreground">{t('secrets.guard_digest_hint')}</p>
                </div>
              </>
            ) : null}
            {scope === 'box-secrets' ? (
              <>
                <div className="space-y-1">
                  <Label htmlFor="sa-vault">{t('secrets.vault_what')}</Label>
                  <Select value={vaultWhat} onValueChange={(v) => setVaultWhat(v as VaultWhat)}>
                    <SelectTrigger id="sa-vault" className="max-lg:h-11" data-testid="approval-vault-what">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="declaration">{t('secrets.vault_declaration')}</SelectItem>
                      <SelectItem value="clear">{t('secrets.vault_clear')}</SelectItem>
                      <SelectItem value="bao-token">{t('secrets.vault_token')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {vaultWhat === 'declaration' ? (
                  <div className="space-y-1">
                    <Label htmlFor="sa-vault-digest">{t('secrets.guard_digest')}</Label>
                    <Input id="sa-vault-digest" className="max-lg:h-11" autoComplete="off" value={digest} onChange={(e) => setDigest(e.target.value.trim().toLowerCase().replace(/^d-/, ''))} />
                    <p className="text-xs text-muted-foreground">{t('secrets.vault_digest_hint')}</p>
                  </div>
                ) : null}
              </>
            ) : null}
            {scope === 'tunnel-token' ? (
              <div className="space-y-1">
                <Label htmlFor="sa-which">{t('secrets.which')}</Label>
                <Select value={which} onValueChange={(v) => setWhich(v as Which)}>
                  <SelectTrigger id="sa-which" className="max-lg:h-11">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="cloudflare">{t('secrets.which_cloudflare')}</SelectItem>
                    <SelectItem value="ngrok">{t('secrets.which_ngrok')}</SelectItem>
                    <SelectItem value="ide">{t('secrets.which_ide')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            ) : null}
          </div>
          <Button className="max-lg:h-11" disabled={busy} onClick={() => void create()} data-testid="approval-create">
            {busy ? t('secrets.creating') : t('secrets.create')}
          </Button>
          {/* below the action, so the form and its button stay inside a phone's first screen */}
          <p className="text-xs text-muted-foreground" data-testid="approval-signer-note">{t('secrets.signer_note')}</p>
        </Card>
      ) : null}

      {/* the long explanation sits below the form, so the form and its button stay inside a phone's first screen */}
      <Card className="space-y-2 p-4" data-testid="secrets-explain">
        <h2 className="text-sm font-semibold">{t('secrets.explain_title')}</h2>
        <p className="text-sm text-muted-foreground">{t('secrets.intro')}</p>
      </Card>

      {s.available ? (
        <Card className="overflow-hidden">
          <h2 className="p-4 pb-2 text-sm font-semibold">{t('secrets.recent_title')}</h2>
          {s.recent.length === 0 ? (
            <p className="px-4 pb-4 text-sm text-muted-foreground" data-testid="approval-recent-empty">{t('secrets.recent_empty')}</p>
          ) : (
            <Table aria-label={t('secrets.recent_title')} data-testid="approval-recent">
              <TableHeader>
                <TableRow>
                  <TableHead>{t('secrets.col_when')}</TableHead>
                  <TableHead>{t('secrets.col_result')}</TableHead>
                  <TableHead>{t('secrets.col_scope')}</TableHead>
                  <TableHead>{t('secrets.col_project')}</TableHead>
                  <TableHead>{t('secrets.col_how')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {s.recent.map((u, i) => (
                  <TableRow key={`${u.at_ms}-${i}`}>
                    <TableCell className="whitespace-nowrap">{new Date(u.at_ms).toLocaleString()}</TableCell>
                    <TableCell>{resultName(u.outcome)}</TableCell>
                    <TableCell>{scopeName(u.scope)}</TableCell>
                    <TableCell>{[u.project, u.env].filter((x) => x !== '').join(' / ') || '—'}</TableCell>
                    <TableCell>{howName(u.via)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Card>
      ) : null}

      {minted ? <CodeSheet minted={minted} onClose={() => setMinted(null)} /> : null}
    </div>
  );
}
