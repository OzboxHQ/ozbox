import { useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ApiError } from '../api/client';
import type { AgentMcpState } from '../api/agent-mcp';
import { useApp } from '../App';
import { withStepUp } from './perm/with-step-up';
import { t } from '../lib/i18n';
import { useAsync } from '../lib/use-async';

/**
 * Whether coding agents the person starts on this box may use the Oz Box tools (the shell, git, files and the browser).
 * Shown only on a box's own dashboard, where the door exists. Turning it on is a loosening, so it asks for a passkey (or says
 * why it cannot); turning it off needs nothing and ends every agent session.
 */
export function AgentMcpCard() {
  const { client } = useApp();
  const state = useAsync<AgentMcpState>((s) => client.agentMcp.get(s), [client], 10_000);
  const [busy, setBusy] = useState(false);
  const [refused, setRefused] = useState<string | null>(null);
  const d = state.data;
  if (!d?.available) return null;
  const on = d.enabled === true;

  async function change(next: boolean) {
    setBusy(true);
    setRefused(null);
    try {
      await withStepUp(() => client.agentMcp.set(next));
      toast.success(t(next ? 'agentmcp.saved_on' : 'agentmcp.saved_off'));
      state.reload();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : t('common.request_failed');
      setRefused(msg);
      toast.error(msg);
    } finally {
      setBusy(false);
    }
  }

  const standingLeft = d.standing_until_ms ? Math.max(0, d.standing_until_ms - Date.now()) : 0;

  async function standing(next: boolean) {
    setBusy(true);
    setRefused(null);
    try {
      await withStepUp(() => client.agentMcp.standing(next));
      toast.success(t(next ? 'agentmcp.saved_standing_on' : 'agentmcp.saved_standing_off'));
      state.reload();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : t('common.request_failed');
      setRefused(msg);
      toast.error(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="space-y-3 p-4" data-testid="agent-mcp-card">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">{t('agentmcp.title')}</h2>
        <Badge variant={on ? 'default' : 'outline'} data-testid="agent-mcp-state">
          {on ? t('agentmcp.on') : t('agentmcp.off')}
        </Badge>
      </div>
      <p className="text-sm text-muted-foreground">{t('agentmcp.intro')}</p>
      <Button
        variant={on ? 'outline' : 'default'}
        className="max-lg:h-11 w-full sm:w-auto"
        disabled={busy}
        onClick={() => void change(!on)}
        data-testid="agent-mcp-toggle"
      >
        {on ? t('agentmcp.turn_off') : t('agentmcp.turn_on')}
      </Button>
      <p className="text-xs text-muted-foreground">{on ? t('agentmcp.on_note') : t('agentmcp.off_note')}</p>
      <p className="text-xs text-muted-foreground" data-testid="agent-mcp-detail">
        {d.at_ms ? `${t('agentmcp.by', { who: d.by ?? '—' })} ` : ''}
        {t('agentmcp.sessions', { n: d.sessions ?? 0 })}
      </p>
      {d.saved === false && (
        <p role="alert" className="text-sm text-destructive" data-testid="agent-mcp-not-saved">
          {t('agentmcp.not_saved')}
        </p>
      )}
      {on && (
        <div className="space-y-2 rounded-md border p-3" data-testid="agent-mcp-standing">
          <h3 className="text-sm font-medium">{t('agentmcp.standing_title')}</h3>
          <p className="text-xs text-muted-foreground">
            {standingLeft > 0 ? t('agentmcp.standing_on', { n: Math.ceil(standingLeft / 60_000) }) : t('agentmcp.standing_off')}
          </p>
          {standingLeft === 0 && <p className="text-xs text-muted-foreground">{t('agentmcp.standing_warn')}</p>}
          <Button
            variant="outline"
            className="max-lg:h-11 w-full sm:w-auto"
            disabled={busy}
            onClick={() => void standing(standingLeft === 0)}
            data-testid="agent-mcp-standing-toggle"
          >
            {standingLeft > 0 ? t('agentmcp.standing_turn_off') : t('agentmcp.standing_turn_on')}
          </Button>
        </div>
      )}
      {refused && (
        <p role="alert" className="text-sm text-destructive" data-testid="agent-mcp-refused">
          {refused}
        </p>
      )}
    </Card>
  );
}
