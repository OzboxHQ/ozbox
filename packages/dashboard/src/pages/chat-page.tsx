import { useEffect, useMemo, useRef, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { useApp } from '../App';
import { ApiError } from '../api/client';
import type { ChatLine, ChatOverview } from '../api/chat';
import type { ApprovalRequest } from '../api/tasks';
import { AppPage, PageHeader } from '../components/page';
import { ReadOnlyScope } from '../components/role-scope';
import { SourceNote } from '../components/source-badge';
import { ChatChannels } from '../components/chat/chat-channels';
import { ChatTranscript } from '../components/chat/chat-view';
import { AgentApprovals } from '../components/tasks/agent-approvals';
import { t } from '../lib/i18n';
import { chatLinkToken } from '../lib/telegram-flow';
import { useAsync } from '../lib/use-async';
import { useCan } from '../lib/use-can';

/** The session a chat follows, in words: what it is doing and whom it waits for. */
function statusLine(o: ChatOverview): string | null {
  const b = o.bound;
  if (!b) return null;
  if (b.kind === 'terminal') return t('chat.status_terminal', { box: b.box_name });
  const s = o.sessions.find((x) => x.id === b.id);
  if (!s) return null;
  if (s.needs?.kind === 'paused') return t('chat.status_paused');
  if (s.state === 'running') return s.awaiting_input ? t('chat.status_waiting') : t('chat.status_working');
  return t('chat.status_other', { state: s.state });
}

export function ChatPage() {
  const { client } = useApp();
  const { can } = useCan();
  const mayStart = can('start_runs');
  const [lines, setLines] = useState<ChatLine[]>([]);
  const after = useRef(0);
  const [draft, setDraft] = useState('');
  const [sending, setSending] = useState(false);
  const [linked, setLinked] = useState<ApprovalRequest | null>(null);
  const [linkNote, setLinkNote] = useState<string | null>(null);
  const redeemed = useRef(false);

  // The server nudges every open tab when anything changes (useAsync already reloads on that nudge); the poll is the safety net.
  const overview = useAsync((s) => client.chat.overview(after.current, s), [client], 3000);
  const data = overview.data;
  useEffect(() => {
    if (!data) return;
    if (data.messages.length > 0) {
      setLines((cur) => {
        const seen = new Set(cur.map((l) => l.seq));
        return [...cur, ...data.messages.filter((m) => !seen.has(m.seq))].slice(-200);
      });
      after.current = Math.max(after.current, ...data.messages.map((m) => m.seq));
    }
  }, [data]);

  // A one-time link from a chat names an approval that needs the passkey: it is shown here and decided here. The token is in
  // the address's fragment (`#link=<token>`), which a browser never sends to a server, a tunnel or a referrer; it leaves the
  // address bar at once and is sent once, in a request body.
  useEffect(() => {
    const token = chatLinkToken(window.location.hash);
    if (!token || redeemed.current) return;
    redeemed.current = true;
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
    client.chat
      .redeem(token)
      .then((r) => {
        setLinked(r.pending ? r.approval : null);
        setLinkNote(r.pending ? t('chat.link_body') : t('chat.link_done'));
      })
      .catch((e: unknown) => setLinkNote(e instanceof ApiError && e.status === 410 ? t('chat.link_used') : t('chat.link_bad')));
  }, [client]);

  const sessionId = data?.bound?.kind === 'task' ? data.bound.id : '';
  const sessions = data?.sessions ?? [];
  const pendingApprovals = useMemo(() => {
    const list = data?.approvals ?? [];
    return linked && !list.some((a) => a.id === linked.id) ? [linked, ...list] : list;
  }, [data, linked]);

  async function send(text: string) {
    const body = text.trim();
    if (!body) return;
    setSending(true);
    try {
      await client.chat.send(body);
      setDraft('');
      overview.reload();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('chat.send_failed'));
    } finally {
      setSending(false);
    }
  }

  async function follow(task: string) {
    try {
      await client.chat.bind(task === '' ? null : task);
      overview.reload();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('chat.send_failed'));
    }
  }

  const line = data ? statusLine(data) : null;
  return (
    <AppPage width="narrow">
      <PageHeader title={t('chat.title')} description={t('chat.desc')} />
      {linkNote ? (
        <Card className="space-y-1 p-4" data-testid="chat-link-note">
          <p className="text-sm font-medium">{t('chat.link_title')}</p>
          <p className="text-sm text-muted-foreground">{linkNote}</p>
        </Card>
      ) : null}
      <SourceNote source={data?.source} what="chat" />
      {data && !data.public_url_set && (data.channels.telegram.enabled || data.channels.slack.enabled || data.channels.whatsapp.enabled) ? (
        <Alert data-testid="chat-no-public-url">
          <AlertDescription>{t('chat.no_public_url')}</AlertDescription>
        </Alert>
      ) : null}
      {data && !data.runs_available ? (
        <Alert data-testid="chat-no-runs">
          <AlertDescription>{t('chat.runs_unavailable')}</AlertDescription>
        </Alert>
      ) : null}
      {overview.error && data ? (
        <p role="alert" data-testid="chat-stale" className="text-sm text-destructive">
          {t('chat.refresh_failed')}
        </p>
      ) : null}
      {!data && !overview.error ? <Skeleton className="h-64 w-full" /> : null}
      {overview.error && !data ? <p className="text-sm text-destructive">{t('chat.load_failed')}</p> : null}
      {data ? (
        <>
          <ReadOnlyScope cap="start_runs">
          <Card className="space-y-3 p-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
              <label htmlFor="chat-session" className="text-sm font-medium sm:w-24">
                {t('chat.session')}
              </label>
              <select
                id="chat-session"
                data-testid="chat-session"
                className="h-11 w-full min-w-0 rounded-md border border-input bg-background px-3 text-sm lg:h-9"
                value={sessionId}
                onChange={(e) => void follow(e.target.value)}
              >
                <option value="">{t('chat.session_none')}</option>
                {sessions.map((s) => (
                  <option key={s.id} value={s.id}>
                    {t('chat.session_label', { task: s.id, box: s.box, state: s.state })}
                  </option>
                ))}
              </select>
            </div>
            {line ? (
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="secondary" data-testid="chat-status">
                  {line}
                </Badge>
                {data.bound?.kind === 'task' ? (
                  <>
                    <Button variant="outline" className="max-lg:h-11" onClick={() => void send('/pause')}>
                      {t('chat.pause')}
                    </Button>
                    <Button variant="outline" className="max-lg:h-11" onClick={() => void send('/resume')}>
                      {t('chat.resume')}
                    </Button>
                    <Button variant="outline" className="max-lg:h-11" onClick={() => void send('/stop')}>
                      {t('chat.stop')}
                    </Button>
                  </>
                ) : (
                  <Button variant="outline" className="max-lg:h-11" onClick={() => void send('/detach')}>
                    {t('chat.detach')}
                  </Button>
                )}
              </div>
            ) : null}
          </Card>
          </ReadOnlyScope>

          <ChatTranscript lines={lines} />
          <p className="text-xs text-muted-foreground" data-testid="chat-transcript-note">
            {t('chat.transcript_note', { lines: data.transcript.lines })}
          </p>

          {pendingApprovals.length > 0 ? (
            <section aria-label={t('chat.approvals')} className="space-y-2" data-testid="chat-approvals">
              <AgentApprovals client={client} pending={pendingApprovals} recent={[]} reload={() => overview.reload()} />
            </section>
          ) : null}

          <form
            className="space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              void send(draft);
            }}
          >
            <fieldset disabled={!mayStart || !data.runs_available} className="m-0 min-w-0 space-y-2 border-0 p-0">
            <label htmlFor="chat-composer" className="text-sm font-medium">
              {t('chat.composer')}
            </label>
            <Textarea
              id="chat-composer"
              data-testid="chat-composer"
              className="min-h-20"
              value={draft}
              placeholder={t('chat.composer_placeholder')}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  void send(draft);
                }
              }}
            />
            <Button type="submit" className="w-full sm:w-auto max-lg:h-11" disabled={sending || draft.trim() === ''}>
              {sending ? t('chat.sending') : t('chat.send')}
            </Button>
            </fieldset>
          </form>

          <ChatChannels channels={data.channels} reload={() => overview.reload()} />
        </>
      ) : null}
    </AppPage>
  );
}
