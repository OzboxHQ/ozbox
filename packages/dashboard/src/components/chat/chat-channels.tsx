import { useState } from 'react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { useApp } from '../../App';
import { ApiError } from '../../api/client';
import type { ChatChannels as Channels } from '../../api/chat';
import { t } from '../../lib/i18n';

type Pairable = 'slack' | 'whatsapp';

/** Which other chats are linked. Telegram pairs in Settings; Slack and WhatsApp pair here with a one-time code. */
export function ChatChannels({ channels, reload }: { channels: Channels; reload: () => void }) {
  const { client } = useApp();
  const [codes, setCodes] = useState<Partial<Record<Pairable, string>>>({});

  async function pair(c: Pairable) {
    try {
      const r = await client.chat.pairing(c);
      setCodes((cur) => ({ ...cur, [c]: r.code }));
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('chat.pair_failed'));
    }
  }

  async function unlink(c: Pairable, id: string) {
    try {
      await client.chat.unlink(c, id);
      toast.success(t('chat.unlinked'));
      reload();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : t('chat.pair_failed'));
    }
  }

  const rows: { key: Pairable; label: 'chat.channel_slack' | 'chat.channel_whatsapp'; ch: Channels['slack'] }[] = [
    { key: 'slack', label: 'chat.channel_slack', ch: channels.slack },
    { key: 'whatsapp', label: 'chat.channel_whatsapp', ch: channels.whatsapp },
  ];
  return (
    <section aria-labelledby="chat-channels-h" className="space-y-3" data-testid="chat-channels">
      <div>
        <h2 id="chat-channels-h" className="text-sm font-semibold">
          {t('chat.channels')}
        </h2>
        <p className="text-xs text-muted-foreground">{t('chat.channels_desc')}</p>
      </div>
      <Card className="space-y-1 p-4">
        <p className="text-sm font-medium">{t('chat.channel_telegram')}</p>
        <p className="text-sm text-muted-foreground">{channels.telegram.enabled ? t('chat.channel_telegram_state', { n: channels.telegram.chats }) : t('chat.channel_off')}</p>
      </Card>
      {rows.map(({ key, label, ch }) => (
        <Card key={key} className="space-y-2 p-4" data-testid={`chat-channel-${key}`}>
          <p className="text-sm font-medium">{t(label)}</p>
          <p className="text-sm text-muted-foreground">{!ch.enabled ? t('chat.channel_off') : !ch.configured ? t('chat.channel_needs_keys') : t('chat.channel_ready', { n: ch.links.length })}</p>
          {ch.links.map((l) => (
            <div key={l.id} className="flex items-center justify-between gap-2">
              <span className="min-w-0 break-all text-sm">{l.name}</span>
              <Button variant="outline" className="max-lg:h-11" onClick={() => void unlink(key, l.id)} aria-label={t('chat.unlink', { name: l.name })}>
                {t('chat.unlink_btn')}
              </Button>
            </div>
          ))}
          {ch.enabled && ch.configured ? (
            <>
              <Button variant="outline" className="w-full sm:w-auto max-lg:h-11" onClick={() => void pair(key)}>
                {t('chat.pair')}
              </Button>
              {codes[key] ? (
                <p className="break-words text-sm" data-testid={`chat-code-${key}`}>
                  {t('chat.pair_code', { code: codes[key] })}
                </p>
              ) : null}
            </>
          ) : null}
        </Card>
      ))}
    </section>
  );
}
