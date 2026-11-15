import { useEffect, useRef } from 'react';

import { Card } from '@/components/ui/card';
import type { ChatLine } from '../../api/chat';
import { fmtRelative } from '../../lib/format';
import { t } from '../../lib/i18n';

const WHO = { you: 'chat.who_you', agent: 'chat.who_agent', system: 'chat.who_system' } as const;

/** The conversation. New lines are announced politely; the list keeps the newest in view. */
export function ChatTranscript({ lines }: { lines: ChatLine[] }) {
  const end = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    end.current?.scrollIntoView?.({ block: 'end' });
  }, [lines.length]);
  return (
    <Card className="max-h-[55vh] min-h-48 overflow-y-auto p-3 sm:p-4" data-testid="chat-transcript" role="log" aria-live="polite" aria-label={t('chat.transcript')} tabIndex={0}>
      {lines.length === 0 ? (
        <div className="space-y-1 py-6 text-center">
          <p className="text-sm font-medium">{t('chat.empty_title')}</p>
          <p className="mx-auto max-w-prose text-sm text-muted-foreground">{t('chat.empty_body')}</p>
        </div>
      ) : (
        <ol className="space-y-3">
          {lines.map((l) => (
            <li key={l.seq} className={l.who === 'you' ? 'flex justify-end' : 'flex justify-start'} data-testid="chat-line" data-who={l.who}>
              <div className={`min-w-0 max-w-[92%] rounded-lg border px-3 py-2 sm:max-w-[80%] ${l.who === 'you' ? 'bg-primary text-primary-foreground' : 'bg-background'}`}>
                <p className={`text-xs ${l.who === 'you' ? 'text-primary-foreground' : 'text-muted-foreground'}`}>
                  {t(WHO[l.who])} · {fmtRelative(new Date(l.ts_ms).toISOString())}
                </p>
                <p className="whitespace-pre-wrap break-words text-sm">{l.text}</p>
              </div>
            </li>
          ))}
        </ol>
      )}
      <div ref={end} />
    </Card>
  );
}
