import { copyAndSay } from '../lib/copy-and-say';
import { t } from '../lib/i18n';

import { Button } from '@/components/ui/button';
import type { BoxRecord } from '../api/types';
import { connectInfo } from '../lib/connect';

/** Open the web IDE and copy the connect command. The IDE button is off, with its reason in words, when it cannot work. */
export function ConnectButtons({ box, domain, className }: { box: BoxRecord; domain: string | null | undefined; className?: string }) {
  const c = connectInfo(box, domain);
  const reasonId = `connect-reason-${box.spec.name}`;
  function copy() {
    return copyAndSay(c.command, { done: t('connect.copied'), failed: t('connect.copy_failed', { command: c.command }) });
  }
  return (
    <div className={className}>
      <div className="flex flex-wrap gap-2">
        {c.ideUrl ? (
          <Button asChild variant="outline" size="sm" className="relative z-10 max-lg:h-11">
            <a href={c.ideUrl} target="_blank" rel="noopener noreferrer">
              Open IDE
            </a>
          </Button>
        ) : (
          <Button variant="outline" size="sm" className="max-lg:h-11" disabled aria-describedby={reasonId}>
            Open IDE
          </Button>
        )}
        <Button variant="outline" size="sm" className="relative z-10 max-lg:h-11" onClick={copy}>
          Copy connect command
        </Button>
      </div>
      {c.reason && (
        <p id={reasonId} className="mt-1 text-xs text-muted-foreground">
          {c.reason}
        </p>
      )}
    </div>
  );
}
