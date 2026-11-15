import { Button } from '@/components/ui/button';
import { t } from '../lib/i18n';

/**
 * A read that failed, said where the page's content would be, with a way to try again. With nothing loaded yet it is the page's
 * whole answer; with data on screen (`stale`) the old data stays and this says it may be out of date.
 */
export function LoadError({ title, error, onRetry, stale = false }: { title: string; error: Error; onRetry: () => void; stale?: boolean }) {
  return (
    <div role="alert" data-testid={stale ? 'load-error-stale' : 'load-error'} className="flex flex-col gap-2 rounded-md border border-destructive/40 p-3 text-sm sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <p className="font-semibold">{stale ? t('common.stale_title') : title}</p>
        <p className="break-words text-muted-foreground">{stale ? t('common.stale_body', { why: error.message }) : error.message}</p>
      </div>
      <Button variant="outline" className="w-full max-lg:h-11 sm:w-auto" onClick={onRetry}>
        {t('common.retry')}
      </Button>
    </div>
  );
}
