import { toast } from 'sonner';

import { copyOnClick, type CopyKind } from './clipboard';
import { t } from './i18n';

/**
 * A Copy button's whole job: copy (only on the person's own click, see `clipboard.ts`) and say what happened. A secret also
 * says that it is now on the clipboard. Call it straight from the click handler.
 */
export async function copyAndSay(text: string, opts: { kind?: CopyKind; done: string; failed: string }): Promise<boolean> {
  const r = await copyOnClick(text);
  if (r === 'copied') {
    if (opts.kind === 'secret') toast.warning(opts.done, { description: t('clipboard.secret_copied') });
    else toast.success(opts.done);
    return true;
  }
  toast.error(r === 'no_gesture' ? t('clipboard.no_gesture') : opts.failed);
  return false;
}
