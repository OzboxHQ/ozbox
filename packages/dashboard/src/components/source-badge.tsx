import { Badge } from '@/components/ui/badge';
import type { MetricsSource } from '../api/types';
import { t, type MessageKey } from '../lib/i18n';

export function SourceBadge({ source }: { source: MetricsSource }) {
  if (source === 'live') return null;
  return (
    <Badge variant="outline" className="mt-1" title={t('source.simulated_hint')}>
      {t('source.simulated')}
    </Badge>
  );
}

const NOTES: Record<'files' | 'tools' | 'terminal' | 'chat' | 'schedules' | 'triggers' | 'backups' | 'local-ai' | 'browser' | 'orch' | 'usage' | 'suggestions' | 'skills', MessageKey> = {
  chat: 'source.chat_note',
  schedules: 'source.schedules_note',
  triggers: 'source.triggers_note',
  backups: 'source.backups_note',
  'local-ai': 'source.local_ai_note',
  usage: 'source.usage_note',
  suggestions: 'source.suggestions_note',
  skills: 'source.skills_note',
  browser: 'source.browser_note',
  orch: 'source.orch_note',
  files: 'source.files_note',
  tools: 'source.tools_note',
  terminal: 'source.terminal_note',
};

/** The badge and one plain sentence for a page whose data the server says it made up: said in words, not only in a tooltip, so a phone shows it too. Nothing for a real box. */
export function SourceNote({ source, what }: { source: MetricsSource | null | undefined; what: keyof typeof NOTES }) {
  if (source !== 'simulated') return null;
  return (
    <div role="status" data-testid={`${what}-source-note`} className="flex flex-wrap items-center gap-2 rounded-md border border-amber-600/50 bg-amber-50 px-3 py-2 text-sm text-amber-950 dark:border-amber-400/50 dark:bg-amber-950/40 dark:text-amber-100">
      <Badge variant="outline" data-testid={`${what}-source-badge`}>
        {t('source.simulated')}
      </Badge>
      <span className="min-w-0 flex-1 break-words">{t(NOTES[what])}</span>
    </div>
  );
}
