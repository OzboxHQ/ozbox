import { ApiError } from '../api/client';
import type { Settings, SettingsResponse } from '../api/types';
import { useApp } from '../App';
import { withStepUp } from '../components/perm/with-step-up';
import { t } from './i18n';
import { useAsync } from './use-async';

/** The server's settings and a save that resolves to an error message, or null when saved. */
export function useSettings() {
  const { client } = useApp();
  const q = useAsync<SettingsResponse>((s) => client.getSettings(s), [client]);
  async function save(next: Settings): Promise<string | null> {
    try {
      // raising or removing a model provider's monthly limit needs a fresh passkey; the server decides and asks
      await withStepUp(() => client.saveSettings(next));
      q.reload();
      return null;
    } catch (e) {
      return e instanceof ApiError ? e.message : t('common.save_failed');
    }
  }
  return { settings: q.data?.settings ?? null, persisted: q.data?.persisted ?? true, error: q.error, save, reload: q.reload };
}
