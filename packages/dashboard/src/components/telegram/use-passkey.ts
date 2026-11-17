import { useCallback, useState } from 'react';

import { ApiError } from '../../api/error';
import { t } from '../../lib/i18n';
import { getPasskey, passkeysSupported, wasCancelled, type AssertionJson, type RequestJson } from '../../lib/webauthn';

/** Runs "challenge, passkey, assertion" as one step and says in words how it went. One press, one challenge. */
export function usePasskeyStep() {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const supported = passkeysSupported();
  const run = useCallback(
    async <T>(challenge: () => Promise<{ options: RequestJson }>, finish: (assertion: AssertionJson) => Promise<T>): Promise<T | null> => {
      setBusy(true);
      setNote(null);
      try {
        const c = await challenge();
        const assertion = await getPasskey(c.options);
        return await finish(assertion);
      } catch (e) {
        if (wasCancelled(e)) setNote(t('tg.cancelled'));
        else setNote(e instanceof ApiError ? e.message : t('tg.failed'));
        return null;
      } finally {
        setBusy(false);
      }
    },
    [],
  );
  return { busy, note, setNote, supported, run };
}
