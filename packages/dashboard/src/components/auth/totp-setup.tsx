import { useEffect, useState } from 'react';
import QRCode from 'qrcode';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { SessionApi, SessionStatus } from '../../api/session';
import { signInMessage } from '../../lib/auth-errors';
import { t } from '../../lib/i18n';

/** Authenticator-app setup: the key is shown once (as a QR code and as text), then a code proves it works. */
export function TotpSetup({ api, onDone, ask }: { api: SessionApi; onDone: (status: SessionStatus | null) => void; ask?: <T>(run: () => Promise<T>) => Promise<T> }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const guard = ask ?? (<T,>(run: () => Promise<T>) => run());

  useEffect(() => {
    if (!setup) return;
    let live = true;
    void QRCode.toDataURL(setup.uri, { margin: 1, width: 220 }).then((u) => live && setQr(u));
    return () => {
      live = false;
    };
  }, [setup]);

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await guard(() => api.totpSetup());
      setSetup({ secret: r.secret, uri: r.otpauth_uri });
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.totpConfirm(code);
      onDone('state' in r ? r : null);
    } catch (e) {
      setError(signInMessage(e));
    } finally {
      setBusy(false);
    }
  };

  if (!setup) {
    return (
      <div className="space-y-2">
        <Button variant="outline" className="h-11 lg:h-9" onClick={() => void start()} disabled={busy}>
          {t('totp.start')}
        </Button>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </div>
    );
  }
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        void confirm();
      }}
    >
      <p className="text-sm text-muted-foreground">{t('totp.scan')}</p>
      {qr && <img src={qr} alt={t('totp.qr_alt')} width={220} height={220} className="rounded-md border bg-white" />}
      <div className="space-y-1">
        <Label htmlFor="totp-key">{t('totp.key_label')}</Label>
        <Input id="totp-key" readOnly value={setup.secret} className="h-11 font-mono lg:h-10" onFocus={(e) => e.currentTarget.select()} />
      </div>
      <div className="space-y-1">
        <Label htmlFor="totp-code">{t('totp.code_label')}</Label>
        <Input className="h-11 lg:h-10" id="totp-code" inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} />
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" className="h-11 lg:h-9" disabled={busy || code.replace(/\s/g, '').length < 6}>
        {t('totp.confirm')}
      </Button>
    </form>
  );
}
