import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Combobox } from '@/components/ui/combobox';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { COUNTRIES } from '../lib/countries';
import { t } from '../lib/i18n';
import { effectiveLocale, validTimeZone } from '../lib/locale';
import { getTimezoneOptions } from '../lib/timezones';
import { useSettings } from '../lib/use-settings';

/** Country and time zone: suggested from the browser, editable, stored in the server's settings (validated there too). */
export function LocaleEditor({ onSaved, idPrefix = 'locale' }: { onSaved?: () => void; idPrefix?: string }) {
  const { settings, save } = useSettings();
  const [country, setCountry] = useState('');
  const [zone, setZone] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const zones = useMemo(() => getTimezoneOptions(), []);
  const countries = useMemo(() => COUNTRIES.map((c) => ({ value: c.code, label: c.name })), []);

  useEffect(() => {
    if (!settings) return;
    const e = effectiveLocale(settings.locale);
    setCountry(e.country_code ?? '');
    setZone(e.time_zone);
    // Only when the settings first arrive: typing must not be overwritten by a refresh.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings === null]);

  if (!settings) return <Skeleton className="h-24 w-full" />;
  const zoneOk = validTimeZone(zone);
  return (
    <form
      className="space-y-4"
      onSubmit={async (e) => {
        e.preventDefault();
        if (!zoneOk) return;
        setBusy(true);
        setError(null);
        const err = await save({ ...settings, locale: { country_code: country || null, time_zone: zone } });
        setBusy(false);
        if (err) setError(err);
        else {
          toast.success(t('locale.saved'));
          onSaved?.();
        }
      }}
    >
      <div className="space-y-1">
        <Label htmlFor={`${idPrefix}-country`}>{t('locale.country')}</Label>
        <Combobox id={`${idPrefix}-country`} label={t('locale.country')} options={countries} value={country} onValueChange={setCountry} placeholder={t('locale.country_placeholder')} emptyText={t('locale.country_empty')} />
      </div>
      <div className="space-y-1">
        <Label htmlFor={`${idPrefix}-zone`}>{t('locale.zone')}</Label>
        <Combobox id={`${idPrefix}-zone`} label={t('locale.zone')} options={zones} value={zone} onValueChange={setZone} placeholder={t('locale.zone_placeholder')} emptyText={t('locale.zone_empty')} aria-invalid={!zoneOk} />
      </div>
      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}
      <Button type="submit" disabled={busy || !zoneOk} className="max-lg:h-11">
        {t('locale.save')}
      </Button>
    </form>
  );
}
