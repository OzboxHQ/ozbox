import { en } from '../i18n/en';

/** Every user-facing string is a key in a catalogue. English is the source; another language is another catalogue. */
export type MessageKey = keyof typeof en;
export type Catalogue = Record<MessageKey, string>;

const catalogues: Record<string, Catalogue> = { en };
let current: Catalogue = en;

/** Choose the catalogue for a locale such as `fr` or `fr-CA`; an unknown locale keeps English. */
export function setLocale(locale: string): void {
  const base = locale.split('-')[0] ?? 'en';
  current = catalogues[locale] ?? catalogues[base] ?? en;
}

export function registerCatalogue(locale: string, c: Catalogue): void {
  catalogues[locale] = c;
}

/** `{name}` in a message is replaced by `vars.name`. A missing variable is left visible rather than hidden. */
export function t(key: MessageKey, vars?: Record<string, string | number>): string {
  const msg = current[key] ?? en[key];
  if (!vars) return msg;
  return msg.replace(/\{(\w+)\}/g, (whole, name: string) => (name in vars ? String(vars[name]) : whole));
}
