import { de } from './i18n/de';
import { en } from './i18n/en';
import { settings } from './state.svelte';

export type Lang = 'de' | 'en';
export type Key = keyof typeof de;

const dicts: Record<Lang, Record<Key, string>> = { de, en };

/** Gibt es diesen Schlüssel? Für Texte, deren Schlüssel aus einem Fehlercode entsteht. */
export const has = (key: string): key is Key => key in de;

/** Datum in der Schreibweise der gewählten Sprache. */
export const formatDate = (ms: number) => new Date(ms).toLocaleDateString(settings.lang === 'de' ? 'de-DE' : 'en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });

/** Wie `t` mit der Anzahl `n`; für genau eins gilt der Text unter `<Schlüssel>.one`, wenn es ihn gibt. */
export function tn(key: Key, n: number, vars?: Record<string, string | number>): string {
  const one = `${key}.one`;
  return t(n === 1 && has(one) ? one : key, { n, ...vars });
}

/** Übersetzt einen Schlüssel. Liest die Sprache aus den Einstellungen, reagiert also auf den Wechsel. */
export function t(key: Key, vars?: Record<string, string | number>): string {
  let s = dicts[settings.lang][key] ?? de[key];
  if (vars) for (const k in vars) s = s.replaceAll(`{${k}}`, String(vars[k]));
  return s;
}
