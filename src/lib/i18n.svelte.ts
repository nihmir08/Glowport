import { de } from './i18n/de';
import { en } from './i18n/en';
import { settings } from './state.svelte';

export type Lang = 'de' | 'en';
export type Key = keyof typeof de;

const dicts: Record<Lang, Record<Key, string>> = { de, en };

/** Does this key exist? For texts whose key is derived from an error code. */
export const has = (key: string): key is Key => key in de;

/** Date in the notation of the chosen language. */
export const formatDate = (ms: number) => new Date(ms).toLocaleDateString(settings.lang === 'de' ? 'de-DE' : 'en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });

/** Like `t` with the count `n`; for exactly one, the text under `<key>.one` applies if it exists. */
export function tn(key: Key, n: number, vars?: Record<string, string | number>): string {
  const one = `${key}.one`;
  return t(n === 1 && has(one) ? one : key, { n, ...vars });
}

/** Translates a key. Reads the language from the settings, so it reacts to a change. */
export function t(key: Key, vars?: Record<string, string | number>): string {
  let s = dicts[settings.lang][key] ?? de[key];
  if (vars) for (const k in vars) s = s.replaceAll(`{${k}}`, String(vars[k]));
  return s;
}
