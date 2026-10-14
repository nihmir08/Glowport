// Regeln für Snippets, die weder Zustand noch Kern brauchen: Variablen, Tastenkürzel, Anzeige von Makros.
// Gegenstück für Variablen und Tastenkürzel im Kern: crates/core/src/model.rs.

import type { MacroStep } from './types';

/** `{{name}}` oder `{{name:vorgabe}}`. Namen bestehen aus Buchstaben, Ziffern, `_` und `-`. */
const VARIABLE = /\{\{\s*([\p{L}\p{N}_-]+)\s*(?::([^{}]*))?\}\}/gu;

export interface Variable {
  name: string;
  /** Vorgabe aus dem Snippet; leer, wenn keine dasteht. */
  fallback: string;
}

/** Die Variablen eines Befehls in der Reihenfolge ihres ersten Auftretens. Die erste Vorgabe eines Namens gilt. */
export function variablesOf(command: string): Variable[] {
  const found: Variable[] = [];
  for (const match of command.matchAll(VARIABLE)) {
    const known = found.find((v) => v.name === match[1]);
    if (!known) found.push({ name: match[1], fallback: match[2]?.trim() ?? '' });
    else if (!known.fallback && match[2]) known.fallback = match[2].trim();
  }
  return found;
}

/** Setzt Werte ein. Was nicht ausgefüllt ist, bekommt seine Vorgabe. */
export function fill(command: string, values: Record<string, string>): string {
  const fallbacks = Object.fromEntries(variablesOf(command).map((v) => [v.name, v.fallback]));
  return command.replace(VARIABLE, (_, name: string) => values[name] || fallbacks[name] || '');
}

/** Was an die Shell geht, wenn ein Befehl ausgeführt wird: jede Zeile mit Eingabetaste abgeschlossen. */
export const asInput = (command: string) => `${command.replace(/\r?\n/g, '\r').replace(/\r+$/, '')}\r`;

export const lineCount = (command: string) => command.trim().split(/\r?\n/).length;
export const firstLine = (command: string) => command.trim().split(/\r?\n/)[0] ?? '';

// ---------- Tastenkürzel ----------

const KEY_NAME = /^([A-Z]|[0-9]|F([1-9]|1[0-2]))$/;
/** Kürzel, die Glowport oder Windows selbst benutzen. */
const RESERVED = new Set(['Ctrl+Shift+W', 'Ctrl+Shift+D', 'Ctrl+Shift+E', 'Ctrl+Shift+M', 'Ctrl+Shift+F', 'Ctrl+Shift+C', 'Ctrl+Shift+V', 'Ctrl+0', 'Alt+F4']);

/**
 * Das Kürzel zu einem Tastendruck in fester Schreibweise („Ctrl+Alt+R“, „Alt+1“), oder null, wenn die Taste
 * keines ergibt. AltGr zählt nie: Darüber kommen auf deutschen Tastaturen Zeichen wie @ und \.
 */
export function hotkeyOf(event: KeyboardEvent): string | null {
  if (event.getModifierState('AltGraph') || event.metaKey) return null;
  const key = /^Key[A-Z]$/.test(event.code) ? event.code.slice(3) : /^Digit[0-9]$/.test(event.code) ? event.code.slice(5) : /^F([1-9]|1[0-2])$/.test(event.key) ? event.key : null;
  if (!key) return null;
  return [event.ctrlKey && 'Ctrl', event.altKey && 'Alt', event.shiftKey && 'Shift', key].filter(Boolean).join('+');
}

/**
 * Ob sich ein Kürzel vergeben lässt. Erlaubt ist, was der Shell nichts wegnimmt: mit Alt, mit Strg+Umschalt
 * oder Strg mit Ziffer oder Funktionstaste. `reserved`: Das Kürzel gehört schon Glowport oder Windows.
 */
export function hotkeyProblem(hotkey: string): 'invalid' | 'reserved' | null {
  const parts = hotkey.split('+');
  const key = parts.pop() ?? '';
  const mods = new Set(parts);
  if (!KEY_NAME.test(key) || parts.some((m) => m !== 'Ctrl' && m !== 'Alt' && m !== 'Shift') || mods.size !== parts.length) return 'invalid';
  const allowed = mods.has('Alt') || (mods.has('Ctrl') && mods.has('Shift')) || (mods.has('Ctrl') && !/^[A-Z]$/.test(key));
  if (!allowed) return 'invalid';
  return RESERVED.has(hotkey) ? 'reserved' : null;
}

/** Schreibweise für die Anzeige: „Strg Alt R“ auf Deutsch, sonst „Ctrl Alt R“. */
export const hotkeyLabel = (hotkey: string, lang: string) =>
  hotkey
    .split('+')
    .map((part) => (lang === 'de' ? ({ Ctrl: 'Strg', Shift: '⇧' }[part] ?? part) : part === 'Shift' ? '⇧' : part))
    .join(' ');

// ---------- Makros ----------

const NAMED: [string, string][] = [
  ['\x1b[A', '↑'],
  ['\x1b[B', '↓'],
  ['\x1b[C', '→'],
  ['\x1b[D', '←'],
  ['\x1bOA', '↑'],
  ['\x1bOB', '↓'],
  ['\x1bOC', '→'],
  ['\x1bOD', '←'],
  ['\x1b[H', 'Pos1'],
  ['\x1b[F', 'Ende'],
  ['\x1b[3~', 'Entf'],
  ['\r', '⏎'],
  ['\t', '⇥'],
  ['\x7f', '⌫'],
  ['\x1b', 'Esc'],
];

/**
 * Teilt aufgezeichnete Tasten in lesbare Stücke: Text bleibt Text (`text`), Steuertasten werden benannt (`key`),
 * etwa ⏎ für die Eingabetaste oder ^C für Strg+C.
 */
export function showKeys(keys: string): { text?: string; key?: string }[] {
  const out: { text?: string; key?: string }[] = [];
  const push = (part: { text?: string; key?: string }) => {
    const last = out[out.length - 1];
    if (part.text !== undefined && last?.text !== undefined) last.text += part.text;
    else out.push(part);
  };
  for (let i = 0; i < keys.length; ) {
    const named = NAMED.find(([sequence]) => keys.startsWith(sequence, i));
    const code = keys.charCodeAt(i);
    if (named) (push({ key: named[1] }), (i += named[0].length));
    else if (code < 32) (push({ key: `^${String.fromCharCode(code + 64)}` }), (i += 1));
    else (push({ text: keys[i] }), (i += 1));
  }
  return out;
}

/** Dauer eines Makros beim Abspielen in Millisekunden; lange Pausen sind dabei gekürzt. */
export const MAX_WAIT = 1500;
export const macroDuration = (steps: MacroStep[]) => steps.reduce((sum, step) => sum + Math.min(step.wait, MAX_WAIT), 0);

/** Alles, was ein Makro tippt, hintereinander. */
export const macroKeys = (steps: MacroStep[]) => steps.map((step) => step.keys).join('');
