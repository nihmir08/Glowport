// Snippet rules that need neither state nor core: variables, shortcuts, display of macros.
// Counterpart for variables and shortcuts in the core: crates/core/src/model.rs.

import type { MacroStep } from './types';

/** `{{name}}` or `{{name:default}}`. Names consist of letters, digits, `_` and `-`. */
const VARIABLE = /\{\{\s*([\p{L}\p{N}_-]+)\s*(?::([^{}]*))?\}\}/gu;

export interface Variable {
  name: string;
  /** Default from the snippet; empty if there is none. */
  fallback: string;
}

/** A command's variables in the order of their first appearance. A name's first default applies. */
export function variablesOf(command: string): Variable[] {
  const found: Variable[] = [];
  for (const match of command.matchAll(VARIABLE)) {
    const known = found.find((v) => v.name === match[1]);
    if (!known) found.push({ name: match[1], fallback: match[2]?.trim() ?? '' });
    else if (!known.fallback && match[2]) known.fallback = match[2].trim();
  }
  return found;
}

/** Fills in values. What is not filled in gets its default. */
export function fill(command: string, values: Record<string, string>): string {
  const fallbacks = Object.fromEntries(variablesOf(command).map((v) => [v.name, v.fallback]));
  return command.replace(VARIABLE, (_, name: string) => values[name] || fallbacks[name] || '');
}

/** What goes to the shell when a command runs: every line terminated with Enter. */
export const asInput = (command: string) => `${command.replace(/\r?\n/g, '\r').replace(/\r+$/, '')}\r`;

export const lineCount = (command: string) => command.trim().split(/\r?\n/).length;
export const firstLine = (command: string) => command.trim().split(/\r?\n/)[0] ?? '';

// ---------- Shortcuts ----------

const KEY_NAME = /^([A-Z]|[0-9]|F([1-9]|1[0-2]))$/;
/** Shortcuts Glowport or Windows use themselves. */
const RESERVED = new Set(['Ctrl+Shift+W', 'Ctrl+Shift+D', 'Ctrl+Shift+E', 'Ctrl+Shift+M', 'Ctrl+Shift+F', 'Ctrl+Shift+C', 'Ctrl+Shift+V', 'Ctrl+0', 'Alt+F4']);

/**
 * The shortcut for a key press in fixed notation (“Ctrl+Alt+R”, “Alt+1”), or null if the key
 * does not make one. AltGr never counts: on German keyboards it produces characters like @ and \.
 */
export function hotkeyOf(event: KeyboardEvent): string | null {
  if (event.getModifierState('AltGraph') || event.metaKey) return null;
  const key = /^Key[A-Z]$/.test(event.code) ? event.code.slice(3) : /^Digit[0-9]$/.test(event.code) ? event.code.slice(5) : /^F([1-9]|1[0-2])$/.test(event.key) ? event.key : null;
  if (!key) return null;
  return [event.ctrlKey && 'Ctrl', event.altKey && 'Alt', event.shiftKey && 'Shift', key].filter(Boolean).join('+');
}

/**
 * Whether a shortcut can be assigned. Allowed is what takes nothing away from the shell: with Alt, with Ctrl+Shift
 * or Ctrl with a digit or function key. `reserved`: the shortcut already belongs to Glowport or Windows.
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

/** Notation for display: “Strg Alt R” in German, otherwise “Ctrl Alt R”. */
export const hotkeyLabel = (hotkey: string, lang: string) =>
  hotkey
    .split('+')
    .map((part) => (lang === 'de' ? ({ Ctrl: 'Strg', Shift: '⇧' }[part] ?? part) : part === 'Shift' ? '⇧' : part))
    .join(' ');

// ---------- Macros ----------

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
 * Splits recorded keys into readable pieces: text stays text (`text`), control keys get names (`key`),
 * e.g. ⏎ for Enter or ^C for Ctrl+C.
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

/** A macro's playback duration in milliseconds; long pauses are shortened. */
export const MAX_WAIT = 1500;
export const macroDuration = (steps: MacroStep[]) => steps.reduce((sum, step) => sum + Math.min(step.wait, MAX_WAIT), 0);

/** Everything a macro types, in a row. */
export const macroKeys = (steps: MacroStep[]) => steps.map((step) => step.keys).join('');
