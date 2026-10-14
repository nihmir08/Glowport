import { keyImport, keyInspect, keyReadFile, pickTextFile } from './backend';
import { applySnapshot, errorText } from './data.svelte';
import { t } from './i18n.svelte';
import { SCHEMES, parseSchemes, type Scheme } from './schemes';
import { settings, toast } from './state.svelte';
import type { KeyFile } from './types';

/**
 * Anlegen und Importieren an Ort und Stelle: Wo man etwas aus dem Tresor auswählt (Schlüssel, Identität, Gruppe,
 * Sprung-Server, Farbschema), lässt es sich dort auch neu anlegen. Das Neue ist danach gleich ausgewählt.
 * Die kleinen Dialoge dafür liegen übereinander; sie zeichnet `QuickCreate.svelte`.
 */
export type Quick =
  /** `file`: schon gewählte Schlüsseldatei, etwa ins Fenster gezogen. */
  | { kind: 'key'; mode: 'generate' | 'import'; file?: KeyFile | null; done: (id: string) => void; closed?: () => void }
  | { kind: 'identity'; done: (id: string) => void; closed?: () => void }
  | { kind: 'group'; parent: string | null; done: (id: string) => void; closed?: () => void }
  | { kind: 'host'; done: (id: string) => void; closed?: () => void };

export const quick = $state({ stack: [] as (Quick & { n: number })[] });
let seq = 0;

export function openQuick(request: Quick) {
  quick.stack.push({ ...request, n: ++seq });
}

/** Schließt einen Dialog; mit Kennung wurde etwas angelegt und der Aufrufer bekommt es. */
export function closeQuick(n: number, id?: string) {
  const index = quick.stack.findIndex((request) => request.n === n);
  if (index < 0) return;
  const [request] = quick.stack.splice(index, 1);
  if (id) request.done(id);
  request.closed?.();
}

/** Ein Eintrag „Neu …“ am Ende einer Auswahl. */
export interface Action {
  label: string;
  run: () => void;
}

export const keyActions = (set: (id: string) => void): Action[] => [
  { label: t('quick.key.import'), run: () => openQuick({ kind: 'key', mode: 'import', done: set }) },
  { label: t('quick.key.generate'), run: () => openQuick({ kind: 'key', mode: 'generate', done: set }) },
];
export const identityActions = (set: (id: string) => void): Action[] => [{ label: t('quick.identity'), run: () => openQuick({ kind: 'identity', done: set }) }];
export const groupActions = (parent: () => string | null, set: (id: string) => void): Action[] => [{ label: t('quick.group'), run: () => openQuick({ kind: 'group', parent: parent(), done: set }) }];
export const hostActions = (set: (id: string) => void): Action[] => [{ label: t('quick.host'), run: () => openQuick({ kind: 'host', done: set }) }];
export const schemeActions = (set: (id: string) => void): Action[] => [
  {
    label: t('quick.scheme'),
    run: () =>
      void importSchemes().then((found) => {
        if (found.length) set(found[0].id);
      }),
  },
];

/**
 * Liest Farbschemata aus einer Datei von Windows Terminal oder iTerm2 und legt sie zu den eigenen.
 * Gleichnamige eigene werden ersetzt. Liefert die neu eingelesenen.
 */
export async function importSchemes(): Promise<Scheme[]> {
  try {
    const file = await pickTextFile('.json,.itermcolors');
    if (!file) return [];
    const found = parseSchemes(file.text, file.name).filter((s) => !SCHEMES.some((own) => own.id === s.id));
    if (!found.length) {
      toast(t('set.scheme.import.none'), 'err');
      return [];
    }
    settings.customSchemes = [...settings.customSchemes.filter((s) => !found.some((f) => f.id === s.id)), ...found];
    toast(t('set.scheme.import.done', { n: found.length }), 'ok');
    return found;
  } catch (e) {
    toast(errorText(e), 'err');
    return [];
  }
}

/**
 * Holt die Datei aus dem Feld „Schlüsseldatei“ in den Tresor: Der Import-Dialog öffnet sich mit ihr; ohne Pfad wählt
 * man die Datei dort. `set` bekommt den neuen Schlüssel.
 */
export async function importKeyFile(path: string, set: (id: string) => void) {
  let file: KeyFile | null = null;
  if (path.trim()) {
    try {
      file = await keyReadFile(path.trim());
    } catch (e) {
      return toast(errorText(e), 'err');
    }
  }
  openQuick({ kind: 'key', mode: 'import', file, done: set });
}

/** Editoren mit einem Feld „Schlüssel“ melden sich hier an; der zuletzt geöffnete bekommt hineingezogene Schlüssel. */
const takers: ((id: string) => void)[] = [];
export function takeKeys(handler: (id: string) => void): () => void {
  takers.push(handler);
  return () => void takers.splice(takers.lastIndexOf(handler), 1);
}

const baseName = (path: string) => path.split(/[\\/]/).pop() || path;

/**
 * Importiert Schlüsseldateien, die ins Fenster gezogen wurden, auch mehrere auf einmal. Was keine Passphrase
 * braucht, landet sofort im Tresor; für verschlüsselte Dateien öffnet sich nacheinander der Import-Dialog.
 * Ist gerade ein Editor mit einem Feld „Schlüssel“ offen, wählt er den zuletzt importierten aus.
 */
export async function importDroppedKeys(files: KeyFile[]) {
  const imported: string[] = [];
  let skipped = 0;
  for (const file of files) {
    try {
      const info = await keyInspect(file.text);
      if (info.encrypted) {
        await new Promise<void>((resolve) => openQuick({ kind: 'key', mode: 'import', file, done: (id) => void imported.push(id), closed: resolve }));
      } else {
        const changed = await keyImport({ name: baseName(file.path), text: file.text });
        applySnapshot(changed.data);
        imported.push(changed.id!);
      }
    } catch {
      skipped += 1;
    }
  }
  if (imported.length) toast(t('drop.done', { n: imported.length }), 'ok');
  if (skipped) toast(t('drop.skipped', { n: skipped }), 'err');
  const last = imported.at(-1);
  if (last) takers.at(-1)?.(last);
}
