import { keyImport, keyInspect, keyReadFile, pickTextFile } from './backend';
import { applySnapshot, errorText } from './data.svelte';
import { t } from './i18n.svelte';
import { SCHEMES, parseSchemes, type Scheme } from './schemes';
import { settings, toast } from './state.svelte';
import type { KeyFile } from './types';

/**
 * Creating and importing in place: wherever you choose something from the vault (key, identity, group,
 * jump host, color scheme), it can also be created there. The new item is then selected right away.
 * The small dialogs for that lie on top of each other; `QuickCreate.svelte` draws them.
 */
export type Quick =
  /** `file`: key file already chosen, e.g. dragged into the window. */
  | { kind: 'key'; mode: 'generate' | 'import'; file?: KeyFile | null; done: (id: string) => void; closed?: () => void }
  | { kind: 'identity'; done: (id: string) => void; closed?: () => void }
  | { kind: 'group'; parent: string | null; done: (id: string) => void; closed?: () => void }
  | { kind: 'host'; done: (id: string) => void; closed?: () => void };

export const quick = $state({ stack: [] as (Quick & { n: number })[] });
let seq = 0;

export function openQuick(request: Quick) {
  quick.stack.push({ ...request, n: ++seq });
}

/** Closes a dialog; with an ID something was created and the caller gets it. */
export function closeQuick(n: number, id?: string) {
  const index = quick.stack.findIndex((request) => request.n === n);
  if (index < 0) return;
  const [request] = quick.stack.splice(index, 1);
  if (id) request.done(id);
  request.closed?.();
}

/** A “New …” entry at the end of a selection. */
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
 * Reads color schemes from a Windows Terminal or iTerm2 file and adds them to the custom ones.
 * Custom ones with the same name are replaced. Returns the newly imported ones.
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
 * Takes the file from the “Key file” field into the vault: the import dialog opens with it; without a path you choose
 * the file there. `set` gets the new key.
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

/** Editors with a “Key” field register here; the one opened last gets keys dragged in. */
const takers: ((id: string) => void)[] = [];
export function takeKeys(handler: (id: string) => void): () => void {
  takers.push(handler);
  return () => void takers.splice(takers.lastIndexOf(handler), 1);
}

const baseName = (path: string) => path.split(/[\\/]/).pop() || path;

/**
 * Imports key files dragged into the window, several at once too. What needs no passphrase
 * lands in the vault right away; for encrypted files the import dialog opens one after another.
 * If an editor with a “Key” field is open, it selects the one imported last.
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
