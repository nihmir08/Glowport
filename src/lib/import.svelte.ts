// Import aus anderen Programmen: welche Quellen es gibt und der Zustand des Dialogs, der von mehreren Stellen aus aufgeht.

import { importFile } from './backend';
import { errorText } from './data.svelte';
import type { IconName } from './icons';
import { has, t, type Key } from './i18n.svelte';
import { toast } from './state.svelte';
import type { ImportDraft, ImportNote, ImportSource } from './types';

export interface SourceInfo {
  id: ImportSource;
  /** Eigenname des Programms; Formate ohne Eigennamen stehen in den Übersetzungen. */
  name: string;
  icon: IconName;
  color: string;
}

/** Quellen in der Reihenfolge, in der die Auswahl sie zeigt. Die Farben sind in hell und dunkel erkennbar, keine Markenfarben. */
export const SOURCES: SourceInfo[] = [
  { id: 'sshconfig', name: 'OpenSSH', icon: 'terminal', color: '#8FA3B8' },
  { id: 'putty', name: 'PuTTY', icon: 'monitor', color: '#E6C229' },
  { id: 'mobaxterm', name: 'MobaXterm', icon: 'layout', color: '#4FA3E3' },
  { id: 'winscp', name: 'WinSCP', icon: 'transfer', color: '#5BBF6A' },
  { id: 'securecrt', name: 'SecureCRT', icon: 'lock', color: '#E0603C' },
  { id: 'mremoteng', name: 'mRemoteNG', icon: 'grid', color: '#3FB7C4' },
  { id: 'xshell', name: 'Xshell', icon: 'terminal', color: '#D9534F' },
  { id: 'wterminal', name: 'Windows Terminal', icon: 'terminal', color: '#9A9AB0' },
  { id: 'filezilla', name: 'FileZilla', icon: 'folder', color: '#D4573B' },
  { id: 'nexusssh', name: 'NexusSSH', icon: 'server', color: '#A78BFA' },
  { id: 'knownhosts', name: 'known_hosts', icon: 'shield', color: '#3ECF8E' },
  { id: 'csv', name: 'CSV', icon: 'list', color: '#F5B83D' },
  { id: 'glowport', name: 'Glowport', icon: 'archive', color: '#FE9803' },
];

export const sourceInfo = (id: ImportSource) => SOURCES.find((s) => s.id === id)!;
export const sourceName = (id: ImportSource) => (has(`imp.src.${id}`) ? t(`imp.src.${id}` as Key) : sourceInfo(id).name);

/** Hinweise, die sagen, dass etwas fehlt oder nicht übernommen wird; die übrigen sind bloße Auskunft. */
const WARNINGS = new Set(['proxy_command', 'password_unreadable', 'key_missing', 'option_ignored', 'jump_missing']);
export const isWarning = (note: ImportNote) => WARNINGS.has(note.code);
export function noteText(note: ImportNote): string {
  const key = `imp.note.${note.code}`;
  return has(key) ? t(key as Key, { detail: note.detail ?? '' }) : (note.detail ?? note.code);
}

export const importUi = $state<{ open: boolean; draft: ImportDraft | null }>({ open: false, draft: null });

/** Öffnet den Import, auf Wunsch gleich mit einem gelesenen Entwurf in der Vorschau. */
export function openImport(draft: ImportDraft | null = null) {
  importUi.draft = draft;
  importUi.open = true;
}

/** Dateien, die nach ihrer Endung ein Import sein könnten. Schlüsseldateien gehören nicht dazu. */
export const looksImportable = (path: string) => /\.(csv|json|reg|ini|mxtsessions|xml|xsh)$/i.test(path) || /(^|[\\/])(config|known_hosts)$/i.test(path);

/** Liest eine ins Fenster gezogene Datei und zeigt, was sich daraus übernehmen ließe. */
export async function importDropped(path: string) {
  try {
    openImport(await importFile(path));
  } catch (e) {
    toast(errorText(e), 'err');
  }
}
