// Import from other programs: which sources exist and the state of the dialog, which opens from several places.

import { importFile } from './backend';
import { errorText } from './data.svelte';
import type { IconName } from './icons';
import { has, t, type Key } from './i18n.svelte';
import { toast } from './state.svelte';
import type { ImportDraft, ImportNote, ImportSource } from './types';

export interface SourceInfo {
  id: ImportSource;
  /** The program's proper name; formats without a proper name are in the translations. */
  name: string;
  icon: IconName;
  color: string;
}

/** Sources in the order the selection shows them. The colors are recognisable in light and dark, not brand colors. */
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

/** Notes saying that something is missing or not taken over; the others are mere information. */
const WARNINGS = new Set(['proxy_command', 'password_unreadable', 'key_missing', 'option_ignored', 'jump_missing']);
export const isWarning = (note: ImportNote) => WARNINGS.has(note.code);
export function noteText(note: ImportNote): string {
  const key = `imp.note.${note.code}`;
  return has(key) ? t(key as Key, { detail: note.detail ?? '' }) : (note.detail ?? note.code);
}

export const importUi = $state<{ open: boolean; draft: ImportDraft | null }>({ open: false, draft: null });

/** Opens the import, on request right away with a draft already read in the preview. */
export function openImport(draft: ImportDraft | null = null) {
  importUi.draft = draft;
  importUi.open = true;
}

/** Files that could be an import by their extension. Key files are not among them. */
export const looksImportable = (path: string) => /\.(csv|json|reg|ini|mxtsessions|xml|xsh)$/i.test(path) || /(^|[\\/])(config|known_hosts)$/i.test(path);

/** Reads a file dragged into the window and shows what could be taken over from it. */
export async function importDropped(path: string) {
  try {
    openImport(await importFile(path));
  } catch (e) {
    toast(errorText(e), 'err');
  }
}
