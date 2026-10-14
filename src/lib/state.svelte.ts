import type { Lang } from './i18n.svelte';
import { AUTO, type Scheme } from './schemes';
import type { Reconnect } from './types';

export type Mode = 'dark' | 'light' | 'system';
export type HostView = 'cards' | 'list';
export type PageId = 'hosts' | 'keys' | 'fwd' | 'snip' | 'files' | 'known' | 'logs' | 'pve' | 'sync' | 'settings' | 'kit';
export type Cursor = 'block' | 'bar' | 'underline';
export type WindowEffect = 'none' | 'mica' | 'acrylic';
export type Conflict = 'ask' | 'overwrite' | 'skip' | 'rename';
export type SideTab = 'info' | 'snip' | 'docker' | 'services' | 'processes';

/** Everything saved without the vault: appearance and operation, no secrets. */
export interface Settings {
  mode: Mode;
  accent: string;
  lang: Lang;
  hostView: HostView;
  /** Minutes without input until locking, 0 = off. */
  autoLockMinutes: number;
  /** What happens on a dropped connection if neither host nor group sets anything. */
  reconnect: Reconnect;
  /** Terminal font size in pixels. */
  termFontSize: number;
  /** ID of the color scheme for all terminals; hosts and groups may differ. */
  termScheme: string;
  /** Name of the terminal font; empty = the bundled JetBrains Mono. */
  termFont: string;
  /** Line height as a multiple of the font size. */
  termLineHeight: number;
  termLigatures: boolean;
  termCursor: Cursor;
  termCursorBlink: boolean;
  /** Opacity of the terminal background in percent. */
  termOpacity: number;
  /** Image behind the terminal as an address, otherwise null. */
  termBackground: string | null;
  /** Blur of the image in pixels. */
  termBlur: number;
  /** Translucent window (Windows 11). */
  windowEffect: WindowEffect;
  /** After a crash, ask whether the tabs should be restored. Off = never restore. */
  restorePrompt: boolean;
  /** Ask when closing with open sessions. With running transfers and port rules Glowport always asks. */
  closePrompt: boolean;
  /** Interval between measurements in the server info, in seconds. */
  statsInterval: number;
  /** Record every new session from the start. */
  recordAuto: boolean;
  /** Imported color schemes. */
  customSchemes: Scheme[];
  /** Show the file bar next to the terminal. */
  fileBar: boolean;
  /** Width of the file bar in pixels. */
  fileBarWidth: number;
  /** The file bar follows the folder the terminal is in. */
  fileFollow: boolean;
  /** Show hidden files. */
  fileHidden: boolean;
  /** Open text files in the built-in editor; off = in your own program. */
  fileEditor: boolean;
  /** Program for editing when the built-in editor is off; empty = what Windows intends for the file. */
  fileEditorPath: string;
  /** How many files are transferred at the same time. */
  transferParallel: number;
  /** What happens if the file already exists at the destination. */
  transferConflict: Conflict;
  /** Folder for downloads from the file bar; empty = the Windows downloads folder. */
  downloadDir: string;
  /** Show the sidebar right of the terminal (server info, snippets). */
  sideBar: boolean;
  /** Width of the sidebar in pixels. */
  sideBarWidth: number;
  /** Which sidebar tab is in front. */
  sideTab: SideTab;
  /** Suggest commands, options and paths while typing in the terminal. */
  termSuggest: boolean;
  /** ID of the shell that opens as local terminal when none is chosen; empty = the first one found. */
  localShell: string;
  /** Check on start whether there is a newer version. */
  updateCheck: boolean;
  /** When it last checked, in milliseconds since 1970. */
  updateChecked: number;
  /** The version that ran last. If it differs on start, Glowport was updated; empty on first start. */
  lastVersion: string;
}

export const DEFAULT_ACCENT = '#FE9803';
export const ACCENTS = ['#FE9803', '#FF2E63', '#00C8E0', '#8BD613', '#8B5CF6', '#5B9DFF'];
export const DEFAULT_FONT_SIZE = 13;

export const settings = $state<Settings>({
  mode: 'dark',
  accent: DEFAULT_ACCENT,
  lang: 'de',
  hostView: 'cards',
  autoLockMinutes: 0,
  reconnect: 'auto',
  termFontSize: DEFAULT_FONT_SIZE,
  termScheme: AUTO,
  termFont: '',
  termLineHeight: 1.15,
  termLigatures: false,
  termCursor: 'block',
  termCursorBlink: true,
  termOpacity: 100,
  termBackground: null,
  termBlur: 0,
  windowEffect: 'none',
  restorePrompt: true,
  closePrompt: true,
  statsInterval: 2,
  recordAuto: false,
  customSchemes: [],
  fileBar: true,
  fileBarWidth: 300,
  fileFollow: true,
  fileHidden: false,
  fileEditor: true,
  fileEditorPath: '',
  transferParallel: 4,
  transferConflict: 'ask',
  downloadDir: '',
  sideBar: false,
  sideBarWidth: 290,
  sideTab: 'info',
  termSuggest: true,
  localShell: '',
  updateCheck: true,
  updateChecked: 0,
  lastVersion: '',
});

export const ui = $state({
  page: 'hosts' as PageId,
  /** Search and quick connect (Ctrl+K). */
  palette: false,
  /** Only save after the settings have loaded, otherwise the defaults overwrite the file. */
  ready: false,
});

export interface Toast {
  id: number;
  text: string;
  kind: 'info' | 'ok' | 'err';
}

export const toasts = $state<Toast[]>([]);
let toastSeq = 0;

export function toast(text: string, kind: Toast['kind'] = 'info') {
  const id = ++toastSeq;
  toasts.push({ id, text, kind });
  setTimeout(() => {
    const i = toasts.findIndex((t) => t.id === id);
    if (i >= 0) toasts.splice(i, 1);
  }, 3600);
}
