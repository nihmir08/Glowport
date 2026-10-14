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

/** Alles, was ohne Tresor gespeichert wird: Aussehen und Bedienung, keine Geheimnisse. */
export interface Settings {
  mode: Mode;
  accent: string;
  lang: Lang;
  hostView: HostView;
  /** Minuten ohne Eingabe bis zur Sperre, 0 = aus. */
  autoLockMinutes: number;
  /** Was bei einem Verbindungsabriss geschieht, wenn weder Host noch Gruppe etwas festlegen. */
  reconnect: Reconnect;
  /** Schriftgröße im Terminal in Pixeln. */
  termFontSize: number;
  /** Kennung des Farbschemas für alle Terminals; Hosts und Gruppen dürfen abweichen. */
  termScheme: string;
  /** Name der Schrift im Terminal; leer = die mitgelieferte JetBrains Mono. */
  termFont: string;
  /** Zeilenhöhe als Vielfaches der Schriftgröße. */
  termLineHeight: number;
  termLigatures: boolean;
  termCursor: Cursor;
  termCursorBlink: boolean;
  /** Deckkraft des Terminal-Hintergrunds in Prozent. */
  termOpacity: number;
  /** Bild hinter dem Terminal als Adresse, sonst null. */
  termBackground: string | null;
  /** Unschärfe des Bildes in Pixeln. */
  termBlur: number;
  /** Durchscheinendes Fenster (Windows 11). */
  windowEffect: WindowEffect;
  /** Nach einem Abbruch fragen, ob die Tabs wiederhergestellt werden sollen. Aus = nie wiederherstellen. */
  restorePrompt: boolean;
  /** Beim Schließen mit offenen Sitzungen nachfragen. Bei laufenden Transfers und Port-Regeln fragt Glowport immer. */
  closePrompt: boolean;
  /** Abstand der Messungen in der Server-Info, in Sekunden. */
  statsInterval: number;
  /** Jede neue Sitzung von Beginn an mitschneiden. */
  recordAuto: boolean;
  /** Selbst eingelesene Farbschemata. */
  customSchemes: Scheme[];
  /** Dateileiste neben dem Terminal zeigen. */
  fileBar: boolean;
  /** Breite der Dateileiste in Pixeln. */
  fileBarWidth: number;
  /** Die Dateileiste folgt dem Ordner, in dem das Terminal steht. */
  fileFollow: boolean;
  /** Versteckte Dateien zeigen. */
  fileHidden: boolean;
  /** Textdateien im eingebauten Editor öffnen; aus = im eigenen Programm. */
  fileEditor: boolean;
  /** Programm zum Bearbeiten, wenn der eingebaute Editor aus ist; leer = was Windows für die Datei vorsieht. */
  fileEditorPath: string;
  /** Wie viele Dateien gleichzeitig übertragen werden. */
  transferParallel: number;
  /** Was geschieht, wenn es die Datei am Ziel schon gibt. */
  transferConflict: Conflict;
  /** Ordner für Downloads aus der Dateileiste; leer = der Download-Ordner von Windows. */
  downloadDir: string;
  /** Seitenleiste rechts neben dem Terminal zeigen (Server-Info, Snippets). */
  sideBar: boolean;
  /** Breite der Seitenleiste in Pixeln. */
  sideBarWidth: number;
  /** Welcher Reiter der Seitenleiste vorn ist. */
  sideTab: SideTab;
  /** Beim Tippen im Terminal Befehle, Optionen und Pfade vorschlagen. */
  termSuggest: boolean;
  /** Kennung der Shell, die als lokales Terminal aufgeht, wenn keine gewählt wird; leer = die erste gefundene. */
  localShell: string;
  /** Beim Start nachsehen, ob es eine neuere Version gibt. */
  updateCheck: boolean;
  /** Wann zuletzt nachgesehen wurde, in Millisekunden seit 1970. */
  updateChecked: number;
  /** Die Version, die zuletzt lief. Weicht sie beim Start ab, wurde Glowport aktualisiert; leer beim ersten Start. */
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
  /** Suche und Schnellverbindung (Strg+K). */
  palette: false,
  /** Erst nach dem Laden der Einstellungen wird gespeichert, sonst überschreiben die Vorgaben die Datei. */
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
