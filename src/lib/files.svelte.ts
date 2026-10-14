import { dragOut, dragStage, fsConnect, fsDownloads, fsHome, fsList, inApp, onTransfers, onWatched, pickUploads, sessionAnswer, sessionClose, transferControl, transferList, transferStart, watchList, watchOpen, ftpConnect } from './backend';
import { errorText, hostById } from './data.svelte';
import type { IconName } from './icons';
import { has, t, type Key } from './i18n.svelte';
import { claim, view } from './sessions.svelte';
import { settings, toast, ui } from './state.svelte';
import type { Answer, BackendError, FileEntry, Listing, Place, Policy, Prompt, Transfer, Watched, FtpPlace } from './types';

/** Sortierung einer Dateiliste. Ordner stehen immer vor Dateien. */
export interface Sort {
  by: 'name' | 'size' | 'modified';
  desc: boolean;
}

const samePlace = (a: Place | null, b: Place | null) => {
  if (!a || !b || a.kind !== b.kind) return false;
  if (a.kind === 'local') return true;
  if (a.kind === 'ftp') return b.kind === 'ftp' && a.host === b.host && a.port === b.port && a.user === b.user && a.security === b.security;
  return a.id === (b as { id: string | number }).id;
};

/**
 * Der Blick in einen Ordner an einem Ort: Pfad, Inhalt, Auswahl, Sortierung.
 * Die Dateileiste am Terminal hat einen je Bereich, die Seite „Dateien“ einen je Spalte.
 */
export class Browser {
  place = $state<Place | null>(null);
  listing = $state<Listing | null>(null);
  loading = $state(false);
  /** Fehlertext, wenn sich der Ordner nicht lesen ließ. */
  error = $state<string | null>(null);
  /** Pfade der ausgewählten Einträge. */
  selected = $state<string[]>([]);
  sort = $state<Sort>({ by: 'name', desc: false });
  /** Eingrenzen der Liste nach Namen. */
  filter = $state('');
  /** Rückfrage, auf die der Verbindungsaufbau zu einem Host gerade wartet (unbekannter Server, Passwort). */
  prompt = $state<Prompt | null>(null);
  /** Die Verbindung, die gerade mit Rückfragen aufgebaut wird, und wie man ihre Ereignisse wieder abgibt. */
  private link: { id: number; release: () => void } | null = null;
  /** Von hier aus spannt Umschalt+Klick die Auswahl auf. */
  private anchor: string | null = null;
  /** Nur die Antwort auf die jüngste Anfrage zählt. */
  private ticket = 0;

  get path(): string | null {
    return this.listing?.path ?? null;
  }

  /** Was zu sehen ist: gefiltert, sortiert, Ordner zuerst. */
  get entries(): FileEntry[] {
    const word = this.filter.trim().toLowerCase();
    const { by, desc } = this.sort;
    const order = (a: FileEntry, b: FileEntry) => (by === 'size' ? a.size - b.size : by === 'modified' ? a.modified - b.modified : 0) || a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
    return (this.listing?.entries ?? [])
      .filter((e) => (settings.fileHidden || !(e.hidden ?? e.name.startsWith('.'))) && (!word || e.name.toLowerCase().includes(word)))
      .sort((a, b) => Number(b.kind === 'dir') - Number(a.kind === 'dir') || (desc ? -order(a, b) : order(a, b)));
  }

  get chosen(): FileEntry[] {
    return (this.listing?.entries ?? []).filter((e) => this.selected.includes(e.path));
  }

  /** Wechselt den Ort und beginnt in `path` oder im Heimatverzeichnis. */
  async open(place: Place, path?: string) {
    this.unlink();
    this.place = place;
    this.error = null;
    this.listing = null;
    this.selected = [];
    this.filter = '';
    await this.go(path);
  }

  /**
   * Öffnet einen Ordner; ohne Angabe das Heimatverzeichnis. Bei einem Fehler bleibt der alte Inhalt stehen.
   * Braucht ein Host erst eine Rückfrage (unbekannter Server, Passwort), wird sie gestellt und danach geöffnet;
   * `ask` verhindert, dass das ein zweites Mal geschieht.
   */
  async go(path?: string, ask = true): Promise<boolean> {
    const place = this.place;
    if (!place) return false;
    const ticket = ++this.ticket;
    this.loading = true;
    try {
      const listing = await fsList(place, path ?? (await fsHome(place)));
      if (ticket !== this.ticket) return false;
      const moved = listing.path !== this.listing?.path;
      this.listing = listing;
      this.error = null;
      if (moved) (this.selected = []), (this.filter = ''), (this.anchor = null);
      else this.selected = this.selected.filter((p) => listing.entries.some((e) => e.path === p));
      return true;
    } catch (e) {
      if (ticket !== this.ticket) return false;
      const code = (e as Partial<BackendError> | null)?.code;
      if (ask && (place.kind === 'host' || place.kind === 'ftp') && (code === 'files_auth' || code === 'files_host_key')) return this.connect(place, path);
      if (this.listing) toast(errorText(e), 'err');
      else this.error = errorText(e);
      return false;
    } finally {
      if (ticket === this.ticket) this.loading = false;
    }
  }

  /** Baut die Verbindung zu einem Host mit Rückfragen auf, wie ein Terminal es täte, und öffnet danach den Ordner. */
  private async connect(place: FtpPlace | { kind: 'host'; id: string }, path?: string): Promise<boolean> {
    const ticket = this.ticket;
    this.unlink();
    let id: number;
    try {
      id = await (place.kind === 'host' ? fsConnect(place.id) : ftpConnect(place));
    } catch (e) {
      if (ticket === this.ticket) this.error = errorText(e);
      return false;
    }
    if (ticket !== this.ticket) return void sessionClose(id), false;
    this.loading = true;
    return new Promise((resolve) => {
      const finish = (error: string | null) => {
        if (this.link?.id !== id) return resolve(false);
        this.unlink(false);
        if (error === null) return resolve(this.go(path, false));
        this.loading = false;
        this.error = error;
        resolve(false);
      };
      const release = claim(id, (event) => {
        if (event.type === 'phase') return void (event.phase === 'connected' && finish(null));
        if (event.type === 'end') {
          const key = event.reason === 'user' ? 'files.connect.cancelled' : `session.end.${event.reason}`;
          return finish(has(key) ? t(key as Key, { message: event.message ?? '' }) : (event.message ?? event.reason));
        }
        if (event.type === 'hostKey' || event.type === 'secret' || event.type === 'interactive' || event.type === 'certificate' || event.type === 'plain') this.prompt = event;
      });
      this.link = { id, release };
    });
  }

  /** Beantwortet die Rückfrage des Verbindungsaufbaus. */
  answer(reply: Answer) {
    if (!this.link) return;
    // Ein Server aus der Schnellverbindung lässt sich nicht umstellen wie ein Host: Er wird als FTPS neu geöffnet.
    if (reply.kind === 'plain' && reply.secure && this.place?.kind === 'ftp') return void this.open({ ...this.place, security: 'explicit' });
    this.prompt = null;
    void sessionAnswer(this.link.id, reply);
  }

  /** Gibt einen laufenden Verbindungsaufbau auf; mit `close` wird er auch im Kern beendet. */
  private unlink(close = true) {
    const link = this.link;
    this.link = null;
    this.prompt = null;
    if (!link) return;
    link.release();
    if (close) void sessionClose(link.id);
  }

  up = () => (this.listing?.parent != null ? this.go(this.listing.parent) : Promise.resolve(false));
  refresh = () => this.go(this.listing?.path);

  /** Vergisst alles; der Ort ist nicht mehr erreichbar. */
  reset() {
    this.unlink();
    this.ticket++;
    this.place = null;
    this.listing = null;
    this.error = null;
    this.loading = false;
    this.selected = [];
  }

  /** Auswahl wie im Explorer: Klick wählt einen, Strg schaltet um, Umschalt spannt auf. */
  pick(entry: FileEntry, event: { ctrlKey: boolean; shiftKey: boolean }) {
    const shown = this.entries.map((e) => e.path);
    if (event.shiftKey && this.anchor && shown.includes(this.anchor)) {
      const [a, b] = [shown.indexOf(this.anchor), shown.indexOf(entry.path)].sort((x, y) => x - y);
      this.selected = shown.slice(a, b + 1);
      return;
    }
    this.anchor = entry.path;
    if (event.ctrlKey) this.selected = this.selected.includes(entry.path) ? this.selected.filter((p) => p !== entry.path) : [...this.selected, entry.path];
    else this.selected = [entry.path];
  }

  /** Rechtsklick: Der Eintrag gehört danach zur Auswahl, eine bestehende Mehrfachauswahl bleibt. */
  include(entry: FileEntry) {
    if (!this.selected.includes(entry.path)) (this.selected = [entry.path]), (this.anchor = entry.path);
  }

  showsPlace = (place: Place) => samePlace(this.place, place);
}

/** Alle Blicke, die gerade etwas zeigen; nach einem fertigen Transfer lesen sie ihren Ordner neu. */
const browsers = new Set<Browser>();
export function newBrowser(): Browser {
  const browser = new Browser();
  browsers.add(browser);
  return browser;
}
export const dropBrowser = (browser: Browser) => void browsers.delete(browser);

/** Die beiden Spalten der Seite „Dateien“. Sie behalten ihren Stand, wenn man die Seite verlässt. */
export const columns = { left: newBrowser(), right: newBrowser() };

const bars = new Map<string, Browser>();
/** Der Blick der Dateileiste für einen Terminal-Bereich. */
export function barFor(pane: string): Browser {
  let browser = bars.get(pane);
  if (!browser) bars.set(pane, (browser = newBrowser()));
  return browser;
}
/** Räumt die Blicke geschlossener Bereiche weg. */
export function pruneBars(alive: string[]) {
  for (const [key, browser] of bars) if (!alive.includes(key)) (bars.delete(key), dropBrowser(browser));
}

// ---------- Transfers ----------

/**
 * Stand der Transfers. Die Liste zeigt sich an zwei Stellen: unten auf der Seite „Dateien“ (`dock`)
 * und sonst schwebend über der Statusleiste (`panel`). Beide merken sich getrennt, ob sie offen sind.
 */
export const transfers = $state<{ list: Transfer[]; watched: Watched[]; panel: boolean; dock: boolean; loaded: boolean }>({ list: [], watched: [], panel: false, dock: false, loaded: false });

const onFilesPage = () => view.active === 'home' && ui.page === 'files';
export const transfersShown = () => (onFilesPage() ? transfers.dock : transfers.panel);
/** Zeigt oder verbirgt die Liste der Transfers dort, wo man gerade ist; ohne Angabe wird umgeschaltet. */
export function showTransfers(on = !transfersShown()) {
  if (onFilesPage()) transfers.dock = on;
  else transfers.panel = on;
}

export const isActive = (x: Transfer) => x.state === 'running' || x.state === 'queued';
export const activeTransfers = () => transfers.list.filter(isActive);
/** Fortschritt aller laufenden und wartenden Transfers zusammen, 0 bis 1. */
export function overallProgress(): number {
  const open = transfers.list.filter((x) => isActive(x) || x.state === 'paused');
  const bytes = open.reduce((n, x) => n + x.bytes, 0);
  return bytes ? open.reduce((n, x) => n + x.done, 0) / bytes : 0;
}
export const overallSpeed = () => transfers.list.reduce((n, x) => n + (x.state === 'running' ? x.speed : 0), 0);

/** Meldet die Oberfläche für den Stand der Transfers an. Einmal beim Start aufrufen. */
export function initFiles(): () => void {
  transferList()
    .then((list) => (transfers.list = list))
    .catch((e) => console.error('Transfers nicht lesbar', e))
    .finally(() => (transfers.loaded = true));
  watchList()
    .then((list) => (transfers.watched = list))
    .catch((e) => console.error('Geöffnete Dateien nicht lesbar', e));
  const stops = [
    onTransfers((list) => {
      const finished = list.filter((x) => x.state === 'done').length > transfers.list.filter((x) => x.state === 'done').length;
      transfers.list = list;
      // Was angekommen ist, soll in den offenen Listen erscheinen.
      if (finished) for (const browser of browsers) if (browser.listing && !browser.loading) void browser.refresh();
    }),
    onWatched((list) => (transfers.watched = list)),
  ];
  return () => stops.forEach((stop) => stop());
}

/** Der letzte Teil eines Pfads, nur zum Vergleichen und Anzeigen von Namen. */
const baseName = (path: string) => path.replace(/[\\/]+$/, '').split(/[\\/]/).pop() ?? path;

/**
 * Was mit Namen geschieht, die es im Zielordner schon gibt. Steht in den Einstellungen „Fragen“, wird nachgesehen
 * und nur dann gefragt, wenn wirklich etwas kollidiert. `null` heißt: Der Nutzer hat abgebrochen.
 */
async function decide(to: Place, dest: string, names: string[]): Promise<Policy | null> {
  if (settings.transferConflict !== 'ask') return settings.transferConflict;
  // Windows unterscheidet Groß- und Kleinschreibung nicht.
  const key = (name: string) => (to.kind === 'local' ? name.toLowerCase() : name);
  const there = new Set((await fsList(to, dest)).entries.map((e) => key(e.name)));
  const present = names.filter((name) => there.has(key(name)));
  if (!present.length) return 'overwrite';
  return new Promise((resolve) => (fileUi.conflict = { names: present, to, dest, resolve }));
}

/** Reiht Pfade eines Orts für einen Zielordner ein. Liefert, ob etwas eingereiht wurde. */
export async function enqueue(from: Place, paths: string[], to: Place, dest: string): Promise<boolean> {
  if (!paths.length) return false;
  try {
    const policy = await decide(to, dest, paths.map(baseName));
    if (!policy) return false;
    // Auf der Seite „Dateien“ zeigt sich die Warteschlange von selbst; im Terminal meldet die Statusleiste den Fortschritt.
    if (onFilesPage()) transfers.dock = true;
    await transferStart({ from, paths, to, dest, policy, parallel: settings.transferParallel });
    return true;
  } catch (e) {
    toast(errorText(e), 'err');
    return false;
  }
}

/** Überträgt Einträge von einem Ort in einen Ordner an einem anderen. */
export const send = (from: Place, entries: FileEntry[], to: Place, dest: string) => enqueue(from, entries.map((e) => e.path), to, dest);

/** Lädt Einträge auf diesen PC, in den Ordner aus den Einstellungen oder den Download-Ordner von Windows. */
export async function download(from: Place, entries: FileEntry[]) {
  try {
    const dest = settings.downloadDir || (await fsDownloads());
    if (await send(from, entries, { kind: 'local' }, dest)) toast(t('files.download.started', { n: entries.length, to: dest }), 'ok');
  } catch (e) {
    toast(errorText(e), 'err');
  }
}

/** Lässt Dateien dieses PCs wählen und lädt sie in den Ordner hoch. */
export async function upload(to: Place, dest: string) {
  try {
    const paths = await pickUploads();
    if (paths?.length) await enqueue({ kind: 'local' }, paths, to, dest);
  } catch (e) {
    toast(errorText(e), 'err');
  }
}

// ---------- Fenster und Dialoge rund um Dateien ----------

/** Was gerade über der Oberfläche offen ist. Gezeichnet wird alles in FileDialogs.svelte. */
export const fileUi = $state<{
  /** Datei im Editor oder in der Vorschau. */
  viewer: { place: Place; entry: FileEntry; edit: boolean; browser: Browser | null } | null;
  /** Rechte und Besitzer ändern. */
  perms: { browser: Browser; entries: FileEntry[] } | null;
  /** Suche unterhalb des offenen Ordners. */
  search: { browser: Browser } | null;
  /** Ordner abgleichen: links gegen rechts. */
  compare: { left: Browser; right: Browser } | null;
  /** Neuer Ordner (ohne Eintrag) oder Umbenennen. */
  naming: { browser: Browser; entry: FileEntry | null } | null;
  removing: { browser: Browser; entries: FileEntry[] } | null;
  /** Kontextmenü eines Eintrags oder der leeren Fläche. */
  menu: { browser: Browser; entry: FileEntry | null; x: number; y: number; other: Browser | null; pane: string | null } | null;
  /** Rückfrage vor einem Transfer: Diese Namen gibt es im Zielordner schon. */
  conflict: { names: string[]; to: Place; dest: string; resolve: (policy: Policy | null) => void } | null;
}>({ viewer: null, perms: null, search: null, compare: null, naming: null, removing: null, menu: null, conflict: null });

const IMAGE = /\.(png|jpe?g|gif|webp|svg|ico|bmp)$/i;
const ARCHIVE = /\.(zip|tar|gz|tgz|bz2|xz|7z|rar|iso|deb|rpm)$/i;
const CODE = /\.(js|ts|mjs|cjs|jsx|tsx|json|ya?ml|toml|xml|html?|css|scss|sh|bash|zsh|py|rb|php|go|rs|c|h|cpp|java|sql|lua|pl|conf|cfg|ini|service|env)$|^\.[a-z_.]+$|^(Dockerfile|Makefile)$/i;
const TEXT = /\.(txt|md|log|csv|pub|reg)$|^(README|LICENSE|fstab|hosts|hostname)$/i;

export const isImage = (name: string) => IMAGE.test(name);

export function iconFor(entry: Pick<FileEntry, 'name' | 'kind'>): IconName {
  if (entry.kind === 'dir') return 'folder';
  if (entry.kind === 'link') return 'link';
  if (IMAGE.test(entry.name)) return 'image';
  if (ARCHIVE.test(entry.name)) return 'archive';
  if (CODE.test(entry.name)) return 'fileCode';
  if (TEXT.test(entry.name) || /\.log(\.\d+)?$/i.test(entry.name)) return 'log';
  return 'file';
}

/** Doppelklick auf eine Datei: Bilder in die Vorschau, alles andere zum Bearbeiten (eingebaut oder im eigenen Programm). */
export function openFile(browser: Browser, entry: FileEntry, edit = !isImage(entry.name)) {
  const place = browser.place;
  if (!place) return;
  if (edit && !settings.fileEditor) {
    void watchOpen(place, entry.path, settings.fileEditorPath)
      .then(() => (toast(t('files.watch.opened', { name: entry.name }), 'ok'), showTransfers(true)))
      .catch((e) => toast(errorText(e), 'err'));
    return;
  }
  fileUi.viewer = { place, entry, edit, browser };
}

/** Beschriftung für „dorthin übertragen“. */
export const sendLabel = (to: Place | null) => (to?.kind === 'local' ? t('files.send.local') : t('files.send', { to: placeName(to) }));

/** Öffnet einen Host in der rechten Spalte der Seite „Dateien“. So „verbindet“ sich ein FTP-Host: Er hat kein Terminal. */
export function openInFiles(id: string) {
  ui.page = 'files';
  if (!columns.left.place) void columns.left.open({ kind: 'local' });
  const dir = hostById(id)?.ftp?.dir;
  void columns.right.open({ kind: 'host', id }, dir || undefined);
}

/** Öffnet einen FTP-Server aus der Schnellverbindung in der rechten Spalte der Seite „Dateien“. */
export function openPlaceInFiles(place: FtpPlace, path?: string) {
  ui.page = 'files';
  if (!columns.left.place) void columns.left.open({ kind: 'local' });
  void columns.right.open(place, path || undefined);
}

/** So heißt ein Server aus der Schnellverbindung: `benutzer@adresse`, mit dem Port, wenn er nicht der übliche ist. */
export const ftpPlaceName = (place: FtpPlace) => `${place.user ? `${place.user}@` : ''}${place.host}${place.port === (place.security === 'implicit' ? 990 : 21) ? '' : `:${place.port}`}`;

export function placeName(place: Place | null, fallback = ''): string {
  if (!place) return fallback;
  if (place.kind === 'local') return t('files.local');
  if (place.kind === 'host') return hostById(place.id)?.name ?? fallback;
  if (place.kind === 'ftp') return ftpPlaceName(place);
  return fallback;
}

// ---------- Darstellung ----------

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) (value /= 1024), unit++;
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1).replace('.', settings.lang === 'de' ? ',' : '.')} ${units[unit]}`;
}

/** Heute die Uhrzeit, sonst das Datum; mit `full` beides. */
export function formatWhen(ms: number, full = false): string {
  const locale = settings.lang === 'de' ? 'de-DE' : 'en-GB';
  const date = new Date(ms);
  const time = date.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
  const day = date.toLocaleDateString(locale, { day: '2-digit', month: '2-digit', year: 'numeric' });
  if (full) return `${day} ${time}`;
  return new Date().toDateString() === date.toDateString() ? time : day;
}

/** Rechte in der Schreibweise von `ls -l`: „drwxr-xr-x“. */
export function modeText(entry: Pick<FileEntry, 'mode' | 'kind'>): string {
  if (entry.mode === null) return '';
  const bits = 'rwxrwxrwx'.split('').map((letter, i) => (entry.mode! & (0o400 >> i) ? letter : '-'));
  return (entry.kind === 'dir' ? 'd' : entry.kind === 'link' ? 'l' : '-') + bits.join('');
}
export const octal = (mode: number) => (mode & 0o777).toString(8).padStart(3, '0');

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '';
  if (seconds < 60) return t('time.seconds', { n: Math.max(1, Math.round(seconds)) });
  if (seconds < 3600) return t('time.minutes', { n: Math.round(seconds / 60) });
  return t('time.hours', { h: Math.floor(seconds / 3600), m: Math.round((seconds % 3600) / 60) });
}

// ---------- Ziehen von einer Liste in eine andere ----------

/** Was gerade zwischen zwei Dateilisten gezogen wird und worüber es schwebt. */
export const fileDrag = $state<{
  item: { from: Browser; entries: FileEntry[] } | null;
  over: Browser | null;
  dir: string | null;
  x: number;
  y: number;
  moved: boolean;
  /** Der Zeiger hat das Fenster verlassen: Die Dateien werden für den Explorer bereitgelegt, Fortschritt 0 bis 1. */
  staging: number | null;
}>({ item: null, over: null, dir: null, x: 0, y: 0, moved: false, staging: null });

/**
 * Zieht Einträge aus dem Fenster heraus, in den Explorer oder ein anderes Programm. Was auf diesem PC liegt, geht
 * sofort; was auf einem Server liegt, wird erst in einen Arbeitsordner geholt, solange die Maustaste gedrückt bleibt.
 * `state` sagt, ob sie es noch ist, ob losgelassen wurde oder ob der Zeiger ins Fenster zurückgekehrt ist.
 * Liefert, ob der Zug an Windows übergeben wurde.
 */
async function leaveWindow(from: Place, entries: FileEntry[], state: () => 'held' | 'released' | 'returned'): Promise<boolean> {
  try {
    let paths = entries.map((e) => e.path);
    if (from.kind !== 'local') {
      fileDrag.staging = 0;
      const staged = await dragStage(from, paths);
      const ready = await new Promise<boolean>((resolve) => {
        const timer = setInterval(() => {
          const mine = transfers.list.filter((x) => staged.ids.includes(x.id));
          const bytes = mine.reduce((n, x) => n + x.bytes, 0);
          fileDrag.staging = bytes ? mine.reduce((n, x) => n + x.done, 0) / bytes : 0;
          const failed = mine.some((x) => x.state === 'failed' || x.state === 'cancelled');
          const done = mine.length === staged.ids.length && mine.every((x) => x.state === 'done');
          if (state() !== 'held' || failed || done) (clearInterval(timer), resolve(done && state() === 'held'));
        }, 50);
      });
      if (!ready) {
        // Losgelassen oder gescheitert, bevor alles da war: Der Rest wird nicht mehr geholt.
        void transferControl(staged.ids, 'cancel');
        // Zurück im Fenster geht der Zug dort weiter; nur wer draußen loslässt, erfährt, warum nichts ankam.
        if (state() !== 'returned') toast(t('files.dragout.released'), 'err');
        return false;
      }
      paths = staged.paths;
    }
    fileDrag.staging = null;
    await dragOut(paths);
    return true;
  } catch (e) {
    toast(errorText(e), 'err');
    return true;
  } finally {
    fileDrag.staging = null;
  }
}

/** Beginnt auf einem Eintrag: Ab ein paar Pixeln Weg wird die Auswahl gezogen; losgelassen über einer anderen Liste wird übertragen. */
export function startFileDrag(event: PointerEvent, from: Browser) {
  const start = { x: event.clientX, y: event.clientY };
  fileDrag.moved = false;
  /** Der Zug hat das Fenster verlassen und geht jetzt an Windows. */
  let left = false;
  /** Der Zug ist zu Ende: losgelassen, abgebrochen oder an Windows übergeben. */
  let ended = false;
  /** Der Zeiger ist ins Fenster zurückgekehrt, bevor Windows übernommen hat. */
  let returned = false;
  const move = (e: PointerEvent) => {
    if (!fileDrag.item) {
      if (Math.hypot(e.clientX - start.x, e.clientY - start.y) < 6 || !from.chosen.length) return;
      fileDrag.item = { from, entries: from.chosen };
      fileDrag.moved = true;
    }
    fileDrag.x = e.clientX;
    fileDrag.y = e.clientY;
    // Über den Rand hinaus: Das Fenster kann nicht mehr sehen, wohin es geht; ab hier zieht Windows.
    const outside = e.clientX < 0 || e.clientY < 0 || e.clientX > innerWidth || e.clientY > innerHeight;
    const item = fileDrag.item;
    if (outside && !left && inApp && item.from.place) {
      left = true;
      returned = false;
      // Hat Windows übernommen, ist der Zug für das Fenster vorbei; sonst geht er hier weiter.
      void leaveWindow(item.from.place, item.entries, () => (ended ? 'released' : returned ? 'returned' : 'held')).then((handed) => (handed ? stop(new Event('dragout')) : (left = false)));
    } else if (!outside && left && fileDrag.staging !== null) {
      returned = true;
    }
  };
  const stop = (e: Event) => {
    if (ended) return;
    ended = true;
    removeEventListener('pointermove', move);
    removeEventListener('pointerup', stop);
    removeEventListener('pointercancel', stop);
    removeEventListener('keydown', escape);
    const { item, over, dir } = fileDrag;
    fileDrag.item = fileDrag.over = fileDrag.dir = null;
    // Der Klick, der auf das Loslassen folgt, soll die Auswahl nicht verändern.
    setTimeout(() => (fileDrag.moved = false));
    if (e.type === 'pointerup' && !left && item?.from.place && over?.place && over.listing && over !== item.from) void send(item.from.place, item.entries, over.place, dir ?? over.listing.path);
  };
  const escape = (e: KeyboardEvent) => e.key === 'Escape' && stop(e);
  addEventListener('pointermove', move);
  addEventListener('pointerup', stop);
  addEventListener('pointercancel', stop);
  addEventListener('keydown', escape);
}
