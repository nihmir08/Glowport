import { dragOut, dragStage, fsConnect, fsDownloads, fsHome, fsList, inApp, onTransfers, onWatched, pickUploads, sessionAnswer, sessionClose, transferControl, transferList, transferStart, watchList, watchOpen, ftpConnect } from './backend';
import { errorText, hostById } from './data.svelte';
import type { IconName } from './icons';
import { has, t, type Key } from './i18n.svelte';
import { claim, view } from './sessions.svelte';
import { settings, toast, ui } from './state.svelte';
import type { Answer, BackendError, FileEntry, Listing, Place, Policy, Prompt, Transfer, Watched, FtpPlace } from './types';

/** Sort order of a file list. Folders always come before files. */
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
 * The view into a folder at a location: path, content, selection, sort order.
 * The file bar at the terminal has one per pane, the Files page one per column.
 */
export class Browser {
  place = $state<Place | null>(null);
  listing = $state<Listing | null>(null);
  loading = $state(false);
  /** Error text if the folder could not be read. */
  error = $state<string | null>(null);
  /** Paths of the selected entries. */
  selected = $state<string[]>([]);
  sort = $state<Sort>({ by: 'name', desc: false });
  /** Filtering the list by name. */
  filter = $state('');
  /** Prompt the connection setup to a host is currently waiting for (unknown server, password). */
  prompt = $state<Prompt | null>(null);
  /** The connection currently being set up with prompts, and how to release its events again. */
  private link: { id: number; release: () => void } | null = null;
  /** From here Shift+click extends the selection. */
  private anchor: string | null = null;
  /** Only the answer to the latest request counts. */
  private ticket = 0;

  get path(): string | null {
    return this.listing?.path ?? null;
  }

  /** What can be seen: filtered, sorted, folders first. */
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

  /** Changes the location and starts in `path` or the home directory. */
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
   * Opens a folder; without one, the home directory. On an error the old content stays.
   * If a host first needs a prompt (unknown server, password), it is asked and the folder opened afterwards;
   * `ask` prevents that from happening a second time.
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

  /** Sets up the connection to a host with prompts, as a terminal would, and then opens the folder. */
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

  /** Answers the connection setup's prompt. */
  answer(reply: Answer) {
    if (!this.link) return;
    // A server from quick connect cannot be switched like a host: it is reopened as FTPS.
    if (reply.kind === 'plain' && reply.secure && this.place?.kind === 'ftp') return void this.open({ ...this.place, security: 'explicit' });
    this.prompt = null;
    void sessionAnswer(this.link.id, reply);
  }

  /** Gives up a running connection setup; with `close` it is also ended in the core. */
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

  /** Forgets everything; the location can no longer be reached. */
  reset() {
    this.unlink();
    this.ticket++;
    this.place = null;
    this.listing = null;
    this.error = null;
    this.loading = false;
    this.selected = [];
  }

  /** Selection as in Explorer: click selects one, Ctrl toggles, Shift extends. */
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

  /** Right-click: the entry then belongs to the selection, an existing multi-selection stays. */
  include(entry: FileEntry) {
    if (!this.selected.includes(entry.path)) (this.selected = [entry.path]), (this.anchor = entry.path);
  }

  showsPlace = (place: Place) => samePlace(this.place, place);
}

/** All views currently showing something; after a finished transfer they read their folder anew. */
const browsers = new Set<Browser>();
export function newBrowser(): Browser {
  const browser = new Browser();
  browsers.add(browser);
  return browser;
}
export const dropBrowser = (browser: Browser) => void browsers.delete(browser);

/** The two columns of the Files page. They keep their state when you leave the page. */
export const columns = { left: newBrowser(), right: newBrowser() };

const bars = new Map<string, Browser>();
/** The file bar's view for a terminal pane. */
export function barFor(pane: string): Browser {
  let browser = bars.get(pane);
  if (!browser) bars.set(pane, (browser = newBrowser()));
  return browser;
}
/** Clears away the views of closed panes. */
export function pruneBars(alive: string[]) {
  for (const [key, browser] of bars) if (!alive.includes(key)) (bars.delete(key), dropBrowser(browser));
}

// ---------- Transfers ----------

/**
 * State of the transfers. The list shows in two places: at the bottom of the Files page (`dock`)
 * and otherwise floating above the status bar (`panel`). Both remember separately whether they are open.
 */
export const transfers = $state<{ list: Transfer[]; watched: Watched[]; panel: boolean; dock: boolean; loaded: boolean }>({ list: [], watched: [], panel: false, dock: false, loaded: false });

const onFilesPage = () => view.active === 'home' && ui.page === 'files';
export const transfersShown = () => (onFilesPage() ? transfers.dock : transfers.panel);
/** Shows or hides the transfer list wherever you are; without a value it toggles. */
export function showTransfers(on = !transfersShown()) {
  if (onFilesPage()) transfers.dock = on;
  else transfers.panel = on;
}

export const isActive = (x: Transfer) => x.state === 'running' || x.state === 'queued';
export const activeTransfers = () => transfers.list.filter(isActive);
/** Progress of all running and waiting transfers together, 0 to 1. */
export function overallProgress(): number {
  const open = transfers.list.filter((x) => isActive(x) || x.state === 'paused');
  const bytes = open.reduce((n, x) => n + x.bytes, 0);
  return bytes ? open.reduce((n, x) => n + x.done, 0) / bytes : 0;
}
export const overallSpeed = () => transfers.list.reduce((n, x) => n + (x.state === 'running' ? x.speed : 0), 0);

/** Subscribes the interface to the transfer state. Call once on start. */
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
      // What arrived should appear in the open lists.
      if (finished) for (const browser of browsers) if (browser.listing && !browser.loading) void browser.refresh();
    }),
    onWatched((list) => (transfers.watched = list)),
  ];
  return () => stops.forEach((stop) => stop());
}

/** The last part of a path, only for comparing and displaying names. */
const baseName = (path: string) => path.replace(/[\\/]+$/, '').split(/[\\/]/).pop() ?? path;

/**
 * What happens with names that already exist in the destination folder. If the settings say “Ask”, it checks
 * and only asks if something really collides. `null` means: the user cancelled.
 */
async function decide(to: Place, dest: string, names: string[]): Promise<Policy | null> {
  if (settings.transferConflict !== 'ask') return settings.transferConflict;
  // Windows does not distinguish upper and lower case.
  const key = (name: string) => (to.kind === 'local' ? name.toLowerCase() : name);
  const there = new Set((await fsList(to, dest)).entries.map((e) => key(e.name)));
  const present = names.filter((name) => there.has(key(name)));
  if (!present.length) return 'overwrite';
  return new Promise((resolve) => (fileUi.conflict = { names: present, to, dest, resolve }));
}

/** Queues a location's paths for a destination folder. Returns whether something was queued. */
export async function enqueue(from: Place, paths: string[], to: Place, dest: string): Promise<boolean> {
  if (!paths.length) return false;
  try {
    const policy = await decide(to, dest, paths.map(baseName));
    if (!policy) return false;
    // On the Files page the queue shows itself; in the terminal the status bar reports the progress.
    if (onFilesPage()) transfers.dock = true;
    await transferStart({ from, paths, to, dest, policy, parallel: settings.transferParallel });
    return true;
  } catch (e) {
    toast(errorText(e), 'err');
    return false;
  }
}

/** Transfers entries from one location into a folder at another. */
export const send = (from: Place, entries: FileEntry[], to: Place, dest: string) => enqueue(from, entries.map((e) => e.path), to, dest);

/** Downloads entries to this PC, into the folder from the settings or the Windows downloads folder. */
export async function download(from: Place, entries: FileEntry[]) {
  try {
    const dest = settings.downloadDir || (await fsDownloads());
    if (await send(from, entries, { kind: 'local' }, dest)) toast(t('files.download.started', { n: entries.length, to: dest }), 'ok');
  } catch (e) {
    toast(errorText(e), 'err');
  }
}

/** Lets the user choose files on this PC and uploads them into the folder. */
export async function upload(to: Place, dest: string) {
  try {
    const paths = await pickUploads();
    if (paths?.length) await enqueue({ kind: 'local' }, paths, to, dest);
  } catch (e) {
    toast(errorText(e), 'err');
  }
}

// ---------- Windows and dialogs around files ----------

/** What is currently open above the interface. Everything is drawn in FileDialogs.svelte. */
export const fileUi = $state<{
  /** File in the editor or the preview. */
  viewer: { place: Place; entry: FileEntry; edit: boolean; browser: Browser | null } | null;
  /** Change permissions and owner. */
  perms: { browser: Browser; entries: FileEntry[] } | null;
  /** Search below the open folder. */
  search: { browser: Browser } | null;
  /** Folder sync: left against right. */
  compare: { left: Browser; right: Browser } | null;
  /** New folder (without entry) or rename. */
  naming: { browser: Browser; entry: FileEntry | null } | null;
  removing: { browser: Browser; entries: FileEntry[] } | null;
  /** Context menu of an entry or the empty area. */
  menu: { browser: Browser; entry: FileEntry | null; x: number; y: number; other: Browser | null; pane: string | null } | null;
  /** Prompt before a transfer: these names already exist in the destination folder. */
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

/** Double-click on a file: images into the preview, everything else for editing (built in or in your own program). */
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

/** Label for “transfer there”. */
export const sendLabel = (to: Place | null) => (to?.kind === 'local' ? t('files.send.local') : t('files.send', { to: placeName(to) }));

/** Opens a host in the right column of the Files page. That is how an FTP host “connects”: it has no terminal. */
export function openInFiles(id: string) {
  ui.page = 'files';
  if (!columns.left.place) void columns.left.open({ kind: 'local' });
  const dir = hostById(id)?.ftp?.dir;
  void columns.right.open({ kind: 'host', id }, dir || undefined);
}

/** Opens an FTP server from quick connect in the right column of the Files page. */
export function openPlaceInFiles(place: FtpPlace, path?: string) {
  ui.page = 'files';
  if (!columns.left.place) void columns.left.open({ kind: 'local' });
  void columns.right.open(place, path || undefined);
}

/** What a server from quick connect is called: `user@address`, with the port if it is not the usual one. */
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

/** Today the time, otherwise the date; with `full` both. */
export function formatWhen(ms: number, full = false): string {
  const locale = settings.lang === 'de' ? 'de-DE' : 'en-GB';
  const date = new Date(ms);
  const time = date.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
  const day = date.toLocaleDateString(locale, { day: '2-digit', month: '2-digit', year: 'numeric' });
  if (full) return `${day} ${time}`;
  return new Date().toDateString() === date.toDateString() ? time : day;
}

/** Permissions in `ls -l` notation: “drwxr-xr-x”. */
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

// ---------- Dragging from one list into another ----------

/** What is currently being dragged between two file lists and what it hovers over. */
export const fileDrag = $state<{
  item: { from: Browser; entries: FileEntry[] } | null;
  over: Browser | null;
  dir: string | null;
  x: number;
  y: number;
  moved: boolean;
  /** The pointer left the window: the files are being prepared for Explorer, progress 0 to 1. */
  staging: number | null;
}>({ item: null, over: null, dir: null, x: 0, y: 0, moved: false, staging: null });

/**
 * Drags entries out of the window, into Explorer or another program. What is on this PC goes
 * right away; what is on a server is first fetched into a working folder while the mouse button stays pressed.
 * `state` says whether it still is, whether it was released or whether the pointer returned into the window.
 * Returns whether the drag was handed to Windows.
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
        // Released or failed before everything was there: the rest is no longer fetched.
        void transferControl(staged.ids, 'cancel');
        // Back in the window the drag continues there; only whoever releases outside learns why nothing arrived.
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

/** Starts on an entry: after a few pixels of movement the selection is dragged; released over another list it is transferred. */
export function startFileDrag(event: PointerEvent, from: Browser) {
  const start = { x: event.clientX, y: event.clientY };
  fileDrag.moved = false;
  /** The drag left the window and now goes to Windows. */
  let left = false;
  /** The drag is over: released, cancelled or handed to Windows. */
  let ended = false;
  /** The pointer returned into the window before Windows took over. */
  let returned = false;
  const move = (e: PointerEvent) => {
    if (!fileDrag.item) {
      if (Math.hypot(e.clientX - start.x, e.clientY - start.y) < 6 || !from.chosen.length) return;
      fileDrag.item = { from, entries: from.chosen };
      fileDrag.moved = true;
    }
    fileDrag.x = e.clientX;
    fileDrag.y = e.clientY;
    // Beyond the edge: the window can no longer see where it is going; from here Windows drags.
    const outside = e.clientX < 0 || e.clientY < 0 || e.clientX > innerWidth || e.clientY > innerHeight;
    const item = fileDrag.item;
    if (outside && !left && inApp && item.from.place) {
      left = true;
      returned = false;
      // If Windows took over, the drag is over for the window; otherwise it continues here.
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
    // The click that follows the release should not change the selection.
    setTimeout(() => (fileDrag.moved = false));
    if (e.type === 'pointerup' && !left && item?.from.place && over?.place && over.listing && over !== item.from) void send(item.from.place, item.entries, over.place, dir ?? over.listing.path);
  };
  const escape = (e: KeyboardEvent) => e.key === 'Escape' && stop(e);
  addEventListener('pointermove', move);
  addEventListener('pointerup', stop);
  addEventListener('pointercancel', stop);
  addEventListener('keydown', escape);
}
