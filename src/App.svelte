<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { getCurrentWebview } from '@tauri-apps/api/webview';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import {
    appInfo,
    backgroundUrl,
    detached,
    inApp,
    keyReadFile,
    loadSettings,
    onAdoptTab,
    onSettingsChanged,
    onVaultChanged,
    onVaultLocked,
    onVaultSync,
    restoreLoad,
    restoreSave,
    saveSettings,
    sessionCount,
    takeDetachedTab,
    vaultSetAutoLock,
    vaultStatus,
    vaultTouch,
    windowReady,
  } from './lib/backend';
  import { applySnapshot, applyStatus, forwardById, hostById, vault } from './lib/data.svelte';
  import FileDialogs from './lib/files/FileDialogs.svelte';
  import Transfers from './lib/files/Transfers.svelte';
  import { activeTransfers, barFor, columns, enqueue, initFiles, placeName, showTransfers, transfers, type Browser } from './lib/files.svelte';
  import { activeForwards, answerForward, forwards, initForwards } from './lib/forwards.svelte';
  import { t, tn } from './lib/i18n.svelte';
  import { leaves, rects } from './lib/layout';
  import LockScreen from './lib/LockScreen.svelte';
  import { look } from './lib/look.svelte';
  import NavRail from './lib/NavRail.svelte';
  import HostsPage from './lib/pages/HostsPage.svelte';
  import KeysPage from './lib/pages/KeysPage.svelte';
  import KitPage from './lib/pages/KitPage.svelte';
  import KnownHostsPage from './lib/pages/KnownHostsPage.svelte';
  import LogsPage from './lib/pages/LogsPage.svelte';
  import FilesPage from './lib/pages/FilesPage.svelte';
  import ForwardsPage from './lib/pages/ForwardsPage.svelte';
  import SettingsPage from './lib/pages/SettingsPage.svelte';
  import ProxmoxPage from './lib/pages/ProxmoxPage.svelte';
  import SyncPage from './lib/pages/SyncPage.svelte';
  import SnippetsPage from './lib/pages/SnippetsPage.svelte';
  import Palette from './lib/Palette.svelte';
  import ImportDialog from './lib/ImportDialog.svelte';
  import { importDropped, looksImportable } from './lib/import.svelte';
  import { importDroppedKeys } from './lib/quick.svelte';
  import QuickCreate from './lib/QuickCreate.svelte';
  import RestorePrompt from './lib/RestorePrompt.svelte';
  import { isScheme } from './lib/schemes';
  import SessionArea from './lib/SessionArea.svelte';
  import SessionPrompt from './lib/SessionPrompt.svelte';
  import SnippetDialogs from './lib/SnippetDialogs.svelte';
  import { hotkeyOf } from './lib/snippets';
  import { snippetForHotkey, snipUi, useSnippet } from './lib/snippets.svelte';
  import { loadShells } from './lib/local.svelte';
  import { activeTab, closePane, closeTab, focusPane, initSessions, liveCount, openLocal, openSaved, paneByKey, paneTitle, savedTab, splitPane, tabs, view } from './lib/sessions.svelte';
  import { settings, toast, ui, type Settings } from './lib/state.svelte';
  import { STATS_INTERVALS } from './lib/stats.svelte';
  import StatusBar from './lib/StatusBar.svelte';
  import { initSync } from './lib/sync.svelte';
  import { applyTheme, isHexColor } from './lib/theme';
  import UpdateDialog from './lib/UpdateDialog.svelte';
  import { initUpdates } from './lib/updates.svelte';
  import TitleBar from './lib/TitleBar.svelte';
  import type { KeyFile, SavedTab } from './lib/types';
  import Button from './lib/ui/Button.svelte';
  import Dialog from './lib/ui/Dialog.svelte';
  import Toasts from './lib/ui/Toasts.svelte';

  const systemQuery = matchMedia('(prefers-color-scheme: dark)');
  let systemDark = $state(systemQuery.matches);
  let closing = $state(false);
  /** Sitzungen, die beim Schließen getrennt würden. Im Hauptfenster zählen die aller Fenster. */
  let closingCount = $state(0);
  /** Transfers, die beim Schließen unterbrochen und zum Fortsetzen vorgemerkt würden. */
  let closingTransfers = $state(0);
  /** Port-Regeln, die beim Schließen enden würden. */
  let closingForwards = $state(0);
  /** Häkchen „Bei offenen Sitzungen nicht erneut fragen“. */
  let closingNever = $state(false);
  /** Über dem Fenster schweben gerade Dateien aus dem Explorer: als Schlüssel für den Tresor oder zum Hochladen. */
  let dropping = $state<'keys' | 'upload' | false>(false);
  /** Waagerechte Stelle des Mauszeigers beim Ablegen; auf der Seite „Dateien“ entscheidet sie über die Spalte. */
  let dropX = $state(0);
  /** Tabs vom letzten Mal, falls Glowport nicht ordentlich beendet wurde und die Rückfrage noch aussteht. */
  let crashed = $state<SavedTab[] | null>(null);
  /** Erst wenn feststeht, was mit den Tabs vom letzten Mal geschieht, wird der neue Stand festgehalten. */
  let tracking = $state(false);

  const inRange = (value: unknown, min: number, max: number): value is number => typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max;

  /** Übernimmt nur gültige Werte, damit eine beschädigte oder alte Datei das Programm nicht aus dem Tritt bringt. */
  function merge(s: Partial<Settings>) {
    if (s.mode === 'dark' || s.mode === 'light' || s.mode === 'system') settings.mode = s.mode;
    if (isHexColor(s.accent)) settings.accent = s.accent;
    if (s.lang === 'de' || s.lang === 'en') settings.lang = s.lang;
    if (s.hostView === 'cards' || s.hostView === 'list') settings.hostView = s.hostView;
    if ([0, 5, 15, 60].includes(s.autoLockMinutes as number)) settings.autoLockMinutes = s.autoLockMinutes as number;
    if (s.reconnect === 'notice' || s.reconnect === 'auto') settings.reconnect = s.reconnect;
    if (Number.isInteger(s.termFontSize) && inRange(s.termFontSize, 8, 32)) settings.termFontSize = s.termFontSize;
    if (Array.isArray(s.customSchemes)) settings.customSchemes = s.customSchemes.filter(isScheme);
    if (typeof s.termScheme === 'string') settings.termScheme = s.termScheme;
    if (typeof s.termFont === 'string' && s.termFont.length <= 80) settings.termFont = s.termFont;
    if (inRange(s.termLineHeight, 1, 1.6)) settings.termLineHeight = s.termLineHeight;
    if (typeof s.termLigatures === 'boolean') settings.termLigatures = s.termLigatures;
    if (s.termCursor === 'block' || s.termCursor === 'bar' || s.termCursor === 'underline') settings.termCursor = s.termCursor;
    if (typeof s.termCursorBlink === 'boolean') settings.termCursorBlink = s.termCursorBlink;
    if (inRange(s.termOpacity, 30, 100)) settings.termOpacity = s.termOpacity;
    if (typeof s.termBackground === 'string' || s.termBackground === null) settings.termBackground = s.termBackground;
    if (inRange(s.termBlur, 0, 24)) settings.termBlur = s.termBlur;
    if (s.windowEffect === 'none' || s.windowEffect === 'mica' || s.windowEffect === 'acrylic') settings.windowEffect = s.windowEffect;
    if (typeof s.restorePrompt === 'boolean') settings.restorePrompt = s.restorePrompt;
    if (typeof s.closePrompt === 'boolean') settings.closePrompt = s.closePrompt;
    if (STATS_INTERVALS.includes(s.statsInterval as number)) settings.statsInterval = s.statsInterval as number;
    if (typeof s.recordAuto === 'boolean') settings.recordAuto = s.recordAuto;
    if (typeof s.fileBar === 'boolean') settings.fileBar = s.fileBar;
    if (inRange(s.fileBarWidth, 220, 520)) settings.fileBarWidth = s.fileBarWidth;
    if (typeof s.fileFollow === 'boolean') settings.fileFollow = s.fileFollow;
    if (typeof s.fileHidden === 'boolean') settings.fileHidden = s.fileHidden;
    if (typeof s.fileEditor === 'boolean') settings.fileEditor = s.fileEditor;
    if (typeof s.fileEditorPath === 'string' && s.fileEditorPath.length <= 400) settings.fileEditorPath = s.fileEditorPath;
    if (Number.isInteger(s.transferParallel) && inRange(s.transferParallel, 1, 8)) settings.transferParallel = s.transferParallel;
    if (s.transferConflict === 'ask' || s.transferConflict === 'overwrite' || s.transferConflict === 'skip' || s.transferConflict === 'rename') settings.transferConflict = s.transferConflict;
    if (typeof s.downloadDir === 'string' && s.downloadDir.length <= 400) settings.downloadDir = s.downloadDir;
    if (typeof s.sideBar === 'boolean') settings.sideBar = s.sideBar;
    if (inRange(s.sideBarWidth, 240, 460)) settings.sideBarWidth = s.sideBarWidth;
    if (s.sideTab === 'info' || s.sideTab === 'snip') settings.sideTab = s.sideTab;
    if (typeof s.termSuggest === 'boolean') settings.termSuggest = s.termSuggest;
    if (typeof s.localShell === 'string' && s.localShell.length <= 80) settings.localShell = s.localShell;
    if (typeof s.updateCheck === 'boolean') settings.updateCheck = s.updateCheck;
    if (inRange(s.updateChecked, 0, Number.MAX_SAFE_INTEGER)) settings.updateChecked = s.updateChecked;
    if (typeof s.lastVersion === 'string' && s.lastVersion.length <= 40) settings.lastVersion = s.lastVersion;
    // Einstellungen einer Fassung, die sich ihre Version noch nicht merkte: Auch das ist ein Update.
    else if (typeof s.updateCheck === 'boolean') settings.lastVersion = 'älter';
  }

  // Der Kern erfährt höchstens alle 15 Sekunden von Eingaben; genauer muss die Auto-Sperre es nicht wissen.
  let lastTouch = 0;
  function activity() {
    if (vault.state !== 'open' || Date.now() - lastTouch < 15_000) return;
    lastTouch = Date.now();
    void vaultTouch();
  }

  /** Wechselt reihum durch Start-Tab und Sitzungen. */
  function cycle(step: number) {
    const order = [...(detached ? [] : ['home']), ...tabs.map((tab) => tab.key)];
    view.active = order[(order.indexOf(view.active) + step + order.length) % order.length];
  }

  /** Gibt die Tastatur dem Bereich, der in Pfeilrichtung am nächsten liegt. */
  function focusNeighbour(dx: number, dy: number) {
    const tab = activeTab();
    if (!tab) return;
    const all = rects(tab.layout);
    const from = all.get(tab.focus);
    if (!from) return;
    const centre = (r: { x: number; y: number; w: number; h: number }) => ({ x: r.x + r.w / 2, y: r.y + r.h / 2 });
    const here = centre(from);
    let best: { key: string; distance: number } | null = null;
    for (const [key, rect] of all) {
      const there = centre(rect);
      const along = (there.x - here.x) * dx + (there.y - here.y) * dy;
      if (key === tab.focus || along <= 0.001) continue;
      const distance = along + Math.abs((there.x - here.x) * dy + (there.y - here.y) * dx) * 2;
      if (!best || distance < best.distance) best = { key, distance };
    }
    if (best) focusPane(best.key);
  }

  function keydown(event: KeyboardEvent) {
    activity();
    const key = event.key.toLowerCase();
    const tab = activeTab();
    // Tastenkürzel eines Snippets: Es läuft im Bereich mit der Tastatur. Solange ein Dialog zu Snippets offen ist, ruht das.
    const hotkey = tab && !snipUi.asking && !snipUi.editing && !snipUi.naming && !ui.palette ? hotkeyOf(event) : null;
    const snippet = hotkey ? snippetForHotkey(hotkey) : undefined;
    if (snippet && tab) {
      event.preventDefault();
      return useSnippet(snippet, tab.focus, 'run');
    }
    if (event.ctrlKey && key === 'tab' && tabs.length) {
      event.preventDefault();
      return cycle(event.shiftKey ? -1 : 1);
    }
    if (event.ctrlKey && event.altKey && tab && key.startsWith('arrow')) {
      event.preventDefault();
      return focusNeighbour(key === 'arrowleft' ? -1 : key === 'arrowright' ? 1 : 0, key === 'arrowup' ? -1 : key === 'arrowdown' ? 1 : 0);
    }
    if (event.ctrlKey && event.shiftKey && !event.altKey && tab) {
      const split = leaves(tab.layout).length > 1;
      // Strg+Umschalt+W schließt den Bereich mit der Tastatur; ist er der einzige, den Tab.
      const action = { w: () => (split ? closePane(tab.focus) : closeTab(tab.key)), d: () => splitPane(tab.focus, 'right'), e: () => splitPane(tab.focus, 'bottom'), m: () => split && (tab.multi = !tab.multi) }[key];
      if (action) {
        event.preventDefault();
        return void action();
      }
    }
    // Strg+Umschalt+T öffnet ein lokales Terminal mit der eingestellten Shell. Solange nur die Sperre zu sehen ist, nicht.
    if (event.ctrlKey && event.shiftKey && !event.altKey && key === 't' && (vault.state === 'open' || tabs.length)) {
      event.preventDefault();
      return openLocal();
    }
    // Strg+K öffnet die Suche, außer im Terminal: Dort gehört es der Sitzung (nano, bash). Strg+Umschalt+K geht überall.
    const inTerminal = event.target instanceof Element && !!event.target.closest('.xterm');
    if ((event.ctrlKey || event.metaKey) && !event.altKey && key === 'k' && (event.shiftKey || !inTerminal) && (vault.state === 'open' || tabs.length)) {
      event.preventDefault();
      ui.palette = !ui.palette;
    }
  }

  const quit = () => void getCurrentWindow().destroy();

  /** Schließt nach der Rückfrage. Das Häkchen muss gespeichert sein, bevor das Fenster verschwindet. */
  async function confirmQuit() {
    if (closingNever && settings.closePrompt) {
      settings.closePrompt = false;
      await saveSettings($state.snapshot(settings)).catch((e) => console.error('Einstellungen nicht speicherbar', e));
    }
    quit();
  }

  /** Schlüsseldateien nimmt der Start-Tab an, solange der Tresor offen ist. Auf der Seite „Dateien“ und in Sitzungen bedeutet Ablegen Hochladen. */
  const acceptsKeys = () => !detached && vault.state === 'open' && view.active === 'home' && ui.page !== 'files';

  /** Der Ordner, in den abgelegte Dateien hochgeladen würden: die Spalte unter dem Mauszeiger oder die Dateileiste des Bereichs mit der Tastatur. */
  function uploadTarget(): Browser | null {
    const usable = (browser: Browser) => !!browser.place && browser.place.kind !== 'local' && !!browser.listing?.writable;
    if (view.active === 'home') {
      if (detached || vault.state !== 'open' || ui.page !== 'files') return null;
      const [near, far] = dropX < innerWidth / 2 ? [columns.left, columns.right] : [columns.right, columns.left];
      return usable(near) ? near : usable(far) ? far : null;
    }
    const focus = activeTab()?.focus;
    const bar = settings.fileBar && focus ? barFor(focus) : null;
    return bar && usable(bar) ? bar : null;
  }
  /** Wie der Ort eines Blicks heißt; bei der Dateileiste ist es der Name des Bereichs. */
  const targetName = (browser: Browser) => (browser.place?.kind === 'session' ? paneTitle(paneByKey(activeTab()?.focus)!) : placeName(browser.place));
  const dropKind = () => (acceptsKeys() ? 'keys' : uploadTarget() ? 'upload' : false);

  /** Lädt abgelegte Dateien und Ordner dorthin hoch. */
  function uploadDropped(paths: string[]) {
    const target = uploadTarget();
    dropping = false;
    if (!target?.place || !target.listing || !paths.length) return;
    void enqueue({ kind: 'local' }, paths, target.place, target.listing.path);
  }

  /** Liest abgelegte Dateien und importiert, was davon ein Schlüssel ist. Unlesbares zählt als „kein Schlüssel“. */
  async function dropped(read: Promise<KeyFile>[]) {
    dropping = false;
    if (!acceptsKeys() || !read.length) return;
    const files = await Promise.all(read.map((file) => file.catch((): KeyFile => ({ path: '', text: '' }))));
    await importDroppedKeys(files);
  }

  /** Dasselbe in der Vorschau im Browser, wo das Ablegen als gewöhnliches Ereignis der Seite ankommt. */
  function browserDrop(event: DragEvent) {
    event.preventDefault();
    if (inApp) return;
    dropX = event.clientX;
    if (!acceptsKeys()) return uploadDropped([...(event.dataTransfer?.files ?? [])].map((file) => `C:\\Users\\ich\\Desktop\\${file.name}`));
    const importable = [...(event.dataTransfer?.files ?? [])].find((file) => looksImportable(file.name));
    if (importable) return ((dropping = false), void importDropped(importable.name));
    void dropped([...(event.dataTransfer?.files ?? [])].map(async (file) => ({ path: file.name, text: await file.text() })));
  }

  /** Holt den Stand des Tresors neu, nachdem er sich geändert hat (auch durch ein anderes Fenster). */
  const syncVault = () =>
    void vaultStatus()
      .then(applyStatus)
      .catch((e) => console.error('Tresor-Zustand nicht lesbar', e));

  function restore(open: boolean) {
    const saved = crashed ?? [];
    crashed = null;
    tracking = true;
    if (!open) return;
    const missing = saved.filter((tab, i) => !openSaved(tab, i === 0)).length;
    if (missing) toast(t('restore.missing', { n: missing }), 'err');
  }

  onMount(() => {
    const onSystem = (e: MediaQueryListEvent) => (systemDark = e.matches);
    systemQuery.addEventListener('change', onSystem);
    const settingsLoaded = loadSettings()
      .then((s) => s && merge(s))
      .catch((e) => console.error('Einstellungen nicht lesbar', e))
      .finally(() => {
        ui.ready = true;
        // Nach Updates sieht nur das Hauptfenster nach, und erst, wenn die Einstellungen sagen, ob es das soll.
        if (!detached) void initUpdates();
      });
    const vaultLoaded = vaultStatus()
      .then(applyStatus)
      .catch((e) => console.error('Tresor-Zustand nicht lesbar', e))
      // Der Tab eines eigenen Fensters nennt Hosts aus dem Tresor; geöffnet wird er, sobald dessen Stand da ist.
      .then(() => (detached ? takeDetachedTab() : null))
      .then((tab) => {
        if (!detached) return;
        if (tab) openSaved(tab);
        tracking = true;
      })
      .catch((e) => console.error('Tab nicht übernommen', e));
    if (!detached) {
      restoreLoad()
        .then((saved) => (saved?.length ? (crashed = saved) : (tracking = true)))
        .catch(() => (tracking = true));
    }
    const infoLoaded = appInfo()
      .then((info) => info?.effect && (document.documentElement.dataset.effect = info.effect))
      .catch(() => {});
    void loadShells();
    // Das Fenster ist bis hierher unsichtbar. Zu sehen ist es erst, wenn Sprache, Farbmodus und der Stand des
    // Tresors feststehen und die Seite dazu gezeichnet ist: kein leeres Fenster, kein Umspringen von dunkel auf hell.
    void Promise.allSettled([settingsLoaded, vaultLoaded, infoLoaded]).then(async () => {
      await tick();
      // Zwei Bilder später ist gezeichnet, was eben entstanden ist. Die Frist greift, wo ein Fenster vorher keine zeichnet.
      await new Promise<void>((done) => {
        const late = setTimeout(done, 300);
        requestAnimationFrame(() => requestAnimationFrame(() => (clearTimeout(late), done())));
      });
      void windowReady();
    });

    const stops = [
      initSessions(),
      initFiles(),
      initForwards(),
      onVaultChanged(applySnapshot),
      initSync(),
      onVaultSync(syncVault),
      onSettingsChanged(merge),
      onAdoptTab((tab) => void openSaved(tab)),
      onVaultLocked(() => {
        applyStatus({ state: 'locked' });
        if (!detached) toast(t('lock.autolocked', { n: settings.autoLockMinutes }));
      }),
    ];
    // Dateien aus dem Explorer: Im Programm meldet Tauri sie mit ihrem Pfad, gelesen werden sie im Kern.
    if (inApp) {
      const stop = getCurrentWebview().onDragDropEvent((event) => {
        const payload = event.payload;
        if (payload.type !== 'leave') dropX = payload.position.x / devicePixelRatio;
        if (payload.type !== 'drop') dropping = payload.type !== 'leave' && dropKind();
        else if (acceptsKeys() && payload.paths.some(looksImportable)) ((dropping = false), void importDropped(payload.paths.find(looksImportable)!));
        else if (acceptsKeys()) void dropped(payload.paths.map((path) => keyReadFile(path)));
        else uploadDropped(payload.paths);
      });
      stops.push(() => void stop.then((off) => off()));
    }
    // Beim Schließen mit laufenden Sitzungen erst nachfragen. Das Hauptfenster nimmt alle anderen Fenster mit.
    if (inApp) {
      const stop = getCurrentWindow().onCloseRequested(async (event) => {
        const count = detached ? liveCount() : await sessionCount().catch(liveCount);
        // Laufende Transfers gehören dem Programm; nur das Hauptfenster nimmt sie beim Schließen mit.
        closingTransfers = detached ? 0 : activeTransfers().length;
        // Port-Regeln gehören ebenfalls dem Programm und enden mit dem Hauptfenster.
        closingForwards = detached ? 0 : activeForwards().length;
        // Offene Sitzungen allein fragen nur, solange der Nutzer das nicht abgeschaltet hat.
        if ((count > 0 && settings.closePrompt) || closingTransfers > 0 || closingForwards > 0) {
          event.preventDefault();
          closingCount = count;
          closingNever = false;
          closing = true;
        }
      });
      stops.push(() => void stop.then((off) => off()));
    }
    return () => {
      systemQuery.removeEventListener('change', onSystem);
      for (const stop of stops) stop();
    };
  });

  $effect(() => {
    applyTheme(settings.mode, settings.accent, systemDark);
    look.dark = document.documentElement.dataset.mode !== 'light';
    document.documentElement.lang = settings.lang;
  });

  $effect(() => {
    const snapshot = $state.snapshot(settings);
    if (!ui.ready) return;
    // Kurz warten: Die Farbauswahl feuert beim Ziehen viele Änderungen.
    const timer = setTimeout(() => saveSettings(snapshot).catch((e) => console.error('Einstellungen nicht speicherbar', e)), 250);
    return () => clearTimeout(timer);
  });

  // Die Auto-Sperre läuft im Kern; er braucht die Einstellung nach jedem Entsperren und bei jeder Änderung.
  $effect(() => {
    if (vault.state === 'open' && ui.ready) void vaultSetAutoLock(settings.autoLockMinutes);
  });

  // Die Rückfrage nach einem Abbruch braucht den offenen Tresor (die Tabs nennen Hosts daraus). Ist sie abgeschaltet, wird nie wiederhergestellt.
  $effect(() => {
    if (crashed && ui.ready && !settings.restorePrompt) restore(false);
  });

  // Das Hintergrundbild: In den Einstellungen steht nur, welches es ist; hier entsteht die Adresse zum Anzeigen.
  $effect(() => {
    const saved = settings.termBackground;
    let current = true;
    if (!saved) look.background = null;
    else
      backgroundUrl(saved)
        .then((url) => current && (look.background = url))
        .catch(() => current && (look.background = null));
    return () => {
      current = false;
      if (look.background?.startsWith('blob:')) URL.revokeObjectURL(look.background);
    };
  });

  // Hält fest, welche Tabs offen sind, damit sie sich nach einem Abbruch anbieten lassen. Jedes Fenster meldet seine.
  $effect(() => {
    const open = tabs.map(savedTab);
    if (!tracking) return;
    const timer = setTimeout(() => restoreSave(open).catch((e) => console.error('Offene Tabs nicht speicherbar', e)), 400);
    return () => clearTimeout(timer);
  });

  // Transfers, die beim letzten Mal unterbrochen wurden, stehen angehalten in der Liste. Darauf weist das Hauptfenster
  // einmal hin, sobald der Tresor offen ist; vorher ließen sie sich nicht fortsetzen.
  let hinted = false;
  $effect(() => {
    if (hinted || detached || vault.state !== 'open' || !transfers.loaded) return;
    hinted = true;
    const waiting = transfers.list.filter((x) => x.resumed && x.state === 'paused').length;
    if (!waiting) return;
    toast(t('transfers.interrupted', { n: waiting }));
    showTransfers(true);
  });

  // Ein eigenes Fenster hat ohne Tabs nichts mehr zu zeigen.
  let hadTabs = false;
  $effect(() => {
    if (tabs.length) hadTabs = true;
    else if (detached && hadTabs) inApp ? quit() : window.close();
  });

  const home = $derived(view.active === 'home' && !detached);
  const closeText = $derived(t(detached ? 'close.text.window' : 'close.text', { n: closingCount }));
</script>

<!-- Das Kontextmenü von WebView2 („Zurück“, „Neu laden“) gibt es nirgends; im Terminal kopiert oder fügt der Rechtsklick ein. -->
<svelte:window
  onpointerdown={activity}
  onkeydown={keydown}
  oncontextmenu={(event) => event.preventDefault()}
  ondragover={(event) => {
    event.preventDefault();
    if (!inApp) (dropX = event.clientX), (dropping = dropKind());
  }}
  ondragleave={(event) => !inApp && !event.relatedTarget && (dropping = false)}
  ondrop={browserDrop}
/>

<div class="win" class:sess-on={!home}>
  <TitleBar />

  <!-- Der Start-Tab bleibt eingehängt, wenn eine Sitzung vorn ist: So bleiben Gruppe, Auswahl und Editor erhalten. -->
  {#if detached}
    <!-- kein Start-Tab -->
  {:else if vault.state === 'open'}
    <div class="home-view" class:off={!home}>
      <NavRail />
      <main class="page">
        {#if ui.page === 'hosts'}
          <HostsPage />
        {:else if ui.page === 'keys'}
          <KeysPage />
        {:else if ui.page === 'fwd'}
          <ForwardsPage />
        {:else if ui.page === 'snip'}
          <SnippetsPage />
        {:else if ui.page === 'files'}
          <FilesPage />
        {:else if ui.page === 'known'}
          <KnownHostsPage />
        {:else if ui.page === 'logs'}
          <LogsPage />
        {:else if ui.page === 'pve'}
          <ProxmoxPage />
        {:else if ui.page === 'sync'}
          <SyncPage />
        {:else if ui.page === 'settings'}
          <SettingsPage />
        {:else}
          <KitPage />
        {/if}
      </main>
    </div>
  {:else if vault.state !== 'loading' && home}
    <LockScreen />
  {/if}

  <!-- Sitzungen laufen weiter, auch wenn der Tresor gesperrt ist. Jede behält ihr Terminal, sichtbar sind nur die des vorderen Tabs. -->
  <SessionArea hidden={home} />

  <StatusBar />
</div>

{#if ui.palette}<Palette />{/if}
<QuickCreate />
{#if !detached}<ImportDialog /><UpdateDialog />{/if}
<FileDialogs />
<SnippetDialogs />
<!-- Eine Port-Regel, die beim Einschalten erst eine Antwort braucht: dieselbe Rückfrage wie bei einem Terminal. -->
{#if forwards.asking}
  {@const rule = forwardById(forwards.asking.rule)}
  <SessionPrompt prompt={forwards.asking.prompt} name={hostById(rule?.host ?? null)?.name ?? rule?.name ?? ''} onanswer={answerForward} />
{/if}
{#if transfers.panel && !(home && ui.page === 'files' && vault.state === 'open')}<Transfers />{/if}
{#if dropping === 'keys'}
  <div class="dropzone"><div><b>{t('drop.keys')}</b><span>{t('drop.keys.sub')}</span></div></div>
{:else if dropping === 'upload'}
  {@const target = uploadTarget()}
  {#if target}<div class="dropzone"><div><b>{t('drop.upload')}</b><span>{t('drop.upload.sub', { to: targetName(target) })} <i class="mono">{target.path}</i></span></div></div>{/if}
{/if}
{#if crashed && settings.restorePrompt && vault.state === 'open'}
  <RestorePrompt saved={crashed} onrestore={() => restore(true)} ondiscard={() => restore(false)} />
{/if}

<Dialog bind:open={closing} title={t(detached ? 'close.title.window' : 'close.title')}>
  {#if closingCount > 0}<p>{closeText}</p>{/if}
  {#if closingTransfers > 0}<p>{t('close.transfers', { n: closingTransfers })}</p>{/if}
  {#if closingForwards > 0}<p>{tn('close.forwards', closingForwards)}</p>{/if}
  {#if closingCount > 0 && settings.closePrompt}
    <label class="check"><input type="checkbox" bind:checked={closingNever} />{t('close.never')}</label>
    {#if closingNever}<p class="fld-h">{t('close.never.hint')}</p>{/if}
  {/if}
  {#snippet actions()}
    <Button onclick={() => (closing = false)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={confirmQuit}>{t('close.confirm')}</Button>
  {/snippet}
</Dialog>
<Toasts />
