import { Channel, invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { readText, writeText } from '@tauri-apps/plugin-clipboard-manager';
import { fake, fakeSession } from './backend-fake';
import { fakeFiles } from './backend-fake-files';
import { fakeManage } from './backend-fake-manage';
import { fakeProxmox } from './backend-fake-proxmox';
import { fakeSync } from './backend-fake-sync';
import { fakeForwards, fakeRun, fakeStats } from './backend-fake-tools';
import type { Settings } from './state.svelte';
import type { ChmodRequest, DiffEntry, DockerContainer, FileContent, Listed, Listing, ManageAbilities, ManageDone, Place, ProcessSample, ProxmoxInput, ProxmoxOverview, ProxmoxProbe, SearchHit, ServiceUnit, Transfer, TransferRequest, Watched, FtpPlace } from './types';
import type { ForwardInput, ForwardState, RunResult, SnippetInput, StatsSample } from './types';
import type { ExportRequest, ImportDraft, ImportFound, ImportOptions, ImportReport, ImportSource, UpdateInfo, UpdateProgress } from './types';
import type { Agent, Answer, Changed, DeployResult, GroupInput, HostInput, IdentityInput, KeyFile, KeyGenerate, KeyImport, KeyInfo, Recording, SavedTab, SessionEvent, SessionPhase, Snapshot, Status, Target, WorkspaceInput } from './types';
import type { LocalShell, SerialPortInfo } from './types';
import type { SyncAccount, SyncCandidate, SyncDevice, SyncInviteCode, SyncLogin, SyncNotice, SyncRegister, SyncServerInfo, SyncState, VaultRole } from './types';

/**
 * Einzige Stelle, an der die Oberfläche mit dem Rust-Kern spricht.
 * Im Browser (Entwicklung, Vorschau) antwortet stattdessen ein Ersatz ohne jede Verschlüsselung.
 */
export const inApp = isTauri();

export interface AppInfo {
  /** „Glowport“ oder „Glowport Dev“. */
  name: string;
  version: string;
  dataDir: string;
  /** Durchscheinendes Fenster, mit dem das Programm gestartet ist: „mica“, „acrylic“ oder leer. */
  effect: string;
  /** Liegen die Daten neben dem Programm (portable Fassung)? */
  portable: boolean;
  /** Kann diese Fassung nach Updates suchen? Nur dann zeigt die Oberfläche etwas dazu. */
  updates: boolean;
  /** Name dieses Rechners, als Vorschlag für den Namen des Geräts beim Abgleich. */
  device?: string;
}

/** Name dieses Fensters im Programm. Das Hauptfenster heißt `main`, Fenster aus herausgezogenen Tabs `tab-…`. */
export const windowLabel = inApp ? getCurrentWindow().label : 'main';
/** Ein Fenster, das aus einem herausgezogenen Tab entstand: Es zeigt nur Sitzungen, ohne Start-Tab. */
export const detached = inApp ? (window as { __GLOWPORT_DETACHED__?: boolean }).__GLOWPORT_DETACHED__ === true : new URLSearchParams(location.search).has('detached');

/** Meldet sich für ein Ereignis des Kerns an und liefert eine Funktion zum Abmelden. Im Browser gibt es keine. */
function on<T>(event: string, handler: (payload: T) => void): () => void {
  if (!inApp) return () => {};
  const stop = listen<T>(event, (e) => handler(e.payload));
  return () => void stop.then((off) => off());
}

const LS_SETTINGS = 'glowport.settings';

export async function loadSettings(): Promise<Partial<Settings> | null> {
  if (inApp) return invoke<Partial<Settings> | null>('settings_load');
  const raw = localStorage.getItem(LS_SETTINGS);
  return raw ? (JSON.parse(raw) as Partial<Settings>) : null;
}

export async function saveSettings(s: Settings): Promise<void> {
  if (inApp) return invoke('settings_save', { settings: s });
  localStorage.setItem(LS_SETTINGS, JSON.stringify(s));
}

export async function appInfo(): Promise<AppInfo | null> {
  return inApp ? invoke<AppInfo>('app_info') : null;
}

/** Öffnet die Seite des Projekts auf GitHub im Browser. */
export const aboutOpen = (): Promise<void> => (inApp ? invoke('about_open') : (window.open('https://github.com/nihmir08/Glowport', '_blank'), Promise.resolve()));

/**
 * Meldet dem Kern, dass die Oberfläche dieses Fensters steht. Bis dahin hält er das Fenster unsichtbar, damit
 * niemand ein leeres Fenster sieht, das sich erst aufbaut.
 */
export const windowReady = (): Promise<void> => (inApp ? invoke('window_ready') : Promise.resolve());

export const vaultStatus = (): Promise<Status> => (inApp ? invoke('vault_status') : fake.status());
export const vaultCreate = (password: string): Promise<Status> => (inApp ? invoke('vault_create', { password }) : fake.create(password));
export const vaultUnlock = (password: string): Promise<Status> => (inApp ? invoke('vault_unlock', { password }) : fake.unlock(password));
export const vaultLock = (): Promise<Status> => (inApp ? invoke('vault_lock') : fake.lock());
/** `logoutOthers`: nur mit Abgleich; meldet alle anderen Geräte des Kontos ab. */
export const vaultChangePassword = (old: string, next: string, logoutOthers = false): Promise<void> =>
  inApp ? invoke('vault_change_password', { old, new: next, logoutOthers }) : fake.changePassword(old, next);
/** Liefert den gewählten Pfad oder null, wenn der Dialog abgebrochen wurde. */
export const vaultBackup = (fileName: string): Promise<string | null> => (inApp ? invoke('vault_backup', { fileName }) : fake.backup(fileName));
/**
 * Spielt eine Sicherung ein, solange es auf diesem PC noch keinen Tresor gibt: Der Nutzer wählt die Datei, sie wird
 * zum Tresor. Danach ist er gesperrt und verlangt das Master-Passwort der Sicherung. null, wenn abgebrochen.
 */
export const vaultRestore = (): Promise<Status | null> => (inApp ? invoke('vault_restore') : fake.restore());
/**
 * Meldet dieses Gerät beim Sync-Server ab (nur bei offenem, verbundenem Tresor) und löscht den Tresor auf diesem PC.
 * Danach startet Glowport neu. Ist der Server nicht erreichbar, scheitert es mit `offline`; `force` löscht trotzdem.
 */
export const vaultWipe = (force = false): Promise<void> => (inApp ? invoke('vault_wipe', { force }) : fake.wipe(force));
export const vaultSetStartUnlock = (enabled: boolean): Promise<Status> => (inApp ? invoke('vault_set_start_unlock', { enabled }) : fake.setStartUnlock(enabled));
export const vaultSetAutoLock = (minutes: number): Promise<void> => (inApp ? invoke('vault_set_auto_lock', { minutes }) : Promise.resolve());
export const vaultTouch = (): Promise<void> => (inApp ? invoke('vault_touch') : Promise.resolve());

// Beim Anlegen nennt `vault` in der Eingabe den Tresor, in den der Eintrag kommt. Der Kern bekommt ihn als eigene Angabe.
export const hostSave = (host: HostInput): Promise<Changed> => (inApp ? invoke('host_save', { host, vault: host.vault }) : fake.hostSave(host));
/** Verschiebt einen Host in einen anderen Tresor. `carry`: Identität und Schlüssel kommen als Kopie mit. */
export const hostMove = (id: string, vault: string, carry: boolean): Promise<Changed> => (inApp ? invoke('host_move', { id, vault, carry }) : fake.hostMove(id, vault));
export const hostDuplicate = (id: string, name: string): Promise<Changed> => (inApp ? invoke('host_duplicate', { id, name }) : fake.hostDuplicate(id, name));
export const hostDelete = (id: string): Promise<Changed> => (inApp ? invoke('host_delete', { id }) : fake.hostDelete(id));
export const groupSave = (group: GroupInput): Promise<Changed> => (inApp ? invoke('group_save', { group, vault: group.vault }) : fake.groupSave(group));
export const groupDelete = (id: string, withContents: boolean): Promise<Changed> =>
  inApp ? invoke('group_delete', { id, withContents }) : fake.groupDelete(id, withContents);

/** Der Kern meldet, wenn die Auto-Sperre zugeschlagen hat. Liefert eine Funktion zum Abmelden. */
export const onVaultLocked = (handler: () => void) => on<void>('vault-locked', handler);
/** Zustand oder Inhalt des Tresors haben sich geändert, womöglich in einem anderen Fenster. Zeit, den Stand neu zu holen. */
export const onVaultSync = (handler: () => void) => on<void>('vault-sync', handler);
/** Ein anderes Fenster hat die Einstellungen geändert. */
export const onSettingsChanged = (handler: (settings: Partial<Settings>) => void) =>
  on<{ window: string; settings: Partial<Settings> }>('settings-changed', (e) => e.window !== windowLabel && handler(e.settings));
/** Ein anderes Fenster gibt diesem einen Tab samt laufender Sitzungen. */
export const onAdoptTab = (handler: (tab: SavedTab) => void) => on<{ window: string; tab: SavedTab }>('adopt-tab', (e) => e.window === windowLabel && handler(e.tab));

export const knownHostDelete = (id: string): Promise<Changed> => (inApp ? invoke('known_host_delete', { id }) : fake.knownHostDelete(id));

export const keyGenerate = (key: KeyGenerate): Promise<Changed> => (inApp ? invoke('key_generate', { key, vault: key.vault }) : fake.keyGenerate(key));
/** Öffnet den Dateidialog und liest die gewählte Schlüsseldatei. null, wenn abgebrochen. */
export const keyPickFile = (): Promise<KeyFile | null> => (inApp ? invoke('key_pick_file') : fake.keyPickFile());
/** Liest eine Schlüsseldatei an einem bekannten Ort: ins Fenster gezogen oder im Feld „Schlüsseldatei“ eingetragen. */
export const keyReadFile = (path: string): Promise<KeyFile> => (inApp ? invoke('key_read_file', { path }) : fake.keyPickFile().then((file) => ({ ...file!, path })));
/** Sagt, was in einem Schlüsseltext steckt, ohne ihn zu speichern. */
export const keyInspect = (text: string, passphrase?: string): Promise<KeyInfo> => (inApp ? invoke('key_inspect', { text, passphrase }) : fake.keyInspect(text, passphrase));
export const keyImport = (key: KeyImport): Promise<Changed> => (inApp ? invoke('key_import', { key, vault: key.vault }) : fake.keyImport(key));
export const keyRename = (id: string, name: string): Promise<Changed> => (inApp ? invoke('key_rename', { id, name }) : fake.keyRename(id, name));
/** Hinterlegt ein Benutzer-Zertifikat am Schlüssel; `null` entfernt es. */
export const keySetCertificate = (id: string, text: string | null): Promise<Changed> => (inApp ? invoke('key_set_certificate', { id, text }) : fake.keySetCertificate(id, text));
export const keyDelete = (id: string): Promise<Changed> => (inApp ? invoke('key_delete', { id }) : fake.keyDelete(id));
/** Schreibt den privaten Schlüssel in eine Datei, die der Nutzer wählt. Liefert den Pfad oder null. */
export const keyExport = (id: string, passphrase: string | null): Promise<string | null> => (inApp ? invoke('key_export', { id, passphrase }) : fake.keyExport(id));
/**
 * Trägt den öffentlichen Schlüssel auf den Hosts in `authorized_keys` ein; `onResult` meldet jeden fertigen Host.
 * Mit `adopt` melden sich die Hosts, bei denen es geklappt hat, künftig mit diesem Schlüssel an.
 */
export function keyDeploy(id: string, hosts: string[], adopt: boolean, onResult: (result: DeployResult) => void): Promise<void> {
  if (!inApp) return fake.keyDeploy(id, hosts, adopt, onResult);
  const results = new Channel<DeployResult>();
  results.onmessage = onResult;
  return invoke('key_deploy', { id, hosts, adopt, results });
}
export const identitySave = (identity: IdentityInput): Promise<Changed> => (inApp ? invoke('identity_save', { identity, vault: identity.vault }) : fake.identitySave(identity));
export const identityDelete = (id: string): Promise<Changed> => (inApp ? invoke('identity_delete', { id }) : fake.identityDelete(id));
/** Vertraut einer Zertifizierungsstelle für Server; `key` ist ihr öffentlicher Schlüssel als Zeile. */
export const authorityAdd = (name: string, pattern: string, key: string): Promise<Changed> => (inApp ? invoke('authority_add', { name, pattern, key }) : fake.authorityAdd(name, pattern, key));
export const authorityDelete = (id: string): Promise<Changed> => (inApp ? invoke('authority_delete', { id }) : fake.authorityDelete(id));
export const agentList = (): Promise<Agent[]> => (inApp ? invoke('agent_list') : fake.agentList());
/** Öffnet den Dateidialog für eine Schlüsseldatei. null, wenn abgebrochen. */
export const pickKeyFile = (): Promise<string | null> => (inApp ? invoke('pick_key_file') : Promise.resolve('C:\\Users\\ich\\.ssh\\id_ed25519'));

/**
 * Öffnet eine Sitzung und liefert ihre Nummer. Die Terminal-Ausgabe kommt als rohe Bytes über `onOutput`,
 * alles andere über `onSessionEvent`.
 */
export function sessionOpen(target: Target, columns: number, rows: number, onOutput: (bytes: Uint8Array) => void): Promise<number> {
  if (!inApp) return fakeSession.open(target, onOutput);
  const output = new Channel<ArrayBuffer | number[]>();
  output.onmessage = (data) => onOutput(data instanceof ArrayBuffer ? new Uint8Array(data) : Uint8Array.from(data));
  return invoke('session_open', { target, columns, rows, output });
}
/** Mosh: die SSH-Verbindung neben dem Terminal neu aufbauen, mit Rückfragen, falls nötig. */
export const sessionRelink = (id: number): Promise<void> => (inApp ? invoke('session_relink', { id }) : Promise.resolve());
export const sessionWrite = (id: number, text: string): Promise<void> => (inApp ? invoke('session_write', { id, text }) : fakeSession.write(id, text));
export const sessionResize = (id: number, columns: number, rows: number): Promise<void> => (inApp ? invoke('session_resize', { id, columns, rows }) : Promise.resolve());
/** Bestätigt gezeichnete Bytes; daran hängt die Flusskontrolle des Kerns. */
export const sessionAck = (id: number, bytes: number): Promise<void> => (inApp ? invoke('session_ack', { id, bytes }) : Promise.resolve());
export const sessionAnswer = (id: number, answer: Answer): Promise<void> => (inApp ? invoke('session_answer', { id, answer }) : fakeSession.answer(id, answer));
export const sessionClose = (id: number): Promise<void> => (inApp ? invoke('session_close', { id }) : fakeSession.close(id));
/** Anzahl laufender Sitzungen in allen Fenstern. */
export const sessionCount = (): Promise<number> => (inApp ? invoke('session_count') : Promise.resolve(0));
/** Hält Sitzungen an, deren Tab das Fenster wechselt: Ihre Ausgabe wird gesammelt, bis das neue Fenster sie aufnimmt. */
export const sessionHold = (ids: number[]): Promise<void> => (inApp ? invoke('session_hold', { ids }) : Promise.resolve());
/** Nimmt eine laufende Sitzung in diesem Fenster auf und liefert ihren Zustand. */
export function sessionAttach(id: number, columns: number, rows: number, onOutput: (bytes: Uint8Array) => void): Promise<{ phase: SessionPhase; mosh?: boolean }> {
  const output = new Channel<ArrayBuffer | number[]>();
  output.onmessage = (data) => onOutput(data instanceof ArrayBuffer ? new Uint8Array(data) : Uint8Array.from(data));
  return invoke('session_attach', { id, columns, rows, output });
}
/** Schaltet den Mitschnitt einer Sitzung. `name` und `address` stehen später in der Liste der Mitschnitte. */
export const sessionRecord = (id: number, on: boolean, name: string, address: string): Promise<void> =>
  inApp ? invoke('session_record', { id, on, name, address }) : fakeSession.record(id, on, name, address);

export const logList = (): Promise<Recording[]> => (inApp ? invoke('log_list') : fake.logList());
/** Der Text eines Mitschnitts, ohne Steuerzeichen. */
export const logRead = (id: string): Promise<string> => (inApp ? invoke('log_read', { id }) : fake.logRead(id));
/** Gibt einem fertigen Mitschnitt einen eigenen Namen (leer = wieder der Name des Hosts). Die Kennung ändert sich dabei. */
export const logRename = (id: string, title: string): Promise<{ id: string; list: Recording[] }> => (inApp ? invoke('log_rename', { id, title }) : fake.logRename(id, title));
export const logDelete = (id: string): Promise<Recording[]> => (inApp ? invoke('log_delete', { id }) : fake.logDelete(id));
/** Zeigt die Datei eines Mitschnitts im Explorer; ohne Angabe den Ordner aller Mitschnitte. */
export const logReveal = (id?: string): Promise<void> => (inApp ? invoke('log_reveal', { id }) : Promise.resolve());

export const workspaceSave = (workspace: WorkspaceInput): Promise<Changed> => (inApp ? invoke('workspace_save', { workspace }) : fake.workspaceSave(workspace));
export const workspaceDelete = (id: string): Promise<Changed> => (inApp ? invoke('workspace_delete', { id }) : fake.workspaceDelete(id));

/** Die Tabs, die beim letzten Mal offen waren, falls Glowport nicht ordentlich beendet wurde; sonst null. */
export const restoreLoad = (): Promise<SavedTab[] | null> => (inApp ? invoke('restore_load') : fake.restoreLoad());
/** Merkt sich die offenen Tabs für den Fall eines Abbruchs. */
export const restoreSave = (tabs: SavedTab[]): Promise<void> => (inApp ? invoke('restore_save', { tabs }) : fake.restoreSave(tabs));

/** Der Tab, mit dem dieses Fenster als eigenes Fenster geöffnet wurde, sonst null. Liefert ihn nur einmal. */
export async function takeDetachedTab(): Promise<SavedTab | null> {
  if (inApp) return invoke<SavedTab | null>('window_payload');
  try {
    const raw = new URLSearchParams(location.search).get('detached');
    return raw ? (JSON.parse(raw) as SavedTab) : null;
  } catch {
    return null;
  }
}
/**
 * Verlegt einen Tab in ein anderes Fenster. `sessions` nennt seine laufenden, zuvor angehaltenen Sitzungen.
 * Ziel ist das Fenster `to`, sonst mit `atCursor` das Fenster unter dem Mauszeiger, sonst ein neues.
 */
export async function windowMove(tab: SavedTab, sessions: number[], target: { to?: string; atCursor?: boolean } = {}): Promise<void> {
  if (inApp) return invoke('window_move', { tab, sessions, to: target.to ?? null, atCursor: target.atCursor ?? false });
  window.open(`${location.pathname}?detached=${encodeURIComponent(JSON.stringify(tab))}`, '_blank', 'popup,width=1000,height=680');
}

/** Lässt den Nutzer eine Textdatei wählen und liefert Namen und Inhalt; null, wenn abgebrochen. */
export function pickTextFile(accept: string): Promise<{ name: string; text: string } | null> {
  if (inApp) return invoke('pick_text_file', { accept });
  return new Promise((resolve) => {
    const input = Object.assign(document.createElement('input'), { type: 'file', accept });
    input.onchange = async () => {
      const file = input.files?.[0];
      resolve(file ? { name: file.name, text: await file.text() } : null);
    };
    input.oncancel = () => resolve(null);
    input.click();
  });
}
/**
 * Lässt den Nutzer ein Bild für den Hintergrund des Terminals wählen; null, wenn abgebrochen.
 * Im Programm kommt der Name der Kopie im Datenordner zurück, in der Vorschau gleich eine Adresse zum Anzeigen.
 */
export const pickBackground = (): Promise<string | null> => (inApp ? invoke('pick_background') : fake.pickBackground());
/** Macht aus dem gespeicherten Hintergrundbild eine Adresse, die sich anzeigen lässt. */
export async function backgroundUrl(saved: string): Promise<string> {
  if (!inApp) return saved;
  const bytes = await invoke<ArrayBuffer>('background_read', { name: saved });
  return URL.createObjectURL(new Blob([bytes]));
}

/** Ereignisse der Sitzungen dieses Fensters. Jede Sitzung gehört einem Fenster; die der anderen kommen hier nicht an. */
export function onSessionEvent(handler: (event: SessionEvent) => void): () => void {
  if (!inApp) return fakeSession.listen(handler);
  return on<SessionEvent & { window: string }>('session', (event) => event.window === windowLabel && handler(event));
}

/** Der Kern meldet, wenn sich der Tresor ohne Zutun der Oberfläche geändert hat (Host-Schlüssel, System, Passwort). */
export const onVaultChanged = (handler: (data: Snapshot) => void) => (inApp ? on<Snapshot>('vault-changed', handler) : fakeSession.onChanged(handler));

export const clipboardRead = (): Promise<string> => (inApp ? readText() : navigator.clipboard.readText());
export const clipboardWrite = (text: string): Promise<void> => (inApp ? writeText(text) : navigator.clipboard.writeText(text));

// ---------- Lokales Terminal, serielle Ports ----------

/** Die Shells dieses PCs, die sich als lokales Terminal öffnen lassen. */
export const localShells = (): Promise<LocalShell[]> => (inApp ? invoke('local_shells') : fakeSession.shells());
/** Die seriellen Ports, die es gerade gibt. Ein USB-Adapter taucht erst auf, wenn er steckt. */
export const serialPorts = (): Promise<SerialPortInfo[]> => (inApp ? invoke('serial_ports') : fakeSession.ports());

// ---------- Dateien ----------

/**
 * Baut für die Seite „Dateien“ eine Verbindung zu einem Host auf, mit denselben Rückfragen wie ein Terminal.
 * Liefert die Nummer, unter der die Ereignisse kommen und `sessionAnswer` die Antworten annimmt.
 */
export const fsConnect = (id: string): Promise<number> => (inApp ? invoke('fs_connect', { id }) : fakeSession.fsConnect(id));
/** Dasselbe für einen FTP-Server aus der Schnellverbindung. */
export const ftpConnect = (place: FtpPlace): Promise<number> => (inApp ? invoke('ftp_connect', { place }) : fakeSession.ftpConnect(place));
/** Der Ordner, in dem man an diesem Ort beginnt: das Heimatverzeichnis. */
export const fsHome = (place: Place): Promise<string> => (inApp ? invoke('fs_home', { place }) : fakeFiles.home(place));
export const fsList = (place: Place, path: string): Promise<Listing> => (inApp ? invoke('fs_list', { place, path }) : fakeFiles.list(place, path));
export const fsMkdir = (place: Place, dir: string, name: string): Promise<void> => (inApp ? invoke('fs_mkdir', { place, dir, name }) : fakeFiles.mkdir(place, dir, name));
export const fsRename = (place: Place, path: string, name: string): Promise<void> => (inApp ? invoke('fs_rename', { place, path, name }) : fakeFiles.rename(place, path, name));
export const fsRemove = (place: Place, paths: string[]): Promise<void> => (inApp ? invoke('fs_remove', { place, paths }) : fakeFiles.remove(place, paths));
/** Ändert Rechte und Besitzer, auf Wunsch samt allem darunter. */
export const fsChmod = (place: Place, request: ChmodRequest): Promise<void> => (inApp ? invoke('fs_chmod', { place, request }) : fakeFiles.chmod(place, request));
/** Liest eine Datei zum Ansehen oder Bearbeiten: Text, Bild oder die Auskunft, dass sie keines von beiden ist. */
export async function fsRead(place: Place, path: string): Promise<FileContent> {
  if (!inApp) return fakeFiles.read(place, path);
  const content = await invoke<Exclude<FileContent, { kind: 'image' }> | { kind: 'image'; mime: string }>('fs_read', { place, path });
  if (content.kind !== 'image') return content;
  // Bilder kommen als rohe Bytes; daraus entsteht eine Adresse zum Anzeigen, die der Betrachter wieder freigibt.
  const bytes = await invoke<ArrayBuffer>('fs_read_bytes', { place, path });
  return { kind: 'image', url: URL.createObjectURL(new Blob([bytes], { type: content.mime })) };
}
export const fsWrite = (place: Place, path: string, text: string): Promise<void> => (inApp ? invoke('fs_write', { place, path, text }) : fakeFiles.write(place, path, text));
/** Sucht am Ort unterhalb von `dir` nach Namen oder im Inhalt; `onHit` meldet jeden Treffer. */
export function fsSearch(place: Place, dir: string, query: string, content: boolean, onHit: (hit: SearchHit) => void): Promise<void> {
  if (!inApp) return fakeFiles.search(place, dir, query, content, onHit);
  const hits = new Channel<SearchHit>();
  hits.onmessage = onHit;
  return invoke('fs_search', { place, dir, query, content, hits });
}
/** Vergleicht zwei Ordner samt Unterordnern. */
export const fsCompare = (left: Place, leftPath: string, right: Place, rightPath: string): Promise<DiffEntry[]> =>
  inApp ? invoke('fs_compare', { left, leftPath, right, rightPath }) : fakeFiles.compare(left, leftPath, right, rightPath);

/** Der Ordner, in dem Downloads landen, wenn in den Einstellungen keiner gewählt ist. */
export const fsDownloads = (): Promise<string> => (inApp ? invoke('fs_downloads') : Promise.resolve('C:\\Users\\ich\\Downloads'));
/** Reiht Dateien und Ordner in die Warteschlange ein. */
export const transferStart = (request: TransferRequest): Promise<number[]> => (inApp ? invoke('transfer_start', { request }) : fakeFiles.transferStart(request));
export const transferList = (): Promise<Transfer[]> => (inApp ? invoke('transfer_list') : fakeFiles.transferList());
/** Hält an, setzt fort, bricht ab oder versucht es erneut. Ohne Nummern gilt es für alle Transfers. */
export const transferControl = (ids: number[] | null, action: 'pause' | 'resume' | 'cancel' | 'retry'): Promise<void> =>
  inApp ? invoke('transfer_control', { ids, action }) : fakeFiles.transferControl(ids, action);
/** Nimmt alles Fertige, Abgebrochene und Gescheiterte aus der Liste. */
export const transferClear = (): Promise<void> => (inApp ? invoke('transfer_clear') : fakeFiles.transferClear());
/** Der Kern meldet den Stand aller Transfers, solange sich etwas tut. Transfers gehören dem Programm, nicht einem Fenster. */
export const onTransfers = (handler: (list: Transfer[]) => void) => (inApp ? on<Transfer[]>('transfers', handler) : fakeFiles.onTransfers(handler));

/** Öffnet eine Datei im eigenen Programm des Nutzers und lädt sie nach jedem Speichern wieder hoch. */
export const watchOpen = (place: Place, path: string, program: string): Promise<void> => (inApp ? invoke('watch_open', { place, path, program: program || null }) : fakeFiles.watchOpen(place, path));
/** In welchem Ordner die Shell einer Sitzung gerade steht; null, wenn der Server das nicht verrät. */
export const sessionCwd = (id: number): Promise<string | null> => (inApp ? invoke('session_cwd', { id }) : Promise.resolve(null));
export const watchStop = (id: number): Promise<void> => (inApp ? invoke('watch_stop', { id }) : fakeFiles.watchStop(id));
export const watchList = (): Promise<Watched[]> => (inApp ? invoke('watch_list') : fakeFiles.watchList());
export const onWatched = (handler: (list: Watched[]) => void) => (inApp ? on<Watched[]>('watched', handler) : fakeFiles.onWatched(handler));
/** Lässt den Nutzer ein Programm zum Bearbeiten wählen; null, wenn abgebrochen. */
export const pickProgram = (): Promise<string | null> => (inApp ? invoke('pick_program') : Promise.resolve('C:\Program Files\Microsoft VS Code\Code.exe'));
/** Lässt den Nutzer einen Ordner wählen; null, wenn abgebrochen. */
export const pickFolder = (): Promise<string | null> => (inApp ? invoke('pick_folder') : Promise.resolve('D:\Backups'));
/** Holt Dateien eines Servers in einen Arbeitsordner, um sie danach aus dem Fenster zu ziehen. */
export const dragStage = (place: Place, paths: string[]): Promise<{ ids: number[]; paths: string[] }> => invoke('drag_stage', { place, paths });
/** Beginnt das Ziehen von Dateien dieses PCs aus dem Fenster heraus, solange die Maustaste gedrückt ist. Liefert, ob abgelegt wurde. */
export const dragOut = (paths: string[]): Promise<boolean> => invoke('drag_out', { paths });
/** Lässt den Nutzer Dateien dieses PCs zum Hochladen wählen; null, wenn abgebrochen. */
export const pickUploads = (): Promise<string[] | null> => (inApp ? invoke('pick_uploads') : Promise.resolve(['C:\Users\ich\Desktop\Rechnung-0931.pdf', 'C:\Users\ich\Desktop\server-liste.xlsx']));
/** Gleicht zwei Ordner an: Jede Zeile nennt den Pfad unterhalb der Ordner und die Richtung. Gelöscht wird dabei nichts. */
export const syncStart = (left: Place, leftPath: string, right: Place, rightPath: string, items: { rel: string; toRight: boolean }[]): Promise<number[]> =>
  inApp ? invoke('sync_start', { left, leftPath, right, rightPath, items }) : fakeFiles.syncStart(left, leftPath, right, rightPath, items);

// ---------- Port-Regeln ----------

export const forwardSave = (rule: ForwardInput): Promise<Changed> => (inApp ? invoke('forward_save', { rule, vault: rule.vault }) : fake.forwardSave(rule));
export const forwardDelete = (id: string): Promise<Changed> => (inApp ? invoke('forward_delete', { id }) : fake.forwardDelete(id));
/**
 * Schaltet eine Regel ein. Liefert die Nummer der Verbindung: Unter ihr kommen Rückfragen wie bei einer Sitzung
 * (`onSessionEvent`), und `sessionAnswer` nimmt die Antworten an. Wie es der Regel geht, meldet `onForwards`.
 */
export const forwardStart = (id: string): Promise<number> => (inApp ? invoke('forward_start', { id }) : fakeForwards.start(id));
export const forwardStop = (id: string): Promise<void> => (inApp ? invoke('forward_stop', { id }) : fakeForwards.stop(id));
/** Der Stand aller eingeschalteten Regeln. */
export const forwardList = (): Promise<ForwardState[]> => (inApp ? invoke('forward_list') : fakeForwards.list());
/** Der Kern meldet den Stand der Regeln, sobald sich etwas tut. Regeln gehören dem Programm, nicht einem Fenster. */
export const onForwards = (handler: (list: ForwardState[]) => void) => (inApp ? on<ForwardState[]>('forwards', handler) : fakeForwards.onChange(handler));

// ---------- Snippets ----------

export const snippetSave = (snippet: SnippetInput): Promise<Changed> => (inApp ? invoke('snippet_save', { snippet, vault: snippet.vault }) : fake.snippetSave(snippet));
export const snippetDelete = (id: string): Promise<Changed> => (inApp ? invoke('snippet_delete', { id }) : fake.snippetDelete(id));
/**
 * Führt einen Befehl auf mehreren Hosts aus, ohne Terminal. `onResult` meldet jeden Host, sobald er beginnt und
 * sobald er fertig ist. `run` ist eine frei gewählte Nummer, mit der sich der Lauf abbrechen lässt.
 */
export function snippetRun(run: number, command: string, hosts: string[], onResult: (result: RunResult) => void): Promise<void> {
  if (!inApp) return fakeRun.run(run, command, hosts, onResult);
  const results = new Channel<RunResult>();
  results.onmessage = onResult;
  return invoke('snippet_run', { run, command, hosts, results });
}
export const snippetCancel = (run: number): Promise<void> => (inApp ? invoke('snippet_cancel', { run }) : fakeRun.cancel(run));

// ---------- Server-Info ----------

/** Misst den Server einer Sitzung; null, wenn er die Zahlen nicht hergibt (kein Linux). */
export const sessionStats = (id: number): Promise<StatsSample | null> => (inApp ? invoke('session_stats', { id }) : fakeStats.sample(id));

// ---------- Import und Export ----------

/** Sieht nach, welche anderen Programme auf diesem PC Verbindungen gespeichert haben, und zählt sie. Gespeichert wird dabei nichts. */
export const importScan = (): Promise<ImportFound[]> => (inApp ? invoke('import_scan') : fake.importScan());
/** Liest eine Quelle, die `importScan` gefunden hat, und liefert, was sich daraus übernehmen ließe. Gespeichert wird nichts. */
export const importRead = (source: ImportSource): Promise<ImportDraft> => (inApp ? invoke('import_read', { source }) : fake.importRead(source));
/**
 * Lässt den Nutzer eine Datei wählen und liest sie. Mit `source` steht fest, was sie ist; ohne erkennt Glowport das
 * Format am Inhalt. null, wenn abgebrochen.
 */
export const importPick = (source: ImportSource | null): Promise<ImportDraft | null> => (inApp ? invoke('import_pick', { source }) : fake.importRead(source ?? 'csv'));
/** Liest eine Datei an einem bekannten Ort, etwa eine ins Fenster gezogene. */
export const importFile = (path: string): Promise<ImportDraft> => (inApp ? invoke('import_file', { path }) : fake.importRead('csv'));
/** Übernimmt die gewählten Einträge eines Entwurfs in den Tresor. */
export const importApply = (token: number, options: ImportOptions): Promise<Changed & { report: ImportReport }> =>
  inApp ? invoke('import_apply', { token, options }) : fake.importApply(token, options);
/** Wirft einen Entwurf weg, samt allem, was der Kern dafür gelesen hat. */
export const importDiscard = (token: number): Promise<void> => (inApp ? invoke('import_discard', { token }) : fake.importDiscard(token));
/** Schreibt Hosts und mehr in eine Datei, die der Nutzer wählt. Passwörter und private Schlüssel sind nie dabei. Liefert den Pfad oder null. */
export const exportData = (request: ExportRequest, fileName: string): Promise<string | null> => (inApp ? invoke('export_data', { request, fileName }) : fake.exportData(request));

// ---------- Updates ----------

const FAKE_UPDATE: UpdateInfo = {
  version: '1.1.0',
  notes: 'Neu: lokales Terminal (PowerShell, WSL, Git Bash) als Tab.\nSchneller: große Ordner in der Dateileiste.\nBehoben: Die Suche im Terminal behält ihre Eingabe beim Wechsel des Tabs.',
  date: Date.UTC(2026, 10, 20),
};

/** Fragt nach einer neueren Version; null, wenn diese die neueste ist. */
export const updateCheck = (): Promise<UpdateInfo | null> => (inApp ? invoke('update_check') : new Promise((ok) => setTimeout(() => ok(FAKE_UPDATE), 600)));
/** Lädt die neue Version, prüft ihre Signatur und installiert sie. Danach startet Glowport neu. */
export function updateInstall(onProgress: (progress: UpdateProgress) => void): Promise<void> {
  if (!inApp) {
    return new Promise((ok) => {
      const total = 11_400_000;
      let done = 0;
      const tick = setInterval(() => {
        done = Math.min(total, done + 620_000);
        onProgress({ done, total });
        if (done === total) (clearInterval(tick), ok());
      }, 120);
    });
  }
  const progress = new Channel<UpdateProgress>();
  progress.onmessage = onProgress;
  return invoke('update_install', { progress });
}

// ── Abgleich und geteilte Tresore (docs/sync.md) ───────────────────────────────────────────────────────────

export const syncState = (): Promise<SyncState> => (inApp ? invoke('sync_state') : fakeSync.state());
/** Jeder Wechsel im Abgleich: gleicht ab, abgeglichen, ohne Verbindung, neue Einladung … */
export const onSyncState = (handler: (state: SyncState) => void) => (inApp ? on<SyncState>('sync-state', handler) : fakeSync.onState(handler));
/** Fragt eine Adresse, ob dort ein Sync-Server von Glowport antwortet. */
export const syncProbe = (server: string): Promise<SyncServerInfo> => (inApp ? invoke('sync_probe', { server }) : fakeSync.probe(server));
/** Macht den Tresor dieses Geräts zu einem Konto auf dem Server. */
export const syncRegister = (request: SyncRegister): Promise<SyncState> => (inApp ? invoke('sync_register', { request }) : fakeSync.register(request));
/** Verbindet den Tresor dieses Geräts mit einem Konto, das es schon gibt. */
export const syncConnect = (request: SyncLogin): Promise<SyncState> => (inApp ? invoke('sync_connect', { request }) : fakeSync.connect(request));
/** Erster Start ohne Tresor: legt den Tresor eines bestehenden Kontos auf diesem Gerät an. */
export const syncLogin = (request: SyncLogin): Promise<Status> => (inApp ? invoke('sync_login', { request }) : fake.syncLogin(request));
export const syncNow = (): Promise<SyncState> => (inApp ? invoke('sync_now') : fakeSync.now());
export const syncUnlink = (): Promise<SyncState> => (inApp ? invoke('sync_unlink') : fakeSync.unlink());
/** Der Server hat einen älteren Stand: den Stand dieses Geräts wieder hochladen. */
export const syncResync = (vault: string): Promise<SyncState> => (inApp ? invoke('sync_resync', { vault }) : fakeSync.resync(vault));
export const syncDevices = (): Promise<SyncDevice[]> => (inApp ? invoke('sync_devices') : fakeSync.devices());
export const syncDeviceRename = (id: string, name: string): Promise<SyncDevice[]> => (inApp ? invoke('sync_device_rename', { id, name }) : fakeSync.deviceRename(id, name));
export const syncDeviceRemove = (id: string): Promise<SyncDevice[]> => (inApp ? invoke('sync_device_remove', { id }) : fakeSync.deviceRemove(id));
export const syncNotices = (): Promise<SyncNotice[]> => (inApp ? invoke('sync_notices') : fakeSync.notices());
export const syncNoticesClear = (): Promise<void> => (inApp ? invoke('sync_notices_clear') : fakeSync.noticesClear());

/** Legt einen geteilten Tresor an und liefert seine Kennung. Die Tresore selbst kommen mit dem nächsten Stand des Tresors. */
export const sharedCreate = (name: string): Promise<string> => (inApp ? invoke('shared_create', { name }) : fakeSync.create(name));
export const sharedRename = (vault: string, name: string): Promise<void> => (inApp ? invoke('shared_rename', { vault, name }) : fakeSync.rename(vault, name));
/** Sucht ein Konto zum Einladen und liefert dessen Sicherheitscode. */
export const sharedLookup = (username: string): Promise<SyncCandidate> => (inApp ? invoke('shared_lookup', { username }) : fakeSync.lookup(username));
export const sharedInvite = (vault: string, account: string, role: VaultRole): Promise<void> => (inApp ? invoke('shared_invite', { vault, account, role }) : fakeSync.invite(vault, account, role));
export const sharedSetRole = (vault: string, account: string, role: VaultRole): Promise<void> => (inApp ? invoke('shared_set_role', { vault, account, role }) : fakeSync.setRole(vault, account, role));
export const sharedRemove = (vault: string, account: string): Promise<void> => (inApp ? invoke('shared_remove', { vault, account }) : fakeSync.remove(vault, account));
export const sharedTransfer = (vault: string, account: string): Promise<void> => (inApp ? invoke('shared_transfer', { vault, account }) : fakeSync.transfer(vault, account));
export const sharedLeave = (vault: string): Promise<void> => (inApp ? invoke('shared_leave', { vault }) : fakeSync.leave(vault));
export const sharedDelete = (vault: string): Promise<void> => (inApp ? invoke('shared_delete', { vault }) : fakeSync.remove_vault(vault));
export const invitationAccept = (vault: string): Promise<void> => (inApp ? invoke('invitation_accept', { vault }) : fakeSync.accept(vault));
export const invitationDecline = (vault: string): Promise<SyncState> => (inApp ? invoke('invitation_decline', { vault }) : fakeSync.decline(vault));

// Verwaltung des Servers; nur für das Konto, das ihn verwaltet.
export const adminInvites = (): Promise<SyncInviteCode[]> => (inApp ? invoke('admin_invites') : fakeSync.adminInvites());
export const adminInviteCreate = (): Promise<SyncInviteCode[]> => (inApp ? invoke('admin_invite_create') : fakeSync.adminInviteCreate());
export const adminInviteRevoke = (code: string): Promise<SyncInviteCode[]> => (inApp ? invoke('admin_invite_revoke', { code }) : fakeSync.adminInviteRevoke(code));
export const adminAccounts = (): Promise<SyncAccount[]> => (inApp ? invoke('admin_accounts') : fakeSync.adminAccounts());
export const adminAccountDisable = (id: string, disabled: boolean): Promise<SyncAccount[]> => (inApp ? invoke('admin_account_disable', { id, disabled }) : fakeSync.adminAccountDisable(id, disabled));
export const adminAccountDelete = (id: string): Promise<SyncAccount[]> => (inApp ? invoke('admin_account_delete', { id }) : fakeSync.adminAccountDelete(id));

// ── Verwaltung in der Seitenleiste: Docker, Dienste, Prozesse (docs/verwaltung.md) ─────────────────────
// Alles läuft über die Verbindung der Sitzung. Aktionen, für die die Rechte fehlen, versucht der Kern mit
// `sudo -n`; will sudo ein Passwort, kommt `{ outcome: 'password', command }` zurück. Andere Fehler: `manage_failed`
// mit der Meldung des Servers.

export const manageProbe = (session: number): Promise<ManageAbilities> => (inApp ? invoke('manage_probe', { session }) : fakeManage.probe(session));
export const dockerList = (session: number): Promise<Listed<DockerContainer[]>> => (inApp ? invoke('docker_list', { session }) : fakeManage.dockerList(session));
export const dockerAction = (session: number, container: string, action: 'start' | 'stop' | 'restart'): Promise<ManageDone> =>
  inApp ? invoke('docker_action', { session, container, action }) : fakeManage.dockerAction(session, container, action);
/** Was in einen neuen Tab getippt wird, damit dort die Logs mitlaufen oder eine Shell im Container aufgeht. */
export const dockerLine = (container: string, kind: 'logs' | 'shell', sudo: boolean): Promise<string> => (inApp ? invoke('docker_line', { container, kind, sudo }) : fakeManage.dockerLine(container, kind, sudo));
export const serviceList = (session: number): Promise<Listed<ServiceUnit[]>> => (inApp ? invoke('service_list', { session }) : fakeManage.serviceList(session));
export const serviceAction = (session: number, unit: string, action: 'start' | 'stop' | 'restart' | 'enable' | 'disable'): Promise<ManageDone> =>
  inApp ? invoke('service_action', { session, unit, action }) : fakeManage.serviceAction(session, unit, action);
/** Zustand und letzte Meldungen eines Dienstes, wie systemd sie ausgibt. */
export const serviceStatus = (session: number, unit: string): Promise<string> => (inApp ? invoke('service_status', { session, unit }) : fakeManage.serviceStatus(session, unit));
/** Was in einen neuen Tab getippt wird, damit dort das Journal des Dienstes mitläuft. */
export const serviceLine = (unit: string, sudo: boolean): Promise<string> => (inApp ? invoke('service_line', { unit, sudo }) : fakeManage.serviceLine(unit, sudo));
/** `null`: Der Server gibt die Liste nicht her. */
export const processList = (session: number): Promise<ProcessSample | null> => (inApp ? invoke('process_list', { session }) : fakeManage.processList(session));
export const processKill = (session: number, pid: number, signal: 'term' | 'kill'): Promise<ManageDone> =>
  inApp ? invoke('process_kill', { session, pid, signal }) : fakeManage.processKill(session, pid, signal);

// ── Proxmox (docs/verwaltung.md) ───────────────────────────────────────────────────────────────────────
// Die Verbindungen stehen im Stand des Tresors (`Snapshot.proxmox`), der Host kennt seine Maschine (`Host.proxmox`).

/** Prüft Adresse, Zertifikat und Token, ohne etwas zu speichern. Zwei Schritte, siehe `ProxmoxProbe`. */
export const proxmoxProbe = (input: ProxmoxInput): Promise<ProxmoxProbe> => (inApp ? invoke('proxmox_probe', { input }) : fakeProxmox.probe(input));
export const proxmoxSave = (input: ProxmoxInput): Promise<Changed> => (inApp ? invoke('proxmox_save', { input }) : fakeProxmox.save(input));
/** Entfernt die Verbindung. Die Hosts bleiben und verlieren nur ihre Verknüpfung. */
export const proxmoxDelete = (id: string): Promise<Changed> => (inApp ? invoke('proxmox_delete', { id }) : fakeProxmox.remove(id));
/** Knoten und Maschinen einer Verbindung. Dabei zieht der Kern verknüpfte Hosts nach (Adresse, Name). `fresh`: jede Maschine neu fragen. */
export const proxmoxOverview = (id: string, fresh = false): Promise<ProxmoxOverview> => (inApp ? invoke('proxmox_overview', { id, fresh }) : fakeProxmox.overview(id));
/** Starten, herunterfahren, hart stoppen, neu starten. Kehrt zurück, wenn Proxmox den Auftrag ausgeführt hat. */
export const proxmoxAction = (id: string, guest: { node: string; vmid: number; kind: 'qemu' | 'lxc' }, action: 'start' | 'shutdown' | 'stop' | 'reboot'): Promise<void> =>
  inApp ? invoke('proxmox_action', { id, guest, action }) : fakeProxmox.action(id, guest, action);
/** Legt aus den gewählten Maschinen Hosts an und verknüpft sie. */
export const proxmoxImport = (id: string, picks: { node: string; vmid: number; kind: 'qemu' | 'lxc' }[], group: string | null): Promise<Changed> =>
  inApp ? invoke('proxmox_import', { id, picks, group }) : fakeProxmox.import(id, picks, group);
/** Löst die Verknüpfung eines Hosts mit seiner Maschine. Der Host bleibt, wie er ist. */
export const proxmoxUnlink = (host: string): Promise<Changed> => (inApp ? invoke('proxmox_unlink', { host }) : fakeProxmox.unlink(host));
/** Nimmt der Host an seinem Port Verbindungen an? Ein einzelner Versuch; über Sprung-Server oder Proxy gilt er als erreichbar. */
export const proxmoxReachable = (host: string): Promise<boolean> => (inApp ? invoke('proxmox_reachable', { host }) : fakeProxmox.reachable(host));
