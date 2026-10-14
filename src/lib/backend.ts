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
 * The only place where the interface talks to the Rust core.
 * In the browser (development, preview) a stand-in without any encryption answers instead.
 */
export const inApp = isTauri();

export interface AppInfo {
  /** “Glowport” or “Glowport Dev”. */
  name: string;
  version: string;
  dataDir: string;
  /** Translucent window the program was started with: “mica”, “acrylic” or empty. */
  effect: string;
  /** Does the data live next to the program (portable version)? */
  portable: boolean;
  /** Can this version look for updates? Only then does the interface show anything about it. */
  updates: boolean;
  /** Name of this computer, as a suggestion for the device name when syncing. */
  device?: string;
}

/** Name of this window in the program. The main window is called `main`, windows from tabs pulled out `tab-…`. */
export const windowLabel = inApp ? getCurrentWindow().label : 'main';
/** A window created from a tab pulled out: it only shows sessions, without a start tab. */
export const detached = inApp ? (window as { __GLOWPORT_DETACHED__?: boolean }).__GLOWPORT_DETACHED__ === true : new URLSearchParams(location.search).has('detached');

/** Subscribes to an event of the core and returns a function to unsubscribe. In the browser there are none. */
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

/** Opens the project's page on GitHub in the browser. */
export const aboutOpen = (): Promise<void> => (inApp ? invoke('about_open') : (window.open('https://github.com/nihmir08/Glowport', '_blank'), Promise.resolve()));

/**
 * Tells the core that this window's interface is ready. Until then it keeps the window invisible, so
 * nobody sees an empty window that is still building up.
 */
export const windowReady = (): Promise<void> => (inApp ? invoke('window_ready') : Promise.resolve());

export const vaultStatus = (): Promise<Status> => (inApp ? invoke('vault_status') : fake.status());
export const vaultCreate = (password: string): Promise<Status> => (inApp ? invoke('vault_create', { password }) : fake.create(password));
export const vaultUnlock = (password: string): Promise<Status> => (inApp ? invoke('vault_unlock', { password }) : fake.unlock(password));
export const vaultLock = (): Promise<Status> => (inApp ? invoke('vault_lock') : fake.lock());
/** `logoutOthers`: only with syncing; signs out all other devices of the account. */
export const vaultChangePassword = (old: string, next: string, logoutOthers = false): Promise<void> =>
  inApp ? invoke('vault_change_password', { old, new: next, logoutOthers }) : fake.changePassword(old, next);
/** Returns the chosen path or null if the dialog was cancelled. */
export const vaultBackup = (fileName: string): Promise<string | null> => (inApp ? invoke('vault_backup', { fileName }) : fake.backup(fileName));
/**
 * Restores a backup as long as there is no vault on this PC yet: the user chooses the file, it becomes
 * the vault. Afterwards it is locked and asks for the backup's master password. null if cancelled.
 */
export const vaultRestore = (): Promise<Status | null> => (inApp ? invoke('vault_restore') : fake.restore());
/**
 * Signs this device out at the sync server (only with an open, linked vault) and deletes the vault on this PC.
 * Then Glowport restarts. If the server cannot be reached, it fails with `offline`; `force` deletes anyway.
 */
export const vaultWipe = (force = false): Promise<void> => (inApp ? invoke('vault_wipe', { force }) : fake.wipe(force));
export const vaultSetStartUnlock = (enabled: boolean): Promise<Status> => (inApp ? invoke('vault_set_start_unlock', { enabled }) : fake.setStartUnlock(enabled));
export const vaultSetAutoLock = (minutes: number): Promise<void> => (inApp ? invoke('vault_set_auto_lock', { minutes }) : Promise.resolve());
export const vaultTouch = (): Promise<void> => (inApp ? invoke('vault_touch') : Promise.resolve());

// When creating, `vault` in the input names the vault the entry goes into. The core gets it as a separate value.
export const hostSave = (host: HostInput): Promise<Changed> => (inApp ? invoke('host_save', { host, vault: host.vault }) : fake.hostSave(host));
/** Moves a host into another vault. `carry`: identity and key come along as a copy. */
export const hostMove = (id: string, vault: string, carry: boolean): Promise<Changed> => (inApp ? invoke('host_move', { id, vault, carry }) : fake.hostMove(id, vault));
export const hostDuplicate = (id: string, name: string): Promise<Changed> => (inApp ? invoke('host_duplicate', { id, name }) : fake.hostDuplicate(id, name));
export const hostDelete = (id: string): Promise<Changed> => (inApp ? invoke('host_delete', { id }) : fake.hostDelete(id));
export const groupSave = (group: GroupInput): Promise<Changed> => (inApp ? invoke('group_save', { group, vault: group.vault }) : fake.groupSave(group));
export const groupDelete = (id: string, withContents: boolean): Promise<Changed> =>
  inApp ? invoke('group_delete', { id, withContents }) : fake.groupDelete(id, withContents);

/** The core reports when the auto-lock struck. Returns a function to unsubscribe. */
export const onVaultLocked = (handler: () => void) => on<void>('vault-locked', handler);
/** State or content of the vault changed, possibly in another window. Time to fetch the state anew. */
export const onVaultSync = (handler: () => void) => on<void>('vault-sync', handler);
/** Another window changed the settings. */
export const onSettingsChanged = (handler: (settings: Partial<Settings>) => void) =>
  on<{ window: string; settings: Partial<Settings> }>('settings-changed', (e) => e.window !== windowLabel && handler(e.settings));
/** Another window gives this one a tab together with running sessions. */
export const onAdoptTab = (handler: (tab: SavedTab) => void) => on<{ window: string; tab: SavedTab }>('adopt-tab', (e) => e.window === windowLabel && handler(e.tab));

export const knownHostDelete = (id: string): Promise<Changed> => (inApp ? invoke('known_host_delete', { id }) : fake.knownHostDelete(id));

export const keyGenerate = (key: KeyGenerate): Promise<Changed> => (inApp ? invoke('key_generate', { key, vault: key.vault }) : fake.keyGenerate(key));
/** Opens the file dialog and reads the chosen key file. null if cancelled. */
export const keyPickFile = (): Promise<KeyFile | null> => (inApp ? invoke('key_pick_file') : fake.keyPickFile());
/** Reads a key file at a known location: dragged into the window or entered in the “Key file” field. */
export const keyReadFile = (path: string): Promise<KeyFile> => (inApp ? invoke('key_read_file', { path }) : fake.keyPickFile().then((file) => ({ ...file!, path })));
/** Says what is inside a key text without saving it. */
export const keyInspect = (text: string, passphrase?: string): Promise<KeyInfo> => (inApp ? invoke('key_inspect', { text, passphrase }) : fake.keyInspect(text, passphrase));
export const keyImport = (key: KeyImport): Promise<Changed> => (inApp ? invoke('key_import', { key, vault: key.vault }) : fake.keyImport(key));
export const keyRename = (id: string, name: string): Promise<Changed> => (inApp ? invoke('key_rename', { id, name }) : fake.keyRename(id, name));
/** Stores a user certificate with the key; `null` removes it. */
export const keySetCertificate = (id: string, text: string | null): Promise<Changed> => (inApp ? invoke('key_set_certificate', { id, text }) : fake.keySetCertificate(id, text));
export const keyDelete = (id: string): Promise<Changed> => (inApp ? invoke('key_delete', { id }) : fake.keyDelete(id));
/** Writes the private key into a file the user chooses. Returns the path or null. */
export const keyExport = (id: string, passphrase: string | null): Promise<string | null> => (inApp ? invoke('key_export', { id, passphrase }) : fake.keyExport(id));
/**
 * Adds the public key to `authorized_keys` on the hosts; `onResult` reports every finished host.
 * With `adopt` the hosts where it worked sign in with this key from now on.
 */
export function keyDeploy(id: string, hosts: string[], adopt: boolean, onResult: (result: DeployResult) => void): Promise<void> {
  if (!inApp) return fake.keyDeploy(id, hosts, adopt, onResult);
  const results = new Channel<DeployResult>();
  results.onmessage = onResult;
  return invoke('key_deploy', { id, hosts, adopt, results });
}
export const identitySave = (identity: IdentityInput): Promise<Changed> => (inApp ? invoke('identity_save', { identity, vault: identity.vault }) : fake.identitySave(identity));
export const identityDelete = (id: string): Promise<Changed> => (inApp ? invoke('identity_delete', { id }) : fake.identityDelete(id));
/** Trusts a certificate authority for servers; `key` is its public key as a line. */
export const authorityAdd = (name: string, pattern: string, key: string): Promise<Changed> => (inApp ? invoke('authority_add', { name, pattern, key }) : fake.authorityAdd(name, pattern, key));
export const authorityDelete = (id: string): Promise<Changed> => (inApp ? invoke('authority_delete', { id }) : fake.authorityDelete(id));
export const agentList = (): Promise<Agent[]> => (inApp ? invoke('agent_list') : fake.agentList());
/** Opens the file dialog for a key file. null if cancelled. */
export const pickKeyFile = (): Promise<string | null> => (inApp ? invoke('pick_key_file') : Promise.resolve('C:\\Users\\ich\\.ssh\\id_ed25519'));

/**
 * Opens a session and returns its number. The terminal output comes as raw bytes through `onOutput`,
 * everything else through `onSessionEvent`.
 */
export function sessionOpen(target: Target, columns: number, rows: number, onOutput: (bytes: Uint8Array) => void): Promise<number> {
  if (!inApp) return fakeSession.open(target, onOutput);
  const output = new Channel<ArrayBuffer | number[]>();
  output.onmessage = (data) => onOutput(data instanceof ArrayBuffer ? new Uint8Array(data) : Uint8Array.from(data));
  return invoke('session_open', { target, columns, rows, output });
}
/** Mosh: re-establish the SSH connection next to the terminal, with prompts if necessary. */
export const sessionRelink = (id: number): Promise<void> => (inApp ? invoke('session_relink', { id }) : Promise.resolve());
export const sessionWrite = (id: number, text: string): Promise<void> => (inApp ? invoke('session_write', { id, text }) : fakeSession.write(id, text));
export const sessionResize = (id: number, columns: number, rows: number): Promise<void> => (inApp ? invoke('session_resize', { id, columns, rows }) : Promise.resolve());
/** Acknowledges drawn bytes; the core's flow control depends on it. */
export const sessionAck = (id: number, bytes: number): Promise<void> => (inApp ? invoke('session_ack', { id, bytes }) : Promise.resolve());
export const sessionAnswer = (id: number, answer: Answer): Promise<void> => (inApp ? invoke('session_answer', { id, answer }) : fakeSession.answer(id, answer));
export const sessionClose = (id: number): Promise<void> => (inApp ? invoke('session_close', { id }) : fakeSession.close(id));
/** Anzahl laufender Sitzungen in allen Fenstern. */
export const sessionCount = (): Promise<number> => (inApp ? invoke('session_count') : Promise.resolve(0));
/** Pauses sessions whose tab changes windows: their output is collected until the new window picks them up. */
export const sessionHold = (ids: number[]): Promise<void> => (inApp ? invoke('session_hold', { ids }) : Promise.resolve());
/** Picks up a running session in this window and returns its state. */
export function sessionAttach(id: number, columns: number, rows: number, onOutput: (bytes: Uint8Array) => void): Promise<{ phase: SessionPhase; mosh?: boolean }> {
  const output = new Channel<ArrayBuffer | number[]>();
  output.onmessage = (data) => onOutput(data instanceof ArrayBuffer ? new Uint8Array(data) : Uint8Array.from(data));
  return invoke('session_attach', { id, columns, rows, output });
}
/** Switches a session's recording. `name` and `address` later appear in the list of recordings. */
export const sessionRecord = (id: number, on: boolean, name: string, address: string): Promise<void> =>
  inApp ? invoke('session_record', { id, on, name, address }) : fakeSession.record(id, on, name, address);

export const logList = (): Promise<Recording[]> => (inApp ? invoke('log_list') : fake.logList());
/** A recording's text, without control characters. */
export const logRead = (id: string): Promise<string> => (inApp ? invoke('log_read', { id }) : fake.logRead(id));
/** Gives a finished recording a name of its own (empty = the host's name again). The ID changes in the process. */
export const logRename = (id: string, title: string): Promise<{ id: string; list: Recording[] }> => (inApp ? invoke('log_rename', { id, title }) : fake.logRename(id, title));
export const logDelete = (id: string): Promise<Recording[]> => (inApp ? invoke('log_delete', { id }) : fake.logDelete(id));
/** Shows a recording's file in Explorer; without one, the folder of all recordings. */
export const logReveal = (id?: string): Promise<void> => (inApp ? invoke('log_reveal', { id }) : Promise.resolve());

export const workspaceSave = (workspace: WorkspaceInput): Promise<Changed> => (inApp ? invoke('workspace_save', { workspace }) : fake.workspaceSave(workspace));
export const workspaceDelete = (id: string): Promise<Changed> => (inApp ? invoke('workspace_delete', { id }) : fake.workspaceDelete(id));

/** The tabs that were open last time, in case Glowport was not quit properly; otherwise null. */
export const restoreLoad = (): Promise<SavedTab[] | null> => (inApp ? invoke('restore_load') : fake.restoreLoad());
/** Remembers the open tabs in case of a crash. */
export const restoreSave = (tabs: SavedTab[]): Promise<void> => (inApp ? invoke('restore_save', { tabs }) : fake.restoreSave(tabs));

/** The tab this window was opened with as a window of its own, otherwise null. Returns it only once. */
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
 * Moves a tab into another window. `sessions` names its running, previously paused sessions.
 * The destination is the window `to`, otherwise with `atCursor` the window under the mouse pointer, otherwise a new one.
 */
export async function windowMove(tab: SavedTab, sessions: number[], target: { to?: string; atCursor?: boolean } = {}): Promise<void> {
  if (inApp) return invoke('window_move', { tab, sessions, to: target.to ?? null, atCursor: target.atCursor ?? false });
  window.open(`${location.pathname}?detached=${encodeURIComponent(JSON.stringify(tab))}`, '_blank', 'popup,width=1000,height=680');
}

/** Lets the user choose a text file and returns name and content; null if cancelled. */
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
 * Lets the user choose an image for the terminal background; null if cancelled.
 * In the program the name of the copy in the data folder comes back, in the preview directly an address for display.
 */
export const pickBackground = (): Promise<string | null> => (inApp ? invoke('pick_background') : fake.pickBackground());
/** Turns the stored background image into an address that can be displayed. */
export async function backgroundUrl(saved: string): Promise<string> {
  if (!inApp) return saved;
  const bytes = await invoke<ArrayBuffer>('background_read', { name: saved });
  return URL.createObjectURL(new Blob([bytes]));
}

/** Events of this window's sessions. Every session belongs to one window; those of the others do not arrive here. */
export function onSessionEvent(handler: (event: SessionEvent) => void): () => void {
  if (!inApp) return fakeSession.listen(handler);
  return on<SessionEvent & { window: string }>('session', (event) => event.window === windowLabel && handler(event));
}

/** The core reports when the vault changed without the interface's doing (host key, system, password). */
export const onVaultChanged = (handler: (data: Snapshot) => void) => (inApp ? on<Snapshot>('vault-changed', handler) : fakeSession.onChanged(handler));

export const clipboardRead = (): Promise<string> => (inApp ? readText() : navigator.clipboard.readText());
export const clipboardWrite = (text: string): Promise<void> => (inApp ? writeText(text) : navigator.clipboard.writeText(text));

// ---------- Lokales Terminal, serielle Ports ----------

/** This PC's shells that can be opened as a local terminal. */
export const localShells = (): Promise<LocalShell[]> => (inApp ? invoke('local_shells') : fakeSession.shells());
/** The serial ports that exist right now. A USB adapter only shows up when it is plugged in. */
export const serialPorts = (): Promise<SerialPortInfo[]> => (inApp ? invoke('serial_ports') : fakeSession.ports());

// ---------- Dateien ----------

/**
 * Sets up a connection to a host for the Files page, with the same prompts as a terminal.
 * Returns the number under which the events arrive and `sessionAnswer` takes the answers.
 */
export const fsConnect = (id: string): Promise<number> => (inApp ? invoke('fs_connect', { id }) : fakeSession.fsConnect(id));
/** The same for an FTP server from quick connect. */
export const ftpConnect = (place: FtpPlace): Promise<number> => (inApp ? invoke('ftp_connect', { place }) : fakeSession.ftpConnect(place));
/** The folder you start in at this location: the home directory. */
export const fsHome = (place: Place): Promise<string> => (inApp ? invoke('fs_home', { place }) : fakeFiles.home(place));
export const fsList = (place: Place, path: string): Promise<Listing> => (inApp ? invoke('fs_list', { place, path }) : fakeFiles.list(place, path));
export const fsMkdir = (place: Place, dir: string, name: string): Promise<void> => (inApp ? invoke('fs_mkdir', { place, dir, name }) : fakeFiles.mkdir(place, dir, name));
export const fsRename = (place: Place, path: string, name: string): Promise<void> => (inApp ? invoke('fs_rename', { place, path, name }) : fakeFiles.rename(place, path, name));
export const fsRemove = (place: Place, paths: string[]): Promise<void> => (inApp ? invoke('fs_remove', { place, paths }) : fakeFiles.remove(place, paths));
/** Changes permissions and owner, on request including everything below. */
export const fsChmod = (place: Place, request: ChmodRequest): Promise<void> => (inApp ? invoke('fs_chmod', { place, request }) : fakeFiles.chmod(place, request));
/** Reads a file for viewing or editing: text, image or the information that it is neither. */
export async function fsRead(place: Place, path: string): Promise<FileContent> {
  if (!inApp) return fakeFiles.read(place, path);
  const content = await invoke<Exclude<FileContent, { kind: 'image' }> | { kind: 'image'; mime: string }>('fs_read', { place, path });
  if (content.kind !== 'image') return content;
  // Images come as raw bytes; they become an address for display that the viewer releases again.
  const bytes = await invoke<ArrayBuffer>('fs_read_bytes', { place, path });
  return { kind: 'image', url: URL.createObjectURL(new Blob([bytes], { type: content.mime })) };
}
export const fsWrite = (place: Place, path: string, text: string): Promise<void> => (inApp ? invoke('fs_write', { place, path, text }) : fakeFiles.write(place, path, text));
/** Searches at the location below `dir` by name or in content; `onHit` reports every hit. */
export function fsSearch(place: Place, dir: string, query: string, content: boolean, onHit: (hit: SearchHit) => void): Promise<void> {
  if (!inApp) return fakeFiles.search(place, dir, query, content, onHit);
  const hits = new Channel<SearchHit>();
  hits.onmessage = onHit;
  return invoke('fs_search', { place, dir, query, content, hits });
}
/** Vergleicht zwei Ordner samt Unterordnern. */
export const fsCompare = (left: Place, leftPath: string, right: Place, rightPath: string): Promise<DiffEntry[]> =>
  inApp ? invoke('fs_compare', { left, leftPath, right, rightPath }) : fakeFiles.compare(left, leftPath, right, rightPath);

/** The folder downloads land in if none is chosen in the settings. */
export const fsDownloads = (): Promise<string> => (inApp ? invoke('fs_downloads') : Promise.resolve('C:\\Users\\ich\\Downloads'));
/** Queues files and folders. */
export const transferStart = (request: TransferRequest): Promise<number[]> => (inApp ? invoke('transfer_start', { request }) : fakeFiles.transferStart(request));
export const transferList = (): Promise<Transfer[]> => (inApp ? invoke('transfer_list') : fakeFiles.transferList());
/** Pauses, resumes, cancels or retries. Without numbers it applies to all transfers. */
export const transferControl = (ids: number[] | null, action: 'pause' | 'resume' | 'cancel' | 'retry'): Promise<void> =>
  inApp ? invoke('transfer_control', { ids, action }) : fakeFiles.transferControl(ids, action);
/** Removes everything finished, cancelled and failed from the list. */
export const transferClear = (): Promise<void> => (inApp ? invoke('transfer_clear') : fakeFiles.transferClear());
/** The core reports the state of all transfers as long as something is happening. Transfers belong to the program, not a window. */
export const onTransfers = (handler: (list: Transfer[]) => void) => (inApp ? on<Transfer[]>('transfers', handler) : fakeFiles.onTransfers(handler));

/** Opens a file in the user's own program and uploads it again after every save. */
export const watchOpen = (place: Place, path: string, program: string): Promise<void> => (inApp ? invoke('watch_open', { place, path, program: program || null }) : fakeFiles.watchOpen(place, path));
/** Which folder a session's shell is currently in; null if the server does not reveal it. */
export const sessionCwd = (id: number): Promise<string | null> => (inApp ? invoke('session_cwd', { id }) : Promise.resolve(null));
export const watchStop = (id: number): Promise<void> => (inApp ? invoke('watch_stop', { id }) : fakeFiles.watchStop(id));
export const watchList = (): Promise<Watched[]> => (inApp ? invoke('watch_list') : fakeFiles.watchList());
export const onWatched = (handler: (list: Watched[]) => void) => (inApp ? on<Watched[]>('watched', handler) : fakeFiles.onWatched(handler));
/** Lets the user choose a program for editing; null if cancelled. */
export const pickProgram = (): Promise<string | null> => (inApp ? invoke('pick_program') : Promise.resolve('C:\Program Files\Microsoft VS Code\Code.exe'));
/** Lets the user choose a folder; null if cancelled. */
export const pickFolder = (): Promise<string | null> => (inApp ? invoke('pick_folder') : Promise.resolve('D:\Backups'));
/** Fetches a server's files into a working folder, to drag them out of the window afterwards. */
export const dragStage = (place: Place, paths: string[]): Promise<{ ids: number[]; paths: string[] }> => invoke('drag_stage', { place, paths });
/** Starts dragging this PC's files out of the window while the mouse button is held. Returns whether they were dropped. */
export const dragOut = (paths: string[]): Promise<boolean> => invoke('drag_out', { paths });
/** Lets the user choose files on this PC for uploading; null if cancelled. */
export const pickUploads = (): Promise<string[] | null> => (inApp ? invoke('pick_uploads') : Promise.resolve(['C:\Users\ich\Desktop\Rechnung-0931.pdf', 'C:\Users\ich\Desktop\server-liste.xlsx']));
/** Syncs two folders: every line names the path below the folders and the direction. Nothing is deleted. */
export const syncStart = (left: Place, leftPath: string, right: Place, rightPath: string, items: { rel: string; toRight: boolean }[]): Promise<number[]> =>
  inApp ? invoke('sync_start', { left, leftPath, right, rightPath, items }) : fakeFiles.syncStart(left, leftPath, right, rightPath, items);

// ---------- Port-Regeln ----------

export const forwardSave = (rule: ForwardInput): Promise<Changed> => (inApp ? invoke('forward_save', { rule, vault: rule.vault }) : fake.forwardSave(rule));
export const forwardDelete = (id: string): Promise<Changed> => (inApp ? invoke('forward_delete', { id }) : fake.forwardDelete(id));
/**
 * Switches a rule on. Returns the connection number: under it prompts arrive as for a session
 * (`onSessionEvent`), and `sessionAnswer` takes the answers. How the rule is doing is reported by `onForwards`.
 */
export const forwardStart = (id: string): Promise<number> => (inApp ? invoke('forward_start', { id }) : fakeForwards.start(id));
export const forwardStop = (id: string): Promise<void> => (inApp ? invoke('forward_stop', { id }) : fakeForwards.stop(id));
/** The state of all rules switched on. */
export const forwardList = (): Promise<ForwardState[]> => (inApp ? invoke('forward_list') : fakeForwards.list());
/** The core reports the rules' state as soon as something happens. Rules belong to the program, not a window. */
export const onForwards = (handler: (list: ForwardState[]) => void) => (inApp ? on<ForwardState[]>('forwards', handler) : fakeForwards.onChange(handler));

// ---------- Snippets ----------

export const snippetSave = (snippet: SnippetInput): Promise<Changed> => (inApp ? invoke('snippet_save', { snippet, vault: snippet.vault }) : fake.snippetSave(snippet));
export const snippetDelete = (id: string): Promise<Changed> => (inApp ? invoke('snippet_delete', { id }) : fake.snippetDelete(id));
/**
 * Runs a command on several hosts, without a terminal. `onResult` reports every host as soon as it starts and
 * as soon as it is done. `run` is a freely chosen number with which the run can be cancelled.
 */
export function snippetRun(run: number, command: string, hosts: string[], onResult: (result: RunResult) => void): Promise<void> {
  if (!inApp) return fakeRun.run(run, command, hosts, onResult);
  const results = new Channel<RunResult>();
  results.onmessage = onResult;
  return invoke('snippet_run', { run, command, hosts, results });
}
export const snippetCancel = (run: number): Promise<void> => (inApp ? invoke('snippet_cancel', { run }) : fakeRun.cancel(run));

// ---------- Server-Info ----------

/** Measures a session's server; null if it does not provide the numbers (not Linux). */
export const sessionStats = (id: number): Promise<StatsSample | null> => (inApp ? invoke('session_stats', { id }) : fakeStats.sample(id));

// ---------- Import and export ----------

/** Looks which other programs on this PC have saved connections, and counts them. Nothing is saved in the process. */
export const importScan = (): Promise<ImportFound[]> => (inApp ? invoke('import_scan') : fake.importScan());
/** Reads a source `importScan` found and returns what could be taken over from it. Nothing is saved. */
export const importRead = (source: ImportSource): Promise<ImportDraft> => (inApp ? invoke('import_read', { source }) : fake.importRead(source));
/**
 * Lets the user choose a file and reads it. With `source` it is settled what it is; without, Glowport recognises the
 * format by its content. null if cancelled.
 */
export const importPick = (source: ImportSource | null): Promise<ImportDraft | null> => (inApp ? invoke('import_pick', { source }) : fake.importRead(source ?? 'csv'));
/** Reads a file at a known location, e.g. one dragged into the window. */
export const importFile = (path: string): Promise<ImportDraft> => (inApp ? invoke('import_file', { path }) : fake.importRead('csv'));
/** Takes the chosen entries of a draft into the vault. */
export const importApply = (token: number, options: ImportOptions): Promise<Changed & { report: ImportReport }> =>
  inApp ? invoke('import_apply', { token, options }) : fake.importApply(token, options);
/** Throws a draft away, together with everything the core read for it. */
export const importDiscard = (token: number): Promise<void> => (inApp ? invoke('import_discard', { token }) : fake.importDiscard(token));
/** Writes hosts and more into a file the user chooses. Passwords and private keys are never included. Returns the path or null. */
export const exportData = (request: ExportRequest, fileName: string): Promise<string | null> => (inApp ? invoke('export_data', { request, fileName }) : fake.exportData(request));

// ---------- Updates ----------

const FAKE_UPDATE: UpdateInfo = {
  version: '1.1.0',
  notes: 'New: local terminal (PowerShell, WSL, Git Bash) as a tab.\nFaster: large folders in the file bar.\nFixed: the terminal search keeps its input when switching tabs.',
  date: Date.UTC(2026, 10, 20),
};

/** Asks for a newer version; null if this one is the newest. */
export const updateCheck = (): Promise<UpdateInfo | null> => (inApp ? invoke('update_check') : new Promise((ok) => setTimeout(() => ok(FAKE_UPDATE), 600)));
/** Downloads the new version, checks its signature and installs it. Then Glowport restarts. */
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

// ── Syncing and shared vaults (docs/sync.md) ───────────────────────────────────────────────────────────

export const syncState = (): Promise<SyncState> => (inApp ? invoke('sync_state') : fakeSync.state());
/** Every change in syncing: syncing, synced, without connection, new invitation … */
export const onSyncState = (handler: (state: SyncState) => void) => (inApp ? on<SyncState>('sync-state', handler) : fakeSync.onState(handler));
/** Asks an address whether a Glowport sync server answers there. */
export const syncProbe = (server: string): Promise<SyncServerInfo> => (inApp ? invoke('sync_probe', { server }) : fakeSync.probe(server));
/** Turns this device's vault into an account on the server. */
export const syncRegister = (request: SyncRegister): Promise<SyncState> => (inApp ? invoke('sync_register', { request }) : fakeSync.register(request));
/** Links this device's vault to an account that already exists. */
export const syncConnect = (request: SyncLogin): Promise<SyncState> => (inApp ? invoke('sync_connect', { request }) : fakeSync.connect(request));
/** First start without a vault: creates an existing account's vault on this device. */
export const syncLogin = (request: SyncLogin): Promise<Status> => (inApp ? invoke('sync_login', { request }) : fake.syncLogin(request));
export const syncNow = (): Promise<SyncState> => (inApp ? invoke('sync_now') : fakeSync.now());
export const syncUnlink = (): Promise<SyncState> => (inApp ? invoke('sync_unlink') : fakeSync.unlink());
/** The server has an older state: upload this device's state again. */
export const syncResync = (vault: string): Promise<SyncState> => (inApp ? invoke('sync_resync', { vault }) : fakeSync.resync(vault));
export const syncDevices = (): Promise<SyncDevice[]> => (inApp ? invoke('sync_devices') : fakeSync.devices());
export const syncDeviceRename = (id: string, name: string): Promise<SyncDevice[]> => (inApp ? invoke('sync_device_rename', { id, name }) : fakeSync.deviceRename(id, name));
export const syncDeviceRemove = (id: string): Promise<SyncDevice[]> => (inApp ? invoke('sync_device_remove', { id }) : fakeSync.deviceRemove(id));
export const syncNotices = (): Promise<SyncNotice[]> => (inApp ? invoke('sync_notices') : fakeSync.notices());
export const syncNoticesClear = (): Promise<void> => (inApp ? invoke('sync_notices_clear') : fakeSync.noticesClear());

/** Creates a shared vault and returns its ID. The vaults themselves come with the vault's next state. */
export const sharedCreate = (name: string): Promise<string> => (inApp ? invoke('shared_create', { name }) : fakeSync.create(name));
export const sharedRename = (vault: string, name: string): Promise<void> => (inApp ? invoke('shared_rename', { vault, name }) : fakeSync.rename(vault, name));
/** Looks up an account to invite and returns its safety code. */
export const sharedLookup = (username: string): Promise<SyncCandidate> => (inApp ? invoke('shared_lookup', { username }) : fakeSync.lookup(username));
export const sharedInvite = (vault: string, account: string, role: VaultRole): Promise<void> => (inApp ? invoke('shared_invite', { vault, account, role }) : fakeSync.invite(vault, account, role));
export const sharedSetRole = (vault: string, account: string, role: VaultRole): Promise<void> => (inApp ? invoke('shared_set_role', { vault, account, role }) : fakeSync.setRole(vault, account, role));
export const sharedRemove = (vault: string, account: string): Promise<void> => (inApp ? invoke('shared_remove', { vault, account }) : fakeSync.remove(vault, account));
export const sharedTransfer = (vault: string, account: string): Promise<void> => (inApp ? invoke('shared_transfer', { vault, account }) : fakeSync.transfer(vault, account));
export const sharedLeave = (vault: string): Promise<void> => (inApp ? invoke('shared_leave', { vault }) : fakeSync.leave(vault));
export const sharedDelete = (vault: string): Promise<void> => (inApp ? invoke('shared_delete', { vault }) : fakeSync.remove_vault(vault));
export const invitationAccept = (vault: string): Promise<void> => (inApp ? invoke('invitation_accept', { vault }) : fakeSync.accept(vault));
export const invitationDecline = (vault: string): Promise<SyncState> => (inApp ? invoke('invitation_decline', { vault }) : fakeSync.decline(vault));

// Server administration; only for the account that administers it.
export const adminInvites = (): Promise<SyncInviteCode[]> => (inApp ? invoke('admin_invites') : fakeSync.adminInvites());
export const adminInviteCreate = (): Promise<SyncInviteCode[]> => (inApp ? invoke('admin_invite_create') : fakeSync.adminInviteCreate());
export const adminInviteRevoke = (code: string): Promise<SyncInviteCode[]> => (inApp ? invoke('admin_invite_revoke', { code }) : fakeSync.adminInviteRevoke(code));
export const adminAccounts = (): Promise<SyncAccount[]> => (inApp ? invoke('admin_accounts') : fakeSync.adminAccounts());
export const adminAccountDisable = (id: string, disabled: boolean): Promise<SyncAccount[]> => (inApp ? invoke('admin_account_disable', { id, disabled }) : fakeSync.adminAccountDisable(id, disabled));
export const adminAccountDelete = (id: string): Promise<SyncAccount[]> => (inApp ? invoke('admin_account_delete', { id }) : fakeSync.adminAccountDelete(id));

// ── Management in the sidebar: Docker, services, processes (docs/management.md) ─────────────────────
// Everything runs over the session's connection. Actions the permissions are missing for the core tries with
// `sudo -n`; if sudo wants a password, `{ outcome: 'password', command }` comes back. Other errors: `manage_failed`
// with the server's message.

export const manageProbe = (session: number): Promise<ManageAbilities> => (inApp ? invoke('manage_probe', { session }) : fakeManage.probe(session));
export const dockerList = (session: number): Promise<Listed<DockerContainer[]>> => (inApp ? invoke('docker_list', { session }) : fakeManage.dockerList(session));
export const dockerAction = (session: number, container: string, action: 'start' | 'stop' | 'restart'): Promise<ManageDone> =>
  inApp ? invoke('docker_action', { session, container, action }) : fakeManage.dockerAction(session, container, action);
/** What is typed into a new tab so the logs follow along there or a shell opens inside the container. */
export const dockerLine = (container: string, kind: 'logs' | 'shell', sudo: boolean): Promise<string> => (inApp ? invoke('docker_line', { container, kind, sudo }) : fakeManage.dockerLine(container, kind, sudo));
export const serviceList = (session: number): Promise<Listed<ServiceUnit[]>> => (inApp ? invoke('service_list', { session }) : fakeManage.serviceList(session));
export const serviceAction = (session: number, unit: string, action: 'start' | 'stop' | 'restart' | 'enable' | 'disable'): Promise<ManageDone> =>
  inApp ? invoke('service_action', { session, unit, action }) : fakeManage.serviceAction(session, unit, action);
/** State and latest messages of a service, as systemd prints them. */
export const serviceStatus = (session: number, unit: string): Promise<string> => (inApp ? invoke('service_status', { session, unit }) : fakeManage.serviceStatus(session, unit));
/** What is typed into a new tab so the service's journal follows along there. */
export const serviceLine = (unit: string, sudo: boolean): Promise<string> => (inApp ? invoke('service_line', { unit, sudo }) : fakeManage.serviceLine(unit, sudo));
/** `null`: the server does not provide the list. */
export const processList = (session: number): Promise<ProcessSample | null> => (inApp ? invoke('process_list', { session }) : fakeManage.processList(session));
export const processKill = (session: number, pid: number, signal: 'term' | 'kill'): Promise<ManageDone> =>
  inApp ? invoke('process_kill', { session, pid, signal }) : fakeManage.processKill(session, pid, signal);

// ── Proxmox (docs/management.md) ───────────────────────────────────────────────────────────────────────
// The connections are in the vault's state (`Snapshot.proxmox`), the host knows its machine (`Host.proxmox`).

/** Checks address, certificate and token without saving anything. Two steps, see `ProxmoxProbe`. */
export const proxmoxProbe = (input: ProxmoxInput): Promise<ProxmoxProbe> => (inApp ? invoke('proxmox_probe', { input }) : fakeProxmox.probe(input));
export const proxmoxSave = (input: ProxmoxInput): Promise<Changed> => (inApp ? invoke('proxmox_save', { input }) : fakeProxmox.save(input));
/** Removes the connection. The hosts stay and only lose their link. */
export const proxmoxDelete = (id: string): Promise<Changed> => (inApp ? invoke('proxmox_delete', { id }) : fakeProxmox.remove(id));
/** Nodes and machines of a connection. The core updates linked hosts along the way (address, name). `fresh`: ask every machine anew. */
export const proxmoxOverview = (id: string, fresh = false): Promise<ProxmoxOverview> => (inApp ? invoke('proxmox_overview', { id, fresh }) : fakeProxmox.overview(id));
/** Start, shut down, hard stop, restart. Returns when Proxmox has carried out the task. */
export const proxmoxAction = (id: string, guest: { node: string; vmid: number; kind: 'qemu' | 'lxc' }, action: 'start' | 'shutdown' | 'stop' | 'reboot'): Promise<void> =>
  inApp ? invoke('proxmox_action', { id, guest, action }) : fakeProxmox.action(id, guest, action);
/** Creates hosts from the chosen machines and links them. */
export const proxmoxImport = (id: string, picks: { node: string; vmid: number; kind: 'qemu' | 'lxc' }[], group: string | null): Promise<Changed> =>
  inApp ? invoke('proxmox_import', { id, picks, group }) : fakeProxmox.import(id, picks, group);
/** Unlinks a host from its machine. The host stays as it is. */
export const proxmoxUnlink = (host: string): Promise<Changed> => (inApp ? invoke('proxmox_unlink', { host }) : fakeProxmox.unlink(host));
/** Does the host accept connections on its port? A single attempt; through a jump host or proxy it counts as reachable. */
export const proxmoxReachable = (host: string): Promise<boolean> => (inApp ? invoke('proxmox_reachable', { host }) : fakeProxmox.reachable(host));
