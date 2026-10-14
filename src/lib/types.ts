// Shapes of the data travelling between interface and core. Counterpart: crates/core/src/directory.rs.

export type Reconnect = 'notice' | 'auto';

/** Inheritable values. If a field is missing, the value comes from further up. */
export interface Fields {
  user?: string;
  port?: number;
  /** Jump host ID; empty = explicitly none. */
  jump?: string;
  startcmd?: string;
  reconnect?: Reconnect;
  /** Path of a key file on this computer. */
  keyFile?: string;
  /** An identity's ID; empty = explicitly none. */
  identity?: string;
  /** ID of a key in the vault; empty = explicitly none. */
  key?: string;
  /** Environment variables as with `SetEnv`: `NAME=value`, several separated by spaces. */
  env?: string;
  /** Offer keys from an SSH agent on this computer. */
  agent?: boolean;
  /** Forward the agent to the server. Only works together with `agent`. */
  agentForward?: boolean;
  /** `http://address:port` or `socks5://address:port`; empty = explicitly none. */
  proxy?: string;
  /** Seconds between keepalives; 0 = off. */
  keepalive?: number;
  /** Seconds to wait for the connection. */
  timeout?: number;
  term?: string;
  charset?: string;
  /** Also offer old algorithms that are weak today. */
  legacy?: boolean;
  /** ID of a color scheme for the terminal. */
  scheme?: string;
  /** Run the terminal over Mosh instead of SSH. Signing in still happens over SSH. */
  mosh?: boolean;
  /** Mosh's local echo: shows what is typed before the server confirms it. */
  moshPredict?: MoshPredict;
  /** UDP port or range for `mosh-server`, e.g. `60001` or `60001:60010`. */
  moshPort?: string;
  /** Path to `mosh-server` on the server, if it is not in the search path. */
  moshServer?: string;
}

export type MoshPredict = 'adaptive' | 'always' | 'never';
/** Why a session runs over SSH instead of Mosh. */
export type MoshFallback = 'missing' | 'ipv6' | 'udp' | 'server';

export type FieldKey = keyof Fields;

export interface Group {
  id: string;
  /** ID of the vault the entry is in. If missing, it is the personal one. */
  vault?: string;
  name: string;
  parent: string | null;
  color: string | null;
  defs: Fields;
  /** Is a password stored for the group's proxy? The password itself never leaves the core. */
  hasProxyPassword?: boolean;
}

/** How a host is addressed. If missing or unknown from a newer version, it counts as `ssh`. */
export type Protocol = 'ssh' | 'telnet' | 'serial' | 'ftp';

/**
 * An FTP host's settings. `explicit` starts in the clear and switches to TLS before signing in (port 21),
 * `implicit` speaks TLS from the start (port 990), `none` stays unencrypted.
 */
export interface FtpSettings {
  security: 'explicit' | 'implicit' | 'none';
  /** Sign in without user and password. */
  anonymous: boolean;
  /** Folder the file manager starts in; empty is the one the server sets. */
  dir?: string;
  /** The prompt before an unencrypted connection is dismissed for this host. */
  plainOk?: boolean;
}

/** A serial line's settings. The usual “9600 8N1” means 9600 baud, 8 data bits, no parity, 1 stop bit. */
export interface SerialSettings {
  baud: number;
  dataBits: 5 | 6 | 7 | 8;
  parity: 'none' | 'odd' | 'even';
  stopBits: 1 | 2;
  /** Flow control: none, XON/XOFF or RTS/CTS. */
  flow: 'none' | 'software' | 'hardware';
}

export interface Host {
  id: string;
  /** ID of the vault the entry is in. If missing, it is the personal one. */
  vault?: string;
  name: string;
  /** Address of the server; for `serial` the port's name (`COM3`). */
  address: string;
  group: string | null;
  protocol: string;
  /** Only for `serial`. */
  serial?: SerialSettings | null;
  /** Only for `ftp`. */
  ftp?: FtpSettings | null;
  color: string | null;
  os: string | null;
  own: Fields;
  /** The password itself never leaves the core. */
  hasPassword: boolean;
  hasProxyPassword?: boolean;
  /** The machine in Proxmox this host belongs to. Glowport keeps its address and name up to date from it. */
  proxmox?: ProxmoxLink;
}

export interface KnownHost {
  id: string;
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  /** Milliseconds since 1970. */
  addedAt: number;
}

export type KeyKind = 'ed25519' | 'ecdsa' | 'rsa';

/** A key pair in the vault. The private part only leaves the core on explicit export. */
export interface SshKey {
  id: string;
  /** ID of the vault the entry is in. If missing, it is the personal one. */
  vault?: string;
  name: string;
  kind: KeyKind;
  /** Length in bits: Ed25519 256, ECDSA 256/384/521, RSA 3072/4096. */
  bits: number;
  fingerprint: string;
  /** A line in OpenSSH format, as it appears in `authorized_keys`. */
  publicKey: string;
  origin: 'generated' | 'imported';
  /** Milliseconds since 1970. */
  addedAt: number;
  certificate?: KeyCertificate | null;
}

/** User certificate for a key: a certificate authority confirms whom it belongs to. Times in seconds since 1970. */
export interface KeyCertificate {
  text: string;
  keyId: string;
  /** User names it applies to; empty = for everyone. */
  principals: string[];
  validAfter: number;
  /** Missing if it does not expire. */
  validBefore?: number | null;
  /** Fingerprint of the certificate authority. */
  authority: string;
}

/** User plus key and/or password, usable for many hosts. */
export interface Identity {
  id: string;
  /** ID of the vault the entry is in. If missing, it is the personal one. */
  vault?: string;
  name: string;
  user: string;
  /** ID of a key in the vault. */
  key: string | null;
  /** The password itself never leaves the core. */
  hasPassword: boolean;
}

/** A certificate authority whose certificates apply to servers. */
export interface Authority {
  id: string;
  name: string;
  /** Addresses it applies to: patterns with `*` and `?`, several separated by commas. */
  pattern: string;
  /** Key type for display. */
  kind: string;
  fingerprint: string;
  /** Milliseconds since 1970. */
  addedAt: number;
}

/** A running session that moves into another window with its pane. */
export interface Moving {
  /** The session's number in the core. */
  session: number;
  /** The terminal's previous content as a sequence of control characters that rebuilds it. */
  content: string;
}

/** A pane of a saved tab: its destination and, only when moving to another window, its running session. */
export interface SavedPane {
  pane: Target;
  moving?: Moving;
  recording?: boolean;
}

/** What a saved tab shows: its panes in their layout, each with its destination. */
export type SavedLayout = SavedPane | { dir: 'row' | 'col'; ratio: number; a: SavedLayout; b: SavedLayout };

/** A tab as it can be opened again: after a crash, in a window of its own or as a workspace. */
export interface SavedTab {
  name: string | null;
  color: string | null;
  /** Multi-exec: input goes to all panes of the tab. */
  multi: boolean;
  layout: SavedLayout;
}

/** Several hosts in a fixed layout, opened with one click. Stored in the vault. */
export interface Workspace {
  id: string;
  name: string;
  multi: boolean;
  layout: SavedLayout;
}

export interface WorkspaceInput {
  id?: string;
  name: string;
  multi: boolean;
  layout: SavedLayout;
}

/** A recording: a session's output as a file on this computer. Times in milliseconds since 1970. */
export interface Recording {
  id: string;
  /** Name of the host or the typed address. */
  name: string;
  /** Name of its own the user gave the recording afterwards. */
  title?: string | null;
  address: string;
  startedAt: number;
  /** Missing while the recording runs. */
  endedAt: number | null;
  bytes: number;
  /** Path of the file. */
  file: string;
}

export interface Snapshot {
  /** Sequence number of the state: one created later has the higher one. The browser preview does not know it. */
  seq?: number;
  groups: Group[];
  hosts: Host[];
  damaged: number;
  knownHosts: KnownHost[];
  keys: SshKey[];
  identities: Identity[];
  authorities: Authority[];
  workspaces: Workspace[];
  forwards: Forward[];
  snippets: Snippet[];
  /** All vaults of this device, the personal one first. */
  vaults?: VaultInfo[];
  /** Connections to Proxmox. They are in the personal vault. */
  proxmox?: ProxmoxConnection[];
  /** For every entry in a shared vault: that vault's ID. Everything else is in the personal one. */
  homes?: Record<string, string>;
}

export type VaultRole = 'owner' | 'write' | 'read';

export interface VaultMember {
  account: string;
  name: string;
  role: VaultRole;
  /** Your own account. */
  me: boolean;
  /** Invited, but has not accepted yet. */
  invited: boolean;
  /** The account's safety code: six words from a checksum of its keys. */
  code: string;
}

export interface VaultInfo {
  id: string;
  kind: 'personal' | 'shared';
  /** Name of the vault; empty for the personal one. */
  name: string;
  /** Your own role. */
  role: VaultRole;
  members: VaultMember[];
  /** The server has an older state than this device; the vault rests until someone decides. */
  rolledBack?: boolean;
  /** An own vault the server no longer knows. */
  orphaned?: boolean;
}

export type SyncPhase = 'syncing' | 'synced' | 'offline' | 'signedOut' | 'error';

export interface SyncInvitation {
  vault: string;
  name: string | null;
  owner: string;
  role: VaultRole;
  /** The owner's safety code. */
  code: string;
  known: 'new' | 'same' | 'changed';
}

/** State of syncing. Not linked: `linked` is false, the rest empty. */
export interface SyncState {
  linked: boolean;
  server: string;
  username: string;
  /** Does this account administer the server? */
  admin: boolean;
  phase: SyncPhase;
  /** Reason when `phase` is “error” or “signedOut”. */
  error?: string;
  /** Changes that have not reached the server yet. */
  pending: number;
  /** When everything was last synced, in milliseconds since 1970. */
  syncedAt: number | null;
  /** Your own safety code. */
  code: string;
  invitations: SyncInvitation[];
  /** Number of notices from syncing. */
  notices: number;
  /** The master password was changed on another device. */
  passwordChanged: boolean;
}

export interface SyncServerInfo {
  /** The address in normalised form. */
  server: string;
  /** The server is waiting for its first account (it becomes the administrator and needs the setup code). */
  fresh: boolean;
}

export interface SyncDevice {
  id: string;
  name: string;
  createdAt: number;
  seenAt: number;
  current: boolean;
}

export interface SyncCandidate {
  account: string;
  username: string;
  code: string;
  known: 'new' | 'same' | 'changed';
}

export interface SyncNotice {
  id: number;
  at: number;
  kind: 'clash' | 'restored' | 'discarded' | 'vault_removed' | 'rejected';
  /** Name of the vault, as far as still known. */
  vaultName: string;
  /** Name of the affected entry, as far as still known. */
  recordName?: string;
  /** The field concerned, e.g. `own.port`. */
  path?: string;
  /** Your own value applies. */
  mine?: boolean;
  count?: number;
}

export interface SyncInviteCode {
  code: string;
  createdAt: number;
  expiresAt: number;
}

export interface SyncAccount {
  id: string;
  username: string;
  admin: boolean;
  disabled: boolean;
  createdAt: number;
  seenAt: number;
  devices: number;
  bytes: number;
}

export interface SyncRegister {
  server: string;
  /** Invite code; for the first account the setup code. */
  code: string;
  username: string;
  password: string;
  device: string;
}

export interface SyncLogin {
  server: string;
  username: string;
  password: string;
  device: string;
  /** Only on a device that already has a vault: what happens to its entries? */
  local?: 'keep' | 'discard';
}

/**
 * Where a session leads: to a saved host (SSH, Telnet or serial), to a typed address
 * (`direct` = SSH, `telnet`) or into a shell of this PC (`local`, `shell` is the ID from `LocalShell`).
 */
export type Target =
  | { kind: 'host'; id: string }
  // `identity` and `key`: identity or key from the vault the quick connection signs in with.
  | { kind: 'direct'; user: string; host: string; port: number; identity?: string; key?: string; mosh?: boolean }
  | { kind: 'telnet'; host: string; port: number }
  | { kind: 'local'; shell: string };

/** A shell Glowport found on this PC and can open as a local terminal. */
export interface LocalShell {
  /** Stays the same across restarts: `pwsh`, `powershell`, `cmd`, `gitbash`, `wsl:Ubuntu`. */
  id: string;
  name: string;
  kind: 'pwsh' | 'powershell' | 'cmd' | 'gitbash' | 'wsl';
  /** For display: path of the program or name of the distribution. */
  detail: string;
}

/** A serial port of this PC. */
export interface SerialPortInfo {
  /** `COM3` */
  name: string;
  /** What is attached to it, as far as Windows names it: “USB-SERIAL CH340”. */
  label: string;
}

export type SessionPhase = 'connecting' | 'authenticating' | 'connected';

export interface HostKeyPrompt {
  type: 'hostKey';
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  changed: boolean;
  /** Fingerprints previously stored for this address. */
  known: string[];
}

export interface SecretPrompt {
  type: 'secret';
  kind: 'password' | 'passphrase';
  attempt: number;
  file: string | null;
  canSave: boolean;
  /** Set if a jump host asks and not the destination: `user@address`. */
  station?: string | null;
}

export interface InteractivePrompt {
  type: 'interactive';
  name: string;
  instructions: string;
  prompts: { text: string; echo: boolean }[];
  station?: string | null;
}

/** The certificate of an FTP server this computer does not trust on its own. `changed`: it differs from the confirmed one. */
export interface CertificatePrompt {
  type: 'certificate';
  host: string;
  port: number;
  /** SHA-256 over the certificate, as browsers show it: `5F:1A:…`. */
  fingerprint: string;
  changed: boolean;
}

/** Before an unencrypted FTP connection. `offersTls`: the server could do TLS. */
export interface PlainPrompt {
  type: 'plain';
  host: string;
  offersTls: boolean;
  /** The question can be dismissed for this host; for a quick connection there is no host for that. */
  canRemember: boolean;
}

export type Prompt = HostKeyPrompt | SecretPrompt | InteractivePrompt | CertificatePrompt | PlainPrompt;

export interface SessionEnd {
  type: 'end';
  /** user, remote, connect_failed, host_key_rejected, auth_failed, connection_lost */
  reason: string;
  message: string | null;
  exitStatus: number | null;
}

export type SessionEvent = { id: number } & (
  | { type: 'phase'; phase: SessionPhase }
  | { type: 'banner'; text: string }
  | { type: 'notice'; code: string; message: string }
  /** The folder the shell is currently in. */
  | { type: 'cwd'; path: string }
  /** The terminal runs over Mosh. */
  | { type: 'mosh'; state: 'active' }
  /** Mosh did not come about; the session continues over SSH. `detail`: first line of an error message from the server. */
  | { type: 'mosh'; state: 'fallback'; reason: MoshFallback; detail?: string }
  /** Mosh: seconds without a message from the server; null as soon as it answers again. */
  | { type: 'reach'; silent: number | null }
  /** Mosh: is the SSH connection next to it up for sidebar and files? */
  | { type: 'side'; linked: boolean }
  | Prompt
  | SessionEnd
);

export type Answer =
  | { kind: 'hostKey'; accept: boolean }
  | { kind: 'secret'; value?: string; save?: boolean }
  | { kind: 'interactive'; values?: string[] }
  | { kind: 'certificate'; accept: boolean }
  /** `remember` dismisses the prompt for this host; `secure` moves it to FTPS instead. */
  | { kind: 'plain'; accept: boolean; remember?: boolean; secure?: boolean };

export interface BackendError {
  code: string;
  reason?: string;
  message: string;
}

export type VaultState = 'missing' | 'locked' | 'open' | 'broken';

export interface Status {
  state: VaultState;
  data?: Snapshot;
  error?: BackendError;
  /** Whether the vault is opened on start without a master password. */
  startUnlock?: boolean;
}

export interface Changed {
  id?: string;
  data: Snapshot;
}

export interface HostInput {
  /** Only when creating: the vault the entry goes into. If missing, it is the personal one. */
  vault?: string;
  id?: string;
  name: string;
  address: string;
  /** Missing = stays as it is; for a new host `ssh`. */
  protocol?: Protocol;
  /** Missing = stays as it is. Only counts for `serial`. */
  serial?: SerialSettings;
  /** Missing = stays as it is. Only counts for `ftp`. */
  ftp?: FtpSettings;
  group: string | null;
  color: string | null;
  os: string | null;
  own: Fields;
  /** Missing = unchanged, null = remove, text = set. */
  password?: string | null;
  /** Password for the host's proxy, with the same rules. */
  proxyPassword?: string | null;
}

export interface GroupInput {
  /** Only when creating: the vault the entry goes into. If missing, it is the personal one. */
  vault?: string;
  id?: string;
  name: string;
  parent: string | null;
  color: string | null;
  defs: Fields;
  proxyPassword?: string | null;
}

export interface KeyGenerate {
  /** Only when creating: the vault the entry goes into. If missing, it is the personal one. */
  vault?: string;
  name: string;
  kind: KeyKind;
  bits: number;
}

export interface KeyImport {
  /** Only when creating: the vault the entry goes into. If missing, it is the personal one. */
  vault?: string;
  name: string;
  /** Content of the key file: OpenSSH, PEM or PuTTY (.ppk). */
  text: string;
  passphrase?: string;
}

/** What the core recognises in a key file before it is imported. */
export interface KeyInfo {
  /** Type, length and fingerprint are missing as long as the file is encrypted and its format does not state them openly. */
  kind: KeyKind | null;
  bits: number | null;
  fingerprint: string | null;
  encrypted: boolean;
  format: 'openssh' | 'pem' | 'ppk';
  comment: string;
}

/** A key file chosen by the user, with its content. */
export interface KeyFile {
  path: string;
  text: string;
}

export interface IdentityInput {
  /** Only when creating: the vault the entry goes into. If missing, it is the personal one. */
  vault?: string;
  id?: string;
  name: string;
  user: string;
  key: string | null;
  /** Missing = unchanged, null = remove, text = set. */
  password?: string | null;
}

/** Result per host when copying a public key. */
export interface DeployResult {
  host: string;
  /** added = added, present = was already there, failed = see `message` */
  outcome: 'added' | 'present' | 'failed';
  message?: string | null;
}

/** An SSH agent on this computer and the keys it offers. */
export interface Agent {
  kind: 'openssh' | 'pageant';
  running: boolean;
  keys: { comment: string; kind: string; fingerprint: string }[];
}

/** Where files are: on this PC, on a saved host or on a running session's server. */
/** An FTP server from quick connect the vault does not know. An empty user signs in anonymously. */
export interface FtpPlace {
  kind: 'ftp';
  host: string;
  port: number;
  user: string;
  security: FtpSettings['security'];
}

export type Place = { kind: 'local' } | { kind: 'host'; id: string } | { kind: 'session'; id: number } | FtpPlace;

export type FileKind = 'dir' | 'file' | 'link';

export interface FileEntry {
  name: string;
  /** Full path as the core understands it. The interface never assembles paths itself. */
  path: string;
  kind: FileKind;
  size: number;
  /** Time of the last change in milliseconds. */
  modified: number;
  /** Permissions as a number (0o755); null where there are none (Windows). */
  mode: number | null;
  owner: string;
  group: string;
  /** Target of a link. */
  target?: string;
  /** For a link: does it lead to a folder? */
  linksToDir?: boolean;
  /** Hidden: the name starts with a dot, or Windows marks the file as hidden. */
  hidden?: boolean;
}

/** A folder's content together with the path there. */
export interface Listing {
  path: string;
  /** The path from the root to here, every piece with its path. This PC's root has no name. */
  crumbs: { name: string; path: string }[];
  parent: string | null;
  entries: FileEntry[];
  /** May one write here? */
  writable: boolean;
  /** Only for FTP: what this server can do beyond what every one can. Content search and “Follow” never exist there. */
  ftp?: { chmod: boolean };
}

/**
 * A file's content for editor and preview. `editable` is false if saving would damage the file
 * (only the beginning loaded or not UTF-8).
 */
export type FileContent = { kind: 'text'; text: string; truncated: boolean; editable: boolean } | { kind: 'image'; url: string } | { kind: 'binary' };

export type TransferState = 'queued' | 'running' | 'paused' | 'done' | 'failed' | 'cancelled';

export interface Transfer {
  id: number;
  /** File or folder concerned. */
  name: string;
  direction: 'upload' | 'download' | 'remote';
  /** Source and destination for display: “web-01:/var/www/app”. */
  source: string;
  dest: string;
  bytes: number;
  done: number;
  files: number;
  filesDone: number;
  state: TransferState;
  /** Bytes per second while it runs. */
  speed: number;
  /** Error code if it failed. */
  error?: string;
  /** Was resumed after a cancellation or restart. */
  resumed?: boolean;
}

/** What happens if something with that name already exists at the destination: replace, skip or put it beside (“name (2)”). */
export type Policy = 'overwrite' | 'skip' | 'rename';

export interface TransferRequest {
  from: Place;
  paths: string[];
  to: Place;
  /** Zielordner. */
  dest: string;
  policy: Policy;
  /** How many files may run at the same time. */
  parallel: number;
}

/** A file open in another program and uploaded on every save. */
export interface Watched {
  id: number;
  name: string;
  /** „web-01:/etc/nginx/nginx.conf“ */
  origin: string;
  uploads: number;
  uploadedAt: number | null;
  /** Error code if the last upload failed. */
  error?: string;
}

export interface SearchHit {
  path: string;
  name: string;
  /** Folder the hit is in. */
  dir: string;
  kind: FileKind;
  size: number;
  /** For content search: line number and line. */
  line?: number;
  text?: string;
}

export type DiffState = 'left' | 'right' | 'newerLeft' | 'newerRight' | 'same';

/** A row of the folder sync: the same path below both folders. */
export interface DiffEntry {
  /** Path below the compared folders. */
  rel: string;
  kind: FileKind;
  state: DiffState;
  left: { path: string; size: number; modified: number } | null;
  right: { path: string; size: number; modified: number } | null;
}

export interface ChmodRequest {
  paths: string[];
  /** New permissions; null leaves them as they are. */
  mode: number | null;
  owner: string | null;
  group: string | null;
  recursive: boolean;
}

// ---------- Port-Forwarding ----------

/** local: a port of this PC leads to the server. remote: a port of the server leads here. dynamic: SOCKS proxy on this PC. */
export type ForwardKind = 'local' | 'remote' | 'dynamic';

/** A saved port rule. Stored in the vault; whether it runs is in `ForwardState`. */
export interface Forward {
  id: string;
  /** ID of the vault the entry is in. If missing, it is the personal one. */
  vault?: string;
  name: string;
  kind: ForwardKind;
  /** ID of the host the rule runs through. */
  host: string;
  /** Address that is listened on: on this PC (local, dynamic) or on the server (remote). */
  bindAddress: string;
  bindPort: number;
  /** Where the connections go, seen from the other end. Empty for `dynamic`. */
  destHost: string;
  destPort: number;
}

export interface ForwardInput {
  /** Only when creating: the vault the entry goes into. If missing, it is the personal one. */
  vault?: string;
  id?: string;
  name: string;
  kind: ForwardKind;
  host: string;
  bindAddress: string;
  bindPort: number;
  destHost: string;
  destPort: number;
}

export type ForwardPhase = 'starting' | 'running' | 'retrying' | 'failed';

/** State of a rule switched on. Rules switched off have none. */
export interface ForwardState {
  id: string;
  phase: ForwardPhase;
  /** Error code if it failed or is currently reconnecting. */
  error?: string | null;
  message?: string | null;
  /** Connections open right now and all since switching on. */
  open: number;
  total: number;
  /** Bytes to the destination and back. */
  sent: number;
  received: number;
  /** Since when it has been running, in milliseconds since 1970. */
  since: number | null;
  /** Seconds until the next attempt while it reconnects. */
  retryIn?: number | null;
}

// ---------- Snippets and macros ----------

/** A macro step: wait this long, then send these keys. */
export interface MacroStep {
  /** Milliseconds since the previous step. */
  wait: number;
  keys: string;
}

/**
 * A saved command (`command`, with variables like `{{name}}`) or a recorded macro (`steps`).
 * Stored in the vault.
 */
export interface Snippet {
  id: string;
  /** ID of the vault the entry is in. If missing, it is the personal one. */
  vault?: string;
  name: string;
  /** Name of the package it is in; empty = none. */
  package: string;
  kind: 'command' | 'macro';
  command: string;
  steps: MacroStep[];
  /** Shortcut like “Alt+1” or null. */
  hotkey: string | null;
}

export interface SnippetInput {
  /** Only when creating: the vault the entry goes into. If missing, it is the personal one. */
  vault?: string;
  id?: string;
  name: string;
  package: string;
  kind: 'command' | 'macro';
  command: string;
  steps: MacroStep[];
  hotkey: string | null;
}

/** Result of a command on a host. */
export interface RunResult {
  host: string;
  /** done = ran (see `exit`), failed = did not come about (see `error`). */
  state: 'running' | 'done' | 'failed';
  exit: number | null;
  /** The command's output, error output included. */
  output: string;
  /** Was the output shortened because it was too long? */
  truncated?: boolean;
  error?: string | null;
  /** Duration in milliseconds. */
  ms: number;
}

// ---------- Server-Info ----------

/**
 * A measurement on the server. Counters (`cpu`, `net`) count up since the server started; the load follows
 * from two successive measurements.
 */
export interface StatsSample {
  /** Time of the measurement in milliseconds. */
  at: number;
  /** CPU time in ticks: all together and the idle part of it. */
  cpu: { total: number; idle: number };
  cores: number;
  /** Memory in bytes. */
  mem: { total: number; available: number; swapTotal: number; swapFree: number };
  load: [number, number, number];
  disks: { mount: string; device: string; total: number; used: number }[];
  /** Bytes over all network cards except loopback. */
  net: { rx: number; tx: number };
  /** Seconds since start. */
  uptime: number;
  system: string;
  kernel: string;
  hostname: string;
}

// ---------- Import and export ----------

/** Programs and file formats Glowport imports from. */
export type ImportSource =
  | 'sshconfig'
  | 'putty'
  | 'mobaxterm'
  | 'winscp'
  | 'securecrt'
  | 'mremoteng'
  | 'xshell'
  | 'wterminal'
  | 'nexusssh'
  | 'filezilla'
  | 'knownhosts'
  | 'csv'
  | 'glowport';

/** A source found on this PC. */
export interface ImportFound {
  source: ImportSource;
  /** Where it is: path of a file or folder; empty if it is in the registry. */
  where: string;
  /** How many entries are there; null if only reading shows that. */
  count: number | null;
}

/** Note on an entry: what is not taken over or what to watch out for. The text is derived from `code`. */
export interface ImportNote {
  code: string;
  detail?: string | null;
}

export interface DraftGroup {
  ref: string;
  name: string;
  /** Reference to the parent group in the same draft. */
  parent: string | null;
}

/** A host as the source provides it. References (`group`, `key`, `jump`) point to entries of the same draft. */
export interface DraftHost {
  ref: string;
  name: string;
  /** Address of the server; for `serial` the port's name. */
  address: string;
  /** `ssh`, `telnet` or `serial`. Missing for SSH. */
  protocol?: string;
  group: string | null;
  user: string | null;
  port: number | null;
  os: string | null;
  /** What it signs in with, for display: key, password, agent or none of them. */
  auth: 'key' | 'password' | 'agent' | 'none';
  hasPassword: boolean;
  key: string | null;
  jump: string | null;
  notes: ImportNote[];
  /** ID of a host in the vault with the same address, port and user. */
  existing: string | null;
}

/**
 * A key of the source. `ready`: can be taken into the vault. `encrypted`: needs a passphrase and therefore stays
 * entered as a key file. `missing`: the file no longer exists.
 */
export interface DraftKey {
  ref: string;
  name: string;
  /** Path of the file on this PC; missing if the key is inside the source itself. */
  path: string | null;
  kind: KeyKind | null;
  bits: number | null;
  fingerprint: string | null;
  state: 'ready' | 'encrypted' | 'missing' | 'unreadable';
  /** ID of a key in the vault with the same fingerprint. */
  existing: string | null;
  /** How many hosts of the draft use it. */
  uses: number;
}

export interface DraftForward {
  ref: string;
  name: string;
  kind: ForwardKind;
  /** Reference to the draft's host the rule runs through. */
  host: string;
  bindAddress: string;
  bindPort: number;
  destHost: string;
  destPort: number;
}

export interface DraftSnippet {
  ref: string;
  name: string;
  package: string;
  command: string;
  /** Is there already a snippet with the same command in the vault? */
  existing: boolean;
}

export interface DraftKnownHost {
  ref: string;
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  /** Is this key already in the vault? */
  existing: boolean;
}

/** What a source provides before anything is saved. Passwords and private keys stay in the core. */
export interface ImportDraft {
  /** Number under which the core keeps the draft ready. */
  token: number;
  source: ImportSource;
  /** From where: path of the file or empty for the registry. */
  origin: string;
  groups: DraftGroup[];
  hosts: DraftHost[];
  keys: DraftKey[];
  forwards: DraftForward[];
  snippets: DraftSnippet[];
  knownHosts: DraftKnownHost[];
  /** Entries Glowport cannot take over, with the reason as a code. */
  skipped: { name: string; reason: string }[];
}

export type ImportExisting = 'skip' | 'add' | 'update';

export interface ImportOptions {
  /** References to what is taken over. */
  hosts: string[];
  keys: string[];
  forwards: string[];
  snippets: string[];
  knownHosts: string[];
  /** Where the hosts go: null = top level, `id` = existing group, `name` = new group. */
  into: { id: string } | { name: string } | null;
  /** What happens to hosts that already exist. */
  existing: ImportExisting;
  /** Take key files into the vault instead of only referring to the file. */
  keysToVault: boolean;
  passwords: boolean;
}

export interface ImportReport {
  hosts: number;
  groups: number;
  keys: number;
  forwards: number;
  snippets: number;
  knownHosts: number;
  /** Existing hosts that were updated. */
  updated: number;
  /** Skipped because they already exist. */
  skipped: number;
  /** Keys that stay entered as key files. */
  keyFiles: number;
  failed: { name: string; reason: string }[];
}

export type ExportFormat = 'glowport' | 'sshconfig' | 'csv';

export interface ExportRequest {
  format: ExportFormat;
  /** ID of a group: only it including subgroups; null = everything. */
  group: string | null;
  snippets: boolean;
  forwards: boolean;
  knownHosts: boolean;
}

// ---------- Updates ----------

/** A newer version that can be installed. */
export interface UpdateInfo {
  version: string;
  /** What changed, as plain text. */
  notes: string;
  /** Day of release in milliseconds since 1970; null if unknown. */
  date: number | null;
}

export interface UpdateProgress {
  /** Downloaded bytes and size; the size is missing if the server does not state it. */
  done: number;
  total: number | null;
}

// ── Management in the sidebar: Docker, services, processes (docs/management.md) ─────────────────────

/** What there is to manage on a session's server. */
export interface ManageAbilities {
  /** The session is signed in as root. */
  root: boolean;
  docker: boolean;
  services: boolean;
  processes: boolean;
  /** sudo works without a password. */
  sudo: boolean;
}

/**
 * A list from the server, or why there is none: `password` means it would only work with sudo, and sudo wants
 * a password; `failed` carries the server's message. `sudo`: the list only came about with sudo.
 */
export type Listed<T> = { state: 'ok'; items: T; sudo: boolean } | { state: 'password' } | { state: 'failed'; message: string };

/** Outcome of an action. `password`: sudo wants a password; `command` belongs in the terminal, the user sends it. */
export type ManageDone = { outcome: 'done' } | { outcome: 'password'; command: string };

export interface DockerContainer {
  /** The full ID; only it goes into commands. */
  id: string;
  name: string;
  image: string;
  state: 'running' | 'paused' | 'restarting' | 'exited' | 'created' | 'dead' | 'other';
  health?: 'healthy' | 'unhealthy' | 'starting';
  /** Published ports, e.g. `8080->80/tcp`. */
  ports: string[];
  /** Seconds it has been running; for an exited one the seconds since the end. */
  since?: number;
  exitCode?: number;
  /** Percent of one core. */
  cpu?: number;
  memory?: { used: number; limit: number };
}

export interface ServiceUnit {
  /** The full name, e.g. `cron.service`. */
  unit: string;
  description: string;
  active: 'active' | 'inactive' | 'failed' | 'activating' | 'deactivating' | 'other';
  /** systemd's finer state: `running`, `exited`, `dead` … */
  sub: string;
  /** Whether it starts along with the server. */
  enabled: 'enabled' | 'disabled' | 'static' | 'masked' | 'other';
}

export interface ProcessInfo {
  pid: number;
  parent: number;
  user: string;
  /** The program without path and arguments. */
  name: string;
  command: string;
  /** Memory in bytes. */
  memory: number;
  /** Seconds it has been running. */
  elapsed: number;
  /** CPU time used since its start, in ticks. */
  ticks: number;
  /** A kernel thread, not a program. */
  kernel: boolean;
}

/** A measurement of the processes. The load follows from two measurements. */
export interface ProcessSample {
  ticksPerSecond: number;
  /** Seconds since the server started. */
  uptime: number;
  memoryTotal: number;
  processes: ProcessInfo[];
}

// ── Proxmox (docs/verwaltung.md) ───────────────────────────────────────────────────────────────────────

/** A connection to a Proxmox server. The token's secret never leaves the core. */
export interface ProxmoxConnection {
  id: string;
  name: string;
  /** `https://pve.example.de:8006` */
  address: string;
  /** `user@realm!name` */
  tokenId: string;
  /** The confirmed fingerprint of a self-signed certificate. If missing, the certificate must be trusted. */
  fingerprint?: string;
  /** The identity Glowport signs in to the machines with for which Cloud-Init names no key from the vault. */
  identity?: string;
}

export interface ProxmoxInput {
  id?: string;
  name: string;
  address: string;
  tokenId: string;
  /** Missing = stays as it is. */
  secret?: string;
  fingerprint?: string;
  /** Missing = none. */
  identity?: string;
}

/**
 * What a check of the details found. It runs in two steps: for a self-signed certificate the
 * first only names the fingerprint (`version` is empty, the token has not gone out yet). Only when the input
 * brings exactly this fingerprint along, because the user confirmed it, does the second read version and permissions.
 */
export interface ProxmoxProbe {
  version: string;
  /** The certificate is trusted on its own (e.g. from Let's Encrypt). */
  trusted: boolean;
  /** SHA-256 of the certificate, for comparing with the Proxmox interface. */
  fingerprint: string;
  /** What the token lacks: seeing, switching on and off, asking the guest agent. */
  missing: ('audit' | 'power' | 'agent')[];
  /** The server shows a different certificate than the one confirmed so far. */
  changed?: boolean;
}

/** Which machine a host belongs to. */
export interface ProxmoxLink {
  connection: string;
  node: string;
  vmid: number;
  kind: 'qemu' | 'lxc';
}

export interface ProxmoxNode {
  node: string;
  online: boolean;
  /** 0 to 1 */
  cpu?: number;
  cores?: number;
  memory?: { used: number; total: number };
  uptime?: number;
}

export interface ProxmoxGuest {
  node: string;
  vmid: number;
  /** `qemu`: a VM. `lxc`: a container. */
  kind: 'qemu' | 'lxc';
  name: string;
  status: 'running' | 'stopped' | 'paused' | 'unknown';
  template: boolean;
  /** 0 to 1 */
  cpu?: number;
  cores?: number;
  memory?: { used: number; total: number };
  uptime?: number;
  tags: string[];
  /** The address at which Glowport reaches the machine, and where it knows it from. */
  address?: string;
  source?: 'cloudinit' | 'agent' | 'config' | 'guest';
  user?: string;
  /** The key in the vault that a public key stored in Cloud-Init belongs to. */
  key?: string;
  keyName?: string;
  os?: string;
  /** ID of the host that belongs to this machine. */
  host?: string;
}

export interface ProxmoxOverview {
  version: string;
  nodes: ProxmoxNode[];
  guests: ProxmoxGuest[];
}
