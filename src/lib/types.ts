// Formen der Daten, die zwischen Oberfläche und Kern wandern. Gegenstück: crates/core/src/directory.rs.

export type Reconnect = 'notice' | 'auto';

/** Vererbbare Werte. Fehlt ein Feld, kommt der Wert von weiter oben. */
export interface Fields {
  user?: string;
  port?: number;
  /** Kennung des Sprung-Servers; leer = ausdrücklich keiner. */
  jump?: string;
  startcmd?: string;
  reconnect?: Reconnect;
  /** Pfad einer Schlüsseldatei auf diesem Rechner. */
  keyFile?: string;
  /** Kennung einer Identität; leer = ausdrücklich keine. */
  identity?: string;
  /** Kennung eines Schlüssels im Tresor; leer = ausdrücklich keiner. */
  key?: string;
  /** Umgebungsvariablen wie bei `SetEnv`: `NAME=wert`, mehrere durch Leerzeichen getrennt. */
  env?: string;
  /** Schlüssel aus einem SSH-Agenten dieses Rechners anbieten. */
  agent?: boolean;
  /** Den Agenten an den Server weiterreichen. Wirkt nur zusammen mit `agent`. */
  agentForward?: boolean;
  /** `http://adresse:port` oder `socks5://adresse:port`; leer = ausdrücklich keiner. */
  proxy?: string;
  /** Sekunden zwischen Lebenszeichen; 0 = aus. */
  keepalive?: number;
  /** Sekunden, die auf die Verbindung gewartet wird. */
  timeout?: number;
  term?: string;
  charset?: string;
  /** Auch alte, heute schwache Verfahren anbieten. */
  legacy?: boolean;
  /** Kennung eines Farbschemas für das Terminal. */
  scheme?: string;
  /** Das Terminal über Mosh statt über SSH führen. Angemeldet wird weiter per SSH. */
  mosh?: boolean;
  /** Lokales Echo von Mosh: zeigt Getipptes, bevor der Server es bestätigt. */
  moshPredict?: MoshPredict;
  /** UDP-Port oder Bereich für `mosh-server`, etwa `60001` oder `60001:60010`. */
  moshPort?: string;
  /** Pfad zu `mosh-server` auf dem Server, wenn er nicht im Suchpfad liegt. */
  moshServer?: string;
}

export type MoshPredict = 'adaptive' | 'always' | 'never';
/** Warum eine Sitzung statt über Mosh per SSH läuft. */
export type MoshFallback = 'missing' | 'ipv6' | 'udp' | 'server';

export type FieldKey = keyof Fields;

export interface Group {
  id: string;
  /** Kennung des Tresors, in dem der Eintrag liegt. Fehlt sie, ist es der persönliche. */
  vault?: string;
  name: string;
  parent: string | null;
  color: string | null;
  defs: Fields;
  /** Ist für den Proxy der Gruppe ein Passwort hinterlegt? Es selbst verlässt den Kern nicht. */
  hasProxyPassword?: boolean;
}

/** Wie ein Host angesprochen wird. Fehlt etwas Unbekanntes aus einer neueren Fassung, gilt es als `ssh`. */
export type Protocol = 'ssh' | 'telnet' | 'serial' | 'ftp';

/**
 * Einstellungen eines FTP-Hosts. `explicit` beginnt offen und schaltet vor der Anmeldung auf TLS um (Port 21),
 * `implicit` spricht von Anfang an TLS (Port 990), `none` bleibt unverschlüsselt.
 */
export interface FtpSettings {
  security: 'explicit' | 'implicit' | 'none';
  /** Ohne Benutzer und Passwort anmelden. */
  anonymous: boolean;
  /** Ordner, in dem der Dateimanager beginnt; leer ist der, den der Server vorgibt. */
  dir?: string;
  /** Die Rückfrage vor einer unverschlüsselten Verbindung ist für diesen Host abbestellt. */
  plainOk?: boolean;
}

/** Einstellungen einer seriellen Leitung. Das übliche „9600 8N1“ sind 9600 Baud, 8 Datenbits, keine Parität, 1 Stoppbit. */
export interface SerialSettings {
  baud: number;
  dataBits: 5 | 6 | 7 | 8;
  parity: 'none' | 'odd' | 'even';
  stopBits: 1 | 2;
  /** Flusskontrolle: keine, XON/XOFF oder RTS/CTS. */
  flow: 'none' | 'software' | 'hardware';
}

export interface Host {
  id: string;
  /** Kennung des Tresors, in dem der Eintrag liegt. Fehlt sie, ist es der persönliche. */
  vault?: string;
  name: string;
  /** Adresse des Servers; bei `serial` der Name des Ports (`COM3`). */
  address: string;
  group: string | null;
  protocol: string;
  /** Nur bei `serial`. */
  serial?: SerialSettings | null;
  /** Nur bei `ftp`. */
  ftp?: FtpSettings | null;
  color: string | null;
  os: string | null;
  own: Fields;
  /** Das Passwort selbst verlässt den Kern nicht. */
  hasPassword: boolean;
  hasProxyPassword?: boolean;
  /** Die Maschine in Proxmox, zu der dieser Host gehört. Glowport hält seine Adresse und seinen Namen danach aktuell. */
  proxmox?: ProxmoxLink;
}

export interface KnownHost {
  id: string;
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  /** Millisekunden seit 1970. */
  addedAt: number;
}

export type KeyKind = 'ed25519' | 'ecdsa' | 'rsa';

/** Ein Schlüsselpaar im Tresor. Der private Teil verlässt den Kern nur beim ausdrücklichen Export. */
export interface SshKey {
  id: string;
  /** Kennung des Tresors, in dem der Eintrag liegt. Fehlt sie, ist es der persönliche. */
  vault?: string;
  name: string;
  kind: KeyKind;
  /** Länge in Bit: Ed25519 256, ECDSA 256/384/521, RSA 3072/4096. */
  bits: number;
  fingerprint: string;
  /** Eine Zeile im OpenSSH-Format, so wie sie in `authorized_keys` steht. */
  publicKey: string;
  origin: 'generated' | 'imported';
  /** Millisekunden seit 1970. */
  addedAt: number;
  certificate?: KeyCertificate | null;
}

/** Benutzer-Zertifikat zu einem Schlüssel: Eine Zertifizierungsstelle bestätigt, wem er gehört. Zeiten in Sekunden seit 1970. */
export interface KeyCertificate {
  text: string;
  keyId: string;
  /** Benutzernamen, für die es gilt; leer = für jeden. */
  principals: string[];
  validAfter: number;
  /** Fehlt, wenn es nicht abläuft. */
  validBefore?: number | null;
  /** Fingerabdruck der Zertifizierungsstelle. */
  authority: string;
}

/** Benutzer plus Schlüssel und/oder Passwort, für viele Hosts verwendbar. */
export interface Identity {
  id: string;
  /** Kennung des Tresors, in dem der Eintrag liegt. Fehlt sie, ist es der persönliche. */
  vault?: string;
  name: string;
  user: string;
  /** Kennung eines Schlüssels im Tresor. */
  key: string | null;
  /** Das Passwort selbst verlässt den Kern nicht. */
  hasPassword: boolean;
}

/** Eine Zertifizierungsstelle, deren Zertifikate für Server gelten. */
export interface Authority {
  id: string;
  name: string;
  /** Adressen, für die sie gilt: Muster mit `*` und `?`, mehrere durch Komma getrennt. */
  pattern: string;
  /** Art des Schlüssels zum Anzeigen. */
  kind: string;
  fingerprint: string;
  /** Millisekunden seit 1970. */
  addedAt: number;
}

/** Eine laufende Sitzung, die mit ihrem Bereich in ein anderes Fenster umzieht. */
export interface Moving {
  /** Nummer der Sitzung im Kern. */
  session: number;
  /** Bisheriger Inhalt des Terminals als Folge von Steuerzeichen, die ihn wieder aufbaut. */
  content: string;
}

/** Ein Bereich eines gespeicherten Tabs: sein Ziel und, nur beim Umzug in ein anderes Fenster, seine laufende Sitzung. */
export interface SavedPane {
  pane: Target;
  moving?: Moving;
  recording?: boolean;
}

/** Was ein gespeicherter Tab zeigt: seine Bereiche in ihrer Anordnung, jeder mit seinem Ziel. */
export type SavedLayout = SavedPane | { dir: 'row' | 'col'; ratio: number; a: SavedLayout; b: SavedLayout };

/** Ein Tab, wie er sich wieder öffnen lässt: nach einem Abbruch, in einem eigenen Fenster oder als Arbeitsbereich. */
export interface SavedTab {
  name: string | null;
  color: string | null;
  /** Multi-Exec: Eingaben gehen an alle Bereiche des Tabs. */
  multi: boolean;
  layout: SavedLayout;
}

/** Mehrere Hosts in fester Anordnung, mit einem Klick zu öffnen. Liegt im Tresor. */
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

/** Ein Mitschnitt: die Ausgabe einer Sitzung als Datei auf diesem Rechner. Zeiten in Millisekunden seit 1970. */
export interface Recording {
  id: string;
  /** Name des Hosts oder die eingetippte Adresse. */
  name: string;
  /** Eigener Name, den der Nutzer dem Mitschnitt nachträglich gegeben hat. */
  title?: string | null;
  address: string;
  startedAt: number;
  /** Fehlt, solange der Mitschnitt läuft. */
  endedAt: number | null;
  bytes: number;
  /** Pfad der Datei. */
  file: string;
}

export interface Snapshot {
  /** Laufende Nummer des Stands: Ein später erzeugter hat die höhere. Die Vorschau im Browser kennt sie nicht. */
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
  /** Alle Tresore dieses Geräts, der persönliche zuerst. */
  vaults?: VaultInfo[];
  /** Verbindungen zu Proxmox. Sie liegen im persönlichen Tresor. */
  proxmox?: ProxmoxConnection[];
  /** Für jeden Eintrag, der in einem geteilten Tresor liegt: dessen Kennung. Alles andere liegt im persönlichen. */
  homes?: Record<string, string>;
}

export type VaultRole = 'owner' | 'write' | 'read';

export interface VaultMember {
  account: string;
  name: string;
  role: VaultRole;
  /** Das eigene Konto. */
  me: boolean;
  /** Eingeladen, hat aber noch nicht angenommen. */
  invited: boolean;
  /** Sicherheitscode des Kontos: sechs Wörter aus einem Prüfwert seiner Schlüssel. */
  code: string;
}

export interface VaultInfo {
  id: string;
  kind: 'personal' | 'shared';
  /** Name des Tresors; beim persönlichen leer. */
  name: string;
  /** Die eigene Rolle. */
  role: VaultRole;
  members: VaultMember[];
  /** Der Server hat einen älteren Stand als dieses Gerät; der Tresor ruht, bis jemand entscheidet. */
  rolledBack?: boolean;
  /** Ein eigener Tresor, den der Server nicht mehr kennt. */
  orphaned?: boolean;
}

export type SyncPhase = 'syncing' | 'synced' | 'offline' | 'signedOut' | 'error';

export interface SyncInvitation {
  vault: string;
  name: string | null;
  owner: string;
  role: VaultRole;
  /** Sicherheitscode des Besitzers. */
  code: string;
  known: 'new' | 'same' | 'changed';
}

/** Stand des Abgleichs. Nicht verbunden: `linked` ist false, der Rest leer. */
export interface SyncState {
  linked: boolean;
  server: string;
  username: string;
  /** Verwaltet dieses Konto den Server? */
  admin: boolean;
  phase: SyncPhase;
  /** Grund, wenn `phase` „error“ oder „signedOut“ ist. */
  error?: string;
  /** Änderungen, die noch nicht beim Server sind. */
  pending: number;
  /** Wann zuletzt alles abgeglichen war, in Millisekunden seit 1970. */
  syncedAt: number | null;
  /** Der eigene Sicherheitscode. */
  code: string;
  invitations: SyncInvitation[];
  /** Zahl der Hinweise aus dem Abgleich. */
  notices: number;
  /** Das Master-Passwort wurde auf einem anderen Gerät geändert. */
  passwordChanged: boolean;
}

export interface SyncServerInfo {
  /** Die Adresse in fester Form. */
  server: string;
  /** Der Server wartet auf sein erstes Konto (es wird Verwalter und braucht den Einrichtungscode). */
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
  /** Name des Tresors, soweit noch bekannt. */
  vaultName: string;
  /** Name des betroffenen Eintrags, soweit noch bekannt. */
  recordName?: string;
  /** Das Feld, um das es ging, etwa `own.port`. */
  path?: string;
  /** Der eigene Wert gilt. */
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
  /** Einladungscode, beim ersten Konto der Einrichtungscode. */
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
  /** Nur auf einem Gerät, das schon einen Tresor hat: Was geschieht mit dessen Einträgen? */
  local?: 'keep' | 'discard';
}

/**
 * Wohin eine Sitzung führt: zu einem gespeicherten Host (SSH, Telnet oder seriell), zu einer eingetippten Adresse
 * (`direct` = SSH, `telnet`) oder in eine Shell dieses PCs (`local`, `shell` ist die Kennung aus `LocalShell`).
 */
export type Target =
  | { kind: 'host'; id: string }
  // `identity` und `key`: Identität oder Schlüssel aus dem Tresor, mit denen sich die Schnellverbindung anmeldet.
  | { kind: 'direct'; user: string; host: string; port: number; identity?: string; key?: string; mosh?: boolean }
  | { kind: 'telnet'; host: string; port: number }
  | { kind: 'local'; shell: string };

/** Eine Shell, die Glowport auf diesem PC gefunden hat und als lokales Terminal öffnen kann. */
export interface LocalShell {
  /** Bleibt über Neustarts gleich: `pwsh`, `powershell`, `cmd`, `gitbash`, `wsl:Ubuntu`. */
  id: string;
  name: string;
  kind: 'pwsh' | 'powershell' | 'cmd' | 'gitbash' | 'wsl';
  /** Zum Anzeigen: Pfad des Programms oder Name der Distribution. */
  detail: string;
}

/** Ein serieller Port dieses PCs. */
export interface SerialPortInfo {
  /** `COM3` */
  name: string;
  /** Was daran hängt, soweit Windows es nennt: „USB-SERIAL CH340“. */
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
  /** Fingerabdrücke, die bisher für diese Adresse hinterlegt waren. */
  known: string[];
}

export interface SecretPrompt {
  type: 'secret';
  kind: 'password' | 'passphrase';
  attempt: number;
  file: string | null;
  canSave: boolean;
  /** Gesetzt, wenn ein Sprung-Server fragt und nicht das Ziel: `benutzer@adresse`. */
  station?: string | null;
}

export interface InteractivePrompt {
  type: 'interactive';
  name: string;
  instructions: string;
  prompts: { text: string; echo: boolean }[];
  station?: string | null;
}

/** Das Zertifikat eines FTP-Servers, dem dieser Rechner nicht von sich aus traut. `changed`: Es ist ein anderes als das bestätigte. */
export interface CertificatePrompt {
  type: 'certificate';
  host: string;
  port: number;
  /** SHA-256 über das Zertifikat, wie Browser ihn zeigen: `5F:1A:…`. */
  fingerprint: string;
  changed: boolean;
}

/** Vor einer unverschlüsselten FTP-Verbindung. `offersTls`: Der Server könnte TLS. */
export interface PlainPrompt {
  type: 'plain';
  host: string;
  offersTls: boolean;
  /** Die Frage lässt sich für diesen Host abbestellen; bei einer Schnellverbindung gibt es dafür keinen Host. */
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
  /** Der Ordner, in dem die Shell gerade steht. */
  | { type: 'cwd'; path: string }
  /** Das Terminal läuft über Mosh. */
  | { type: 'mosh'; state: 'active' }
  /** Mosh kam nicht zustande; die Sitzung läuft per SSH weiter. `detail`: erste Zeile einer Fehlermeldung des Servers. */
  | { type: 'mosh'; state: 'fallback'; reason: MoshFallback; detail?: string }
  /** Mosh: Sekunden ohne Nachricht vom Server; null, sobald er wieder antwortet. */
  | { type: 'reach'; silent: number | null }
  /** Mosh: Steht die SSH-Verbindung daneben für Seitenleiste und Dateien? */
  | { type: 'side'; linked: boolean }
  | Prompt
  | SessionEnd
);

export type Answer =
  | { kind: 'hostKey'; accept: boolean }
  | { kind: 'secret'; value?: string; save?: boolean }
  | { kind: 'interactive'; values?: string[] }
  | { kind: 'certificate'; accept: boolean }
  /** `remember` bestellt die Rückfrage für diesen Host ab; `secure` stellt ihn stattdessen auf FTPS um. */
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
  /** Ob der Tresor beim Start ohne Master-Passwort geöffnet wird. */
  startUnlock?: boolean;
}

export interface Changed {
  id?: string;
  data: Snapshot;
}

export interface HostInput {
  /** Nur beim Anlegen: der Tresor, in den der Eintrag kommt. Fehlt er, ist es der persönliche. */
  vault?: string;
  id?: string;
  name: string;
  address: string;
  /** Fehlt = bleibt, wie es ist; bei einem neuen Host `ssh`. */
  protocol?: Protocol;
  /** Fehlt = bleibt, wie es ist. Zählt nur bei `serial`. */
  serial?: SerialSettings;
  /** Fehlt = bleibt, wie es ist. Zählt nur bei `ftp`. */
  ftp?: FtpSettings;
  group: string | null;
  color: string | null;
  os: string | null;
  own: Fields;
  /** Fehlt = unverändert, null = entfernen, Text = setzen. */
  password?: string | null;
  /** Passwort für den Proxy des Hosts, mit denselben Regeln. */
  proxyPassword?: string | null;
}

export interface GroupInput {
  /** Nur beim Anlegen: der Tresor, in den der Eintrag kommt. Fehlt er, ist es der persönliche. */
  vault?: string;
  id?: string;
  name: string;
  parent: string | null;
  color: string | null;
  defs: Fields;
  proxyPassword?: string | null;
}

export interface KeyGenerate {
  /** Nur beim Anlegen: der Tresor, in den der Eintrag kommt. Fehlt er, ist es der persönliche. */
  vault?: string;
  name: string;
  kind: KeyKind;
  bits: number;
}

export interface KeyImport {
  /** Nur beim Anlegen: der Tresor, in den der Eintrag kommt. Fehlt er, ist es der persönliche. */
  vault?: string;
  name: string;
  /** Inhalt der Schlüsseldatei: OpenSSH, PEM oder PuTTY (.ppk). */
  text: string;
  passphrase?: string;
}

/** Was der Kern in einer Schlüsseldatei erkennt, bevor sie importiert wird. */
export interface KeyInfo {
  /** Art, Länge und Fingerabdruck fehlen, solange die Datei verschlüsselt ist und ihr Format sie nicht offen nennt. */
  kind: KeyKind | null;
  bits: number | null;
  fingerprint: string | null;
  encrypted: boolean;
  format: 'openssh' | 'pem' | 'ppk';
  comment: string;
}

/** Eine vom Nutzer gewählte Schlüsseldatei samt Inhalt. */
export interface KeyFile {
  path: string;
  text: string;
}

export interface IdentityInput {
  /** Nur beim Anlegen: der Tresor, in den der Eintrag kommt. Fehlt er, ist es der persönliche. */
  vault?: string;
  id?: string;
  name: string;
  user: string;
  key: string | null;
  /** Fehlt = unverändert, null = entfernen, Text = setzen. */
  password?: string | null;
}

/** Ergebnis je Host beim Kopieren eines öffentlichen Schlüssels. */
export interface DeployResult {
  host: string;
  /** added = eingetragen, present = stand schon dort, failed = siehe `message` */
  outcome: 'added' | 'present' | 'failed';
  message?: string | null;
}

/** Ein SSH-Agent auf diesem Rechner und die Schlüssel, die er anbietet. */
export interface Agent {
  kind: 'openssh' | 'pageant';
  running: boolean;
  keys: { comment: string; kind: string; fingerprint: string }[];
}

/** Wo Dateien liegen: auf diesem PC, auf einem gespeicherten Host oder am Server einer laufenden Sitzung. */
/** Ein FTP-Server aus der Schnellverbindung, den der Tresor nicht kennt. Ein leerer Benutzer meldet anonym an. */
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
  /** Voller Pfad, wie ihn der Kern versteht. Die Oberfläche setzt Pfade nie selbst zusammen. */
  path: string;
  kind: FileKind;
  size: number;
  /** Zeitpunkt der letzten Änderung in Millisekunden. */
  modified: number;
  /** Rechte als Zahl (0o755); null, wo es keine gibt (Windows). */
  mode: number | null;
  owner: string;
  group: string;
  /** Ziel einer Verknüpfung. */
  target?: string;
  /** Bei einer Verknüpfung: Führt sie zu einem Ordner? */
  linksToDir?: boolean;
  /** Versteckt: Der Name beginnt mit einem Punkt, oder Windows führt die Datei als versteckt. */
  hidden?: boolean;
}

/** Inhalt eines Ordners samt dem Weg dorthin. */
export interface Listing {
  path: string;
  /** Der Weg von der Wurzel bis hierher, jedes Stück mit seinem Pfad. Die Wurzel dieses PCs hat keinen Namen. */
  crumbs: { name: string; path: string }[];
  parent: string | null;
  entries: FileEntry[];
  /** Darf hier geschrieben werden? */
  writable: boolean;
  /** Nur bei FTP: was dieser Server über das hinaus kann, was jeder kann. Suche im Inhalt und „Folgen“ gibt es dort nie. */
  ftp?: { chmod: boolean };
}

/**
 * Inhalt einer Datei für Editor und Vorschau. `editable` ist falsch, wenn Speichern die Datei beschädigen würde
 * (nur der Anfang geladen oder kein UTF-8).
 */
export type FileContent = { kind: 'text'; text: string; truncated: boolean; editable: boolean } | { kind: 'image'; url: string } | { kind: 'binary' };

export type TransferState = 'queued' | 'running' | 'paused' | 'done' | 'failed' | 'cancelled';

export interface Transfer {
  id: number;
  /** Datei oder Ordner, um den es geht. */
  name: string;
  direction: 'upload' | 'download' | 'remote';
  /** Quelle und Ziel zum Anzeigen: „web-01:/var/www/app“. */
  source: string;
  dest: string;
  bytes: number;
  done: number;
  files: number;
  filesDone: number;
  state: TransferState;
  /** Bytes je Sekunde, solange er läuft. */
  speed: number;
  /** Fehlercode, wenn er gescheitert ist. */
  error?: string;
  /** Wurde nach einem Abbruch oder Neustart fortgesetzt. */
  resumed?: boolean;
}

/** Was geschieht, wenn es am Ziel schon etwas unter dem Namen gibt: ersetzen, auslassen oder daneben legen („name (2)“). */
export type Policy = 'overwrite' | 'skip' | 'rename';

export interface TransferRequest {
  from: Place;
  paths: string[];
  to: Place;
  /** Zielordner. */
  dest: string;
  policy: Policy;
  /** Wie viele Dateien gleichzeitig laufen dürfen. */
  parallel: number;
}

/** Eine Datei, die in einem anderen Programm offen ist und bei jedem Speichern hochgeladen wird. */
export interface Watched {
  id: number;
  name: string;
  /** „web-01:/etc/nginx/nginx.conf“ */
  origin: string;
  uploads: number;
  uploadedAt: number | null;
  /** Fehlercode, wenn das letzte Hochladen gescheitert ist. */
  error?: string;
}

export interface SearchHit {
  path: string;
  name: string;
  /** Ordner, in dem der Treffer liegt. */
  dir: string;
  kind: FileKind;
  size: number;
  /** Bei der Suche im Inhalt: Zeilennummer und Zeile. */
  line?: number;
  text?: string;
}

export type DiffState = 'left' | 'right' | 'newerLeft' | 'newerRight' | 'same';

/** Eine Zeile des Ordner-Abgleichs: derselbe Pfad unterhalb beider Ordner. */
export interface DiffEntry {
  /** Pfad unterhalb der verglichenen Ordner. */
  rel: string;
  kind: FileKind;
  state: DiffState;
  left: { path: string; size: number; modified: number } | null;
  right: { path: string; size: number; modified: number } | null;
}

export interface ChmodRequest {
  paths: string[];
  /** Neue Rechte; null lässt sie, wie sie sind. */
  mode: number | null;
  owner: string | null;
  group: string | null;
  recursive: boolean;
}

// ---------- Port-Forwarding ----------

/** local: Port dieses PCs führt zum Server. remote: Port des Servers führt hierher. dynamic: SOCKS-Proxy auf diesem PC. */
export type ForwardKind = 'local' | 'remote' | 'dynamic';

/** Eine gespeicherte Port-Regel. Liegt im Tresor; ob sie läuft, steht in `ForwardState`. */
export interface Forward {
  id: string;
  /** Kennung des Tresors, in dem der Eintrag liegt. Fehlt sie, ist es der persönliche. */
  vault?: string;
  name: string;
  kind: ForwardKind;
  /** Kennung des Hosts, über den die Regel läuft. */
  host: string;
  /** Adresse, an der gelauscht wird: auf diesem PC (local, dynamic) oder am Server (remote). */
  bindAddress: string;
  bindPort: number;
  /** Wohin die Verbindungen gehen, vom anderen Ende aus gesehen. Bei `dynamic` leer. */
  destHost: string;
  destPort: number;
}

export interface ForwardInput {
  /** Nur beim Anlegen: der Tresor, in den der Eintrag kommt. Fehlt er, ist es der persönliche. */
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

/** Stand einer eingeschalteten Regel. Ausgeschaltete Regeln haben keinen. */
export interface ForwardState {
  id: string;
  phase: ForwardPhase;
  /** Fehlercode, wenn sie gescheitert ist oder gerade neu verbindet. */
  error?: string | null;
  message?: string | null;
  /** Gerade offene Verbindungen und alle seit dem Einschalten. */
  open: number;
  total: number;
  /** Bytes zum Ziel und zurück. */
  sent: number;
  received: number;
  /** Seit wann sie läuft, in Millisekunden seit 1970. */
  since: number | null;
  /** Sekunden bis zum nächsten Versuch, solange sie neu verbindet. */
  retryIn?: number | null;
}

// ---------- Snippets und Makros ----------

/** Ein Schritt eines Makros: so lange warten, dann diese Tasten schicken. */
export interface MacroStep {
  /** Millisekunden seit dem vorigen Schritt. */
  wait: number;
  keys: string;
}

/**
 * Ein gespeicherter Befehl (`command`, mit Variablen wie `{{name}}`) oder ein aufgezeichnetes Makro (`steps`).
 * Liegt im Tresor.
 */
export interface Snippet {
  id: string;
  /** Kennung des Tresors, in dem der Eintrag liegt. Fehlt sie, ist es der persönliche. */
  vault?: string;
  name: string;
  /** Name des Pakets, in dem es liegt; leer = keines. */
  package: string;
  kind: 'command' | 'macro';
  command: string;
  steps: MacroStep[];
  /** Tastenkürzel wie „Alt+1“ oder null. */
  hotkey: string | null;
}

export interface SnippetInput {
  /** Nur beim Anlegen: der Tresor, in den der Eintrag kommt. Fehlt er, ist es der persönliche. */
  vault?: string;
  id?: string;
  name: string;
  package: string;
  kind: 'command' | 'macro';
  command: string;
  steps: MacroStep[];
  hotkey: string | null;
}

/** Ergebnis eines Befehls auf einem Host. */
export interface RunResult {
  host: string;
  /** done = gelaufen (siehe `exit`), failed = nicht zustande gekommen (siehe `error`). */
  state: 'running' | 'done' | 'failed';
  exit: number | null;
  /** Ausgabe des Befehls, Fehlerausgabe eingeschlossen. */
  output: string;
  /** Wurde die Ausgabe gekürzt, weil sie zu lang war? */
  truncated?: boolean;
  error?: string | null;
  /** Dauer in Millisekunden. */
  ms: number;
}

// ---------- Server-Info ----------

/**
 * Eine Messung am Server. Zähler (`cpu`, `net`) laufen seit dem Start des Servers hoch; die Auslastung ergibt sich
 * aus zwei Messungen nacheinander.
 */
export interface StatsSample {
  /** Zeitpunkt der Messung in Millisekunden. */
  at: number;
  /** Rechenzeit in Ticks: alle zusammen und davon untätig. */
  cpu: { total: number; idle: number };
  cores: number;
  /** Speicher in Bytes. */
  mem: { total: number; available: number; swapTotal: number; swapFree: number };
  load: [number, number, number];
  disks: { mount: string; device: string; total: number; used: number }[];
  /** Bytes über alle Netzwerkkarten außer der Schleife. */
  net: { rx: number; tx: number };
  /** Sekunden seit dem Start. */
  uptime: number;
  system: string;
  kernel: string;
  hostname: string;
}

// ---------- Import und Export ----------

/** Programme und Dateiformate, aus denen Glowport importiert. */
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

/** Eine Quelle, die auf diesem PC gefunden wurde. */
export interface ImportFound {
  source: ImportSource;
  /** Wo sie liegt: Pfad einer Datei oder eines Ordners; leer, wenn sie in der Registry steht. */
  where: string;
  /** Wie viele Einträge dort liegen; null, wenn das erst das Lesen zeigt. */
  count: number | null;
}

/** Hinweis zu einem Eintrag: Was nicht übernommen wird oder worauf zu achten ist. Der Text entsteht aus `code`. */
export interface ImportNote {
  code: string;
  detail?: string | null;
}

export interface DraftGroup {
  ref: string;
  name: string;
  /** Verweis auf die übergeordnete Gruppe im selben Entwurf. */
  parent: string | null;
}

/** Ein Host, wie ihn die Quelle hergibt. Verweise (`group`, `key`, `jump`) zeigen auf Einträge desselben Entwurfs. */
export interface DraftHost {
  ref: string;
  name: string;
  /** Adresse des Servers; bei `serial` der Name des Ports. */
  address: string;
  /** `ssh`, `telnet` oder `serial`. Fehlt bei SSH. */
  protocol?: string;
  group: string | null;
  user: string | null;
  port: number | null;
  os: string | null;
  /** Womit er sich anmeldet, zum Anzeigen: Schlüssel, Passwort, Agent oder nichts davon. */
  auth: 'key' | 'password' | 'agent' | 'none';
  hasPassword: boolean;
  key: string | null;
  jump: string | null;
  notes: ImportNote[];
  /** Kennung eines Hosts im Tresor mit derselben Adresse, demselben Port und Benutzer. */
  existing: string | null;
}

/**
 * Ein Schlüssel der Quelle. `ready`: lässt sich in den Tresor holen. `encrypted`: braucht eine Passphrase und bleibt
 * deshalb als Schlüsseldatei eingetragen. `missing`: Die Datei gibt es nicht mehr.
 */
export interface DraftKey {
  ref: string;
  name: string;
  /** Pfad der Datei auf diesem PC; fehlt, wenn der Schlüssel in der Quelle selbst steckt. */
  path: string | null;
  kind: KeyKind | null;
  bits: number | null;
  fingerprint: string | null;
  state: 'ready' | 'encrypted' | 'missing' | 'unreadable';
  /** Kennung eines Schlüssels im Tresor mit demselben Fingerabdruck. */
  existing: string | null;
  /** Wie viele Hosts des Entwurfs ihn benutzen. */
  uses: number;
}

export interface DraftForward {
  ref: string;
  name: string;
  kind: ForwardKind;
  /** Verweis auf den Host des Entwurfs, über den die Regel läuft. */
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
  /** Gibt es im Tresor schon ein Snippet mit demselben Befehl? */
  existing: boolean;
}

export interface DraftKnownHost {
  ref: string;
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  /** Steht dieser Schlüssel schon im Tresor? */
  existing: boolean;
}

/** Was eine Quelle hergibt, bevor irgendetwas gespeichert ist. Passwörter und private Schlüssel bleiben im Kern. */
export interface ImportDraft {
  /** Nummer, unter der der Kern den Entwurf bereithält. */
  token: number;
  source: ImportSource;
  /** Woher: Pfad der Datei oder leer für die Registry. */
  origin: string;
  groups: DraftGroup[];
  hosts: DraftHost[];
  keys: DraftKey[];
  forwards: DraftForward[];
  snippets: DraftSnippet[];
  knownHosts: DraftKnownHost[];
  /** Einträge, die Glowport nicht übernehmen kann, mit dem Grund als Code. */
  skipped: { name: string; reason: string }[];
}

export type ImportExisting = 'skip' | 'add' | 'update';

export interface ImportOptions {
  /** Verweise auf das, was übernommen wird. */
  hosts: string[];
  keys: string[];
  forwards: string[];
  snippets: string[];
  knownHosts: string[];
  /** Wohin die Hosts kommen: null = oberste Ebene, `id` = vorhandene Gruppe, `name` = neue Gruppe. */
  into: { id: string } | { name: string } | null;
  /** Was mit Hosts geschieht, die es schon gibt. */
  existing: ImportExisting;
  /** Schlüsseldateien in den Tresor holen, statt nur auf die Datei zu verweisen. */
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
  /** Vorhandene Hosts, die aktualisiert wurden. */
  updated: number;
  /** Ausgelassen, weil schon vorhanden. */
  skipped: number;
  /** Schlüssel, die als Schlüsseldatei eingetragen bleiben. */
  keyFiles: number;
  failed: { name: string; reason: string }[];
}

export type ExportFormat = 'glowport' | 'sshconfig' | 'csv';

export interface ExportRequest {
  format: ExportFormat;
  /** Kennung einer Gruppe: nur sie samt Untergruppen; null = alles. */
  group: string | null;
  snippets: boolean;
  forwards: boolean;
  knownHosts: boolean;
}

// ---------- Updates ----------

/** Eine neuere Version, die sich installieren lässt. */
export interface UpdateInfo {
  version: string;
  /** Was sich geändert hat, als schlichter Text. */
  notes: string;
  /** Tag der Veröffentlichung in Millisekunden seit 1970; null, wenn unbekannt. */
  date: number | null;
}

export interface UpdateProgress {
  /** Geladene Bytes und Größe; die Größe fehlt, wenn der Server sie nicht nennt. */
  done: number;
  total: number | null;
}

// ── Verwaltung in der Seitenleiste: Docker, Dienste, Prozesse (docs/verwaltung.md) ─────────────────────

/** Was es auf dem Server einer Sitzung zu verwalten gibt. */
export interface ManageAbilities {
  /** Die Sitzung ist als root angemeldet. */
  root: boolean;
  docker: boolean;
  services: boolean;
  processes: boolean;
  /** sudo geht ohne Passwort. */
  sudo: boolean;
}

/**
 * Eine Liste vom Server, oder warum es sie nicht gibt: `password` heißt, sie ginge nur mit sudo, und sudo will
 * ein Passwort; `failed` trägt die Meldung des Servers. `sudo`: Die Liste kam nur mit sudo zustande.
 */
export type Listed<T> = { state: 'ok'; items: T; sudo: boolean } | { state: 'password' } | { state: 'failed'; message: string };

/** Ausgang einer Aktion. `password`: sudo will ein Passwort; `command` gehört ins Terminal, der Nutzer schickt ihn ab. */
export type ManageDone = { outcome: 'done' } | { outcome: 'password'; command: string };

export interface DockerContainer {
  /** Die volle Kennung; nur sie geht in Befehle. */
  id: string;
  name: string;
  image: string;
  state: 'running' | 'paused' | 'restarting' | 'exited' | 'created' | 'dead' | 'other';
  health?: 'healthy' | 'unhealthy' | 'starting';
  /** Veröffentlichte Ports, etwa `8080->80/tcp`. */
  ports: string[];
  /** Sekunden, die er läuft; bei einem beendeten die Sekunden seit dem Ende. */
  since?: number;
  exitCode?: number;
  /** Prozent eines Kerns. */
  cpu?: number;
  memory?: { used: number; limit: number };
}

export interface ServiceUnit {
  /** Der volle Name, etwa `cron.service`. */
  unit: string;
  description: string;
  active: 'active' | 'inactive' | 'failed' | 'activating' | 'deactivating' | 'other';
  /** Der feinere Zustand von systemd: `running`, `exited`, `dead` … */
  sub: string;
  /** Ob er beim Start des Servers mitläuft. */
  enabled: 'enabled' | 'disabled' | 'static' | 'masked' | 'other';
}

export interface ProcessInfo {
  pid: number;
  parent: number;
  user: string;
  /** Das Programm ohne Pfad und Argumente. */
  name: string;
  command: string;
  /** Arbeitsspeicher in Bytes. */
  memory: number;
  /** Sekunden, die er läuft. */
  elapsed: number;
  /** Verbrauchte Rechenzeit seit seinem Start, in Ticks. */
  ticks: number;
  /** Ein Faden des Kerns, kein Programm. */
  kernel: boolean;
}

/** Eine Messung der Prozesse. Die Auslastung ergibt sich aus zwei Messungen. */
export interface ProcessSample {
  ticksPerSecond: number;
  /** Sekunden seit dem Start des Servers. */
  uptime: number;
  memoryTotal: number;
  processes: ProcessInfo[];
}

// ── Proxmox (docs/verwaltung.md) ───────────────────────────────────────────────────────────────────────

/** Eine Verbindung zu einem Proxmox-Server. Das Geheimnis des Tokens verlässt den Kern nicht. */
export interface ProxmoxConnection {
  id: string;
  name: string;
  /** `https://pve.example.de:8006` */
  address: string;
  /** `benutzer@realm!name` */
  tokenId: string;
  /** Der bestätigte Fingerabdruck eines selbst erstellten Zertifikats. Fehlt er, muss das Zertifikat anerkannt sein. */
  fingerprint?: string;
  /** Die Identität, mit der sich Glowport an den Maschinen anmeldet, für die Cloud-Init keinen Schlüssel aus dem Tresor nennt. */
  identity?: string;
}

export interface ProxmoxInput {
  id?: string;
  name: string;
  address: string;
  tokenId: string;
  /** Fehlt = bleibt, wie es ist. */
  secret?: string;
  fingerprint?: string;
  /** Fehlt = keine. */
  identity?: string;
}

/**
 * Was eine Prüfung der Angaben ergab. Sie läuft in zwei Schritten: Bei einem selbst erstellten Zertifikat nennt der
 * erste nur den Fingerabdruck (`version` ist leer, der Token ist noch nicht hinausgegangen). Erst wenn die Eingabe
 * genau diesen Fingerabdruck mitbringt, weil der Nutzer ihn bestätigt hat, liest der zweite Version und Rechte.
 */
export interface ProxmoxProbe {
  version: string;
  /** Das Zertifikat ist von sich aus anerkannt (etwa von Let's Encrypt). */
  trusted: boolean;
  /** SHA-256 des Zertifikats, zum Vergleichen mit der Proxmox-Oberfläche. */
  fingerprint: string;
  /** Was dem Token fehlt: sehen, ein- und ausschalten, den Gastagenten fragen. */
  missing: ('audit' | 'power' | 'agent')[];
  /** Der Server zeigt ein anderes Zertifikat als das bisher bestätigte. */
  changed?: boolean;
}

/** Zu welcher Maschine ein Host gehört. */
export interface ProxmoxLink {
  connection: string;
  node: string;
  vmid: number;
  kind: 'qemu' | 'lxc';
}

export interface ProxmoxNode {
  node: string;
  online: boolean;
  /** 0 bis 1 */
  cpu?: number;
  cores?: number;
  memory?: { used: number; total: number };
  uptime?: number;
}

export interface ProxmoxGuest {
  node: string;
  vmid: number;
  /** `qemu`: eine VM. `lxc`: ein Container. */
  kind: 'qemu' | 'lxc';
  name: string;
  status: 'running' | 'stopped' | 'paused' | 'unknown';
  template: boolean;
  /** 0 bis 1 */
  cpu?: number;
  cores?: number;
  memory?: { used: number; total: number };
  uptime?: number;
  tags: string[];
  /** Die Adresse, unter der Glowport die Maschine erreicht, und woher es sie weiß. */
  address?: string;
  source?: 'cloudinit' | 'agent' | 'config' | 'guest';
  user?: string;
  /** Der Schlüssel im Tresor, zu dem ein in Cloud-Init hinterlegter öffentlicher Schlüssel gehört. */
  key?: string;
  keyName?: string;
  os?: string;
  /** Kennung des Hosts, der zu dieser Maschine gehört. */
  host?: string;
}

export interface ProxmoxOverview {
  version: string;
  nodes: ProxmoxNode[];
  guests: ProxmoxGuest[];
}
